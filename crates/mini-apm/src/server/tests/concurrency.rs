use super::*;
use rama::bytes::Bytes;
use rama::http::body::Frame;
use rama::http::body::util::{Channel, StreamBody};
use std::task::{Context, Poll};

/// Signals the first body read, then holds it until completion, failure or cancellation.
fn held_body(
    payload: &'static str,
) -> (
    Body,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let (read, reading) = tokio::sync::oneshot::channel();
    let (finish, mut finished) = tokio::sync::oneshot::channel();
    let mut read = Some(read);
    let mut payload = Some(payload);
    let stream = rama::futures::stream::poll_fn(move |cx: &mut Context<'_>| {
        if let Some(read) = read.take() {
            read.send(()).expect("body-read observer alive");
        }
        if payload.is_none() {
            return Poll::Ready(None);
        }
        match std::pin::Pin::new(&mut finished).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(_) => Poll::Ready(Some(Ok::<_, Infallible>(Frame::data(
                Bytes::from_static(payload.take().unwrap().as_bytes()),
            )))),
        }
    });
    (Body::new(StreamBody::new(stream)), reading, finish)
}

#[tokio::test]
async fn concurrency_is_shared_and_releases_on_cancellation() -> anyhow::Result<()> {
    let pool = db::test_pool().await;
    let project = models::project::ensure_default_project(&pool).await?;
    let other = models::project::create(&pool, "Other").await?;
    let app = make_app(AppState {
        pool: pool.clone(),
        config: Config {
            ingest_max_in_flight: Some(api::admission::InFlightLimit::new(1)?),
            ingest_admission: Some(api::admission::AdmissionConfig::new(0.001, 1, 4096)?),
            ..Config::default()
        },
    });
    let auth = format!("Bearer {}", project.api_key);
    let other_auth = format!("Bearer {}", other.api_key);
    let (body, reading, _finish) = held_body("{}");
    let held = Request::builder()
        .method(Method::POST)
        .uri("/ingest/errors")
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .body(body)?;
    let worker = tokio::spawn({
        let app = app.clone();
        async move { app.serve(held).await }
    });
    tokio::time::timeout(Duration::from_secs(5), reading).await??;
    let response = app
        .serve(post_error(Some(&other_auth), "must not be stored"))
        .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["retry-after"], "1");
    let grpc = Request::builder()
        .method(Method::POST)
        .uri("/opentelemetry.proto.collector.trace.v1.TraceService/Export")
        .header("Authorization", &other_auth)
        .header("Content-Type", "application/grpc")
        .body(Body::empty())?;
    let response = app.serve(grpc).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["grpc-status"], "14");
    assert_eq!(app.serve(get("/health")).await?.status(), StatusCode::OK);
    assert_eq!(
        app.serve(post_error(None, "unauthenticated"))
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());

    // Capacity refusals did not spend the second project's single rate admission.
    assert_eq!(
        app.serve(post_error(Some(&other_auth), "after cancellation"))
            .await?
            .status(),
        StatusCode::ACCEPTED
    );
    // A rate refusal must return its acquired concurrency permit too.
    assert_eq!(
        app.serve(post_error(Some(&other_auth), "rate refused"))
            .await?
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let fresh = models::project::create(&pool, "Fresh").await?;
    let fresh_auth = format!("Bearer {}", fresh.api_key);
    assert_eq!(
        app.serve(post_error(Some(&fresh_auth), "after rate refusal"))
            .await?
            .status(),
        StatusCode::ACCEPTED
    );
    let messages: Vec<String> = sqlx::query_scalar("SELECT message FROM errors ORDER BY id")
        .fetch_all(&pool)
        .await?;
    assert_eq!(messages, ["after cancellation", "after rate refusal"]);
    Ok(())
}

#[tokio::test]
async fn concurrency_releases_when_cancelled_waiting_for_storage() -> anyhow::Result<()> {
    let pool = db::test_pool().await;
    let project = models::project::ensure_default_project(&pool).await?;
    let config = Config {
        ingest_max_in_flight: Some(api::admission::InFlightLimit::new(1)?),
        ..Config::default()
    };
    let app = make_app(AppState {
        pool: pool.clone(),
        config: config.clone(),
    });
    let second_collector = make_app(AppState {
        pool: pool.clone(),
        config,
    });
    let auth = format!("Bearer {}", project.api_key);
    let mut occupied = Vec::new();
    {
        let (body, reading, finish) = held_body(
            r#"{"exception_class":"E","message":"cancelled","backtrace":[],"fingerprint":"fp"}"#,
        );
        let held = Request::builder()
            .method(Method::POST)
            .uri("/ingest/errors")
            .header("Authorization", &auth)
            .header("Content-Type", "application/json")
            .body(body)?;
        let pending = app.serve(held);
        tokio::pin!(pending);
        tokio::select! {
            result = &mut pending => panic!("upload completed before sending its body: {result:?}"),
            result = reading => result?,
        }
        // The other collector owns its own limit even though storage is shared.
        assert_eq!(
            second_collector
                .serve(post_error(Some(&auth), "other collector"))
                .await?
                .status(),
            StatusCode::ACCEPTED
        );
        for _ in 0..pool.options().get_max_connections() {
            occupied.push(pool.acquire().await?);
        }
        assert_eq!(
            occupied.len(),
            usize::try_from(pool.options().get_max_connections())?
        );
        assert_eq!(pool.num_idle(), 0);
        finish.send(()).expect("held request alive");
        // Drive parsing to the pending pool acquisition, then drop the request future.
        std::future::poll_fn(|cx| {
            assert!(pending.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }
    occupied.clear();
    assert_eq!(app.serve(post_json("/ingest/errors", Some(&auth), &serde_json::json!({
                "exception_class": "AfterCancellation", "message": "after storage cancellation", "backtrace": [], "fingerprint": "after",
    }))).await?.status(), StatusCode::ACCEPTED);
    let messages: Vec<String> = sqlx::query_scalar("SELECT message FROM errors ORDER BY id")
        .fetch_all(&pool)
        .await?;
    assert_eq!(messages, ["other collector", "after storage cancellation"]);
    Ok(())
}

#[tokio::test]
async fn concurrency_releases_on_body_and_storage_failures() -> anyhow::Result<()> {
    let pool = db::test_pool().await;
    let project = models::project::ensure_default_project(&pool).await?;
    let app = make_app(AppState {
        pool: pool.clone(),
        config: Config {
            ingest_max_in_flight: Some(api::admission::InFlightLimit::new(1)?),
            ..Config::default()
        },
    });
    let auth = format!("Bearer {}", project.api_key);
    let malformed = Request::builder()
        .method(Method::POST)
        .uri("/ingest/errors")
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .body(Body::from("{"))?;
    assert_eq!(
        app.serve(malformed).await?.status(),
        StatusCode::BAD_REQUEST
    );
    let (sender, body) = Channel::<Bytes, std::io::Error>::new(1);
    sender.abort(std::io::Error::other("interrupted upload"));
    let interrupted = Request::builder()
        .method(Method::POST)
        .uri("/ingest/errors")
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .body(Body::new(body))?;
    assert_eq!(
        app.serve(interrupted).await?.status(),
        StatusCode::BAD_REQUEST
    );
    db::reject_inserts(&pool, "errors", "exception_class", "E").await?;
    assert_eq!(
        app.serve(post_error(Some(&auth), "storage failure"))
            .await?
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    // An empty trace export does not use the deliberately rejected error table.
    assert_eq!(
        app.serve(post_json(
            "/ingest/v1/traces",
            Some(&auth),
            &serde_json::json!({"resourceSpans": []})
        ))
        .await?
        .status(),
        StatusCode::ACCEPTED
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM errors")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 0);
    Ok(())
}
