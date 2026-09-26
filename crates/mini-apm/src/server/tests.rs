use super::*;
use crate::db;
use rama::http::{Body, Method, StatusCode};

fn post_error(authorization: Option<&str>, message: &str) -> Request {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/ingest/errors")
        .header("Content-Type", "application/json");
    if let Some(value) = authorization {
        req = req.header("Authorization", value);
    }
    req.body(Body::from(format!(
        r#"{{"exception_class":"E","message":"{message}","backtrace":[],"fingerprint":"fp"}}"#
    )))
    .unwrap()
}

fn get(uri: &str) -> Request {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

async fn setup() -> (
    impl Service<Request, Output = Response, Error = Infallible>,
    DbPool,
    models::project::Project,
) {
    let config = Config::default();
    let pool = db::init(&config).await.unwrap();
    let project = models::project::ensure_default_project(&pool)
        .await
        .unwrap();
    let app = make_app(AppState {
        pool: pool.clone(),
        config,
    });
    (app, pool, project)
}

#[tokio::test]
async fn test_collector_routes() {
    let (app, pool, project) = setup().await;

    assert_eq!(
        app.serve(get("/health")).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        app.serve(get("/nope")).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );

    let valid = format!("Bearer {}", project.api_key);
    let self_project = models::project::ensure_self_project(&pool).await.unwrap();
    let self_key = format!("Bearer {}", self_project.api_key);
    let oversized = "x".repeat(MAX_BODY_SIZE);
    for (auth, message, expected) in [
        (None, "boom", StatusCode::UNAUTHORIZED),
        (Some("Bearer proj_nope"), "boom", StatusCode::UNAUTHORIZED),
        (Some(self_key.as_str()), "boom", StatusCode::UNAUTHORIZED),
        (Some(valid.as_str()), "boom", StatusCode::ACCEPTED),
        (
            Some(valid.as_str()),
            oversized.as_str(),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let res = app.serve(post_error(auth, message)).await.unwrap();
        assert_eq!(res.status(), expected, "{auth:?} ({} bytes)", message.len());
    }

    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM errors WHERE project_id = ?1")
        .bind(project.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        stored, 1,
        "only the authenticated, in-limit request is stored"
    );
}

#[tokio::test]
async fn test_errors_from_one_location_share_a_group() {
    let (app, pool, project) = setup().await;
    let auth = format!("Bearer {}", project.api_key);

    for message in ["boom", "completely unrelated failure"] {
        let res = app.serve(post_error(Some(&auth), message)).await.unwrap();
        assert_eq!(res.status(), StatusCode::ACCEPTED, "{message}");
    }

    let (groups, occurrences): (i64, i64) =
        sqlx::query_as("SELECT COUNT(*), SUM(occurrence_count) FROM errors WHERE project_id = ?1")
            .bind(project.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((groups, occurrences), (1, 2));
}

#[tokio::test]
async fn test_routes_summary_for_route_without_db_spans() {
    let (app, pool, project) = setup().await;
    let start = jiff::Timestamp::now().as_nanosecond();
    let span = format!(
        r#"{{"traceId":"0af7651916cd43dd8448eb211c80319c","spanId":"b7ad6b7169203331","name":"GET /users","kind":2,"startTimeUnixNano":"{start}","endTimeUnixNano":"{}","attributes":[{{"key":"http.method","value":{{"stringValue":"GET"}}}}]}}"#,
        start + 1_000_000
    );
    let req = Request::builder()
        .method(Method::POST)
        .uri("/ingest/v1/traces")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", project.api_key))
        .body(Body::from(format!(
            r#"{{"resourceSpans":[{{"scopeSpans":[{{"spans":[{span}]}}]}}]}}"#
        )))
        .unwrap();
    assert_eq!(app.serve(req).await.unwrap().status(), StatusCode::ACCEPTED);

    let since = crate::time::rfc3339(crate::time::hours_ago(1));
    let routes =
        models::span::routes_summary(&pool, Some(project.id), &since, None, "requests", 10)
            .await
            .unwrap();
    assert_eq!(routes.len(), 1);
}

#[tokio::test]
async fn test_ingest_validates_payloads() {
    let (app, pool, project) = setup().await;
    let span = |id: u8, start: &str| {
        format!(
            r#"{{"resourceSpans":[{{"scopeSpans":[{{"spans":[{{"traceId":"0af7651916cd43dd8448eb211c80319c","spanId":"b7ad6b716920333{id}","name":"x","startTimeUnixNano":{start},"endTimeUnixNano":"2000000000"}}]}}]}}]}}"#
        )
    };

    for (uri, body, expected) in [
        (
            "/ingest/v1/traces",
            span(1, "1000000000"),
            StatusCode::ACCEPTED,
        ),
        (
            "/ingest/v1/traces",
            span(2, r#""1000000000""#),
            StatusCode::ACCEPTED,
        ),
        (
            "/ingest/v1/traces",
            span(3, r#""soon""#),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/ingest/deploys",
            r#"{"git_sha":"a","timestamp":"2026-09-26T10:49:01Z"}"#.into(),
            StatusCode::ACCEPTED,
        ),
        (
            "/ingest/deploys",
            r#"{"git_sha":"b","timestamp":"yesterday"}"#.into(),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", project.api_key))
            .body(Body::from(body.clone()))
            .unwrap();
        assert_eq!(app.serve(req).await.unwrap().status(), expected, "{body}");
    }

    let trace_ids: Vec<String> = sqlx::query_scalar("SELECT DISTINCT trace_id FROM spans")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(trace_ids, ["0af7651916cd43dd8448eb211c80319c"]);

    let deployed_at: String = sqlx::query_scalar("SELECT deployed_at FROM deploys")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(deployed_at, "2026-09-26T10:49:01+00:00");
}
