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
    let pool = db::test_pool().await;
    let project = models::project::ensure_default_project(&pool)
        .await
        .unwrap();
    let app = make_app(AppState {
        pool: pool.clone(),
        config: Config::default(),
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
async fn test_routes_summary_stats() {
    let (app, pool, project) = setup().await;
    let now = jiff::Timestamp::now().as_nanosecond() as i64;
    let span = |trace: u32, id: u32, parent: Option<u32>, name: &str, ms: i64| {
        let (kind, attribute, parent) = match parent {
            Some(p) => (
                3,
                r#"{"key":"db.system","value":{"stringValue":"sqlite"}}"#,
                format!(r#""parentSpanId":"{p:016x}","#),
            ),
            None => (
                2,
                r#"{"key":"http.method","value":{"stringValue":"GET"}}"#,
                String::new(),
            ),
        };
        format!(
            r#"{{"traceId":"{trace:032x}","spanId":"{id:016x}",{parent}"name":"{name}","kind":{kind},"startTimeUnixNano":{now},"endTimeUnixNano":{},"attributes":[{attribute}]}}"#,
            now + ms * 1_000_000
        )
    };
    let mut spans = vec![span(9, 90, None, "GET /b", 5)];
    for (i, ms) in [(1, 10), (2, 20), (3, 30)] {
        spans.push(span(i, i * 10, None, "GET /a", ms));
        spans.push(span(i, i * 10 + 1, Some(i * 10), "SELECT", 2));
    }
    let req = Request::builder()
        .method(Method::POST)
        .uri("/ingest/v1/traces")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", project.api_key))
        .body(Body::from(format!(
            r#"{{"resourceSpans":[{{"scopeSpans":[{{"spans":[{}]}}]}}]}}"#,
            spans.join(",")
        )))
        .unwrap();
    assert_eq!(app.serve(req).await.unwrap().status(), StatusCode::ACCEPTED);

    let since = crate::time::rfc3339(crate::time::hours_ago(1));
    let mut routes: Vec<_> =
        models::span::routes_summary(&pool, Some(project.id), &since, None, "requests", 10)
            .await
            .unwrap()
            .into_iter()
            .map(|r| {
                (
                    r.path,
                    r.request_count,
                    r.avg_ms,
                    r.p95_ms,
                    r.p99_ms,
                    r.avg_db_ms,
                    r.avg_db_count,
                )
            })
            .collect();
    routes.sort();
    assert_eq!(
        routes,
        [
            ("GET /a".to_string(), 3, 20, 30, 30, 2, 1),
            ("GET /b".to_string(), 1, 5, 5, 5, 0, 0),
        ]
    );
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

#[tokio::test]
async fn test_ingest_otlp_protobuf_and_grpc() {
    use rama::http::grpc::protobuf::prost::Message;
    use rama::http::grpc::service::opentelemetry::proto::collector::trace::v1::ExportTraceServiceRequest;
    use rama::http::grpc::service::opentelemetry::proto::trace::v1::{
        ResourceSpans, ScopeSpans, Span,
    };

    let (app, pool, project) = setup().await;
    let payload = |id: u8| {
        ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                scope_spans: vec![ScopeSpans {
                    spans: vec![Span {
                        trace_id: vec![0xab; 16],
                        span_id: vec![id; 8],
                        name: "GET /proto".into(),
                        kind: 2,
                        start_time_unix_nano: 1_000_000_000,
                        end_time_unix_nano: 2_000_000_000,
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec()
    };
    let grpc_frame = |message: Vec<u8>| {
        let mut frame = vec![0];
        frame.extend((message.len() as u32).to_be_bytes());
        frame.extend(message);
        frame
    };
    let key = format!("Bearer {}", project.api_key);
    let export = "/opentelemetry.proto.collector.trace.v1.TraceService/Export";

    for (uri, content_type, body, auth, expected) in [
        (
            "/ingest/v1/traces",
            "application/x-protobuf",
            payload(1),
            Some(&key),
            StatusCode::ACCEPTED,
        ),
        (
            "/ingest/v1/traces",
            "application/x-protobuf",
            b"junk".to_vec(),
            Some(&key),
            StatusCode::BAD_REQUEST,
        ),
        (
            export,
            "application/grpc",
            grpc_frame(payload(2)),
            Some(&key),
            StatusCode::OK,
        ),
        (
            export,
            "application/grpc",
            grpc_frame(payload(3)),
            None,
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("Content-Type", content_type)
            .header("te", "trailers");
        if let Some(auth) = auth {
            req = req.header("Authorization", auth.as_str());
        }
        let res = app
            .serve(req.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), expected, "{uri} {content_type}");
    }

    let span_ids: Vec<String> = sqlx::query_scalar("SELECT span_id FROM spans ORDER BY span_id")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(span_ids, ["01".repeat(8), "02".repeat(8)]);
}

#[tokio::test]
async fn test_recurring_error_reopens_unless_ignored() {
    use crate::models::error::{self, ErrorStatusEvent};

    let (app, pool, project) = setup().await;
    let auth = format!("Bearer {}", project.api_key);
    let status = async || -> String {
        sqlx::query_scalar("SELECT status FROM errors")
            .fetch_one(&pool)
            .await
            .unwrap()
    };

    app.serve(post_error(Some(&auth), "boom")).await.unwrap();
    let id: i64 = sqlx::query_scalar("SELECT id FROM errors")
        .fetch_one(&pool)
        .await
        .unwrap();

    for (event, after_event, after_recurrence) in [
        (ErrorStatusEvent::Resolve, "resolved", "open"),
        (ErrorStatusEvent::Ignore, "ignored", "ignored"),
    ] {
        assert_eq!(
            error::apply(&pool, id, event).await.unwrap(),
            Some(after_event)
        );
        app.serve(post_error(Some(&auth), "boom")).await.unwrap();
        assert_eq!(status().await, after_recurrence);
    }
    assert_eq!(
        error::apply(&pool, id, ErrorStatusEvent::Recur)
            .await
            .unwrap(),
        None
    );
}
