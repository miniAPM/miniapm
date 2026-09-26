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
    let oversized = "x".repeat(MAX_BODY_SIZE);
    for (auth, message, expected) in [
        (None, "boom", StatusCode::UNAUTHORIZED),
        (Some("Bearer proj_nope"), "boom", StatusCode::UNAUTHORIZED),
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
