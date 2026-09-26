use super::*;
use crate::db;
use rama::http::{Body, Method, StatusCode};

fn post_error(authorization: Option<&str>) -> Request {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/ingest/errors")
        .header("Content-Type", "application/json");
    if let Some(value) = authorization {
        req = req.header("Authorization", value);
    }
    req.body(Body::from(
        r#"{"exception_class":"E","message":"boom","backtrace":[],"fingerprint":"fp"}"#,
    ))
    .unwrap()
}

#[tokio::test]
async fn test_ingest_requires_project_api_key() {
    let config = Config::default();
    let pool = db::init(&config).await.unwrap();
    let project = models::project::ensure_default_project(&pool)
        .await
        .unwrap();
    let app = make_app(AppState {
        pool: pool.clone(),
        config,
    });

    let health = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.serve(health).await.unwrap().status(), StatusCode::OK);

    let valid = format!("Bearer {}", project.api_key);
    for (auth, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some("Bearer proj_nope"), StatusCode::UNAUTHORIZED),
        (Some(valid.as_str()), StatusCode::ACCEPTED),
    ] {
        let res = app.serve(post_error(auth)).await.unwrap();
        assert_eq!(res.status(), expected, "{auth:?}");
    }

    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM errors WHERE project_id = ?1")
        .bind(project.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, 1, "only the authenticated request is stored");
}
