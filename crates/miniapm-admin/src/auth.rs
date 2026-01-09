use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode, header},
    middleware::Next,
    response::Response,
};

use miniapm::{DbPool, models};

/// Holds project information extracted from API key authentication
#[derive(Clone, Debug)]
pub struct ProjectContext {
    pub project_id: Option<i64>,
}

pub async fn auth_middleware(
    State(pool): State<DbPool>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let api_key = match auth_header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => return Err(StatusCode::UNAUTHORIZED),
    };

    // Always authenticate against project API keys
    // A default project is always created on startup
    match models::project::find_by_api_key(&pool, api_key) {
        Ok(Some(project)) => {
            request.extensions_mut().insert(ProjectContext {
                project_id: Some(project.id),
            });
            Ok(next.run(request).await)
        }
        Ok(None) => Err(StatusCode::UNAUTHORIZED),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::get,
    };
    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;
    use tower::util::ServiceExt;

    fn create_test_pool() -> DbPool {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder().max_size(1).build(manager).unwrap();

        let conn = pool.get().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE projects (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                slug TEXT NOT NULL UNIQUE,
                api_key TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );
            "#,
        )
        .unwrap();

        pool
    }

    async fn handler() -> &'static str {
        "ok"
    }

    fn create_app(pool: DbPool) -> Router {
        Router::new()
            .route("/test", get(handler))
            .layer(middleware::from_fn_with_state(
                pool.clone(),
                auth_middleware,
            ))
            .with_state(pool)
    }

    #[tokio::test]
    async fn test_auth_requires_authorization_header() {
        let pool = create_test_pool();
        let app = create_app(pool);

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_requires_bearer_prefix() {
        let pool = create_test_pool();
        let app = create_app(pool);

        let req = Request::builder()
            .uri("/test")
            .header("Authorization", "Basic xyz")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_rejects_invalid_key() {
        let pool = create_test_pool();
        // Create a valid project API key first
        crate::models::project::ensure_default_project(&pool).unwrap();

        let app = create_app(pool);

        let req = Request::builder()
            .uri("/test")
            .header("Authorization", "Bearer wrong_key")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_accepts_valid_project_key() {
        let pool = create_test_pool();
        let project = crate::models::project::ensure_default_project(&pool).unwrap();

        let app = create_app(pool);

        let req = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {}", project.api_key))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
