use axum::{
    body::Body,
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::env;

use crate::DbPool;

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

    // Check if projects are enabled
    let projects_enabled = env::var("ENABLE_PROJECTS")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);

    if projects_enabled {
        // Try to find project by API key
        match crate::models::project::find_by_api_key(&pool, api_key) {
            Ok(Some(project)) => {
                request
                    .extensions_mut()
                    .insert(ProjectContext { project_id: Some(project.id) });
                return Ok(next.run(request).await);
            }
            Ok(None) => {
                // No matching project - return unauthorized
                return Err(StatusCode::UNAUTHORIZED);
            }
            Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        }
    } else {
        // Single API key mode - verify against settings
        match crate::models::settings::verify_api_key(&pool, api_key) {
            Ok(true) => {
                request
                    .extensions_mut()
                    .insert(ProjectContext { project_id: None });
                return Ok(next.run(request).await);
            }
            Ok(false) => {
                // Also check against env var for backward compatibility
                if let Ok(env_key) = env::var("MINI_APM_API_KEY") {
                    if api_key == env_key {
                        request
                            .extensions_mut()
                            .insert(ProjectContext { project_id: None });
                        return Ok(next.run(request).await);
                    }
                }
                return Err(StatusCode::UNAUTHORIZED);
            }
            Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::get,
        Router,
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
            CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
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
            .layer(middleware::from_fn_with_state(pool.clone(), auth_middleware))
            .with_state(pool)
    }

    #[tokio::test]
    async fn test_auth_requires_authorization_header() {
        let pool = create_test_pool();
        let app = create_app(pool);

        let req = Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();

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
        // Create a valid API key first
        crate::models::settings::get_or_create_api_key(&pool).unwrap();

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
    async fn test_auth_accepts_valid_settings_key() {
        let pool = create_test_pool();
        let api_key = crate::models::settings::get_or_create_api_key(&pool).unwrap();

        let app = create_app(pool);

        let req = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
