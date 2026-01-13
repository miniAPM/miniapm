//! API key authentication middleware for rama
//!
//! Validates Bearer token authentication and injects ProjectContext
//! into request extensions for downstream handlers.

use std::future::Future;

use rama::Layer;
use rama::extensions::ExtensionsMut;
use rama::http::header::AUTHORIZATION;
use rama::http::{Body, Request, Response, StatusCode};
use rama::service::Service;

use crate::server::AppState;

/// Holds project information extracted from API key authentication
#[derive(Clone, Debug)]
pub struct ProjectContext {
    pub project_id: Option<i64>,
}

/// Layer that applies API key authentication
#[derive(Clone)]
pub struct ApiKeyAuthMiddleware {
    state: AppState,
}

impl ApiKeyAuthMiddleware {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

impl<S> Layer<S> for ApiKeyAuthMiddleware {
    type Service = ApiKeyAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ApiKeyAuthService {
            inner,
            state: self.state.clone(),
        }
    }
}

/// Service that validates API key and injects ProjectContext
#[derive(Clone)]
pub struct ApiKeyAuthService<S> {
    inner: S,
    state: AppState,
}

impl<S> Service<Request> for ApiKeyAuthService<S>
where
    S: Service<Request, Output = Response, Error = std::convert::Infallible>
        + Clone
        + Send
        + Sync
        + 'static,
{
    type Output = Response;
    type Error = std::convert::Infallible;

    fn serve(
        &self,
        mut req: Request,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send {
        let inner = self.inner.clone();
        let pool = self.state.pool.clone();

        async move {
            // Extract Authorization header
            let auth_header = req
                .headers()
                .get(AUTHORIZATION)
                .and_then(|h| h.to_str().ok());

            let api_key = match auth_header {
                Some(h) if h.starts_with("Bearer ") => &h[7..],
                _ => {
                    return Ok(Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(Body::empty())
                        .unwrap());
                }
            };

            // Validate API key against database
            match crate::models::project::find_by_api_key(&pool, api_key) {
                Ok(Some(project)) => {
                    req.extensions_mut().insert(ProjectContext {
                        project_id: Some(project.id),
                    });
                    inner.serve(req).await
                }
                Ok(None) => Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Body::empty())
                    .unwrap()),
                Err(e) => {
                    tracing::error!("Database error validating API key: {}", e);
                    Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::empty())
                        .unwrap())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DbPool;
    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;
    use rama::service::Service;

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

    fn create_test_config() -> crate::config::Config {
        crate::config::Config {
            sqlite_path: ":memory:".to_string(),
            api_key: None,
            retention_days_errors: 30,
            retention_days_hourly_rollups: 90,
            retention_days_spans: 7,
            slow_request_threshold_ms: 500.0,
            mini_apm_url: "http://localhost:3000".to_string(),
            enable_user_accounts: false,
            enable_projects: false,
            session_secret: "test_secret".to_string(),
        }
    }

    fn create_app(
        pool: DbPool,
    ) -> impl Service<Request, Output = Response, Error = std::convert::Infallible> {
        let config = create_test_config();
        let state = AppState { pool, config };

        // Create a simple service that handles the test route
        let test_service =
            rama::service::BoxService::new(rama::service::service_fn(|req: Request| async move {
                let uri = req.uri();
                if uri.path() == "/test" {
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::from("ok"))
                        .unwrap())
                } else {
                    Ok(Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Body::empty())
                        .unwrap())
                }
            }));

        ApiKeyAuthMiddleware::new(state).layer(test_service)
    }

    #[tokio::test]
    async fn test_auth_requires_authorization_header() {
        let pool = create_test_pool();
        let app = create_app(pool);

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.serve(req).await.unwrap();
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

        let response = app.serve(req).await.unwrap();
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

        let response = app.serve(req).await.unwrap();
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

        let response = app.serve(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
