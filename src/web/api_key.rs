use askama::Template;
use axum::{
    extract::State,
    response::{IntoResponse, Redirect},
};
use tower_cookies::Cookies;

use crate::{models::settings, DbPool};

use super::project_context::{get_project_context, WebProjectContext};

#[derive(Template)]
#[template(path = "api_key/index.html")]
pub struct ApiKeyTemplate {
    pub api_key: String,
    pub ctx: WebProjectContext,
}

pub async fn index(
    State(pool): State<DbPool>,
    cookies: Cookies,
) -> ApiKeyTemplate {
    let ctx = get_project_context(&pool, &cookies);

    // Get or create the API key
    let api_key = settings::get_or_create_api_key(&pool)
        .unwrap_or_else(|_| "Error loading API key".to_string());

    ApiKeyTemplate { api_key, ctx }
}

pub async fn regenerate(
    State(pool): State<DbPool>,
) -> impl IntoResponse {
    let _ = settings::regenerate_api_key(&pool);
    Redirect::to("/api-key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::{get, post},
        Router,
    };
    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;
    use tower::util::ServiceExt;
    use tower_cookies::CookieManagerLayer;

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

    fn create_app(pool: DbPool) -> Router {
        Router::new()
            .route("/api-key", get(index))
            .route("/api-key/regenerate", post(regenerate))
            .layer(CookieManagerLayer::new())
            .with_state(pool)
    }

    #[tokio::test]
    async fn test_api_key_index_creates_key_if_missing() {
        let pool = create_test_pool();
        let app = create_app(pool.clone());

        let req = Request::builder()
            .uri("/api-key")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Verify key was created
        let key = settings::get_api_key(&pool).unwrap();
        assert!(key.is_some());
        assert!(key.unwrap().starts_with("mapm_"));
    }

    #[tokio::test]
    async fn test_api_key_regenerate() {
        let pool = create_test_pool();
        let original_key = settings::get_or_create_api_key(&pool).unwrap();

        let app = create_app(pool.clone());

        let req = Request::builder()
            .method("POST")
            .uri("/api-key/regenerate")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        // Verify key was regenerated
        let new_key = settings::get_api_key(&pool).unwrap().unwrap();
        assert_ne!(original_key, new_key);
        assert!(new_key.starts_with("mapm_"));
    }
}
