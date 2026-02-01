pub mod web;

mod cookies;
mod template;

use rama::Layer;
use rama::conversion::FromRef;
use rama::http::service::web::{Router, response::Html};

use mini_apm::DbPool;

/// Combined state for routes that need pool
#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
}

// Allow extracting DbPool from AppState
impl FromRef<AppState> for DbPool {
    fn from_ref(state: &AppState) -> Self {
        state.pool.clone()
    }
}

pub fn make_app(
    pool: DbPool,
) -> mini_apm::api::rate_limit::RateLimitService<
    web::security_headers::SecurityHeadersService<
        web::auth_middleware::WebAuthService<Router<AppState>>,
    >,
> {
    let state = AppState { pool };

    let app = Router::new_with_state(state.clone())
        // Auth routes (no auth middleware needed)
        .with_get("/auth/login", web::auth::login_page)
        .with_post("/auth/login", web::auth::login_submit)
        .with_post("/auth/logout", web::auth::logout)
        .with_get("/auth/invite/{token}", web::auth::invite_page)
        .with_post("/auth/invite/{token}", web::auth::invite_submit)
        .with_get("/auth/change-password", web::auth::change_password_page)
        .with_post("/auth/change-password", web::auth::change_password_submit)
        .with_get("/auth/users", web::auth::users_page)
        .with_post("/auth/users/create", web::auth::create_user)
        .with_post("/auth/users/delete", web::auth::delete_user)
        // Protected Web UI routes
        .with_get("/", web::dashboard::index)
        .with_get("/errors", web::errors::index)
        .with_get("/errors/{id}", web::errors::show)
        .with_post("/errors/{id}/status", web::errors::update_status)
        .with_get("/traces", web::traces::index)
        .with_get("/traces/{trace_id}", web::traces::show)
        .with_get("/performance", web::performance::index)
        .with_get("/deploys", web::deploys::index)
        .with_post("/projects/switch", web::projects::switch_project)
        .with_get("/projects", web::projects::index)
        .with_post("/projects/create", web::projects::create)
        .with_post("/projects/delete", web::projects::delete)
        .with_post("/projects/regenerate-key", web::projects::regenerate_key)
        .with_get("/api-key", web::api_key::index)
        .with_post("/api-key/regenerate", web::api_key::regenerate)
        // Static files
        .with_dir("/static", "./static")
        // 404 handler
        .with_not_found(Html("<h1>404 Not Found</h1>".to_owned()));

    // Apply middleware layers (outermost first)
    // Auth middleware checks authentication
    let auth_layer = web::auth_middleware::WebAuthMiddleware::new(state.clone());
    let with_auth = auth_layer.layer(app);

    // Security headers middleware adds security headers to all responses
    let security_layer = web::security_headers::SecurityHeadersMiddleware::new();
    let with_security = security_layer.layer(with_auth);

    // Rate limiting middleware (100 requests per minute per IP)
    let rate_limit = mini_apm::api::RateLimitMiddleware::with_defaults();
    rate_limit.layer(with_security)
}
