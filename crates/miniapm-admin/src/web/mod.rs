mod api_key;
pub mod auth;
mod auth_middleware;
mod dashboard;
mod deploys;
mod errors;
mod performance;
pub mod project_context;
mod projects;
mod traces;

use axum::{
    Router, middleware,
    routing::{get, post},
};

use miniapm::DbPool;

pub fn routes(pool: DbPool) -> Router<DbPool> {
    Router::new()
        .route("/", get(dashboard::index))
        .route("/errors", get(errors::index))
        .route("/errors/:id", get(errors::show))
        .route("/errors/:id/status", post(errors::update_status))
        .route("/traces", get(traces::index))
        .route("/traces/:trace_id", get(traces::show))
        .route("/performance", get(performance::index))
        .route("/deploys", get(deploys::index))
        .route("/projects/switch", post(projects::switch_project))
        .route("/projects", get(projects::index))
        .route("/projects/create", post(projects::create))
        .route("/projects/delete", post(projects::delete))
        .route("/projects/regenerate-key", post(projects::regenerate_key))
        .route("/api-key", get(api_key::index))
        .route("/api-key/regenerate", post(api_key::regenerate))
        .layer(middleware::from_fn_with_state(
            pool,
            auth_middleware::web_auth_middleware,
        ))
}

pub fn auth_routes() -> Router<DbPool> {
    Router::new()
        .route(
            "/auth/login",
            get(auth::login_page).post(auth::login_submit),
        )
        .route("/auth/logout", post(auth::logout))
        .route(
            "/auth/change-password",
            get(auth::change_password_page).post(auth::change_password_submit),
        )
        .route("/auth/users", get(auth::users_page))
        .route("/auth/users/create", post(auth::create_user))
        .route("/auth/users/delete", post(auth::delete_user))
        .route(
            "/auth/invite/{token}",
            get(auth::invite_page).post(auth::invite_submit),
        )
}
