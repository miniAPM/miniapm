use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tower_cookies::CookieManagerLayer;
use tower_http::trace::TraceLayer;

use crate::{api, config::Config, jobs, models, web, DbPool};

/// Combined state for routes that need both pool and config
#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub config: Config,
}

pub async fn run(pool: DbPool, config: Config, port: u16) -> anyhow::Result<()> {
    // Initialize start time for uptime tracking
    api::health::init_start_time();

    // Initialize default admin user if user accounts are enabled
    if config.enable_user_accounts {
        models::user::ensure_default_admin(&pool)?;
    }

    // Start background jobs
    jobs::start(pool.clone(), config.clone());

    // Build router
    let app = Router::new()
        // Health check (no auth)
        .route("/health", get(api::health_handler))
        // Ingestion API (with API key auth)
        .nest(
            "/ingest",
            Router::new()
                .route("/requests", post(api::ingest_requests))
                .route("/errors", post(api::ingest_errors))
                .route("/deploys", post(api::ingest_deploys))
                .route("/v1/traces", post(api::ingest_spans))
                .layer(middleware::from_fn_with_state(pool.clone(), api::auth_middleware)),
        )
        // Auth routes (always available)
        .merge(web::auth_routes())
        // Web UI (protected when user accounts enabled)
        .merge(web::routes(pool.clone()))
        // Static files
        .nest_service("/static", tower_http::services::ServeDir::new("static"))
        // State and middleware
        .with_state(pool)
        .layer(CookieManagerLayer::new())
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("MiniAPM server listening on http://{}", addr);

    if config.enable_user_accounts {
        tracing::info!("User accounts ENABLED - login required");
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
