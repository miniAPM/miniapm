use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
};
use std::net::SocketAddr;
use tokio::signal;
use tower_cookies::CookieManagerLayer;
use tower_http::trace::TraceLayer;

use crate::{DbPool, api, config::Config, jobs, models, web};

/// Combined state for routes that need both pool and config
#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub config: Config,
}

/// Maximum request body size (10 MB)
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

pub async fn run(pool: DbPool, config: Config, port: u16) -> anyhow::Result<()> {
    // Initialize start time for uptime tracking
    api::health::init_start_time();

    // Always ensure default project and admin exist
    // When features are disabled, we just skip the UI/auth, not the data
    let default_project = models::project::ensure_default_project(&pool)?;
    models::user::ensure_default_admin(&pool)?;

    if !config.enable_projects {
        tracing::info!("Single-project mode - API key: {}", default_project.api_key);
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
                .route("/deploys", post(api::ingest_deploys))
                .route("/v1/traces", post(api::ingest_spans))
                .route("/errors", post(api::ingest_errors))
                .route("/errors/batch", post(api::ingest_errors_batch))
                .layer(middleware::from_fn_with_state(
                    pool.clone(),
                    api::auth_middleware,
                )),
        )
        // Auth routes (always available)
        .merge(web::auth_routes())
        // Web UI (protected when user accounts enabled)
        .merge(web::routes(pool.clone()))
        // Static files
        .nest_service("/static", tower_http::services::ServeDir::new("static"))
        // State and middleware
        .with_state(pool)
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
        .layer(CookieManagerLayer::new())
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("MiniAPM server listening on http://{}", addr);

    if config.enable_user_accounts {
        tracing::info!("User accounts ENABLED - login required");
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;

    // Graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("Server shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, starting graceful shutdown...");
        }
        _ = terminate => {
            tracing::info!("Received SIGTERM, starting graceful shutdown...");
        }
    }
}
