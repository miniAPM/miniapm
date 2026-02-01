use std::time::Duration;

use rama::Layer;
use rama::conversion::FromRef;
use rama::graceful::Shutdown;
use rama::http::server::HttpServer;
use rama::http::service::web::{Router, response::Html};
use rama::rt::Executor;

use crate::{DbPool, api, config::Config, jobs, models};

/// Combined state for routes that need both pool and config
#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub config: Config,
}

// Allow extracting DbPool from AppState
impl FromRef<AppState> for DbPool {
    fn from_ref(state: &AppState) -> Self {
        state.pool.clone()
    }
}

// Allow extracting Config from AppState
impl FromRef<AppState> for Config {
    fn from_ref(state: &AppState) -> Self {
        state.config.clone()
    }
}

/// Maximum request body size (10 MB)
#[allow(dead_code)]
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

pub async fn run(pool: DbPool, config: Config, port: u16) -> anyhow::Result<()> {
    // Initialize start time for uptime tracking
    api::health::init_start_time();

    // Always ensure default project exists (collector only)
    let default_project = models::project::ensure_default_project(&pool)?;

    if !config.enable_projects {
        tracing::info!("Single-project mode - API key: {}", default_project.api_key);
    }

    // Start background jobs
    jobs::start(pool.clone(), config.clone());

    let state = AppState {
        pool: pool.clone(),
        config: config.clone(),
    };

    // Build router with API routes only
    let app = Router::new_with_state(state.clone())
        // Health check (no auth)
        .with_get("/health", api::health_handler)
        // Ingestion API (API key auth required)
        .with_sub_router_make_fn("/ingest", |router| {
            router
                .with_post("/deploys", api::ingest_deploys)
                .with_post("/v1/traces", api::ingest_spans)
                .with_post("/errors", api::ingest_errors)
                .with_post("/errors/batch", api::ingest_errors_batch)
        })
        // 404 handler
        .with_not_found(Html("<h1>404 - Collector API Only</h1>".to_owned()));

    let addr = format!("0.0.0.0:{}", port);
    tracing::info!("MiniAPM collector listening on http://{} (API only)", addr);

    // Graceful shutdown setup
    let graceful = Shutdown::default();

    graceful.spawn_task_fn(move |guard| async move {
        let exec = Executor::graceful(guard);

        if let Err(e) = HttpServer::auto(exec).listen(&addr, app).await {
            tracing::error!("Server error: {}", e);
        }
    });

    // Wait for shutdown signal
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received Ctrl+C, starting graceful shutdown...");
        }
        _ = async {
            #[cfg(unix)]
            {
                let mut sigterm = tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::terminate()
                ).expect("Failed to install SIGTERM handler");
                sigterm.recv().await;
            }
            #[cfg(not(unix))]
            {
                std::future::pending::<()>().await;
            }
        } => {
            tracing::info!("Received SIGTERM, starting graceful shutdown...");
        }
    }

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .map_err(|e| anyhow::anyhow!("Graceful shutdown failed: {:?}", e))?;

    tracing::info!("Server shutdown complete");
    Ok(())
}
