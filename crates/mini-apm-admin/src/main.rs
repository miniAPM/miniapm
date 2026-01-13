use std::time::Duration;

use mini_apm::{DbPool, config::Config, db, models};
use mini_apm_admin::make_app;
use rama::graceful::Shutdown;
use rama::http::server::HttpServer;
use rama::rt::Executor;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let port = std::env::var("ADMIN_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3001);

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "miniapm-admin=info".into()),
        )
        .init();

    let config = Config::from_env()?;
    let pool = db::init(&config)?;
    models::user::ensure_default_admin(&pool)?;

    run(pool, port).await
}

async fn run(pool: DbPool, port: u16) -> anyhow::Result<()> {
    let app = make_app(pool.clone());

    let addr = format!("0.0.0.0:{}", port);
    tracing::info!("MiniAPM Admin listening on http://{}", addr);

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
