use clap::Parser;
use miniapm::{config::Config, db};
use miniapm_admin::{auth_routes, routes};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "miniapm-admin")]
#[command(about = "MiniAPM Admin Dashboard", version)]
struct Cli {
    #[arg(short, long, default_value = "3001")]
    port: u16,
}

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
                .unwrap_or_else(|_| "miniapm-admin=info,tower_http=info".into()),
        )
        .init();

    let config = Config::from_env()?;
    let pool = db::init(&config)?;

    let app = routes(pool.clone())
        .merge(auth_routes())
        .nest_service("/static", tower_http::services::ServeDir::new("static"))
        .with_state(pool);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("MiniAPM Admin listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("Received Ctrl+C, shutting down..."),
        _ = terminate => tracing::info!("Received SIGTERM, shutting down..."),
    }
}
