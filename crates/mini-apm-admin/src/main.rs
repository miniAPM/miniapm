use mini_apm::self_monitor::SelfMonitor;
use mini_apm::server::serve_with_graceful_shutdown;
use mini_apm::{DbPool, config::Config, db, init_tracing, models};
use mini_apm_admin::make_app;

mod port;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let port = port::from_env()?;

    // Binary, admin library, and shared collector library targets
    init_tracing("miniapm_admin=info,mini_apm_admin=info,mini_apm=info");
    mini_apm::api::health::init_start_time();

    let config = Config::from_env()?;

    // Validate configuration before starting
    config.validate()?;
    config.log_summary();

    let pool = db::init(&config).await?;
    models::user::ensure_default_admin(&pool).await?;
    models::project::ensure_default_project(&pool).await?;

    // MiniAPM records its own requests and errors into the `self` project
    let self_project = models::project::ensure_self_project(&pool).await?;
    let (monitor, writer) = SelfMonitor::start(pool.clone(), self_project.id, "miniapm-admin");
    monitor.install();

    let result = run(pool.clone(), port).await;
    if let Err(error) = writer.shutdown().await {
        tracing::warn!(%error, "Self-monitor shutdown incomplete");
    }
    pool.close().await;
    result
}

async fn run(pool: DbPool, port: u16) -> anyhow::Result<()> {
    let app = make_app(pool.clone())?;

    let addr = format!("0.0.0.0:{port}");
    tracing::info!("MiniAPM Admin listening on http://{}", addr);

    serve_with_graceful_shutdown(addr, app).await
}
