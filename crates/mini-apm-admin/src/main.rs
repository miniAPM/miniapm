use mini_apm::server::serve_with_graceful_shutdown;
use mini_apm::{DbPool, config::Config, db, init_tracing, models};
use mini_apm_admin::make_app;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let port = std::env::var("ADMIN_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3001);

    init_tracing("mini_apm_admin=info");
    mini_apm::api::health::init_start_time();

    let config = Config::from_env()?;

    // Validate configuration before starting
    config.validate()?;
    config.log_summary();

    let pool = db::init(&config).await?;
    models::user::ensure_default_admin(&pool).await?;

    run(pool, port).await
}

async fn run(pool: DbPool, port: u16) -> anyhow::Result<()> {
    let app = make_app(pool.clone());

    let addr = format!("0.0.0.0:{}", port);
    tracing::info!("MiniAPM Admin listening on http://{}", addr);

    serve_with_graceful_shutdown(addr, app).await
}
