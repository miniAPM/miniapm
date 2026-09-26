use anyhow::Context;
use mini_apm::{cli, config::Config, db, init_tracing, server};

const USAGE: &str = include_str!("miniapm.usage.kdl");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing("mini_apm=info");

    let args = cli::parse_env(USAGE);
    let port: u16 = cli::value(&args, "port")
        .context("missing --port")?
        .parse()
        .context("--port must be a number from 0 to 65535")?;
    let config = Config::from_env()?;

    // Validate configuration before starting
    config.validate()?;
    config.log_summary();

    let pool = db::init(&config).await?;

    server::run(pool, config, port).await?;

    Ok(())
}
