use clap::Parser;
use mini_apm::{config::Config, db, init_tracing, server};

#[derive(Parser)]
#[command(name = "miniapm")]
#[command(about = "MiniAPM Server", version)]
struct Cli {
    #[arg(short, long, default_value = "3000")]
    port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing("mini_apm=info,tower_http=info");

    let cli = Cli::parse();
    let config = Config::from_env()?;

    // Validate configuration before starting
    config.validate()?;
    config.log_summary();

    let pool = db::init(&config)?;

    server::run(pool, config, cli.port).await?;

    Ok(())
}
