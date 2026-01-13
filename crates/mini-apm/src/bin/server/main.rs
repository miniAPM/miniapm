use clap::Parser;
use mini_apm::{config::Config, db, server};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "miniapm")]
#[command(about = "MiniAPM Server", version)]
struct Cli {
    #[arg(short, long, default_value = "3000")]
    port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "miniapm=info,tower_http=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config = Config::from_env()?;
    let pool = db::init(&config)?;

    server::run(pool, config, cli.port).await?;

    Ok(())
}
