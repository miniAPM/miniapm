use clap::{Parser, Subcommand};
use miniapm::{config::Config, db};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "miniapm")]
#[command(about = "MiniAPM CLI", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new API key
    CreateKey {
        /// Name for the API key
        name: String,
    },
    /// List all API keys
    ListKeys,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "miniapm=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config = Config::from_env()?;

    match cli.command {
        Commands::CreateKey { name } => {
            let pool = db::init(&config)?;
            let key = miniapm::models::api_key::create(&pool, &name)?;
            println!("API Key created successfully!\n");
            println!("Name: {}", name);
            println!("Key:  {}", key);
            println!("\nStore this key securely - it cannot be retrieved later.");
        }
        Commands::ListKeys => {
            let pool = db::init(&config)?;
            let keys = miniapm::models::api_key::list(&pool)?;
            if keys.is_empty() {
                println!("No API keys found.");
            } else {
                println!("API Keys:");
                for k in keys {
                    println!(
                        "  - {} (created: {}, last used: {})",
                        k.name,
                        k.created_at,
                        k.last_used_at.as_deref().unwrap_or("never")
                    );
                }
            }
        }
    }

    Ok(())
}
