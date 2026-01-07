use clap::{Parser, Subcommand};
use miniapm::{config::Config, db, server};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "miniapm")]
#[command(about = "Minimal APM for Rails", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the MiniAPM server
    Server {
        #[arg(short, long, default_value = "3000")]
        port: u16,
    },
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
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "miniapm=info,tower_http=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config = Config::from_env()?;

    match cli.command {
        Some(Commands::Server { port }) => {
            let pool = db::init(&config)?;
            server::run(pool, config, port).await?;
        }
        Some(Commands::CreateKey { name }) => {
            let pool = db::init(&config)?;
            let key = miniapm::models::api_key::create(&pool, &name)?;
            println!("API Key created successfully!\n");
            println!("Name: {}", name);
            println!("Key:  {}", key);
            println!("\nStore this key securely - it cannot be retrieved later.");
        }
        Some(Commands::ListKeys) => {
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
        None => {
            // Default to server
            let pool = db::init(&config)?;
            server::run(pool, config, 3000).await?;
        }
    }

    Ok(())
}
