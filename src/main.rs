use clap::{Parser, Subcommand};
use miniapm::{config::Config, db, server, simulator};
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
    /// Run database migrations
    Migrate,
    /// Create a new API key
    CreateKey {
        /// Name for the API key
        name: String,
    },
    /// List all API keys
    ListKeys,
    /// Run the data simulator
    Simulate {
        #[arg(short, long, default_value = "60")]
        requests_per_minute: u32,
        #[arg(short, long, default_value = "0.02")]
        error_rate: f64,
        #[arg(long)]
        backfill: bool,
        #[arg(long, default_value = "7")]
        days: u32,
        /// Run only once instead of continuously
        #[arg(long)]
        once: bool,
    },
    /// Start the MCP server (stdio)
    Mcp,
    /// Print MCP configuration for Claude Desktop
    McpConfig,
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
        Some(Commands::Migrate) => {
            let _pool = db::init(&config)?;
            tracing::info!("Database migrated successfully");
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
        Some(Commands::Simulate {
            requests_per_minute,
            error_rate,
            backfill,
            days,
            once,
        }) => {
            // Get API key from database if not set via env var
            let mut config = config;
            if config.api_key.is_none() {
                let pool = db::init(&config)?;
                let default_project = miniapm::models::project::ensure_default_project(&pool)?;
                config.api_key = Some(default_project.api_key);
                tracing::info!("Using API key from default project");
            }

            if backfill {
                simulator::backfill(&config, days, requests_per_minute * 60 * 24).await?;
            } else {
                simulator::run(&config, requests_per_minute, error_rate, !once).await?;
            }
        }
        Some(Commands::Mcp) => {
            let pool = db::init(&config)?;
            miniapm::mcp::run(pool).await?;
        }
        Some(Commands::McpConfig) => {
            let exe_path = std::env::current_exe()?;
            let pool = db::init(&config)?;
            let default_project = miniapm::models::project::ensure_default_project(&pool)?;

            println!("# MCP Configuration for MiniAPM\n");
            println!("## Option 1: Stdio (for Claude Desktop)\n");
            println!("Add to ~/.config/claude/claude_desktop_config.json:\n");

            let stdio_config = serde_json::json!({
                "mcpServers": {
                    "miniapm": {
                        "command": exe_path.to_string_lossy(),
                        "args": ["mcp"],
                        "env": {
                            "SQLITE_PATH": config.sqlite_path
                        }
                    }
                }
            });
            println!("{}\n", serde_json::to_string_pretty(&stdio_config)?);

            println!("## Option 2: HTTP (for remote access)\n");
            println!("Endpoint: POST {}/mcp", config.mini_apm_url);
            println!("Authorization: Bearer {}\n", default_project.api_key);
            println!("Example request:");
            println!("```bash");
            println!("curl -X POST {}/mcp \\", config.mini_apm_url);
            println!("  -H 'Authorization: Bearer {}' \\", default_project.api_key);
            println!("  -H 'Content-Type: application/json' \\");
            println!("  -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}}'");
            println!("```");
        }
        None => {
            // Default to server
            let pool = db::init(&config)?;
            server::run(pool, config, 3000).await?;
        }
    }

    Ok(())
}
