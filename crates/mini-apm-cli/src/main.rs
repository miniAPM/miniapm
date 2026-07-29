use clap::{Parser, Subcommand};
use mini_apm::{config::Config, db, init_tracing, models};

#[derive(Parser)]
#[command(name = "miniapm-cli")]
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
    /// Reset a user's password
    ResetPassword {
        /// Username to reset password for
        username: String,
        /// New password
        password: String,
    },
    /// List all users
    ListUsers,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing("miniapm=info");

    let cli = Cli::parse();
    let config = Config::from_env()?;

    match cli.command {
        Commands::CreateKey { name } => {
            let pool = db::init(&config)?;
            let key = mini_apm::models::api_key::create(&pool, &name)?;
            println!("API Key created successfully!\n");
            println!("Name: {}", name);
            println!("Key:  {}", key);
            println!("\nStore this key securely - it cannot be retrieved later.");
        }
        Commands::ListKeys => {
            let pool = db::init(&config)?;
            let keys = mini_apm::models::api_key::list(&pool)?;
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
        Commands::ResetPassword { username, password } => {
            let pool = db::init(&config)?;
            match models::user::reset_password(&pool, &username, &password) {
                Ok(()) => {
                    println!("Password reset successfully for user: {}", username);
                }
                Err(e) => {
                    eprintln!("Failed to reset password: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::ListUsers => {
            let pool = db::init(&config)?;
            let users = models::user::list_all(&pool)?;
            if users.is_empty() {
                println!("No users found.");
            } else {
                println!("Users:");
                for u in users {
                    println!(
                        "  - {} (admin: {}, must_change_password: {})",
                        u.username, u.is_admin, u.must_change_password
                    );
                }
            }
        }
    }

    Ok(())
}
