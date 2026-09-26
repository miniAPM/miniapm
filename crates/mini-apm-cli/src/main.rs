use anyhow::Context;
use mini_apm::{cli, config::Config, db, init_tracing, models};

#[cfg(test)]
mod tests;

const USAGE: &str = include_str!("miniapm-cli.usage.kdl");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing("miniapm=info");

    let args = cli::parse_env(USAGE);
    let arg = |name: &'static str| cli::value(&args, name).context(name);
    let config = Config::from_env()?;

    match args.cmd.name.as_str() {
        "create-key" => {
            let name = arg("name")?;
            let pool = db::init(&config).await?;
            let key = mini_apm::models::api_key::create(&pool, name).await?;
            println!("API Key created successfully!\n");
            println!("Name: {}", name);
            println!("Key:  {}", key);
            println!("\nStore this key securely - it cannot be retrieved later.");
        }
        "list-keys" => {
            let pool = db::init(&config).await?;
            let keys = mini_apm::models::api_key::list(&pool).await?;
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
        "reset-password" => {
            let (username, password) = (arg("username")?, arg("password")?);
            let pool = db::init(&config).await?;
            match models::user::reset_password(&pool, username, password).await {
                Ok(()) => {
                    println!("Password reset successfully for user: {}", username);
                }
                Err(e) => {
                    eprintln!("Failed to reset password: {}", e);
                    std::process::exit(1);
                }
            }
        }
        "list-users" => {
            let pool = db::init(&config).await?;
            let users = models::user::list_all(&pool).await?;
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
        other => anyhow::bail!("unknown command: {other}"),
    }

    Ok(())
}
