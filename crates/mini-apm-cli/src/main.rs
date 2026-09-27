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
        "list-projects" => {
            let pool = db::init(&config).await?;
            println!("Projects:");
            for p in models::project::list_all(&pool).await? {
                if p.slug != models::project::SELF_SLUG {
                    println!("  - {} ({}): {}", p.name, p.slug, p.api_key);
                }
            }
        }
        "regenerate-key" => {
            let slug = arg("project")?;
            let pool = db::init(&config).await?;
            let project = models::project::find_by_slug(&pool, slug)
                .await?
                .filter(|p| p.slug != models::project::SELF_SLUG)
                .with_context(|| format!("no project with slug `{slug}`"))?;
            let key = models::project::regenerate_api_key(&pool, project.id).await?;
            println!("New API key for {}: {}", project.name, key);
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
