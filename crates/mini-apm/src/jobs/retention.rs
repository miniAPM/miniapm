use crate::time;
use crate::{DbPool, config::Config, db, models::user};

pub async fn cleanup(pool: &DbPool, config: &Config) -> anyhow::Result<()> {
    db::maintain(pool).await?;
    for (table, column, days) in [
        ("spans", "happened_at", config.retention_days_spans),
        (
            "error_occurrences",
            "happened_at",
            config.retention_days_errors,
        ),
        ("deploys", "deployed_at", 90),
    ] {
        db::expire(pool, table, column, time::days_ago(days)).await?;
    }

    // Delete expired invite tokens (users who never activated)
    let deleted_invites = user::delete_expired_invites(pool).await?;
    if deleted_invites > 0 {
        tracing::info!("Deleted {} expired invite tokens", deleted_invites);
    }

    Ok(())
}

#[cfg(test)]
mod tests;
