use crate::{
    DbPool,
    config::Config,
    models::{self, deploy},
};
use chrono::{Duration, Utc};

pub fn cleanup(pool: &DbPool, config: &Config) -> anyhow::Result<()> {
    // Delete old spans
    let spans_cutoff = (Utc::now() - Duration::days(config.retention_days_spans)).to_rfc3339();
    let deleted_spans = models::span::delete_before(pool, &spans_cutoff)?;
    tracing::info!("Deleted {} old spans", deleted_spans);

    // Delete old error occurrences
    let errors_cutoff = (Utc::now() - Duration::days(config.retention_days_errors)).to_rfc3339();
    let deleted_occurrences = models::error::delete_occurrences_before(pool, &errors_cutoff)?;
    tracing::info!("Deleted {} old error occurrences", deleted_occurrences);

    // Delete old hourly rollups
    let hourly_cutoff =
        (Utc::now() - Duration::days(config.retention_days_hourly_rollups)).to_rfc3339();
    let deleted_hourly = models::rollup::delete_hourly_before(pool, &hourly_cutoff)?;
    tracing::info!("Deleted {} old hourly rollups", deleted_hourly);

    // Delete old deploys (keep for 90 days)
    let deploys_cutoff = (Utc::now() - Duration::days(90)).to_rfc3339();
    let deleted_deploys = deploy::delete_before(pool, &deploys_cutoff)?;
    tracing::info!("Deleted {} old deploys", deleted_deploys);

    // Vacuum on Sundays
    if Utc::now().format("%u").to_string() == "7" {
        let conn = pool.get()?;
        conn.execute_batch("VACUUM")?;
        tracing::info!("Database vacuumed");
    }

    Ok(())
}
