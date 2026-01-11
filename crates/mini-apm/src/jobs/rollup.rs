use crate::{DbPool, models::rollup};
use chrono::{Duration, Utc};

pub fn hourly(pool: &DbPool) -> anyhow::Result<()> {
    let conn = pool.get()?;

    // Get previous hour
    let prev_hour = (Utc::now() - Duration::hours(1))
        .format("%Y-%m-%dT%H:00:00Z")
        .to_string();

    // Aggregate requests for the hour
    let mut stmt = conn.prepare(
        r#"
        SELECT path, method,
               COUNT(*) as request_count,
               SUM(total_ms) as total_ms_sum,
               SUM(db_ms) as db_ms_sum,
               SUM(db_count) as db_count_sum
        FROM requests
        WHERE happened_at >= ?1 AND happened_at < datetime(?1, '+1 hour')
        GROUP BY path, method
        "#,
    )?;

    let rollups: Vec<_> = stmt
        .query_map([&prev_hour], |row| {
            Ok(rollup::HourlyRollup {
                id: 0,
                hour: prev_hour.clone(),
                path: row.get(0)?,
                method: row.get(1)?,
                request_count: row.get(2)?,
                error_count: 0,
                total_ms_sum: row.get(3)?,
                total_ms_p50: None,
                total_ms_p95: None,
                total_ms_p99: None,
                db_ms_sum: row.get(4)?,
                db_count_sum: row.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    for r in rollups {
        rollup::insert_hourly(pool, &r)?;
    }

    tracing::debug!("Hourly rollup completed for {}", prev_hour);
    Ok(())
}

pub fn daily(pool: &DbPool) -> anyhow::Result<()> {
    let conn = pool.get()?;

    // Get previous day
    let prev_day = (Utc::now() - Duration::days(1))
        .format("%Y-%m-%d")
        .to_string();

    // Aggregate hourly rollups for the day
    let mut stmt = conn.prepare(
        r#"
        SELECT path, method,
               SUM(request_count) as request_count,
               SUM(error_count) as error_count,
               AVG(total_ms_p50) as avg_p50,
               AVG(total_ms_p95) as avg_p95,
               AVG(total_ms_p99) as avg_p99,
               SUM(db_ms_sum) / SUM(request_count) as avg_db_ms,
               SUM(db_count_sum) / SUM(request_count) as avg_db_count
        FROM rollups_hourly
        WHERE hour >= ?1 AND hour < date(?1, '+1 day')
        GROUP BY path, method
        "#,
    )?;

    let rollups: Vec<_> = stmt
        .query_map([&prev_day], |row| {
            Ok(rollup::DailyRollup {
                id: 0,
                date: prev_day.clone(),
                path: row.get(0)?,
                method: row.get(1)?,
                request_count: row.get(2)?,
                error_count: row.get(3)?,
                total_ms_p50: row.get(4)?,
                total_ms_p95: row.get(5)?,
                total_ms_p99: row.get(6)?,
                avg_db_ms: row.get(7)?,
                avg_db_count: row.get(8)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    for r in rollups {
        rollup::insert_daily(pool, &r)?;
    }

    tracing::debug!("Daily rollup completed for {}", prev_day);
    Ok(())
}
