use crate::time;
use crate::{DbPool, models::rollup};
use jiff::Timestamp;

pub async fn hourly(pool: &DbPool) -> anyhow::Result<()> {
    // Get previous hour boundaries
    // Use SQLite-compatible format (space separator) for datetime() function compatibility
    let prev_hour_start = time::hours_ago(1).strftime("%Y-%m-%d %H:00:00").to_string();
    let prev_hour_end = Timestamp::now().strftime("%Y-%m-%d %H:00:00").to_string();

    // Aggregate requests for the hour
    // Use explicit start/end times to avoid datetime() format issues
    let rows: Vec<(String, String, i64, f64, f64, i64)> = sqlx::query_as(
        r#"
        SELECT path, method,
               COUNT(*) as request_count,
               SUM(total_ms) as total_ms_sum,
               SUM(db_ms) as db_ms_sum,
               SUM(db_count) as db_count_sum
        FROM requests
        WHERE datetime(happened_at) >= datetime(?1)
          AND datetime(happened_at) < datetime(?2)
        GROUP BY path, method
        "#,
    )
    .bind(&prev_hour_start)
    .bind(&prev_hour_end)
    .fetch_all(pool)
    .await?;

    let rollups: Vec<rollup::HourlyRollup> = rows
        .into_iter()
        .map(
            |(path, method, request_count, total_ms_sum, db_ms_sum, db_count_sum)| {
                rollup::HourlyRollup {
                    id: 0,
                    hour: prev_hour_start.clone(),
                    path,
                    method,
                    request_count,
                    error_count: 0,
                    total_ms_sum,
                    total_ms_p50: None,
                    total_ms_p95: None,
                    total_ms_p99: None,
                    db_ms_sum,
                    db_count_sum,
                }
            },
        )
        .collect();

    for r in rollups {
        rollup::insert_hourly(pool, &r).await?;
    }

    tracing::debug!("Hourly rollup completed for {}", prev_hour_start);
    Ok(())
}

pub async fn daily(pool: &DbPool) -> anyhow::Result<()> {
    // Get previous day
    let prev_day = time::days_ago(1).strftime("%Y-%m-%d").to_string();

    // Aggregate hourly rollups for the day
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        String,
        i64,
        i64,
        Option<f64>,
        Option<f64>,
        Option<f64>,
        Option<f64>,
        Option<f64>,
    )> = sqlx::query_as(
        r#"
        SELECT path, method,
               SUM(request_count) as request_count,
               SUM(error_count) as error_count,
               AVG(total_ms_p50) as avg_p50,
               AVG(total_ms_p95) as avg_p95,
               AVG(total_ms_p99) as avg_p99,
               SUM(db_ms_sum) / SUM(request_count) as avg_db_ms,
               CAST(SUM(db_count_sum) AS REAL) / SUM(request_count) as avg_db_count
        FROM rollups_hourly
        WHERE hour >= ?1 AND hour < date(?1, '+1 day')
        GROUP BY path, method
        "#,
    )
    .bind(&prev_day)
    .fetch_all(pool)
    .await?;

    let rollups: Vec<rollup::DailyRollup> = rows
        .into_iter()
        .map(
            |(
                path,
                method,
                request_count,
                error_count,
                total_ms_p50,
                total_ms_p95,
                total_ms_p99,
                avg_db_ms,
                avg_db_count,
            )| {
                rollup::DailyRollup {
                    id: 0,
                    date: prev_day.clone(),
                    path,
                    method,
                    request_count,
                    error_count,
                    total_ms_p50,
                    total_ms_p95,
                    total_ms_p99,
                    avg_db_ms,
                    avg_db_count,
                }
            },
        )
        .collect();

    for r in rollups {
        rollup::insert_daily(pool, &r).await?;
    }

    tracing::debug!("Daily rollup completed for {}", prev_day);
    Ok(())
}

#[cfg(test)]
mod tests;
