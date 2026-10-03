use crate::DbPool;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct HourlyRollup {
    pub id: i64,
    pub hour: String,
    pub path: String,
    pub method: String,
    pub request_count: i64,
    pub error_count: i64,
    pub total_ms_sum: f64,
    pub total_ms_p50: Option<f64>,
    pub total_ms_p95: Option<f64>,
    pub total_ms_p99: Option<f64>,
    pub db_ms_sum: f64,
    pub db_count_sum: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DailyRollup {
    pub id: i64,
    pub date: String,
    pub path: String,
    pub method: String,
    pub request_count: i64,
    pub error_count: i64,
    pub total_ms_p50: Option<f64>,
    pub total_ms_p95: Option<f64>,
    pub total_ms_p99: Option<f64>,
    pub avg_db_ms: Option<f64>,
    pub avg_db_count: Option<f64>,
}

pub async fn insert_hourly(pool: &DbPool, rollup: &HourlyRollup) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT OR REPLACE INTO rollups_hourly
        (hour, path, method, request_count, error_count, total_ms_sum, total_ms_p50, total_ms_p95, total_ms_p99, db_ms_sum, db_count_sum)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#,
    )
    .bind(&rollup.hour)
    .bind(&rollup.path)
    .bind(&rollup.method)
    .bind(rollup.request_count)
    .bind(rollup.error_count)
    .bind(rollup.total_ms_sum)
    .bind(rollup.total_ms_p50)
    .bind(rollup.total_ms_p95)
    .bind(rollup.total_ms_p99)
    .bind(rollup.db_ms_sum)
    .bind(rollup.db_count_sum)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn insert_daily(pool: &DbPool, rollup: &DailyRollup) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT OR REPLACE INTO rollups_daily
        (date, path, method, request_count, error_count, total_ms_p50, total_ms_p95, total_ms_p99, avg_db_ms, avg_db_count)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        "#,
    )
    .bind(&rollup.date)
    .bind(&rollup.path)
    .bind(&rollup.method)
    .bind(rollup.request_count)
    .bind(rollup.error_count)
    .bind(rollup.total_ms_p50)
    .bind(rollup.total_ms_p95)
    .bind(rollup.total_ms_p99)
    .bind(rollup.avg_db_ms)
    .bind(rollup.avg_db_count)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn daily_for_range(
    pool: &DbPool,
    start: &str,
    end: &str,
    limit: i64,
) -> anyhow::Result<Vec<DailyRollup>> {
    let rollups = sqlx::query_as::<_, DailyRollup>(
        r#"
        SELECT id, date, path, method, request_count, error_count,
               total_ms_p50, total_ms_p95, total_ms_p99, avg_db_ms, avg_db_count
        FROM rollups_daily
        WHERE date >= ?1 AND date <= ?2
        ORDER BY request_count DESC
        LIMIT ?3
        "#,
    )
    .bind(start)
    .bind(end)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rollups)
}

#[cfg(test)]
mod tests;
