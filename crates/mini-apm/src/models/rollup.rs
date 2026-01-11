use crate::DbPool;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

pub fn insert_hourly(pool: &DbPool, rollup: &HourlyRollup) -> anyhow::Result<()> {
    let conn = pool.get()?;
    conn.execute(
        r#"
        INSERT OR REPLACE INTO rollups_hourly
        (hour, path, method, request_count, error_count, total_ms_sum, total_ms_p50, total_ms_p95, total_ms_p99, db_ms_sum, db_count_sum)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#,
        (
            &rollup.hour,
            &rollup.path,
            &rollup.method,
            rollup.request_count,
            rollup.error_count,
            rollup.total_ms_sum,
            rollup.total_ms_p50,
            rollup.total_ms_p95,
            rollup.total_ms_p99,
            rollup.db_ms_sum,
            rollup.db_count_sum,
        ),
    )?;
    Ok(())
}

pub fn insert_daily(pool: &DbPool, rollup: &DailyRollup) -> anyhow::Result<()> {
    let conn = pool.get()?;
    conn.execute(
        r#"
        INSERT OR REPLACE INTO rollups_daily
        (date, path, method, request_count, error_count, total_ms_p50, total_ms_p95, total_ms_p99, avg_db_ms, avg_db_count)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        "#,
        (
            &rollup.date,
            &rollup.path,
            &rollup.method,
            rollup.request_count,
            rollup.error_count,
            rollup.total_ms_p50,
            rollup.total_ms_p95,
            rollup.total_ms_p99,
            rollup.avg_db_ms,
            rollup.avg_db_count,
        ),
    )?;
    Ok(())
}

pub fn daily_for_range(
    pool: &DbPool,
    start: &str,
    end: &str,
    limit: i64,
) -> anyhow::Result<Vec<DailyRollup>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        r#"
        SELECT id, date, path, method, request_count, error_count,
               total_ms_p50, total_ms_p95, total_ms_p99, avg_db_ms, avg_db_count
        FROM rollups_daily
        WHERE date >= ?1 AND date <= ?2
        ORDER BY request_count DESC
        LIMIT ?3
        "#,
    )?;

    let rollups = stmt
        .query_map(rusqlite::params![start, end, limit], |row| {
            Ok(DailyRollup {
                id: row.get(0)?,
                date: row.get(1)?,
                path: row.get(2)?,
                method: row.get(3)?,
                request_count: row.get(4)?,
                error_count: row.get(5)?,
                total_ms_p50: row.get(6)?,
                total_ms_p95: row.get(7)?,
                total_ms_p99: row.get(8)?,
                avg_db_ms: row.get(9)?,
                avg_db_count: row.get(10)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rollups)
}

pub fn delete_hourly_before(pool: &DbPool, before: &str) -> anyhow::Result<usize> {
    let conn = pool.get()?;
    let deleted = conn.execute("DELETE FROM rollups_hourly WHERE hour < ?1", [before])?;
    Ok(deleted)
}
