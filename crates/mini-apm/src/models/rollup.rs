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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db;

    fn test_pool() -> DbPool {
        let config = Config::default();
        db::init(&config).expect("Failed to create test database")
    }

    fn sample_hourly_rollup(hour: &str, path: &str) -> HourlyRollup {
        HourlyRollup {
            id: 0,
            hour: hour.to_string(),
            path: path.to_string(),
            method: "GET".to_string(),
            request_count: 100,
            error_count: 5,
            total_ms_sum: 5000.0,
            total_ms_p50: Some(45.0),
            total_ms_p95: Some(120.0),
            total_ms_p99: Some(250.0),
            db_ms_sum: 1000.0,
            db_count_sum: 200,
        }
    }

    fn sample_daily_rollup(date: &str, path: &str) -> DailyRollup {
        DailyRollup {
            id: 0,
            date: date.to_string(),
            path: path.to_string(),
            method: "GET".to_string(),
            request_count: 2400,
            error_count: 120,
            total_ms_p50: Some(50.0),
            total_ms_p95: Some(150.0),
            total_ms_p99: Some(300.0),
            avg_db_ms: Some(10.0),
            avg_db_count: Some(2.0),
        }
    }

    #[test]
    fn test_insert_hourly_rollup() {
        let pool = test_pool();
        let rollup = sample_hourly_rollup("2024-01-15T10:00:00Z", "/api/users");

        let result = insert_hourly(&pool, &rollup);

        assert!(result.is_ok());

        // Verify it was inserted
        let conn = pool.get().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM rollups_hourly", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_insert_hourly_rollup_replaces_duplicate() {
        let pool = test_pool();

        // Insert first rollup
        let mut rollup = sample_hourly_rollup("2024-01-15T10:00:00Z", "/api/users");
        rollup.request_count = 100;
        insert_hourly(&pool, &rollup).unwrap();

        // Insert again with same key but different count
        rollup.request_count = 200;
        insert_hourly(&pool, &rollup).unwrap();

        // Should still be 1 row (replaced)
        let conn = pool.get().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM rollups_hourly", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);

        // And should have the updated value
        let request_count: i64 = conn
            .query_row(
                "SELECT request_count FROM rollups_hourly WHERE path = '/api/users'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(request_count, 200);
    }

    #[test]
    fn test_insert_daily_rollup() {
        let pool = test_pool();
        let rollup = sample_daily_rollup("2024-01-15", "/api/users");

        let result = insert_daily(&pool, &rollup);

        assert!(result.is_ok());

        // Verify it was inserted
        let conn = pool.get().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM rollups_daily", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_insert_daily_rollup_replaces_duplicate() {
        let pool = test_pool();

        let mut rollup = sample_daily_rollup("2024-01-15", "/api/users");
        rollup.request_count = 1000;
        insert_daily(&pool, &rollup).unwrap();

        rollup.request_count = 2000;
        insert_daily(&pool, &rollup).unwrap();

        let conn = pool.get().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM rollups_daily", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_daily_for_range() {
        let pool = test_pool();

        // Insert multiple daily rollups
        insert_daily(&pool, &sample_daily_rollup("2024-01-10", "/api/users")).unwrap();
        insert_daily(&pool, &sample_daily_rollup("2024-01-15", "/api/posts")).unwrap();
        insert_daily(&pool, &sample_daily_rollup("2024-01-20", "/api/comments")).unwrap();

        // Query range that includes first two
        let rollups = daily_for_range(&pool, "2024-01-08", "2024-01-17", 100).unwrap();

        assert_eq!(rollups.len(), 2);
    }

    #[test]
    fn test_daily_for_range_with_limit() {
        let pool = test_pool();

        insert_daily(&pool, &sample_daily_rollup("2024-01-10", "/api/a")).unwrap();
        insert_daily(&pool, &sample_daily_rollup("2024-01-10", "/api/b")).unwrap();
        insert_daily(&pool, &sample_daily_rollup("2024-01-10", "/api/c")).unwrap();

        let rollups = daily_for_range(&pool, "2024-01-01", "2024-01-31", 2).unwrap();

        assert_eq!(rollups.len(), 2);
    }

    #[test]
    fn test_daily_for_range_empty() {
        let pool = test_pool();

        let rollups = daily_for_range(&pool, "2024-01-01", "2024-01-31", 100).unwrap();

        assert!(rollups.is_empty());
    }

    #[test]
    fn test_daily_for_range_orders_by_request_count() {
        let pool = test_pool();

        let mut low = sample_daily_rollup("2024-01-10", "/api/low");
        low.request_count = 10;
        insert_daily(&pool, &low).unwrap();

        let mut high = sample_daily_rollup("2024-01-10", "/api/high");
        high.request_count = 1000;
        insert_daily(&pool, &high).unwrap();

        let rollups = daily_for_range(&pool, "2024-01-01", "2024-01-31", 100).unwrap();

        assert_eq!(rollups.len(), 2);
        assert_eq!(rollups[0].path, "/api/high"); // Highest count first
        assert_eq!(rollups[1].path, "/api/low");
    }

    #[test]
    fn test_delete_hourly_before() {
        let pool = test_pool();

        insert_hourly(&pool, &sample_hourly_rollup("2024-01-01T10:00:00Z", "/api/old")).unwrap();
        insert_hourly(&pool, &sample_hourly_rollup("2024-01-15T10:00:00Z", "/api/recent")).unwrap();

        let deleted = delete_hourly_before(&pool, "2024-01-10T00:00:00Z").unwrap();

        assert_eq!(deleted, 1);

        // Only recent should remain
        let conn = pool.get().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM rollups_hourly", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_delete_hourly_before_none_to_delete() {
        let pool = test_pool();

        insert_hourly(&pool, &sample_hourly_rollup("2024-06-01T10:00:00Z", "/api/recent")).unwrap();

        let deleted = delete_hourly_before(&pool, "2024-01-01T00:00:00Z").unwrap();

        assert_eq!(deleted, 0);
    }

    #[test]
    fn test_hourly_rollup_with_null_percentiles() {
        let pool = test_pool();

        let rollup = HourlyRollup {
            id: 0,
            hour: "2024-01-15T10:00:00Z".to_string(),
            path: "/api/test".to_string(),
            method: "POST".to_string(),
            request_count: 50,
            error_count: 0,
            total_ms_sum: 2500.0,
            total_ms_p50: None,
            total_ms_p95: None,
            total_ms_p99: None,
            db_ms_sum: 500.0,
            db_count_sum: 100,
        };

        let result = insert_hourly(&pool, &rollup);
        assert!(result.is_ok());
    }

    #[test]
    fn test_daily_rollup_with_null_averages() {
        let pool = test_pool();

        let rollup = DailyRollup {
            id: 0,
            date: "2024-01-15".to_string(),
            path: "/api/test".to_string(),
            method: "DELETE".to_string(),
            request_count: 10,
            error_count: 0,
            total_ms_p50: None,
            total_ms_p95: None,
            total_ms_p99: None,
            avg_db_ms: None,
            avg_db_count: None,
        };

        let result = insert_daily(&pool, &rollup);
        assert!(result.is_ok());
    }
}
