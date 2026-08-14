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

pub async fn delete_hourly_before(pool: &DbPool, before: &str) -> anyhow::Result<usize> {
    let result = sqlx::query("DELETE FROM rollups_hourly WHERE hour < ?1")
        .bind(before)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db;

    async fn test_pool() -> DbPool {
        let config = Config::default();
        db::init(&config)
            .await
            .expect("Failed to create test database")
    }

    async fn count_rows(pool: &DbPool, table: &str) -> i64 {
        let sql = format!("SELECT COUNT(*) FROM {table}");
        sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_one(pool)
            .await
            .unwrap()
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

    #[tokio::test]
    async fn test_insert_hourly_rollup() {
        let pool = test_pool().await;
        let rollup = sample_hourly_rollup("2024-01-15T10:00:00Z", "/api/users");

        let result = insert_hourly(&pool, &rollup).await;

        assert!(result.is_ok());

        // Verify it was inserted
        let count = count_rows(&pool, "rollups_hourly").await;
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_insert_hourly_rollup_replaces_duplicate() {
        let pool = test_pool().await;

        // Insert first rollup
        let mut rollup = sample_hourly_rollup("2024-01-15T10:00:00Z", "/api/users");
        rollup.request_count = 100;
        insert_hourly(&pool, &rollup).await.unwrap();

        // Insert again with same key but different count
        rollup.request_count = 200;
        insert_hourly(&pool, &rollup).await.unwrap();

        // Should still be 1 row (replaced)
        let count = count_rows(&pool, "rollups_hourly").await;
        assert_eq!(count, 1);

        // And should have the updated value
        let request_count: i64 = sqlx::query_scalar(
            "SELECT request_count FROM rollups_hourly WHERE path = '/api/users'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(request_count, 200);
    }

    #[tokio::test]
    async fn test_insert_daily_rollup() {
        let pool = test_pool().await;
        let rollup = sample_daily_rollup("2024-01-15", "/api/users");

        let result = insert_daily(&pool, &rollup).await;

        assert!(result.is_ok());

        // Verify it was inserted
        let count = count_rows(&pool, "rollups_daily").await;
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_insert_daily_rollup_replaces_duplicate() {
        let pool = test_pool().await;

        let mut rollup = sample_daily_rollup("2024-01-15", "/api/users");
        rollup.request_count = 1000;
        insert_daily(&pool, &rollup).await.unwrap();

        rollup.request_count = 2000;
        insert_daily(&pool, &rollup).await.unwrap();

        let count = count_rows(&pool, "rollups_daily").await;
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_daily_for_range() {
        let pool = test_pool().await;

        // Insert multiple daily rollups
        insert_daily(&pool, &sample_daily_rollup("2024-01-10", "/api/users"))
            .await
            .unwrap();
        insert_daily(&pool, &sample_daily_rollup("2024-01-15", "/api/posts"))
            .await
            .unwrap();
        insert_daily(&pool, &sample_daily_rollup("2024-01-20", "/api/comments"))
            .await
            .unwrap();

        // Query range that includes first two
        let rollups = daily_for_range(&pool, "2024-01-08", "2024-01-17", 100)
            .await
            .unwrap();

        assert_eq!(rollups.len(), 2);
    }

    #[tokio::test]
    async fn test_daily_for_range_with_limit() {
        let pool = test_pool().await;

        insert_daily(&pool, &sample_daily_rollup("2024-01-10", "/api/a"))
            .await
            .unwrap();
        insert_daily(&pool, &sample_daily_rollup("2024-01-10", "/api/b"))
            .await
            .unwrap();
        insert_daily(&pool, &sample_daily_rollup("2024-01-10", "/api/c"))
            .await
            .unwrap();

        let rollups = daily_for_range(&pool, "2024-01-01", "2024-01-31", 2)
            .await
            .unwrap();

        assert_eq!(rollups.len(), 2);
    }

    #[tokio::test]
    async fn test_daily_for_range_empty() {
        let pool = test_pool().await;

        let rollups = daily_for_range(&pool, "2024-01-01", "2024-01-31", 100)
            .await
            .unwrap();

        assert!(rollups.is_empty());
    }

    #[tokio::test]
    async fn test_daily_for_range_orders_by_request_count() {
        let pool = test_pool().await;

        let mut low = sample_daily_rollup("2024-01-10", "/api/low");
        low.request_count = 10;
        insert_daily(&pool, &low).await.unwrap();

        let mut high = sample_daily_rollup("2024-01-10", "/api/high");
        high.request_count = 1000;
        insert_daily(&pool, &high).await.unwrap();

        let rollups = daily_for_range(&pool, "2024-01-01", "2024-01-31", 100)
            .await
            .unwrap();

        assert_eq!(rollups.len(), 2);
        assert_eq!(rollups[0].path, "/api/high"); // Highest count first
        assert_eq!(rollups[1].path, "/api/low");
    }

    #[tokio::test]
    async fn test_delete_hourly_before() {
        let pool = test_pool().await;

        insert_hourly(
            &pool,
            &sample_hourly_rollup("2024-01-01T10:00:00Z", "/api/old"),
        )
        .await
        .unwrap();
        insert_hourly(
            &pool,
            &sample_hourly_rollup("2024-01-15T10:00:00Z", "/api/recent"),
        )
        .await
        .unwrap();

        let deleted = delete_hourly_before(&pool, "2024-01-10T00:00:00Z")
            .await
            .unwrap();

        assert_eq!(deleted, 1);

        // Only recent should remain
        let count = count_rows(&pool, "rollups_hourly").await;
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_delete_hourly_before_none_to_delete() {
        let pool = test_pool().await;

        insert_hourly(
            &pool,
            &sample_hourly_rollup("2024-06-01T10:00:00Z", "/api/recent"),
        )
        .await
        .unwrap();

        let deleted = delete_hourly_before(&pool, "2024-01-01T00:00:00Z")
            .await
            .unwrap();

        assert_eq!(deleted, 0);
    }

    #[tokio::test]
    async fn test_hourly_rollup_with_null_percentiles() {
        let pool = test_pool().await;

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

        let result = insert_hourly(&pool, &rollup).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_daily_rollup_with_null_averages() {
        let pool = test_pool().await;

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

        let result = insert_daily(&pool, &rollup).await;
        assert!(result.is_ok());
    }
}
