use crate::config::Config;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use std::fs;
use std::path::Path;
use std::time::Duration;

pub type DbPool = SqlitePool;

pub async fn init(config: &Config) -> anyhow::Result<DbPool> {
    let is_memory = config.sqlite_path == ":memory:";

    // Ensure data directory exists
    if !is_memory && let Some(parent) = Path::new(&config.sqlite_path).parent() {
        fs::create_dir_all(parent)?;
    }

    let options = SqliteConnectOptions::new()
        .filename(&config.sqlite_path)
        .in_memory(is_memory)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_millis(100))
        .foreign_keys(true);

    // A shared, on-disk pool wants several connections; an in-memory database
    // only exists for the lifetime of a single connection, so pooling more
    // than one would silently hand out unrelated empty databases.
    let max_connections = if is_memory { 1 } else { 10 };

    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .connect_with(options)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::debug!("Database schema initialized");

    Ok(pool)
}

pub async fn delete_before(
    pool: &DbPool,
    table: &'static str,
    column: &'static str,
    before: &str,
) -> anyhow::Result<u64> {
    let sql = format!("DELETE FROM {table} WHERE {column} < ?1");
    let result = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(before)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

pub async fn get_db_size(pool: &DbPool) -> anyhow::Result<f64> {
    let size: i64 = sqlx::query_scalar(
        "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()",
    )
    .fetch_one(pool)
    .await?;
    Ok(size as f64 / 1_048_576.0) // Convert to MB
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            sqlite_path: ":memory:".to_string(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_init_creates_pool() {
        let config = test_config();
        let pool = init(&config).await;

        assert!(pool.is_ok());
        let pool = pool.unwrap();
        assert!(pool.acquire().await.is_ok());
    }

    #[tokio::test]
    async fn test_init_creates_tables() {
        let config = test_config();
        let pool = init(&config).await.unwrap();

        // Check that all expected tables exist
        let tables = vec![
            "projects",
            "users",
            "sessions",
            "errors",
            "error_occurrences",
            "deploys",
            "spans",
            "requests",
            "rollups_hourly",
            "rollups_daily",
            "settings",
        ];

        for table in tables {
            let exists: Option<i64> =
                sqlx::query_scalar("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1")
                    .bind(table)
                    .fetch_optional(&pool)
                    .await
                    .unwrap();
            assert!(exists.is_some(), "Table {} should exist", table);
        }
    }

    #[tokio::test]
    async fn test_init_creates_indexes() {
        let config = test_config();
        let pool = init(&config).await.unwrap();

        // Check some key indexes exist
        let indexes = vec![
            "idx_spans_trace_id",
            "idx_errors_project_id",
            "idx_projects_api_key",
        ];

        for index in indexes {
            let exists: Option<i64> =
                sqlx::query_scalar("SELECT 1 FROM sqlite_master WHERE type='index' AND name=?1")
                    .bind(index)
                    .fetch_optional(&pool)
                    .await
                    .unwrap();
            assert!(exists.is_some(), "Index {} should exist", index);
        }
    }

    #[tokio::test]
    async fn test_get_db_size() {
        let config = test_config();
        let pool = init(&config).await.unwrap();

        let size = get_db_size(&pool).await.unwrap();

        // In-memory DB should have some size
        assert!(size >= 0.0);
    }

    #[tokio::test]
    async fn test_multiple_init_is_idempotent() {
        let config = test_config();
        let pool = init(&config).await.unwrap();

        // Run migrations again against the same pool (simulates restart)
        let result = sqlx::migrate!("./migrations").run(&pool).await;

        assert!(result.is_ok());
    }
}
