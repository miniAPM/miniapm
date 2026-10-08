use super::{DbPool, DbTransaction};
use crate::config::Config;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use std::fs;
use std::path::Path;
use std::time::Duration;

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
        .busy_timeout(Duration::from_secs(5))
        .foreign_keys(true);

    // A shared, on-disk pool wants several connections; an in-memory database
    // only exists for the lifetime of a single connection, so pooling more
    // than one would silently hand out unrelated empty databases.
    let max_connections = if is_memory { 1 } else { 10 };

    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .connect_with(options)
        .await?;

    sqlx::migrate!("./migrations/sqlite").run(&pool).await?;
    tracing::debug!("Database schema initialized");

    Ok(pool)
}

pub fn describe(config: &Config) -> String {
    format!("SQLite {}", config.sqlite_path)
}

/// Open a transaction that takes SQLite's write lock up front, so a batch
/// never fails halfway on a lock upgrade
pub async fn begin_write(pool: &DbPool) -> sqlx::Result<DbTransaction> {
    pool.begin_with("BEGIN IMMEDIATE").await
}

pub async fn get_db_size(pool: &DbPool) -> anyhow::Result<f64> {
    let size: i64 = sqlx::query_scalar(
        "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()",
    )
    .fetch_one(pool)
    .await?;
    Ok(size as f64 / 1_048_576.0) // Convert to MB
}

#[cfg(any(test, feature = "test-support"))]
pub async fn test_pool() -> DbPool {
    init(&Config::default())
        .await
        .expect("Failed to create test database")
}

/// Make inserts into `table` fail when `column` equals `value`
#[cfg(test)]
pub async fn reject_inserts(
    pool: &DbPool,
    table: &str,
    column: &str,
    value: &str,
) -> sqlx::Result<()> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE TRIGGER reject_{table} BEFORE INSERT ON {table} WHEN NEW.{column} = '{value}'
         BEGIN SELECT RAISE(ABORT, 'rejected'); END"
    )))
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests;
