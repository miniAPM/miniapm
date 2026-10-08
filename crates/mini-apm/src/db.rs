#[cfg(not(feature = "sqlite"))]
compile_error!("mini-apm needs a database backend: enable the `sqlite` feature");

use crate::config::Config;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub type Db = sqlx::Sqlite;
pub type DbPool = sqlx::Pool<Db>;
pub type DbRow = <Db as sqlx::Database>::Row;

const DELETE_CHUNK_ROWS: i64 = 5_000;
const WRITE_LOCK_HANDOFF: Duration = Duration::from_millis(200);

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

    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::debug!("Database schema initialized");

    Ok(pool)
}

#[cfg(test)]
pub async fn test_pool() -> DbPool {
    init(&Config::default())
        .await
        .expect("Failed to create test database")
}

pub async fn delete_before(
    pool: &DbPool,
    table: &'static str,
    column: &'static str,
    before: &str,
) -> anyhow::Result<u64> {
    let sql: Arc<str> = format!(
        "DELETE FROM {table} WHERE id IN (SELECT id FROM {table} WHERE {column} < $1 LIMIT $2)"
    )
    .into();
    let mut total = 0;
    loop {
        let deleted = sqlx::query(sqlx::AssertSqlSafe(Arc::clone(&sql)))
            .bind(before)
            .bind(DELETE_CHUNK_ROWS)
            .execute(pool)
            .await?
            .rows_affected();
        total += deleted;
        if deleted < DELETE_CHUNK_ROWS.cast_unsigned() {
            return Ok(total);
        }
        tokio::time::sleep(WRITE_LOCK_HANDOFF).await;
    }
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
mod tests;
