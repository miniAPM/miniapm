use super::{DbPool, DbTransaction};
use crate::config::Config;
use crate::time::Stamp;
use anyhow::Context;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

const MIN_SERVER_VERSION: i32 = 180_000;

/// Tables partitioned by UTC day on `happened_at`
const PARTITIONED: [&str; 2] = ["spans", "error_occurrences"];
const PARTITION_DAYS_AHEAD: i32 = 7;

pub async fn init(config: &Config) -> anyhow::Result<DbPool> {
    let url = config
        .database_url
        .as_deref()
        .context("DATABASE_URL is required when MiniAPM is built for PostgreSQL")?;
    connect(url.parse()?, 10).await
}

async fn connect(options: PgConnectOptions, max_connections: u32) -> anyhow::Result<DbPool> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect_with(options.options([("timezone", "UTC")]))
        .await?;

    let (version_num, version): (i32, String) = sqlx::query_as(
        "SELECT current_setting('server_version_num')::int, current_setting('server_version')",
    )
    .fetch_one(&pool)
    .await?;
    anyhow::ensure!(
        version_num >= MIN_SERVER_VERSION,
        "MiniAPM needs PostgreSQL 18 or newer, the server runs {version}"
    );

    sqlx::migrate!("./migrations/postgres").run(&pool).await?;
    tracing::debug!("Database schema initialized");

    Ok(pool)
}

/// The server and database `DATABASE_URL` points at, without credentials
pub fn describe(config: &Config) -> String {
    match config
        .database_url
        .as_deref()
        .map(str::parse::<PgConnectOptions>)
    {
        Some(Ok(options)) => format!(
            "PostgreSQL {}:{}/{}",
            options.get_host(),
            options.get_port(),
            options.get_database().unwrap_or_default()
        ),
        Some(Err(_)) => "PostgreSQL (invalid DATABASE_URL)".to_string(),
        None => "PostgreSQL (DATABASE_URL not set)".to_string(),
    }
}

/// SQL testing a value against the list bound as parameter `param` with
/// [`text_list`]
pub fn in_text_list(param: u8) -> String {
    format!("= ANY(${param})")
}

/// Bind value for [`in_text_list`]
pub fn text_list(items: &[String]) -> &[String] {
    items
}

/// Run `job` unless another MiniAPM instance on this database is running the
/// job called `name`, and say whether it ran. The advisory lock lives on one
/// connection, so a crashed instance releases it.
pub async fn exclusively(
    pool: &DbPool,
    name: &str,
    job: impl Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<bool> {
    let mut lock = pool.acquire().await?;
    let locked: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtext('miniapm'), hashtext($1))")
            .bind(name)
            .fetch_one(&mut *lock)
            .await?;
    if !locked {
        return Ok(false);
    }
    let result = job.await;
    sqlx::query("SELECT pg_advisory_unlock(hashtext('miniapm'), hashtext($1))")
        .bind(name)
        .execute(&mut *lock)
        .await?;
    result.map(|()| true)
}

/// Create day partitions from yesterday to a week ahead, so retention can
/// drop whole days
pub async fn maintain(pool: &DbPool) -> anyhow::Result<()> {
    for table in PARTITIONED {
        sqlx::query("SELECT create_day_partitions($1::regclass, $2)")
            .bind(table)
            .bind(PARTITION_DAYS_AHEAD)
            .execute(pool)
            .await?;
    }
    Ok(())
}

/// Remove the rows of `table` whose `column` is before `cutoff`. Partitioned
/// tables drop the days that ended by then, so rows can outlive `cutoff` by
/// up to a day.
pub async fn expire(
    pool: &DbPool,
    table: &'static str,
    column: &'static str,
    cutoff: Stamp,
) -> anyhow::Result<()> {
    if PARTITIONED.contains(&table) {
        let (dropped, deleted): (i32, i64) =
            sqlx::query_as("SELECT dropped, deleted FROM drop_partitions_before($1::regclass, $2)")
                .bind(table)
                .bind(cutoff)
                .fetch_one(pool)
                .await?;
        tracing::info!("Dropped {dropped} day partitions and {deleted} old rows from {table}");
        if table == "spans" {
            sqlx::query("DELETE FROM span_rollups WHERE hour < date_trunc('hour', $1, 'UTC')")
                .bind(cutoff)
                .execute(pool)
                .await?;
        }
    } else {
        let deleted = super::delete_before(pool, table, column, cutoff).await?;
        tracing::info!("Deleted {deleted} old rows from {table}");
    }
    Ok(())
}

pub async fn begin_write(pool: &DbPool) -> sqlx::Result<DbTransaction> {
    pool.begin().await
}

pub async fn get_db_size(pool: &DbPool) -> anyhow::Result<f64> {
    let size: i64 = sqlx::query_scalar("SELECT pg_database_size(current_database())")
        .fetch_one(pool)
        .await?;
    Ok(size as f64 / 1_048_576.0)
}

/// A pool on a fresh schema of `MINIAPM_TEST_DATABASE_URL`. Schemas left by
/// runs older than ten minutes are dropped the first time this is called.
#[cfg(any(test, feature = "test-support"))]
pub async fn test_pool() -> DbPool {
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::sync::OnceCell;

    static NEXT: AtomicU32 = AtomicU32::new(0);
    static SWEPT: OnceCell<()> = OnceCell::const_new();

    let url = std::env::var("MINIAPM_TEST_DATABASE_URL")
        .expect("MINIAPM_TEST_DATABASE_URL must name a PostgreSQL 18 database for the tests");
    let options: PgConnectOptions = url.parse().expect("MINIAPM_TEST_DATABASE_URL");
    let now = jiff::Timestamp::now().as_second();
    let schema = format!(
        "test_{now}_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );

    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .expect("connect to MINIAPM_TEST_DATABASE_URL");
    SWEPT
        .get_or_init(|| sweep_test_schemas(&admin, now - 600))
        .await;
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await
        .expect("create test schema");
    admin.close().await;

    connect(
        options.options([("search_path", format!("{schema},public"))]),
        2,
    )
    .await
    .expect("Failed to create test database")
}

#[cfg(any(test, feature = "test-support"))]
async fn sweep_test_schemas(admin: &DbPool, before: i64) {
    let schemas: Vec<String> =
        sqlx::query_scalar("SELECT nspname FROM pg_namespace WHERE nspname ~ '^test_[0-9]+_'")
            .fetch_all(admin)
            .await
            .expect("list test schemas");
    for schema in schemas {
        let created: i64 = schema
            .split('_')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(i64::MAX);
        if created < before {
            sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
                .execute(admin)
                .await
                .expect("drop stale test schema");
        }
    }
}

/// Make inserts into `table` fail when `column` equals `value`
#[cfg(test)]
pub async fn reject_inserts(
    pool: &DbPool,
    table: &str,
    column: &str,
    value: &str,
) -> sqlx::Result<()> {
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE OR REPLACE FUNCTION reject_insert() RETURNS trigger LANGUAGE plpgsql
         AS $$ BEGIN RAISE EXCEPTION 'rejected'; END $$;
         CREATE TRIGGER reject_{table} BEFORE INSERT ON {table} FOR EACH ROW
         WHEN (NEW.{column} = '{value}') EXECUTE FUNCTION reject_insert();"
    )))
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests;
