use crate::time::Stamp;
use std::sync::Arc;
use std::time::Duration;

cfg_select! {
    feature = "postgres" => {
        mod postgres;
        use postgres as backend;
        pub type Db = sqlx::Postgres;
    }
    feature = "sqlite" => {
        mod sqlite;
        use sqlite as backend;
        pub type Db = sqlx::Sqlite;
    }
    _ => {
        compile_error!("mini-apm needs a database backend: enable the `sqlite` or `postgres` feature");
    }
}

#[cfg(test)]
pub use backend::reject_inserts;
#[cfg(any(test, feature = "test-support"))]
pub use backend::test_pool;
pub use backend::{
    begin_write, describe, expire, get_db_size, in_text_list, init, maintain, text_list,
};

pub type DbPool = sqlx::Pool<Db>;
pub type DbRow = <Db as sqlx::Database>::Row;
pub type DbTransaction = sqlx::Transaction<'static, Db>;

const DELETE_CHUNK_ROWS: i64 = 5_000;
const WRITE_LOCK_HANDOFF: Duration = Duration::from_millis(200);

pub async fn delete_before(
    pool: &DbPool,
    table: &'static str,
    column: &'static str,
    before: Stamp,
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

#[cfg(test)]
mod tests;
