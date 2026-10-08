use super::*;
use crate::models::project;
use crate::time;

#[tokio::test]
async fn migrations_create_schema_and_preserve_data_when_reapplied() -> anyhow::Result<()> {
    let pool = test_pool().await;
    let created = project::create(&pool, "Survives restart").await?;

    sqlx::migrate!("./migrations/postgres").run(&pool).await?;

    let stored = project::find(&pool, created.id)
        .await?
        .expect("project preserved");
    assert_eq!(stored.api_key, created.api_key);

    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p')
           AND NOT c.relispartition AND c.relname <> '_sqlx_migrations'
         ORDER BY 1",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        tables,
        [
            "deploys",
            "error_occurrences",
            "errors",
            "projects",
            "sessions",
            "settings",
            "spans",
            "users"
        ]
    );
    Ok(())
}

#[tokio::test]
async fn day_partitions_take_over_default_rows_and_expire_whole_days() -> anyhow::Result<()> {
    let pool = test_pool().await;
    for (span_id, days) in [("old", 10), ("mid", 3), ("new", 0)] {
        sqlx::query(
            "INSERT INTO spans (trace_id, span_id, name, start_time_unix_nano, end_time_unix_nano,
                span_category, happened_at)
             VALUES ('trace', $1, 'x', 0, 1, 'internal', $2)",
        )
        .bind(span_id)
        .bind(time::days_ago(days))
        .execute(&pool)
        .await?;
    }
    for days in [10, 3] {
        sqlx::query("SELECT create_day_partition('spans', ($1 AT TIME ZONE 'UTC')::date)")
            .bind(time::days_ago(days))
            .execute(&pool)
            .await?;
    }
    maintain(&pool).await?;
    let placed: Vec<(String, String)> =
        sqlx::query_as("SELECT span_id, tableoid::regclass::text FROM spans ORDER BY span_id")
            .fetch_all(&pool)
            .await?;
    assert!(
        placed.iter().all(|(_, table)| table.starts_with("spans_p")),
        "{placed:?}"
    );

    expire(&pool, "spans", "happened_at", time::days_ago(5)).await?;
    let left: Vec<String> = sqlx::query_scalar("SELECT span_id FROM spans ORDER BY span_id")
        .fetch_all(&pool)
        .await?;
    assert_eq!(left, ["mid", "new"]);
    Ok(())
}
