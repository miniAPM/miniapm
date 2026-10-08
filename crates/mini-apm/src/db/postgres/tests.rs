use super::*;
use crate::models::project;

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
        "SELECT table_name::text FROM information_schema.tables
         WHERE table_schema = current_schema() AND table_name <> '_sqlx_migrations'
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
