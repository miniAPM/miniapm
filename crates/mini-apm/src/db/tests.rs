use super::*;
use crate::models::project;

#[tokio::test]
async fn migrations_create_schema_and_preserve_data_when_reapplied() -> anyhow::Result<()> {
    let pool = init(&Config::default()).await?;
    let created = project::create(&pool, "Survives restart").await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    let stored = project::find(&pool, created.id)
        .await?
        .expect("project preserved");
    assert_eq!(stored.api_key, created.api_key);

    for (kind, names) in [
        (
            "table",
            &[
                "projects",
                "users",
                "sessions",
                "errors",
                "error_occurrences",
                "deploys",
                "spans",
                "settings",
            ][..],
        ),
        (
            "index",
            &[
                "idx_spans_trace_id",
                "idx_errors_project_id",
                "idx_projects_api_key",
            ][..],
        ),
    ] {
        for name in names {
            let exists: Option<i64> =
                sqlx::query_scalar("SELECT 1 FROM sqlite_master WHERE type = $1 AND name = $2")
                    .bind(kind)
                    .bind(name)
                    .fetch_optional(&pool)
                    .await?;
            assert_eq!(exists, Some(1), "{kind} {name}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn delete_before_drains_old_rows_across_chunk_boundaries() -> anyhow::Result<()> {
    for old in [0, DELETE_CHUNK_ROWS, DELETE_CHUNK_ROWS + 1] {
        let pool = test_pool().await;
        sqlx::query(
            "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < $1)
             INSERT INTO deploys (git_sha, deployed_at)
             SELECT i, IIF(i < $1, '2000-01-01T00:00:00Z', '2100-01-01T00:00:00Z') FROM n",
        )
        .bind(old)
        .execute(&pool)
        .await?;

        let deleted =
            delete_before(&pool, "deploys", "deployed_at", "2050-01-01T00:00:00Z").await?;
        let remaining: Vec<String> = sqlx::query_scalar("SELECT deployed_at FROM deploys")
            .fetch_all(&pool)
            .await?;
        assert_eq!(deleted, old.cast_unsigned(), "old rows: {old}");
        assert_eq!(remaining, ["2100-01-01T00:00:00Z"], "old rows: {old}");
    }
    Ok(())
}
