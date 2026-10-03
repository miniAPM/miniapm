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
                "requests",
                "rollups_hourly",
                "rollups_daily",
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
                sqlx::query_scalar("SELECT 1 FROM sqlite_master WHERE type = ?1 AND name = ?2")
                    .bind(kind)
                    .bind(name)
                    .fetch_optional(&pool)
                    .await?;
            assert_eq!(exists, Some(1), "{kind} {name}");
        }
    }
    Ok(())
}
