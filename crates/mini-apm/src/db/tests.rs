use super::*;

#[tokio::test]
async fn delete_before_drains_old_rows_across_chunk_boundaries() -> anyhow::Result<()> {
    let old_at = Stamp("2000-01-01T00:00:00Z".parse()?);
    let new_at = Stamp("2100-01-01T00:00:00Z".parse()?);
    for old in [0, DELETE_CHUNK_ROWS, DELETE_CHUNK_ROWS + 1] {
        let pool = test_pool().await;
        sqlx::query(
            "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < $1)
             INSERT INTO deploys (git_sha, deployed_at)
             SELECT CAST(i AS TEXT), CASE WHEN i < $1 THEN $2 ELSE $3 END FROM n",
        )
        .bind(old)
        .bind(old_at)
        .bind(new_at)
        .execute(&pool)
        .await?;

        let deleted = delete_before(
            &pool,
            "deploys",
            "deployed_at",
            Stamp("2050-01-01T00:00:00Z".parse()?),
        )
        .await?;
        let remaining: Vec<Stamp> = sqlx::query_scalar("SELECT deployed_at FROM deploys")
            .fetch_all(&pool)
            .await?;
        assert_eq!(deleted, old.cast_unsigned(), "old rows: {old}");
        assert_eq!(remaining, [new_at], "old rows: {old}");
    }
    Ok(())
}
