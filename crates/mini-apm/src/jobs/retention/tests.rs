use super::*;
use crate::db::test_pool;

#[tokio::test]
async fn cleanup_applies_each_retention_policy_and_preserves_recent_data() -> anyhow::Result<()> {
    let pool = test_pool().await;
    let config = Config {
        retention_days_spans: 2,
        retention_days_errors: 5,
        retention_days_hourly_rollups: 4,
        ..Config::default()
    };
    let recent = time::rfc3339(time::days_ago(1));
    let old_span = time::rfc3339(time::days_ago(3));
    let old_error = time::rfc3339(time::days_ago(6));
    let old_rollup = time::rfc3339(time::days_ago(5));
    let old_deploy = time::rfc3339(time::days_ago(91));
    let error_id = sqlx::query(
        "INSERT INTO errors (fingerprint, exception_class, message, first_seen_at, last_seen_at, occurrence_count, status)
         VALUES ('fp', 'Error', 'failure', ?1, ?1, 2, 'open')",
    ).bind(&old_error).execute(&pool).await?.last_insert_rowid();

    for (name, span_time, error_time, rollup_time, deploy_time) in [
        ("old", &old_span, &old_error, &old_rollup, &old_deploy),
        ("recent", &recent, &recent, &recent, &recent),
    ] {
        sqlx::query(
            "INSERT INTO spans (trace_id, span_id, name, start_time_unix_nano, end_time_unix_nano, span_category, happened_at)
             VALUES (?1, ?1, 'test', 1000000000, 2000000000, 'http_server', ?2)",
        ).bind(name).bind(span_time).execute(&pool).await?;
        sqlx::query(
            "INSERT INTO error_occurrences (error_id, request_id, backtrace, happened_at) VALUES (?1, ?2, '[]', ?3)",
        ).bind(error_id).bind(name).bind(error_time).execute(&pool).await?;
        sqlx::query(
            "INSERT INTO rollups_hourly (hour, path, method, request_count, error_count, total_ms_sum, db_ms_sum, db_count_sum)
             VALUES (?1, ?2, 'GET', 10, 0, 100.0, 10.0, 5)",
        ).bind(rollup_time).bind(name).execute(&pool).await?;
        sqlx::query("INSERT INTO deploys (git_sha, deployed_at) VALUES (?1, ?2)")
            .bind(name)
            .bind(deploy_time)
            .execute(&pool)
            .await?;
    }
    for (username, days) in [("expired", 1), ("valid", -1)] {
        sqlx::query(
            "INSERT INTO users (username, is_admin, invite_token, invite_expires_at, created_at)
             VALUES (?1, 0, ?1, ?2, ?3)",
        )
        .bind(username)
        .bind(time::rfc3339(time::days_ago(days)))
        .bind(&recent)
        .execute(&pool)
        .await?;
    }

    for _ in 0..2 {
        cleanup(&pool, &config).await?;
        for (query, expected) in [
            ("SELECT trace_id FROM spans", "recent"),
            ("SELECT request_id FROM error_occurrences", "recent"),
            ("SELECT path FROM rollups_hourly", "recent"),
            ("SELECT git_sha FROM deploys", "recent"),
            ("SELECT username FROM users", "valid"),
        ] {
            let remaining: Vec<String> = sqlx::query_scalar(query).fetch_all(&pool).await?;
            assert_eq!(remaining, [expected], "{query}");
        }
        let remaining_groups: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM errors")
            .fetch_one(&pool)
            .await?;
        assert_eq!(
            remaining_groups, 1,
            "cleanup retains the parent error group"
        );
    }
    Ok(())
}

#[tokio::test]
async fn cleanup_is_safe_on_an_empty_database() -> anyhow::Result<()> {
    let pool = test_pool().await;
    cleanup(&pool, &Config::default()).await?;
    Ok(())
}
