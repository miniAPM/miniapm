use crate::time;
use crate::{
    DbPool,
    config::Config,
    models::{self, deploy, user},
};
use jiff::Timestamp;

pub async fn cleanup(pool: &DbPool, config: &Config) -> anyhow::Result<()> {
    // Delete old spans
    let spans_cutoff = time::rfc3339(time::days_ago(config.retention_days_spans));
    let deleted_spans = models::span::delete_before(pool, &spans_cutoff).await?;
    tracing::info!("Deleted {} old spans", deleted_spans);

    // Delete old error occurrences
    let errors_cutoff = time::rfc3339(time::days_ago(config.retention_days_errors));
    let deleted_occurrences =
        models::error::delete_occurrences_before(pool, &errors_cutoff).await?;
    tracing::info!("Deleted {} old error occurrences", deleted_occurrences);

    // Delete old hourly rollups
    let hourly_cutoff = time::rfc3339(time::days_ago(config.retention_days_hourly_rollups));
    let deleted_hourly = models::rollup::delete_hourly_before(pool, &hourly_cutoff).await?;
    tracing::info!("Deleted {} old hourly rollups", deleted_hourly);

    // Delete old deploys (keep for 90 days)
    let deploys_cutoff = time::rfc3339(time::days_ago(90));
    let deleted_deploys = deploy::delete_before(pool, &deploys_cutoff).await?;
    tracing::info!("Deleted {} old deploys", deleted_deploys);

    // Delete expired invite tokens (users who never activated)
    let deleted_invites = user::delete_expired_invites(pool).await?;
    if deleted_invites > 0 {
        tracing::info!("Deleted {} expired invite tokens", deleted_invites);
    }

    // Vacuum on Sundays
    if Timestamp::now().strftime("%u").to_string() == "7" {
        sqlx::query("VACUUM").execute(pool).await?;
        tracing::info!("Database vacuumed");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db;

    async fn test_pool() -> DbPool {
        let config = Config::default();
        db::init(&config)
            .await
            .expect("Failed to create test database")
    }

    fn test_config() -> Config {
        Config {
            retention_days_errors: 30,
            retention_days_spans: 7,
            retention_days_hourly_rollups: 90,
            ..Config::default()
        }
    }

    #[tokio::test]
    async fn test_cleanup_deletes_old_spans() {
        let pool = test_pool().await;
        let config = test_config();

        let old_time = time::rfc3339(time::days_ago(10));
        let recent_time = time::now_rfc3339();

        // Insert an old span (project_id can be NULL)
        sqlx::query(
            "INSERT INTO spans (trace_id, span_id, name, start_time_unix_nano, end_time_unix_nano, span_category, happened_at) VALUES ('old-trace', 'old-span', 'test', 1000000000, 2000000000, 'http', ?1)",
        )
        .bind(&old_time)
        .execute(&pool)
        .await
        .unwrap();

        // Insert a recent span
        sqlx::query(
            "INSERT INTO spans (trace_id, span_id, name, start_time_unix_nano, end_time_unix_nano, span_category, happened_at) VALUES ('new-trace', 'new-span', 'test', 1000000000, 2000000000, 'http', ?1)",
        )
        .bind(&recent_time)
        .execute(&pool)
        .await
        .unwrap();

        // Run cleanup
        cleanup(&pool, &config).await.unwrap();

        // Check that old span was deleted
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM spans")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_cleanup_deletes_old_error_occurrences() {
        let pool = test_pool().await;
        let config = test_config();

        let old_time = time::rfc3339(time::days_ago(40));
        let recent_time = time::now_rfc3339();

        // First insert the parent error record (project_id can be NULL)
        let result = sqlx::query(
            "INSERT INTO errors (fingerprint, exception_class, message, first_seen_at, last_seen_at, occurrence_count, status) VALUES ('test-fp', 'TestError', 'test message', ?1, ?1, 1, 'open')",
        )
        .bind(&old_time)
        .execute(&pool)
        .await
        .unwrap();
        let error_id: i64 = result.last_insert_rowid();

        // Insert old occurrence
        sqlx::query(
            "INSERT INTO error_occurrences (error_id, backtrace, happened_at) VALUES (?1, '[]', ?2)",
        )
        .bind(error_id)
        .bind(&old_time)
        .execute(&pool)
        .await
        .unwrap();

        // Insert recent occurrence
        sqlx::query(
            "INSERT INTO error_occurrences (error_id, backtrace, happened_at) VALUES (?1, '[]', ?2)",
        )
        .bind(error_id)
        .bind(&recent_time)
        .execute(&pool)
        .await
        .unwrap();

        // Run cleanup
        cleanup(&pool, &config).await.unwrap();

        // Check that old occurrence was deleted
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM error_occurrences")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_cleanup_deletes_old_hourly_rollups() {
        let pool = test_pool().await;
        let config = test_config();

        // Insert old hourly rollup (100 days ago)
        let old_time = time::days_ago(100)
            .strftime("%Y-%m-%dT%H:00:00Z")
            .to_string();
        sqlx::query(
            "INSERT INTO rollups_hourly (hour, path, method, request_count, error_count, total_ms_sum, db_ms_sum, db_count_sum) VALUES (?1, '/test', 'GET', 10, 0, 100.0, 10.0, 5)",
        )
        .bind(&old_time)
        .execute(&pool)
        .await
        .unwrap();

        // Insert recent hourly rollup
        let recent_time = Timestamp::now().strftime("%Y-%m-%dT%H:00:00Z").to_string();
        sqlx::query(
            "INSERT INTO rollups_hourly (hour, path, method, request_count, error_count, total_ms_sum, db_ms_sum, db_count_sum) VALUES (?1, '/test', 'GET', 10, 0, 100.0, 10.0, 5)",
        )
        .bind(&recent_time)
        .execute(&pool)
        .await
        .unwrap();

        // Run cleanup
        cleanup(&pool, &config).await.unwrap();

        // Check that old rollup was deleted
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rollups_hourly")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_cleanup_deletes_old_deploys() {
        let pool = test_pool().await;
        let config = test_config();

        // Insert old deploy (100 days ago - deploys keep for 90 days, project_id can be NULL)
        let old_time = time::rfc3339(time::days_ago(100));
        sqlx::query("INSERT INTO deploys (git_sha, deployed_at) VALUES ('old-sha', ?1)")
            .bind(&old_time)
            .execute(&pool)
            .await
            .unwrap();

        // Insert recent deploy
        let recent_time = time::now_rfc3339();
        sqlx::query("INSERT INTO deploys (git_sha, deployed_at) VALUES ('new-sha', ?1)")
            .bind(&recent_time)
            .execute(&pool)
            .await
            .unwrap();

        // Run cleanup
        cleanup(&pool, &config).await.unwrap();

        // Check that old deploy was deleted
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deploys")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_cleanup_preserves_recent_data() {
        let pool = test_pool().await;
        let config = test_config();

        let recent_time = time::now_rfc3339();

        // Insert recent span
        sqlx::query(
            "INSERT INTO spans (trace_id, span_id, name, start_time_unix_nano, end_time_unix_nano, span_category, happened_at) VALUES ('recent-trace', 'recent-span', 'test', 1000000000, 2000000000, 'http', ?1)",
        )
        .bind(&recent_time)
        .execute(&pool)
        .await
        .unwrap();

        // Run cleanup
        cleanup(&pool, &config).await.unwrap();

        // Recent data should still exist
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM spans")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_cleanup_with_empty_database() {
        let pool = test_pool().await;
        let config = test_config();

        // Should not error on empty database
        let result = cleanup(&pool, &config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_cleanup_deletes_expired_invites() {
        let pool = test_pool().await;
        let config = test_config();

        // Create an expired invite
        let expired_time = time::rfc3339(time::days_ago(1));
        let now = time::now_rfc3339();
        sqlx::query(
            "INSERT INTO users (username, is_admin, invite_token, invite_expires_at, created_at) VALUES (?1, 0, 'expired-token', ?2, ?3)",
        )
        .bind("expired_user")
        .bind(&expired_time)
        .bind(&now)
        .execute(&pool)
        .await
        .unwrap();

        // Create a valid invite
        let future_time = time::rfc3339(time::days_ago(-1));
        sqlx::query(
            "INSERT INTO users (username, is_admin, invite_token, invite_expires_at, created_at) VALUES (?1, 0, 'valid-token', ?2, ?3)",
        )
        .bind("valid_user")
        .bind(&future_time)
        .bind(&now)
        .execute(&pool)
        .await
        .unwrap();

        // Run cleanup
        cleanup(&pool, &config).await.unwrap();

        // Check that only expired invite was deleted
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);

        // Verify the valid user remains
        let username: String = sqlx::query_scalar("SELECT username FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(username, "valid_user");
    }
}
