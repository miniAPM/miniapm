use crate::{
    DbPool,
    config::Config,
    models::{self, deploy, user},
};
use chrono::{Duration, Utc};

pub fn cleanup(pool: &DbPool, config: &Config) -> anyhow::Result<()> {
    // Delete old spans
    let spans_cutoff = (Utc::now() - Duration::days(config.retention_days_spans)).to_rfc3339();
    let deleted_spans = models::span::delete_before(pool, &spans_cutoff)?;
    tracing::info!("Deleted {} old spans", deleted_spans);

    // Delete old error occurrences
    let errors_cutoff = (Utc::now() - Duration::days(config.retention_days_errors)).to_rfc3339();
    let deleted_occurrences = models::error::delete_occurrences_before(pool, &errors_cutoff)?;
    tracing::info!("Deleted {} old error occurrences", deleted_occurrences);

    // Delete old hourly rollups
    let hourly_cutoff =
        (Utc::now() - Duration::days(config.retention_days_hourly_rollups)).to_rfc3339();
    let deleted_hourly = models::rollup::delete_hourly_before(pool, &hourly_cutoff)?;
    tracing::info!("Deleted {} old hourly rollups", deleted_hourly);

    // Delete old deploys (keep for 90 days)
    let deploys_cutoff = (Utc::now() - Duration::days(90)).to_rfc3339();
    let deleted_deploys = deploy::delete_before(pool, &deploys_cutoff)?;
    tracing::info!("Deleted {} old deploys", deleted_deploys);

    // Delete expired invite tokens (users who never activated)
    let deleted_invites = user::delete_expired_invites(pool)?;
    if deleted_invites > 0 {
        tracing::info!("Deleted {} expired invite tokens", deleted_invites);
    }

    // Vacuum on Sundays
    if Utc::now().format("%u").to_string() == "7" {
        let conn = pool.get()?;
        conn.execute_batch("VACUUM")?;
        tracing::info!("Database vacuumed");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_pool() -> DbPool {
        // Use a unique named in-memory database for each test to ensure isolation
        let test_id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let db_name = format!("file:retention_test_{}?mode=memory&cache=shared", test_id);
        let config = Config {
            sqlite_path: db_name,
            ..Default::default()
        };
        db::init(&config).expect("Failed to create test database")
    }

    fn test_config() -> Config {
        Config {
            retention_days_errors: 30,
            retention_days_spans: 7,
            retention_days_hourly_rollups: 90,
            ..Config::default()
        }
    }

    #[test]
    fn test_cleanup_deletes_old_spans() {
        let pool = test_pool();
        let config = test_config();
        let conn = pool.get().unwrap();

        let old_time = (Utc::now() - Duration::days(10)).to_rfc3339();
        let recent_time = Utc::now().to_rfc3339();

        // Insert an old span (project_id can be NULL)
        conn.execute(
            "INSERT INTO spans (trace_id, span_id, name, start_time_unix_nano, end_time_unix_nano, span_category, happened_at) VALUES ('old-trace', 'old-span', 'test', 1000000000, 2000000000, 'http', ?1)",
            [&old_time],
        ).unwrap();

        // Insert a recent span
        conn.execute(
            "INSERT INTO spans (trace_id, span_id, name, start_time_unix_nano, end_time_unix_nano, span_category, happened_at) VALUES ('new-trace', 'new-span', 'test', 1000000000, 2000000000, 'http', ?1)",
            [&recent_time],
        ).unwrap();

        // Run cleanup
        cleanup(&pool, &config).unwrap();

        // Check that old span was deleted
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM spans", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_cleanup_deletes_old_error_occurrences() {
        let pool = test_pool();
        let config = test_config();
        let conn = pool.get().unwrap();

        let old_time = (Utc::now() - Duration::days(40)).to_rfc3339();
        let recent_time = Utc::now().to_rfc3339();

        // First insert the parent error record (project_id can be NULL)
        conn.execute(
            "INSERT INTO errors (fingerprint, exception_class, message, first_seen_at, last_seen_at, occurrence_count, status) VALUES ('test-fp', 'TestError', 'test message', ?1, ?1, 1, 'open')",
            [&old_time],
        ).unwrap();
        let error_id: i64 = conn.last_insert_rowid();

        // Insert old occurrence
        conn.execute(
            "INSERT INTO error_occurrences (error_id, backtrace, happened_at) VALUES (?1, '[]', ?2)",
            (error_id, &old_time),
        ).unwrap();

        // Insert recent occurrence
        conn.execute(
            "INSERT INTO error_occurrences (error_id, backtrace, happened_at) VALUES (?1, '[]', ?2)",
            (error_id, &recent_time),
        ).unwrap();

        // Run cleanup
        cleanup(&pool, &config).unwrap();

        // Check that old occurrence was deleted
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM error_occurrences", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_cleanup_deletes_old_hourly_rollups() {
        let pool = test_pool();
        let config = test_config();
        let conn = pool.get().unwrap();

        // Insert old hourly rollup (100 days ago)
        let old_time = (Utc::now() - Duration::days(100))
            .format("%Y-%m-%dT%H:00:00Z")
            .to_string();
        conn.execute(
            "INSERT INTO rollups_hourly (hour, path, method, request_count, error_count, total_ms_sum, db_ms_sum, db_count_sum) VALUES (?1, '/test', 'GET', 10, 0, 100.0, 10.0, 5)",
            [&old_time],
        ).unwrap();

        // Insert recent hourly rollup
        let recent_time = Utc::now()
            .format("%Y-%m-%dT%H:00:00Z")
            .to_string();
        conn.execute(
            "INSERT INTO rollups_hourly (hour, path, method, request_count, error_count, total_ms_sum, db_ms_sum, db_count_sum) VALUES (?1, '/test', 'GET', 10, 0, 100.0, 10.0, 5)",
            [&recent_time],
        ).unwrap();

        // Run cleanup
        cleanup(&pool, &config).unwrap();

        // Check that old rollup was deleted
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM rollups_hourly", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_cleanup_deletes_old_deploys() {
        let pool = test_pool();
        let config = test_config();
        let conn = pool.get().unwrap();

        // Insert old deploy (100 days ago - deploys keep for 90 days, project_id can be NULL)
        let old_time = (Utc::now() - Duration::days(100)).to_rfc3339();
        conn.execute(
            "INSERT INTO deploys (git_sha, deployed_at) VALUES ('old-sha', ?1)",
            [&old_time],
        ).unwrap();

        // Insert recent deploy
        let recent_time = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO deploys (git_sha, deployed_at) VALUES ('new-sha', ?1)",
            [&recent_time],
        ).unwrap();

        // Run cleanup
        cleanup(&pool, &config).unwrap();

        // Check that old deploy was deleted
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM deploys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_cleanup_preserves_recent_data() {
        let pool = test_pool();
        let config = test_config();
        let conn = pool.get().unwrap();

        let recent_time = Utc::now().to_rfc3339();

        // Insert recent span
        conn.execute(
            "INSERT INTO spans (trace_id, span_id, name, start_time_unix_nano, end_time_unix_nano, span_category, happened_at) VALUES ('recent-trace', 'recent-span', 'test', 1000000000, 2000000000, 'http', ?1)",
            [&recent_time],
        ).unwrap();

        // Run cleanup
        cleanup(&pool, &config).unwrap();

        // Recent data should still exist
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM spans", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_cleanup_with_empty_database() {
        let pool = test_pool();
        let config = test_config();

        // Should not error on empty database
        let result = cleanup(&pool, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cleanup_deletes_expired_invites() {
        let pool = test_pool();
        let config = test_config();
        let conn = pool.get().unwrap();

        // Create an expired invite
        let expired_time = (Utc::now() - Duration::days(1)).to_rfc3339();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO users (username, is_admin, invite_token, invite_expires_at, created_at) VALUES (?1, 0, 'expired-token', ?2, ?3)",
            ("expired_user", &expired_time, &now),
        ).unwrap();

        // Create a valid invite
        let future_time = (Utc::now() + Duration::days(1)).to_rfc3339();
        conn.execute(
            "INSERT INTO users (username, is_admin, invite_token, invite_expires_at, created_at) VALUES (?1, 0, 'valid-token', ?2, ?3)",
            ("valid_user", &future_time, &now),
        ).unwrap();

        // Run cleanup
        cleanup(&pool, &config).unwrap();

        // Check that only expired invite was deleted
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 1);

        // Verify the valid user remains
        let username: String = conn.query_row("SELECT username FROM users", [], |row| row.get(0)).unwrap();
        assert_eq!(username, "valid_user");
    }
}
