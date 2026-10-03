use super::*;
use crate::db::test_pool;

#[tokio::test]
async fn hourly_groups_routes_and_methods_in_the_previous_hour_only() -> anyhow::Result<()> {
    let pool = test_pool().await;
    let previous = time::hours_ago(1);
    let sql_time = previous.strftime("%Y-%m-%d %H:30:00").to_string();
    let otlp_time = previous.strftime("%Y-%m-%dT%H:30:00Z").to_string();
    let older = time::hours_ago(2)
        .strftime("%Y-%m-%dT%H:30:00Z")
        .to_string();
    let current = Timestamp::now().strftime("%Y-%m-%dT%H:00:00Z").to_string();
    for (id, path, method, ms, db_ms, db_count, happened_at) in [
        ("a", "/users", "GET", 100.0, 10.0, 2, &sql_time),
        ("b", "/users", "GET", 200.0, 20.0, 3, &otlp_time),
        ("c", "/users", "POST", 150.0, 15.0, 1, &otlp_time),
        ("d", "/orders", "GET", 50.0, 5.0, 1, &otlp_time),
        ("old", "/excluded", "GET", 999.0, 0.0, 0, &older),
        ("current", "/excluded", "GET", 999.0, 0.0, 0, &current),
    ] {
        sqlx::query(
            "INSERT INTO requests (request_id, method, path, status, total_ms, db_ms, db_count, happened_at)
             VALUES (?1, ?2, ?3, 200, ?4, ?5, ?6, ?7)",
        ).bind(id).bind(method).bind(path).bind(ms).bind(db_ms).bind(db_count)
            .bind(happened_at).execute(&pool).await?;
    }

    for _ in 0..2 {
        hourly(&pool).await?;
        let rows: Vec<(String, String, i64, f64, f64, i64)> = sqlx::query_as(
            "SELECT path, method, request_count, total_ms_sum, db_ms_sum, db_count_sum
             FROM rollups_hourly ORDER BY path, method",
        )
        .fetch_all(&pool)
        .await?;
        assert_eq!(
            rows,
            [
                ("/orders".into(), "GET".into(), 1, 50.0, 5.0, 1),
                ("/users".into(), "GET".into(), 2, 300.0, 30.0, 5),
                ("/users".into(), "POST".into(), 1, 150.0, 15.0, 1),
            ]
        );
    }
    Ok(())
}

#[tokio::test]
async fn daily_aggregates_counts_and_weighted_database_averages() -> anyhow::Result<()> {
    let pool = test_pool().await;
    let previous = time::days_ago(1).strftime("%Y-%m-%d").to_string();
    let current = Timestamp::now().strftime("%Y-%m-%d").to_string();
    for (hour, requests, errors, db_ms, db_count) in [
        (format!("{previous}T10:00:00Z"), 100, 5, 200.0, 50),
        (format!("{previous}T14:00:00Z"), 200, 10, 1000.0, 400),
        (format!("{current}T00:00:00Z"), 999, 99, 9999.0, 9999),
    ] {
        sqlx::query(
            "INSERT INTO rollups_hourly (hour, path, method, request_count, error_count, total_ms_sum,
             total_ms_p50, total_ms_p95, total_ms_p99, db_ms_sum, db_count_sum)
             VALUES (?1, '/api/data', 'GET', ?2, ?3, 1000.0, 10.0, 50.0, 100.0, ?4, ?5)",
        ).bind(hour).bind(requests).bind(errors).bind(db_ms).bind(db_count).execute(&pool).await?;
    }
    for _ in 0..2 {
        daily(&pool).await?;
        let rows = rollup::daily_for_range(&pool, &previous, &previous, 10).await?;
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!((row.request_count, row.error_count), (300, 15));
        assert_eq!((row.avg_db_ms, row.avg_db_count), (Some(4.0), Some(1.5)));
        assert_eq!(
            (row.total_ms_p50, row.total_ms_p95, row.total_ms_p99),
            (Some(10.0), Some(50.0), Some(100.0))
        );
    }
    Ok(())
}

#[tokio::test]
async fn empty_periods_do_not_produce_rollups() -> anyhow::Result<()> {
    let pool = test_pool().await;
    hourly(&pool).await?;
    daily(&pool).await?;
    for query in [
        "SELECT COUNT(*) FROM rollups_hourly",
        "SELECT COUNT(*) FROM rollups_daily",
    ] {
        let count: i64 = sqlx::query_scalar(query).fetch_one(&pool).await?;
        assert_eq!(count, 0, "{query}");
    }
    Ok(())
}
