use super::*;
use crate::db::test_pool;

#[tokio::test]
async fn hourly_recalculation_replaces_values_without_merging_methods() -> anyhow::Result<()> {
    let pool = test_pool().await;
    let mut rollup = HourlyRollup {
        id: 0,
        hour: "2024-01-15T10:00:00Z".into(),
        path: "/users".into(),
        method: "GET".into(),
        request_count: 100,
        error_count: 5,
        total_ms_sum: 5000.0,
        total_ms_p50: Some(45.0),
        total_ms_p95: Some(120.0),
        total_ms_p99: Some(250.0),
        db_ms_sum: 1000.0,
        db_count_sum: 200,
    };
    insert_hourly(&pool, &rollup).await?;
    rollup.request_count = 200;
    rollup.total_ms_p50 = None;
    rollup.total_ms_p95 = None;
    rollup.total_ms_p99 = None;
    insert_hourly(&pool, &rollup).await?;
    rollup.method = "POST".into();
    rollup.request_count = 10;
    insert_hourly(&pool, &rollup).await?;

    let rows: Vec<(String, i64, Option<f64>, Option<f64>, Option<f64>)> = sqlx::query_as(
        "SELECT method, request_count, total_ms_p50, total_ms_p95, total_ms_p99 FROM rollups_hourly ORDER BY method",
    ).fetch_all(&pool).await?;
    assert_eq!(
        rows,
        [
            ("GET".into(), 200, None, None, None),
            ("POST".into(), 10, None, None, None)
        ]
    );
    Ok(())
}

#[tokio::test]
async fn daily_queries_apply_inclusive_range_ranking_limit_and_replacements() -> anyhow::Result<()>
{
    let pool = test_pool().await;
    for (date, path, count) in [
        ("2024-01-09", "/before", 9999),
        ("2024-01-10", "/start", 100),
        ("2024-01-15", "/middle", 300),
        ("2024-01-20", "/end", 200),
        ("2024-01-21", "/after", 9999),
        ("2024-01-15", "/middle", 400),
    ] {
        insert_daily(
            &pool,
            &DailyRollup {
                id: 0,
                date: date.into(),
                path: path.into(),
                method: "GET".into(),
                request_count: count,
                error_count: 0,
                total_ms_p50: None,
                total_ms_p95: None,
                total_ms_p99: None,
                avg_db_ms: None,
                avg_db_count: None,
            },
        )
        .await?;
    }

    let rows = daily_for_range(&pool, "2024-01-10", "2024-01-20", 100).await?;
    assert_eq!(
        rows.iter()
            .map(|r| (r.path.as_str(), r.request_count))
            .collect::<Vec<_>>(),
        [("/middle", 400), ("/end", 200), ("/start", 100)]
    );
    assert!(rows.iter().all(|r| r.total_ms_p50.is_none()
        && r.total_ms_p95.is_none()
        && r.total_ms_p99.is_none()
        && r.avg_db_ms.is_none()
        && r.avg_db_count.is_none()));
    let limited = daily_for_range(&pool, "2024-01-10", "2024-01-20", 2).await?;
    assert_eq!(
        limited.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
        ["/middle", "/end"]
    );
    assert!(
        daily_for_range(&pool, "2025-01-01", "2025-01-31", 100)
            .await?
            .is_empty()
    );
    Ok(())
}
