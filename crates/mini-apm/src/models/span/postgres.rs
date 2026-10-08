use super::TimeSeriesPoint;
use crate::DbPool;
use crate::time::Stamp;

pub async fn hourly_stats(
    pool: &DbPool,
    project_id: Option<i64>,
    hours: i64,
) -> anyhow::Result<Vec<TimeSeriesPoint>> {
    let rows: Vec<(String, i64, f64, i64)> = sqlx::query_as(
        r#"
        SELECT
            to_char(hour, 'YYYY-MM-DD HH24:00'),
            COUNT(s.id),
            COALESCE(AVG(s.duration_ms), 0),
            COUNT(s.id) FILTER (WHERE s.status_code = 2 OR s.http_status_code >= 500)
        FROM hour_buckets($2, $3::int) AS hour
        LEFT JOIN spans s
            ON s.happened_at >= hour
           AND s.happened_at < hour + interval '1 hour'
           AND s.happened_at >= $2::timestamptz - make_interval(hours => $3::int)
           AND s.parent_span_id IS NULL
           AND ($1::bigint IS NULL OR s.project_id = $1)
        GROUP BY hour
        ORDER BY hour
        "#,
    )
    .bind(project_id)
    .bind(Stamp::now())
    .bind(hours)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(hour, count, avg_ms, error_count)| TimeSeriesPoint {
            hour,
            count,
            avg_ms,
            error_count,
        })
        .collect())
}
