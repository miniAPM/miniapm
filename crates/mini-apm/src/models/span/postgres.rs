use super::TimeSeriesPoint;
use crate::DbPool;
use crate::time::Stamp;
use std::collections::HashMap;

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
        FROM generate_series(
            date_trunc('hour', $2::timestamptz) - make_interval(hours => $3::int - 1),
            date_trunc('hour', $2::timestamptz),
            interval '1 hour'
        ) AS hour
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

pub(super) async fn route_durations(
    pool: &DbPool,
    project_id: Option<i64>,
    since: Stamp,
    paths: &[String],
) -> anyhow::Result<HashMap<String, Vec<f64>>> {
    let rows: Vec<(String, f64)> = sqlx::query_as(
        r#"
        SELECT COALESCE(name, http_url, 'unknown') AS path, duration_ms
        FROM spans
        WHERE parent_span_id IS NULL
          AND ($1 IS NULL OR project_id = $1)
          AND happened_at >= $2
          AND COALESCE(name, http_url, 'unknown') = ANY($3)
        ORDER BY duration_ms ASC
        "#,
    )
    .bind(project_id)
    .bind(since)
    .bind(paths)
    .fetch_all(pool)
    .await?;

    let mut durations: HashMap<String, Vec<f64>> = HashMap::new();
    for (path, duration) in rows {
        durations.entry(path).or_default().push(duration);
    }
    Ok(durations)
}

pub(super) async fn route_db_stats(
    pool: &DbPool,
    project_id: Option<i64>,
    since: Stamp,
    paths: &[String],
) -> anyhow::Result<HashMap<String, (i64, i64)>> {
    let rows: Vec<(String, f64, f64)> = sqlx::query_as(
        r#"
        WITH roots AS (
            SELECT trace_id, COALESCE(name, http_url, 'unknown') AS path
            FROM spans
            WHERE parent_span_id IS NULL
              AND ($1 IS NULL OR project_id = $1)
              AND happened_at >= $2
              AND COALESCE(name, http_url, 'unknown') = ANY($3)
        ),
        db AS (
            SELECT s.trace_id, SUM(s.duration_ms) AS db_ms, COUNT(*) AS db_count
            FROM spans s
            JOIN (SELECT DISTINCT trace_id FROM roots) r ON r.trace_id = s.trace_id
            WHERE s.span_category = 'db'
            GROUP BY s.trace_id
        )
        SELECT roots.path, AVG(db.db_ms), AVG(CAST(db.db_count AS DOUBLE PRECISION))
        FROM roots
        JOIN db ON db.trace_id = roots.trace_id
        GROUP BY roots.path
        "#,
    )
    .bind(project_id)
    .bind(since)
    .bind(paths)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(path, db_ms, db_count)| (path, (db_ms.round() as i64, db_count.round() as i64)))
        .collect())
}
