use super::TimeSeriesPoint;
use crate::DbPool;
use crate::time::{self, Stamp};
use std::collections::HashMap;

pub async fn hourly_stats(
    pool: &DbPool,
    project_id: Option<i64>,
    hours: i64,
) -> anyhow::Result<Vec<TimeSeriesPoint>> {
    let rows: Vec<(String, i64, f64, i64)> = sqlx::query_as(
        r#"
        SELECT
            strftime('%Y-%m-%d %H:00', happened_at) as hour,
            COUNT(*) as count,
            COALESCE(AVG(duration_ms), 0.0) as avg_ms,
            SUM(CASE WHEN status_code = 2 OR http_status_code >= 500 THEN 1 ELSE 0 END) as error_count
        FROM spans
        WHERE parent_span_id IS NULL
          AND ($1 IS NULL OR project_id = $1)
          AND happened_at >= $2
        GROUP BY strftime('%Y-%m-%d %H:00', happened_at)
        ORDER BY hour ASC
        "#,
    )
    .bind(project_id)
    .bind(time::hours_ago(hours))
    .fetch_all(pool)
    .await?;

    let data_points: std::collections::HashMap<String, TimeSeriesPoint> = rows
        .into_iter()
        .map(|(hour, count, avg_ms, error_count)| {
            (
                hour.clone(),
                TimeSeriesPoint {
                    hour,
                    count,
                    avg_ms,
                    error_count,
                },
            )
        })
        .collect();

    // Fill in all hours with zeros for missing data
    let mut points = Vec::with_capacity(hours as usize);
    for i in (0..hours).rev() {
        let hour_key = time::hours_ago(i).0.strftime("%Y-%m-%d %H:00").to_string();
        points.push(
            data_points
                .get(&hour_key)
                .cloned()
                .unwrap_or(TimeSeriesPoint {
                    hour: hour_key,
                    count: 0,
                    avg_ms: 0.0,
                    error_count: 0,
                }),
        );
    }

    Ok(points)
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
          AND COALESCE(name, http_url, 'unknown') IN (SELECT value FROM json_each($3))
        ORDER BY duration_ms ASC
        "#,
    )
    .bind(project_id)
    .bind(since)
    .bind(serde_json::to_string(paths)?)
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
              AND COALESCE(name, http_url, 'unknown') IN (SELECT value FROM json_each($3))
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
    .bind(serde_json::to_string(paths)?)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(path, db_ms, db_count)| (path, (db_ms.round() as i64, db_count.round() as i64)))
        .collect())
}
