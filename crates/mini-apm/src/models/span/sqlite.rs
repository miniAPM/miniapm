use super::{LatencyStats, SPAN_COLUMNS, SPAN_UPSERT, SpanRow, TimeSeriesPoint};
use crate::DbPool;
use crate::db;
use crate::time::{self, Stamp};
use std::collections::HashMap;
use std::sync::LazyLock;

pub async fn hourly_stats(
    pool: &DbPool,
    project_id: Option<i64>,
    hours: i64,
) -> anyhow::Result<Vec<TimeSeriesPoint>> {
    let rows: Vec<(String, i64, f64, i64)> = sqlx::query_as(
        r"
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
        ",
    )
    .bind(project_id)
    .bind(time::hours_ago(hours))
    .fetch_all(pool)
    .await?;

    let mut data_points: HashMap<String, (i64, f64, i64)> = rows
        .into_iter()
        .map(|(hour, count, avg_ms, error_count)| (hour, (count, avg_ms, error_count)))
        .collect();

    // Fill in all hours with zeros for missing data
    let points = (0..hours)
        .rev()
        .map(|i| {
            let hour = time::hours_ago(i).hour_label();
            let (count, avg_ms, error_count) = data_points.remove(&hour).unwrap_or_default();
            TimeSeriesPoint {
                hour,
                count,
                avg_ms,
                error_count,
            }
        })
        .collect();

    Ok(points)
}

/// Root spans since `since`
pub async fn count_since(
    pool: &DbPool,
    project_id: Option<i64>,
    since: Stamp,
) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COUNT(*) FROM spans WHERE parent_span_id IS NULL AND ($1 IS NULL OR project_id = $1) AND happened_at >= $2",
    )
    .bind(project_id)
    .bind(since)
    .fetch_one(pool)
    .await?)
}

/// The unique key a resent span is matched on
pub(super) const SPAN_KEY: &[&str] = &["trace_id", "span_id"];

static INSERT_SPAN: LazyLock<String> = LazyLock::new(|| {
    let values = (1..=SPAN_COLUMNS.len() + 1)
        .map(|i| format!("${i}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "INSERT INTO spans (project_id, {}) VALUES ({values}) {}",
        SPAN_COLUMNS.join(", "),
        *SPAN_UPSERT
    )
});

/// Upsert `rows` one statement each, inside a single write transaction. The
/// rows are consumed so their owned text moves into the statement uncopied.
pub(super) async fn insert_spans(
    pool: &DbPool,
    project_id: Option<i64>,
    rows: Vec<SpanRow<'_>>,
) -> anyhow::Result<()> {
    let mut tx = db::begin_write(pool).await?;
    for row in rows {
        sqlx::query(sqlx::AssertSqlSafe(INSERT_SPAN.as_str()))
            .bind(project_id)
            .bind(row.trace_id)
            .bind(row.span_id)
            .bind(row.parent_span_id)
            .bind(row.start_time_unix_nano)
            .bind(row.end_time_unix_nano)
            .bind(row.duration_ms)
            .bind(row.name)
            .bind(row.kind)
            .bind(row.status_code)
            .bind(row.status_message)
            .bind(row.span_category)
            .bind(row.root_span_type)
            .bind(row.service_name)
            .bind(row.http_method)
            .bind(row.http_url)
            .bind(row.http_status_code)
            .bind(row.db_system)
            .bind(row.db_statement)
            .bind(row.db_operation)
            .bind(row.messaging_system)
            .bind(row.messaging_operation)
            .bind(row.request_id)
            .bind(row.attributes_json)
            .bind(row.events_json)
            .bind(row.resource_attributes_json)
            .bind(row.happened_at)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// The nearest-rank `percent`th percentile of `sorted` (ascending), rounded to
/// the nearest ms: the smallest sample that at least `percent`% of samples are
/// at or below, as SQL `percentile_disc` picks it. `sorted` must be non-empty.
fn percentile_ms(sorted: &[f64], percent: usize) -> i64 {
    let rank = (percent * sorted.len())
        .div_ceil(100)
        .clamp(1, sorted.len());
    super::round_i64(sorted[rank - 1])
}

pub async fn latency_stats_since(
    pool: &DbPool,
    project_id: Option<i64>,
    since: Stamp,
) -> anyhow::Result<LatencyStats> {
    let values: Vec<f64> = sqlx::query_scalar(
        "SELECT duration_ms FROM spans WHERE parent_span_id IS NULL AND happened_at >= $1 AND ($2 IS NULL OR project_id = $2) ORDER BY duration_ms ASC",
    )
    .bind(since)
    .bind(project_id)
    .fetch_all(pool)
    .await?;

    if values.is_empty() {
        return Ok(LatencyStats {
            avg_ms: 0,
            p95_ms: 0,
            p99_ms: 0,
        });
    }

    let avg = values.iter().sum::<f64>() / values.len() as f64;

    Ok(LatencyStats {
        avg_ms: super::round_i64(avg),
        p95_ms: percentile_ms(&values, 95),
        p99_ms: percentile_ms(&values, 99),
    })
}

/// p95 and p99 of each route in `paths`, computed from its root span durations
pub(super) async fn route_percentiles(
    pool: &DbPool,
    project_id: Option<i64>,
    since: Stamp,
    paths: &[&str],
) -> anyhow::Result<HashMap<String, (i64, i64)>> {
    Ok(route_durations(pool, project_id, since, paths)
        .await?
        .into_iter()
        .map(|(path, d)| (path, (percentile_ms(&d, 95), percentile_ms(&d, 99))))
        .collect())
}

async fn route_durations(
    pool: &DbPool,
    project_id: Option<i64>,
    since: Stamp,
    paths: &[&str],
) -> anyhow::Result<HashMap<String, Vec<f64>>> {
    let in_paths = db::in_text_list(3);
    let rows: Vec<(String, f64)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        r"
        SELECT name AS path, duration_ms
        FROM spans
        WHERE parent_span_id IS NULL
          AND ($1 IS NULL OR project_id = $1)
          AND happened_at >= $2
          AND name {in_paths}
        ORDER BY duration_ms ASC
        "
    )))
    .bind(project_id)
    .bind(since)
    .bind(db::text_list(paths))
    .fetch_all(pool)
    .await?;

    let mut durations: HashMap<String, Vec<f64>> = HashMap::new();
    for (path, duration) in rows {
        durations.entry(path).or_default().push(duration);
    }
    Ok(durations)
}

#[cfg(test)]
mod tests;
