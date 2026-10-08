use super::{LatencyStats, SPAN_COLUMNS, SPAN_UPSERT, SpanRow, TimeSeriesPoint};
use crate::DbPool;
use crate::db;
use crate::time::Stamp;
use std::collections::HashMap;
use std::sync::LazyLock;

pub async fn hourly_stats(
    pool: &DbPool,
    project_id: Option<i64>,
    hours: i64,
) -> anyhow::Result<Vec<TimeSeriesPoint>> {
    let rows: Vec<(String, i64, f64, i64)> = sqlx::query_as(
        r#"
        SELECT
            to_char(b.hour, 'YYYY-MM-DD HH24:00'),
            COALESCE(SUM(r.requests), 0)::bigint,
            COALESCE(SUM(r.duration_ms) / NULLIF(SUM(r.timed), 0), 0),
            COALESCE(SUM(r.errors), 0)::bigint
        FROM hour_buckets($2, $3::int) AS b(hour)
        LEFT JOIN span_rollups r
            ON r.hour = b.hour AND ($1::bigint IS NULL OR r.project_id = $1)
        GROUP BY b.hour
        ORDER BY b.hour
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

/// Root spans since `since`: whole hours from the rollups, the partial hour
/// `since` falls in from the spans themselves
pub async fn count_since(
    pool: &DbPool,
    project_id: Option<i64>,
    since: Stamp,
) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT
            (SELECT COALESCE(SUM(requests), 0)::bigint FROM span_rollups
              WHERE hour > date_trunc('hour', $2, 'UTC')
                AND ($1::bigint IS NULL OR project_id = $1))
          + (SELECT COUNT(*) FROM spans
              WHERE parent_span_id IS NULL
                AND ($1::bigint IS NULL OR project_id = $1)
                AND happened_at >= $2
                AND happened_at < date_trunc('hour', $2, 'UTC') + interval '1 hour')",
    )
    .bind(project_id)
    .bind(since)
    .fetch_one(pool)
    .await?)
}

/// The unique key a resent span is matched on, which on a table partitioned
/// by `happened_at` has to include it
pub(super) const SPAN_KEY: &[&str] = &["trace_id", "span_id", "happened_at"];

/// One statement for the whole batch: each column arrives as an array and
/// `unnest` turns them back into rows. A span repeated in the batch keeps its
/// last copy, as `ON CONFLICT` may not touch the same row twice.
static INSERT_SPANS: LazyLock<String> = LazyLock::new(|| {
    let columns = SPAN_COLUMNS.join(", ");
    let values = SPAN_COLUMNS
        .map(|c| match c {
            "attributes_json" | "events_json" | "resource_attributes_json" => format!("{c}::jsonb"),
            _ => c.to_string(),
        })
        .join(", ");
    let arrays = (2..=SPAN_COLUMNS.len() + 1)
        .map(|i| format!("${i}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "INSERT INTO spans (project_id, {columns})
         SELECT DISTINCT ON (trace_id, span_id) $1, {values}
         FROM unnest({arrays}) WITH ORDINALITY AS r({columns}, ord)
         ORDER BY trace_id, span_id, ord DESC
         {}",
        *SPAN_UPSERT
    )
});

fn column<'r, T>(rows: &'r [SpanRow], field: impl Fn(&'r SpanRow) -> T) -> Vec<T> {
    rows.iter().map(field).collect()
}

pub(super) async fn insert_spans(
    pool: &DbPool,
    project_id: Option<i64>,
    rows: &[SpanRow],
) -> anyhow::Result<()> {
    sqlx::query(sqlx::AssertSqlSafe(INSERT_SPANS.as_str()))
        .bind(project_id)
        .bind(column(rows, |r| r.trace_id.as_str()))
        .bind(column(rows, |r| r.span_id.as_str()))
        .bind(column(rows, |r| r.parent_span_id.as_deref()))
        .bind(column(rows, |r| r.start_time_unix_nano))
        .bind(column(rows, |r| r.end_time_unix_nano))
        .bind(column(rows, |r| r.duration_ms))
        .bind(column(rows, |r| r.name.as_str()))
        .bind(column(rows, |r| r.kind))
        .bind(column(rows, |r| r.status_code))
        .bind(column(rows, |r| r.status_message.as_deref()))
        .bind(column(rows, |r| r.span_category))
        .bind(column(rows, |r| r.root_span_type))
        .bind(column(rows, |r| r.service_name.as_deref()))
        .bind(column(rows, |r| r.http_method.as_deref()))
        .bind(column(rows, |r| r.http_url.as_deref()))
        .bind(column(rows, |r| r.http_status_code))
        .bind(column(rows, |r| r.db_system.as_deref()))
        .bind(column(rows, |r| r.db_statement.as_deref()))
        .bind(column(rows, |r| r.db_operation.as_deref()))
        .bind(column(rows, |r| r.messaging_system.as_deref()))
        .bind(column(rows, |r| r.messaging_operation.as_deref()))
        .bind(column(rows, |r| r.request_id.as_deref()))
        .bind(column(rows, |r| r.attributes_json.as_str()))
        .bind(column(rows, |r| r.events_json.as_deref()))
        .bind(column(rows, |r| r.resource_attributes_json.as_str()))
        .bind(column(rows, |r| r.happened_at))
        .execute(pool)
        .await?;
    Ok(())
}

/// A duration as whole ms, rounded half away from zero as `percentile_ms` does
fn ms(duration: Option<f64>) -> i64 {
    duration.map_or(0, |d| d.round() as i64)
}

/// Average and nearest-rank p95/p99 of root span durations since `since`
pub async fn latency_stats_since(
    pool: &DbPool,
    project_id: Option<i64>,
    since: Stamp,
) -> anyhow::Result<LatencyStats> {
    let (avg, p95, p99): (Option<f64>, Option<f64>, Option<f64>) = sqlx::query_as(
        "SELECT AVG(duration_ms),
                percentile_disc(0.95) WITHIN GROUP (ORDER BY duration_ms),
                percentile_disc(0.99) WITHIN GROUP (ORDER BY duration_ms)
         FROM spans
         WHERE parent_span_id IS NULL AND happened_at >= $1 AND ($2 IS NULL OR project_id = $2)",
    )
    .bind(since)
    .bind(project_id)
    .fetch_one(pool)
    .await?;
    Ok(LatencyStats {
        avg_ms: ms(avg),
        p95_ms: ms(p95),
        p99_ms: ms(p99),
    })
}

/// Nearest-rank p95 and p99 of each route in `paths`
pub(super) async fn route_percentiles(
    pool: &DbPool,
    project_id: Option<i64>,
    since: Stamp,
    paths: &[String],
) -> anyhow::Result<HashMap<String, (i64, i64)>> {
    let rows: Vec<(String, Option<f64>, Option<f64>)> =
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT name,
                percentile_disc(0.95) WITHIN GROUP (ORDER BY duration_ms),
                percentile_disc(0.99) WITHIN GROUP (ORDER BY duration_ms)
         FROM spans
         WHERE parent_span_id IS NULL
           AND ($1 IS NULL OR project_id = $1)
           AND happened_at >= $2
           AND name {}
         GROUP BY name",
            db::in_text_list(3)
        )))
        .bind(project_id)
        .bind(since)
        .bind(db::text_list(paths))
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(path, p95, p99)| (path, (ms(p95), ms(p99))))
        .collect())
}
