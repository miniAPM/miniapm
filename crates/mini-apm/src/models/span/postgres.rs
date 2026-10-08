use super::{SPAN_COLUMNS, SPAN_UPSERT, SpanRow, TimeSeriesPoint};
use crate::DbPool;
use crate::time::Stamp;
use std::sync::LazyLock;

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
