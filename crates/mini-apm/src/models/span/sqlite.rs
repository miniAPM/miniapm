use super::{SPAN_COLUMNS, SPAN_UPSERT, SpanRow, TimeSeriesPoint};
use crate::DbPool;
use crate::db;
use crate::time;
use std::sync::LazyLock;

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
        let hour_key = time::hours_ago(i).hour_label();
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

/// Upsert `rows` one statement each, inside a single write transaction
pub(super) async fn insert_spans(
    pool: &DbPool,
    project_id: Option<i64>,
    rows: &[SpanRow],
) -> anyhow::Result<()> {
    let mut tx = db::begin_write(pool).await?;
    for row in rows {
        sqlx::query(sqlx::AssertSqlSafe(INSERT_SPAN.as_str()))
            .bind(project_id)
            .bind(&row.trace_id)
            .bind(&row.span_id)
            .bind(row.parent_span_id.as_deref())
            .bind(row.start_time_unix_nano)
            .bind(row.end_time_unix_nano)
            .bind(row.duration_ms)
            .bind(&row.name)
            .bind(row.kind)
            .bind(row.status_code)
            .bind(row.status_message.as_deref())
            .bind(row.span_category)
            .bind(row.root_span_type)
            .bind(row.service_name.as_deref())
            .bind(row.http_method.as_deref())
            .bind(row.http_url.as_deref())
            .bind(row.http_status_code)
            .bind(row.db_system.as_deref())
            .bind(row.db_statement.as_deref())
            .bind(row.db_operation.as_deref())
            .bind(row.messaging_system.as_deref())
            .bind(row.messaging_operation.as_deref())
            .bind(row.request_id.as_deref())
            .bind(&row.attributes_json)
            .bind(row.events_json.as_deref())
            .bind(&row.resource_attributes_json)
            .bind(row.happened_at)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}
