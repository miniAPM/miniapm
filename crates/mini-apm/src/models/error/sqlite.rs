use super::status::{self, ErrorStatusEvent};
use super::{ErrorTrendPoint, Recording};
use crate::DbPool;
use crate::db;
use crate::time;

/// Get simplified 24h trend for an error (returns just the hourly counts as a string for sparkline)
pub async fn error_trend_24h(pool: &DbPool, error_id: i64) -> anyhow::Result<Vec<i64>> {
    // Get occurrence counts per hour for the last 24 hours
    let rows: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT strftime('%Y-%m-%d %H', happened_at) as hour, COUNT(*) as cnt
        FROM error_occurrences
        WHERE error_id = $1 AND happened_at >= $2
        GROUP BY hour
        ORDER BY hour ASC
        "#,
    )
    .bind(error_id)
    .bind(time::hours_ago(24))
    .fetch_all(pool)
    .await?;

    let hour_counts: std::collections::HashMap<String, i64> = rows.into_iter().collect();

    // Generate 24 hours of data, filling in zeros where no occurrences
    let mut counts = Vec::with_capacity(24);
    for i in (0..24).rev() {
        let hour_key = time::hours_ago(i).0.strftime("%Y-%m-%d %H").to_string();
        counts.push(*hour_counts.get(&hour_key).unwrap_or(&0));
    }

    Ok(counts)
}

/// Get overall hourly error counts (for error index chart)
pub async fn hourly_error_stats(
    pool: &DbPool,
    project_id: Option<i64>,
    hours: i64,
) -> anyhow::Result<Vec<ErrorTrendPoint>> {
    // Collect data into a HashMap for lookup
    let rows: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT strftime('%Y-%m-%d %H:00', eo.happened_at) as hour_label, COUNT(*) as cnt
        FROM error_occurrences eo
        JOIN errors e ON e.id = eo.error_id
        WHERE eo.happened_at >= $2
          AND ($1 IS NULL OR e.project_id = $1)
        GROUP BY strftime('%Y-%m-%d %H', eo.happened_at)
        ORDER BY eo.happened_at ASC
        "#,
    )
    .bind(project_id)
    .bind(time::hours_ago(hours))
    .fetch_all(pool)
    .await?;

    let mut data_points: std::collections::HashMap<String, i64> = rows.into_iter().collect();

    // Fill in all hours with zeros for missing data
    let mut points = Vec::with_capacity(hours as usize);
    for i in (0..hours).rev() {
        let hour_key = time::hours_ago(i).hour_label();
        points.push(ErrorTrendPoint {
            count: data_points.remove(&hour_key).unwrap_or(0),
            hour: hour_key,
        });
    }

    Ok(points)
}

/// Store an occurrence and bump its group in one write transaction
pub(super) async fn record(pool: &DbPool, r: &Recording<'_>) -> anyhow::Result<i64> {
    let mut tx = db::begin_write(pool).await?;
    let grouped: Option<(i64, String)> = match r.group {
        Some(id) => {
            sqlx::query_as(
                "UPDATE errors SET last_seen_at = $1, occurrence_count = occurrence_count + 1
                 WHERE id = $2 RETURNING id, status",
            )
            .bind(r.happened_at)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
        }
        None => None,
    };
    let (id, status) = match grouped {
        Some(grouped) => grouped,
        None => {
            sqlx::query_as(
                "INSERT INTO errors (project_id, fingerprint, exception_class, message, first_seen_at, last_seen_at)
                 VALUES ($1, $2, $3, $4, $5, $5)
                 ON CONFLICT (project_id, fingerprint) DO UPDATE SET
                     last_seen_at = excluded.last_seen_at,
                     occurrence_count = errors.occurrence_count + 1
                 RETURNING id, status",
            )
            .bind(r.project_id)
            .bind(r.fingerprint)
            .bind(r.exception_class)
            .bind(r.message)
            .bind(r.happened_at)
            .fetch_one(&mut *tx)
            .await?
        }
    };
    if let Some(next) = status::transition(&status, ErrorStatusEvent::Recur) {
        sqlx::query("UPDATE errors SET status = $1 WHERE id = $2")
            .bind(next)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(
        "INSERT INTO error_occurrences (error_id, request_id, user_id, backtrace, params, happened_at, source_context)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(r.request_id)
    .bind(r.user_id)
    .bind(&r.backtrace)
    .bind(r.params.as_deref())
    .bind(r.happened_at)
    .bind(r.source_context.as_deref())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}
