use super::status;
use super::{ErrorTrendPoint, Recording};
use crate::DbPool;
use crate::time::Stamp;

/// Occurrence counts of one error for each of the last 24 hours, oldest first
pub async fn error_trend_24h(pool: &DbPool, error_id: i64) -> anyhow::Result<Vec<i64>> {
    Ok(sqlx::query_scalar(
        r"
        SELECT COUNT(eo.id)
        FROM hour_buckets($2, 24) AS hour
        LEFT JOIN error_occurrences eo
            ON eo.error_id = $1
           AND eo.happened_at >= hour
           AND eo.happened_at < hour + interval '1 hour'
           AND eo.happened_at >= $2::timestamptz - interval '24 hours'
        GROUP BY hour
        ORDER BY hour
        ",
    )
    .bind(error_id)
    .bind(Stamp::now())
    .fetch_all(pool)
    .await?)
}

/// Occurrence counts across errors for each of the last `hours` hours
pub async fn hourly_error_stats(
    pool: &DbPool,
    project_id: Option<i64>,
    hours: i64,
) -> anyhow::Result<Vec<ErrorTrendPoint>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        r"
        SELECT to_char(hour, 'YYYY-MM-DD HH24:00'), COUNT(eo.id)
        FROM hour_buckets($2, $3::int) AS hour
        LEFT JOIN (
            error_occurrences eo
            JOIN errors e ON e.id = eo.error_id AND ($1::bigint IS NULL OR e.project_id = $1)
        )
            ON eo.happened_at >= hour
           AND eo.happened_at < hour + interval '1 hour'
           AND eo.happened_at >= $2::timestamptz - make_interval(hours => $3::int)
        GROUP BY hour
        ORDER BY hour
        ",
    )
    .bind(project_id)
    .bind(Stamp::now())
    .bind(hours)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(hour, count)| ErrorTrendPoint { hour, count })
        .collect())
}

/// Store an occurrence and bump its group with `record_error`, which applies
/// the status changes a recurrence makes as the state machine lists them
pub(super) async fn record(pool: &DbPool, r: &Recording<'_>) -> anyhow::Result<i64> {
    let (recur_from, recur_to): (Vec<_>, Vec<_>) = status::recur_transitions().unzip();
    Ok(sqlx::query_scalar(
        "SELECT record_error($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
    )
    .bind(r.group)
    .bind(r.project_id)
    .bind(r.fingerprint)
    .bind(r.exception_class)
    .bind(r.message)
    .bind(r.happened_at)
    .bind(recur_from)
    .bind(recur_to)
    .bind(r.request_id)
    .bind(r.user_id)
    .bind(&r.backtrace)
    .bind(r.params.as_deref())
    .bind(r.source_context.as_deref())
    .fetch_one(pool)
    .await?)
}
