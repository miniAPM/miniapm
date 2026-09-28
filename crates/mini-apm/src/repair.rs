//! One-off repairs of data stored by earlier versions

use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::{DbPool, time};

#[cfg(test)]
mod tests;

const OTLP_IDS: &str = "repair.otlp_hex_ids";

/// Span and trace ids sent as hex were decoded as base64 before storing,
/// turning 32 and 16 character ids into 48 and 24 characters. Encoding the
/// stored bytes back to base64 restores the text the client sent.
pub async fn otlp_ids(pool: &DbPool) -> anyhow::Result<u64> {
    let done: Option<String> = sqlx::query_scalar("SELECT value FROM settings WHERE key = ?1")
        .bind(OTLP_IDS)
        .fetch_optional(pool)
        .await?;
    if done.is_some() {
        return Ok(0);
    }

    let mut tx = pool.begin().await?;
    let spans: Vec<(i64, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, trace_id, span_id, parent_span_id FROM spans
         WHERE length(trace_id) = 48 OR length(span_id) = 24 OR length(parent_span_id) = 24",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut repaired = 0;
    for (id, trace_id, span_id, parent_span_id) in spans {
        let result = sqlx::query(
            "UPDATE OR IGNORE spans SET trace_id = ?1, span_id = ?2, parent_span_id = ?3 WHERE id = ?4",
        )
        .bind(restore(&trace_id, 48))
        .bind(restore(&span_id, 24))
        .bind(parent_span_id.map(|p| restore(&p, 24)))
        .bind(id)
        .execute(&mut *tx)
        .await?;
        repaired += result.rows_affected();
    }

    let occurrences: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, request_id FROM error_occurrences WHERE length(request_id) = 48",
    )
    .fetch_all(&mut *tx)
    .await?;
    for (id, request_id) in occurrences {
        sqlx::query("UPDATE error_occurrences SET request_id = ?1 WHERE id = ?2")
            .bind(restore(&request_id, 48))
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }

    sqlx::query("INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)")
        .bind(OTLP_IDS)
        .bind(repaired.to_string())
        .bind(time::now_rfc3339())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(repaired)
}

fn restore(stored: &str, mangled_len: usize) -> String {
    if stored.len() != mangled_len {
        return stored.to_string();
    }
    hex::decode(stored)
        .map(|bytes| STANDARD.encode(bytes))
        .ok()
        .filter(|original| original.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(|original| original.to_ascii_lowercase())
        .unwrap_or_else(|| stored.to_string())
}
