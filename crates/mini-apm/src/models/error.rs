use crate::DbPool;
use crate::time;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AppError {
    pub id: i64,
    pub fingerprint: String,
    pub exception_class: String,
    pub message: String,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub occurrence_count: i64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorOccurrence {
    pub id: i64,
    pub error_id: i64,
    pub request_id: Option<String>,
    pub user_id: Option<String>,
    pub backtrace: Vec<String>,
    pub params: Option<serde_json::Value>,
    pub happened_at: String,
    pub source_context: Option<SourceContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceContext {
    pub file: String,
    pub lineno: i64,
    pub pre_context: Vec<String>,
    pub context_line: String,
    pub post_context: Vec<String>,
}

impl SourceContext {
    /// Returns pre_context lines with their line numbers
    pub fn pre_context_with_lines(&self) -> Vec<(i64, &str)> {
        let start = self.lineno - self.pre_context.len() as i64;
        self.pre_context
            .iter()
            .enumerate()
            .map(|(idx, line)| (start + idx as i64, line.as_str()))
            .collect()
    }

    /// Returns post_context lines with their line numbers
    pub fn post_context_with_lines(&self) -> Vec<(i64, &str)> {
        self.post_context
            .iter()
            .enumerate()
            .map(|(idx, line)| (self.lineno + 1 + idx as i64, line.as_str()))
            .collect()
    }
}

#[derive(Debug, Deserialize)]
pub struct IncomingError {
    pub exception_class: String,
    pub message: String,
    pub backtrace: Vec<String>,
    pub fingerprint: String,
    pub request_id: Option<String>,
    pub user_id: Option<String>,
    pub params: Option<serde_json::Value>,
    pub timestamp: Option<String>,
    pub source_context: Option<IncomingSourceContext>,
}

#[derive(Debug, Deserialize)]
pub struct IncomingSourceContext {
    pub file: String,
    pub lineno: i64,
    pub pre_context: Option<Vec<String>>,
    pub context_line: String,
    pub post_context: Option<Vec<String>>,
}

/// Minimum similarity threshold for grouping errors (50%)
const SIMILARITY_THRESHOLD: f64 = 0.5;

pub async fn insert(
    pool: &DbPool,
    error: &IncomingError,
    project_id: Option<i64>,
) -> anyhow::Result<i64> {
    let now = time::now_rfc3339();
    let timestamp = error.timestamp.as_deref().unwrap_or(&now);

    // Generate location-based fingerprint for smart grouping
    let location_fingerprint =
        generate_location_fingerprint(&error.exception_class, &error.backtrace);

    // Try to find existing error by:
    // 1. First check exact fingerprint match (backward compatibility)
    // 2. Then check location fingerprint + message similarity >= 50%
    let existing: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM errors WHERE fingerprint = ?1 AND ((?2 IS NULL AND project_id IS NULL) OR project_id = ?2)",
    )
    .bind(&error.fingerprint)
    .bind(project_id)
    .fetch_optional(pool)
    .await?;

    let error_id = if let Some(id) = existing {
        // Exact fingerprint match - update existing error
        sqlx::query(
            "UPDATE errors SET last_seen_at = ?1, occurrence_count = occurrence_count + 1 WHERE id = ?2",
        )
        .bind(timestamp)
        .bind(id)
        .execute(pool)
        .await?;
        id
    } else {
        // Try to find similar error by location + message similarity
        let similar_error =
            find_similar_error(pool, project_id, &location_fingerprint, &error.message).await?;

        if let Some(id) = similar_error {
            // Found similar error - group with it
            sqlx::query(
                "UPDATE errors SET last_seen_at = ?1, occurrence_count = occurrence_count + 1 WHERE id = ?2",
            )
            .bind(timestamp)
            .bind(id)
            .execute(pool)
            .await?;
            id
        } else {
            // No similar error found - create new one with location fingerprint.
            // The fingerprint is unique per project, so a dissimilar message
            // from an already known location counts towards that group.
            sqlx::query_scalar(
                r#"
                INSERT INTO errors (project_id, fingerprint, exception_class, message, first_seen_at, last_seen_at, occurrence_count, status)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 'open')
                ON CONFLICT (project_id, fingerprint) DO UPDATE SET
                    last_seen_at = excluded.last_seen_at,
                    occurrence_count = occurrence_count + 1
                RETURNING id
                "#,
            )
            .bind(project_id)
            .bind(&location_fingerprint)
            .bind(&error.exception_class)
            .bind(&error.message)
            .bind(timestamp)
            .bind(timestamp)
            .fetch_one(pool)
            .await?
        }
    };

    // Convert IncomingSourceContext to SourceContext for storage
    let source_context_json = error.source_context.as_ref().and_then(|sc| {
        let ctx = SourceContext {
            file: sc.file.clone(),
            lineno: sc.lineno,
            pre_context: sc.pre_context.clone().unwrap_or_default(),
            context_line: sc.context_line.clone(),
            post_context: sc.post_context.clone().unwrap_or_default(),
        };
        serde_json::to_string(&ctx).ok()
    });

    // Insert occurrence
    sqlx::query(
        r#"
        INSERT INTO error_occurrences (error_id, request_id, user_id, backtrace, params, happened_at, source_context)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
    )
    .bind(error_id)
    .bind(error.request_id.as_deref())
    .bind(error.user_id.as_deref())
    .bind(serde_json::to_string(&error.backtrace)?)
    .bind(error.params.as_ref().and_then(|p| serde_json::to_string(p).ok()))
    .bind(timestamp)
    .bind(source_context_json)
    .execute(pool)
    .await?;

    Ok(error_id)
}

/// Find an existing error with the same location fingerprint and similar message
async fn find_similar_error(
    pool: &DbPool,
    project_id: Option<i64>,
    location_fingerprint: &str,
    message: &str,
) -> anyhow::Result<Option<i64>> {
    // Find errors with the same location fingerprint
    let candidates: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, message FROM errors WHERE fingerprint = ?1 AND ((?2 IS NULL AND project_id IS NULL) OR project_id = ?2)"
    )
    .bind(location_fingerprint)
    .bind(project_id)
    .fetch_all(pool)
    .await?;

    // Check message similarity for each candidate
    for (id, existing_message) in candidates {
        let similarity = text_similarity(message, &existing_message);
        if similarity >= SIMILARITY_THRESHOLD {
            return Ok(Some(id));
        }
    }

    Ok(None)
}

pub async fn list(
    pool: &DbPool,
    project_id: Option<i64>,
    status: Option<&str>,
    limit: i64,
) -> anyhow::Result<Vec<AppError>> {
    list_filtered(pool, project_id, status, None, None, "last_seen", limit).await
}

pub struct ErrorListResult {
    pub errors: Vec<AppError>,
    pub total_count: i64,
}

pub async fn list_filtered(
    pool: &DbPool,
    project_id: Option<i64>,
    status: Option<&str>,
    search: Option<&str>,
    since: Option<&str>,
    sort_by: &str,
    limit: i64,
) -> anyhow::Result<Vec<AppError>> {
    list_paginated(pool, project_id, status, search, since, sort_by, limit, 0).await
}

#[allow(clippy::too_many_arguments)]
pub async fn list_paginated(
    pool: &DbPool,
    project_id: Option<i64>,
    status: Option<&str>,
    search: Option<&str>,
    since: Option<&str>,
    sort_by: &str,
    limit: i64,
    offset: i64,
) -> anyhow::Result<Vec<AppError>> {
    let order_clause = match sort_by {
        "first_seen" => "first_seen_at DESC",
        "count" => "occurrence_count DESC",
        _ => "last_seen_at DESC", // default: last_seen
    };

    let sql = format!(
        r#"
        SELECT id, fingerprint, exception_class, message,
               strftime('%Y-%m-%d %H:%M', first_seen_at) AS first_seen_at,
               strftime('%Y-%m-%d %H:%M', last_seen_at) AS last_seen_at,
               occurrence_count, status
        FROM errors
        WHERE (?1 IS NULL OR project_id = ?1)
          AND (?2 IS NULL OR status = ?2)
          AND (?3 IS NULL OR exception_class LIKE '%' || ?3 || '%' OR message LIKE '%' || ?3 || '%')
          AND (?4 IS NULL OR last_seen_at >= ?4)
        ORDER BY {}
        LIMIT ?5 OFFSET ?6
        "#,
        order_clause
    );

    let errors = sqlx::query_as::<_, AppError>(sqlx::AssertSqlSafe(sql))
        .bind(project_id)
        .bind(status)
        .bind(search)
        .bind(since)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

    Ok(errors)
}

pub async fn count_filtered(
    pool: &DbPool,
    project_id: Option<i64>,
    status: Option<&str>,
    search: Option<&str>,
    since: Option<&str>,
) -> anyhow::Result<i64> {
    let count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM errors
        WHERE (?1 IS NULL OR project_id = ?1)
          AND (?2 IS NULL OR status = ?2)
          AND (?3 IS NULL OR exception_class LIKE '%' || ?3 || '%' OR message LIKE '%' || ?3 || '%')
          AND (?4 IS NULL OR last_seen_at >= ?4)
        "#,
    )
    .bind(project_id)
    .bind(status)
    .bind(search)
    .bind(since)
    .fetch_one(pool)
    .await?;

    Ok(count)
}

pub async fn find(pool: &DbPool, id: i64) -> anyhow::Result<Option<AppError>> {
    let error = sqlx::query_as::<_, AppError>(
        "SELECT id, fingerprint, exception_class, message,
                strftime('%Y-%m-%d %H:%M', first_seen_at) AS first_seen_at,
                strftime('%Y-%m-%d %H:%M', last_seen_at) AS last_seen_at,
                occurrence_count, status
         FROM errors WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(error)
}

pub async fn occurrences(
    pool: &DbPool,
    error_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<ErrorOccurrence>> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        i64,
        i64,
        Option<String>,
        Option<String>,
        String,
        Option<String>,
        String,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id, error_id, request_id, user_id, backtrace, params,
                strftime('%Y-%m-%d %H:%M', happened_at), source_context
         FROM error_occurrences WHERE error_id = ?1 ORDER BY happened_at DESC LIMIT ?2",
    )
    .bind(error_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let occs = rows
        .into_iter()
        .map(
            |(
                id,
                error_id,
                request_id,
                user_id,
                backtrace_str,
                params_str,
                happened_at,
                source_context_str,
            )| {
                ErrorOccurrence {
                    id,
                    error_id,
                    request_id,
                    user_id,
                    backtrace: serde_json::from_str(&backtrace_str).unwrap_or_default(),
                    params: params_str.and_then(|s| serde_json::from_str(&s).ok()),
                    happened_at,
                    source_context: source_context_str.and_then(|s| serde_json::from_str(&s).ok()),
                }
            },
        )
        .collect();

    Ok(occs)
}

pub async fn count_since(
    pool: &DbPool,
    project_id: Option<i64>,
    since: &str,
) -> anyhow::Result<i64> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM error_occurrences eo
         JOIN errors e ON e.id = eo.error_id
         WHERE eo.happened_at >= ?1 AND (?2 IS NULL OR e.project_id = ?2)",
    )
    .bind(since)
    .bind(project_id)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

pub async fn update_status(pool: &DbPool, id: i64, status: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE errors SET status = ?1 WHERE id = ?2")
        .bind(status)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_occurrences_before(pool: &DbPool, before: &str) -> anyhow::Result<usize> {
    let result = sqlx::query("DELETE FROM error_occurrences WHERE happened_at < ?1")
        .bind(before)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() as usize)
}

/// Error trend point for charting
#[derive(Debug, Clone, Serialize)]
pub struct ErrorTrendPoint {
    pub hour: String,
    pub count: i64,
}

/// Get hourly error occurrence counts for a specific error (for trend sparklines)
pub async fn error_trend(
    pool: &DbPool,
    error_id: i64,
    hours: i64,
) -> anyhow::Result<Vec<ErrorTrendPoint>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        r#"
        WITH hours AS (
            SELECT datetime('now', '-' || (value - 1) || ' hours') as hour
            FROM generate_series(1, ?2)
        )
        SELECT strftime('%Y-%m-%d %H:00', h.hour) as hour,
               COALESCE(SUM(CASE WHEN eo.happened_at IS NOT NULL THEN 1 ELSE 0 END), 0) as cnt
        FROM (
            SELECT datetime('now', '-' || (value - 1) || ' hours') as hour
            FROM (
                SELECT 1 as value UNION SELECT 2 UNION SELECT 3 UNION SELECT 4
                UNION SELECT 5 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8
                UNION SELECT 9 UNION SELECT 10 UNION SELECT 11 UNION SELECT 12
                UNION SELECT 13 UNION SELECT 14 UNION SELECT 15 UNION SELECT 16
                UNION SELECT 17 UNION SELECT 18 UNION SELECT 19 UNION SELECT 20
                UNION SELECT 21 UNION SELECT 22 UNION SELECT 23 UNION SELECT 24
            )
            WHERE value <= ?2
        ) h
        LEFT JOIN error_occurrences eo
            ON strftime('%Y-%m-%d %H', eo.happened_at) = strftime('%Y-%m-%d %H', h.hour)
            AND eo.error_id = ?1
        GROUP BY strftime('%Y-%m-%d %H:00', h.hour)
        ORDER BY hour ASC
        "#,
    )
    .bind(error_id)
    .bind(hours)
    .fetch_all(pool)
    .await?;

    let points = rows
        .into_iter()
        .map(|(hour, count)| ErrorTrendPoint { hour, count })
        .collect();

    Ok(points)
}

/// Get simplified 24h trend for an error (returns just the hourly counts as a string for sparkline)
pub async fn error_trend_24h(pool: &DbPool, error_id: i64) -> anyhow::Result<Vec<i64>> {
    // Get occurrence counts per hour for the last 24 hours
    let rows: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT strftime('%Y-%m-%d %H', happened_at) as hour, COUNT(*) as cnt
        FROM error_occurrences
        WHERE error_id = ?1 AND happened_at >= datetime('now', '-24 hours')
        GROUP BY hour
        ORDER BY hour ASC
        "#,
    )
    .bind(error_id)
    .fetch_all(pool)
    .await?;

    let hour_counts: std::collections::HashMap<String, i64> = rows.into_iter().collect();

    // Generate 24 hours of data, filling in zeros where no occurrences
    let mut counts = Vec::with_capacity(24);
    for i in (0..24).rev() {
        let hour_key = time::hours_ago(i).strftime("%Y-%m-%d %H").to_string();
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
        WHERE eo.happened_at >= datetime('now', '-' || ?2 || ' hours')
          AND (?1 IS NULL OR e.project_id = ?1)
        GROUP BY strftime('%Y-%m-%d %H', eo.happened_at)
        ORDER BY eo.happened_at ASC
        "#,
    )
    .bind(project_id)
    .bind(hours)
    .fetch_all(pool)
    .await?;

    let data_points: std::collections::HashMap<String, i64> = rows.into_iter().collect();

    // Fill in all hours with zeros for missing data
    let mut points = Vec::with_capacity(hours as usize);
    for i in (0..hours).rev() {
        let hour_key = time::hours_ago(i).strftime("%Y-%m-%d %H:00").to_string();
        points.push(ErrorTrendPoint {
            hour: hour_key.clone(),
            count: *data_points.get(&hour_key).unwrap_or(&0),
        });
    }

    Ok(points)
}

/// Calculate text similarity using word-based Jaccard similarity (0.0 to 1.0)
fn text_similarity(a: &str, b: &str) -> f64 {
    let normalize = |s: &str| -> HashSet<String> {
        s.to_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .map(|w| w.to_string())
            .collect()
    };

    let words_a = normalize(a);
    let words_b = normalize(b);

    if words_a.is_empty() && words_b.is_empty() {
        return 1.0;
    }
    if words_a.is_empty() || words_b.is_empty() {
        return 0.0;
    }

    let intersection = words_a.intersection(&words_b).count();
    let union = words_a.union(&words_b).count();

    if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    }
}

/// Extract first app frame from backtrace (skip library/framework frames)
fn extract_error_location(backtrace: &[String]) -> Option<String> {
    // Common patterns for library/framework code to skip
    let skip_patterns = [
        "/gems/",
        "/vendor/",
        "/ruby/",
        "/lib/ruby/",
        "node_modules/",
        "/usr/lib/",
        "/usr/local/lib/",
        "<internal:",
        "(eval)",
        "(irb)",
        "/activerecord-",
        "/activesupport-",
        "/actionpack-",
        "/rack-",
        "/railties-",
        "/bundler/",
    ];

    for frame in backtrace {
        let is_library = skip_patterns.iter().any(|p| frame.contains(p));
        if !is_library && !frame.trim().is_empty() {
            // Extract file:line portion (strip method name if present)
            // Format is usually "path/to/file.rb:123:in `method_name'"
            if let Some(colon_pos) = frame.rfind(":in ") {
                return Some(frame[..colon_pos].to_string());
            }
            // Or just "path/to/file.rb:123"
            return Some(frame.to_string());
        }
    }

    // Fallback to first frame if all look like library code
    backtrace.first().map(|s| {
        if let Some(colon_pos) = s.rfind(":in ") {
            s[..colon_pos].to_string()
        } else {
            s.to_string()
        }
    })
}

/// Generate a location-based fingerprint from exception class and backtrace
fn generate_location_fingerprint(exception_class: &str, backtrace: &[String]) -> String {
    let location = extract_error_location(backtrace).unwrap_or_default();
    format!("{}:{}", exception_class, location)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_similarity_identical() {
        assert_eq!(text_similarity("hello world", "hello world"), 1.0);
    }

    #[test]
    fn test_text_similarity_completely_different() {
        assert_eq!(text_similarity("hello world", "foo bar baz"), 0.0);
    }

    #[test]
    fn test_text_similarity_partial_overlap() {
        // "undefined method foo for nil" vs "undefined method bar for nil"
        // Words: {undefined, method, foo, for, nil} vs {undefined, method, bar, for, nil}
        // Intersection: {undefined, method, for, nil} = 4
        // Union: {undefined, method, foo, bar, for, nil} = 6
        // Similarity: 4/6 = 0.666...
        let sim = text_similarity(
            "undefined method foo for nil",
            "undefined method bar for nil",
        );
        assert!(sim > 0.6 && sim < 0.7);
    }

    #[test]
    fn test_text_similarity_case_insensitive() {
        assert_eq!(text_similarity("Hello World", "hello world"), 1.0);
    }

    #[test]
    fn test_text_similarity_splits_on_punctuation() {
        // "can't find user_id!" -> words: {can, t, find, user, id}
        // "can t find user id" -> words: {can, t, find, user, id}
        // These should be identical
        assert_eq!(
            text_similarity("can't find user_id!", "can t find user id"),
            1.0
        );
    }

    #[test]
    fn test_text_similarity_empty_strings() {
        assert_eq!(text_similarity("", ""), 1.0);
        assert_eq!(text_similarity("hello", ""), 0.0);
        assert_eq!(text_similarity("", "hello"), 0.0);
    }

    #[test]
    fn test_text_similarity_above_threshold() {
        // Similar error messages should be >= 50%
        let sim = text_similarity(
            "PG::ConnectionBad: connection to server at \"localhost\" failed",
            "PG::ConnectionBad: connection to server at \"192.168.1.1\" failed",
        );
        assert!(sim >= SIMILARITY_THRESHOLD);
    }

    #[test]
    fn test_extract_error_location_app_frame() {
        let backtrace = vec![
            "/usr/local/lib/ruby/gems/3.0.0/gems/activerecord-7.0.0/lib/active_record/base.rb:123:in `find'".to_string(),
            "/app/models/user.rb:42:in `authenticate'".to_string(),
            "/app/controllers/sessions_controller.rb:15:in `create'".to_string(),
        ];
        let location = extract_error_location(&backtrace);
        assert_eq!(location, Some("/app/models/user.rb:42".to_string()));
    }

    #[test]
    fn test_extract_error_location_skips_gems() {
        let backtrace = vec![
            "/gems/rack-2.0.0/lib/rack/handler.rb:10:in `call'".to_string(),
            "/vendor/bundle/gems/rails-7.0.0/lib/rails.rb:5:in `run'".to_string(),
            "app/services/payment.rb:88:in `process'".to_string(),
        ];
        let location = extract_error_location(&backtrace);
        assert_eq!(location, Some("app/services/payment.rb:88".to_string()));
    }

    #[test]
    fn test_extract_error_location_no_app_frame() {
        let backtrace = vec![
            "/gems/activerecord-7.0.0/lib/active_record/base.rb:123:in `find'".to_string(),
            "/vendor/bundle/gems/rails-7.0.0/lib/rails.rb:5:in `run'".to_string(),
        ];
        let location = extract_error_location(&backtrace);
        // Falls back to first frame with method stripped
        assert_eq!(
            location,
            Some("/gems/activerecord-7.0.0/lib/active_record/base.rb:123".to_string())
        );
    }

    #[test]
    fn test_extract_error_location_empty_backtrace() {
        let backtrace: Vec<String> = vec![];
        let location = extract_error_location(&backtrace);
        assert_eq!(location, None);
    }

    #[test]
    fn test_generate_location_fingerprint() {
        let backtrace = vec!["app/models/user.rb:42:in `save'".to_string()];
        let fingerprint = generate_location_fingerprint("ActiveRecord::RecordInvalid", &backtrace);
        assert_eq!(
            fingerprint,
            "ActiveRecord::RecordInvalid:app/models/user.rb:42"
        );
    }

    #[test]
    fn test_generate_location_fingerprint_empty_backtrace() {
        let backtrace: Vec<String> = vec![];
        let fingerprint = generate_location_fingerprint("RuntimeError", &backtrace);
        assert_eq!(fingerprint, "RuntimeError:");
    }

    #[test]
    fn test_similar_errors_should_group() {
        // These errors occur on the same line with similar messages
        let msg1 = "Couldn't find User with 'id'=123";
        let msg2 = "Couldn't find User with 'id'=456";
        let sim = text_similarity(msg1, msg2);
        assert!(
            sim >= SIMILARITY_THRESHOLD,
            "Similar errors should group: similarity = {}",
            sim
        );
    }

    #[test]
    fn test_different_errors_should_not_group() {
        // These errors have completely different messages
        let msg1 = "undefined method 'foo' for nil:NilClass";
        let msg2 = "PG::ConnectionBad: connection refused";
        let sim = text_similarity(msg1, msg2);
        assert!(
            sim < SIMILARITY_THRESHOLD,
            "Different errors should not group: similarity = {}",
            sim
        );
    }
}
