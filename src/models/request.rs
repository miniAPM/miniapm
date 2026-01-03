use crate::DbPool;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: Option<i64>,
    pub request_id: String,
    pub method: String,
    pub path: String,
    pub controller: Option<String>,
    pub action: Option<String>,
    pub status: i32,
    pub total_ms: f64,
    pub db_ms: f64,
    pub db_count: i32,
    pub view_ms: f64,
    pub host: Option<String>,
    pub env: Option<String>,
    pub git_sha: Option<String>,
    pub happened_at: String,
}

#[derive(Debug, Deserialize)]
pub struct RequestBatch {
    pub metadata: Option<RequestMetadata>,
    pub requests: Vec<IncomingRequest>,
}

#[derive(Debug, Deserialize)]
pub struct RequestMetadata {
    pub host: Option<String>,
    pub env: Option<String>,
    pub rails_version: Option<String>,
    pub ruby_version: Option<String>,
    pub git_sha: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IncomingRequest {
    pub request_id: String,
    pub method: String,
    pub path: String,
    pub controller: Option<String>,
    pub action: Option<String>,
    pub status: i32,
    pub total_ms: f64,
    #[serde(default)]
    pub db_ms: f64,
    #[serde(default)]
    pub db_count: i32,
    #[serde(default)]
    pub view_ms: f64,
    pub timestamp: Option<String>,
}

pub fn insert_batch(
    pool: &DbPool,
    batch: &RequestBatch,
    project_id: Option<i64>,
) -> anyhow::Result<usize> {
    let conn = pool.get()?;
    let metadata = batch.metadata.as_ref();
    let now = chrono::Utc::now().to_rfc3339();

    let mut count = 0;
    for req in &batch.requests {
        conn.execute(
            r#"
            INSERT INTO requests
            (project_id, request_id, method, path, controller, action, status, total_ms, db_ms, db_count, view_ms, host, env, git_sha, happened_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
            "#,
            (
                project_id,
                &req.request_id,
                &req.method,
                &req.path,
                &req.controller,
                &req.action,
                req.status,
                req.total_ms,
                req.db_ms,
                req.db_count,
                req.view_ms,
                metadata.and_then(|m| m.host.as_ref()),
                metadata.and_then(|m| m.env.as_ref()),
                metadata.and_then(|m| m.git_sha.as_ref()),
                req.timestamp.as_ref().unwrap_or(&now),
            ),
        )?;
        count += 1;
    }

    Ok(count)
}

pub fn recent(pool: &DbPool, project_id: Option<i64>, limit: i64) -> anyhow::Result<Vec<Request>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        r#"
        SELECT id, request_id, method, path, controller, action, status,
               total_ms, db_ms, db_count, view_ms, host, env, git_sha, happened_at
        FROM requests
        WHERE (?1 IS NULL OR project_id = ?1)
        ORDER BY happened_at DESC
        LIMIT ?2
        "#,
    )?;

    let requests = stmt
        .query_map(rusqlite::params![project_id, limit], |row| {
            Ok(Request {
                id: row.get(0)?,
                request_id: row.get(1)?,
                method: row.get(2)?,
                path: row.get(3)?,
                controller: row.get(4)?,
                action: row.get(5)?,
                status: row.get(6)?,
                total_ms: row.get(7)?,
                db_ms: row.get(8)?,
                db_count: row.get(9)?,
                view_ms: row.get(10)?,
                host: row.get(11)?,
                env: row.get(12)?,
                git_sha: row.get(13)?,
                happened_at: row.get(14)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(requests)
}

pub fn slow(pool: &DbPool, project_id: Option<i64>, threshold_ms: f64, limit: i64) -> anyhow::Result<Vec<Request>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        r#"
        SELECT id, request_id, method, path, controller, action, status,
               total_ms, db_ms, db_count, view_ms, host, env, git_sha, happened_at
        FROM requests
        WHERE total_ms >= ?1 AND (?2 IS NULL OR project_id = ?2)
        ORDER BY total_ms DESC
        LIMIT ?3
        "#,
    )?;

    let requests = stmt
        .query_map(rusqlite::params![threshold_ms, project_id, limit], |row| {
            Ok(Request {
                id: row.get(0)?,
                request_id: row.get(1)?,
                method: row.get(2)?,
                path: row.get(3)?,
                controller: row.get(4)?,
                action: row.get(5)?,
                status: row.get(6)?,
                total_ms: row.get(7)?,
                db_ms: row.get(8)?,
                db_count: row.get(9)?,
                view_ms: row.get(10)?,
                host: row.get(11)?,
                env: row.get(12)?,
                git_sha: row.get(13)?,
                happened_at: row.get(14)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(requests)
}

pub fn count_since(pool: &DbPool, project_id: Option<i64>, since: &str) -> anyhow::Result<i64> {
    let conn = pool.get()?;
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM requests WHERE happened_at >= ?1 AND (?2 IS NULL OR project_id = ?2)",
        rusqlite::params![since, project_id],
        |row| row.get(0),
    )?;
    Ok(count)
}

pub fn avg_ms_since(pool: &DbPool, project_id: Option<i64>, since: &str) -> anyhow::Result<i64> {
    let conn = pool.get()?;
    let avg: f64 = conn
        .query_row(
            "SELECT COALESCE(AVG(total_ms), 0) FROM requests WHERE happened_at >= ?1 AND (?2 IS NULL OR project_id = ?2)",
            rusqlite::params![since, project_id],
            |row| row.get(0),
        )
        .unwrap_or(0.0);
    Ok(avg.round() as i64)
}

/// Calculate percentile latency (p50, p95, p99) since a given time
pub fn percentile_ms_since(pool: &DbPool, project_id: Option<i64>, since: &str, percentile: f64) -> anyhow::Result<i64> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT total_ms FROM requests WHERE happened_at >= ?1 AND (?2 IS NULL OR project_id = ?2) ORDER BY total_ms ASC",
    )?;

    let values: Vec<f64> = stmt
        .query_map(rusqlite::params![since, project_id], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;

    if values.is_empty() {
        return Ok(0);
    }

    let index = ((percentile / 100.0) * (values.len() as f64 - 1.0)).round() as usize;
    let index = index.min(values.len() - 1);
    Ok(values[index].round() as i64)
}

#[derive(Debug, Clone, Serialize)]
pub struct LatencyStats {
    pub avg_ms: i64,
    pub p95_ms: i64,
    pub p99_ms: i64,
}

pub fn latency_stats_since(pool: &DbPool, project_id: Option<i64>, since: &str) -> anyhow::Result<LatencyStats> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT total_ms FROM requests WHERE happened_at >= ?1 AND (?2 IS NULL OR project_id = ?2) ORDER BY total_ms ASC",
    )?;

    let values: Vec<f64> = stmt
        .query_map(rusqlite::params![since, project_id], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;

    if values.is_empty() {
        return Ok(LatencyStats { avg_ms: 0, p95_ms: 0, p99_ms: 0 });
    }

    let avg = values.iter().sum::<f64>() / values.len() as f64;
    let p95_idx = ((0.95 * (values.len() as f64 - 1.0)).round() as usize).min(values.len() - 1);
    let p99_idx = ((0.99 * (values.len() as f64 - 1.0)).round() as usize).min(values.len() - 1);

    Ok(LatencyStats {
        avg_ms: avg.round() as i64,
        p95_ms: values[p95_idx].round() as i64,
        p99_ms: values[p99_idx].round() as i64,
    })
}

/// Time-series data point for charts
#[derive(Debug, Clone, Serialize)]
pub struct TimeSeriesPoint {
    pub label: String,
    pub requests: i64,
    pub avg_ms: i64,
}

/// Get hourly time series data for the last 24 hours
pub fn hourly_stats(pool: &DbPool, project_id: Option<i64>, hours: i64) -> anyhow::Result<Vec<TimeSeriesPoint>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        r#"
        SELECT
            strftime('%H:00', happened_at) as hour,
            COUNT(*) as requests,
            ROUND(AVG(total_ms)) as avg_ms
        FROM requests
        WHERE happened_at >= datetime('now', ?1)
          AND (?2 IS NULL OR project_id = ?2)
        GROUP BY strftime('%Y-%m-%d %H', happened_at)
        ORDER BY happened_at ASC
        "#,
    )?;

    let since = format!("-{} hours", hours);
    let points: Vec<TimeSeriesPoint> = stmt
        .query_map(rusqlite::params![since, project_id], |row| {
            Ok(TimeSeriesPoint {
                label: row.get(0)?,
                requests: row.get(1)?,
                avg_ms: row.get::<_, f64>(2).unwrap_or(0.0) as i64,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(points)
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteSummary {
    pub path: String,
    pub method: String,
    pub request_count: i64,
    pub avg_ms: i64,
    pub p95_ms: i64,
    pub p99_ms: i64,
    pub max_ms: i64,
    pub min_ms: i64,
    pub avg_db_ms: i64,
    pub avg_db_count: i64,
    pub error_count: i64,
    pub error_rate: f64,
}

pub fn routes_summary(pool: &DbPool, project_id: Option<i64>, since: &str, limit: i64) -> anyhow::Result<Vec<RouteSummary>> {
    routes_summary_filtered(pool, project_id, since, None, None, "requests", limit)
}

pub fn routes_summary_filtered(
    pool: &DbPool,
    project_id: Option<i64>,
    since: &str,
    method_filter: Option<&str>,
    search: Option<&str>,
    sort_by: &str,
    limit: i64,
) -> anyhow::Result<Vec<RouteSummary>> {
    let conn = pool.get()?;

    let order_clause = match sort_by {
        "avg" => "avg_ms DESC",
        "p95" => "p95_ms DESC",
        "p99" => "p99_ms DESC",
        "max" => "max_ms DESC",
        "errors" => "error_count DESC",
        "db" => "avg_db_ms DESC",
        _ => "request_count DESC", // default: requests
    };

    // First, get the basic stats
    let sql = format!(
        r#"
        SELECT path, method,
               COUNT(*) as request_count,
               ROUND(AVG(total_ms)) as avg_ms,
               ROUND(MAX(total_ms)) as max_ms,
               ROUND(MIN(total_ms)) as min_ms,
               ROUND(AVG(db_ms)) as avg_db_ms,
               ROUND(AVG(db_count)) as avg_db_count,
               SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END) as error_count
        FROM requests
        WHERE happened_at >= ?1
          AND (?2 IS NULL OR project_id = ?2)
          AND (?3 IS NULL OR method = ?3)
          AND (?4 IS NULL OR path LIKE '%' || ?4 || '%')
        GROUP BY path, method
        ORDER BY {}
        LIMIT ?5
        "#,
        order_clause
    );

    let mut stmt = conn.prepare(&sql)?;

    let routes: Vec<(String, String, i64, i64, i64, i64, i64, i64, i64)> = stmt
        .query_map(rusqlite::params![since, project_id, method_filter, search, limit], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get::<_, f64>(3)? as i64,
                row.get::<_, f64>(4)? as i64,
                row.get::<_, f64>(5)? as i64,
                row.get::<_, f64>(6)? as i64,
                row.get::<_, f64>(7)? as i64,
                row.get(8)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    // Now calculate percentiles for each route
    let mut result = Vec::with_capacity(routes.len());
    for (path, method, request_count, avg_ms, max_ms, min_ms, avg_db_ms, avg_db_count, error_count) in routes {
        let (p95_ms, p99_ms) = compute_route_percentiles(&conn, &path, &method, since, project_id)?;

        let error_rate = if request_count > 0 {
            (error_count as f64 / request_count as f64) * 100.0
        } else {
            0.0
        };

        result.push(RouteSummary {
            path,
            method,
            request_count,
            avg_ms,
            p95_ms,
            p99_ms,
            max_ms,
            min_ms,
            avg_db_ms,
            avg_db_count,
            error_count,
            error_rate,
        });
    }

    Ok(result)
}

fn compute_route_percentiles(
    conn: &r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>,
    path: &str,
    method: &str,
    since: &str,
    project_id: Option<i64>,
) -> anyhow::Result<(i64, i64)> {
    let mut stmt = conn.prepare(
        r#"
        SELECT total_ms FROM requests
        WHERE path = ?1 AND method = ?2 AND happened_at >= ?3 AND (?4 IS NULL OR project_id = ?4)
        ORDER BY total_ms ASC
        "#,
    )?;

    let values: Vec<f64> = stmt
        .query_map(rusqlite::params![path, method, since, project_id], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;

    if values.is_empty() {
        return Ok((0, 0));
    }

    let p95_idx = ((0.95 * (values.len() as f64 - 1.0)).round() as usize).min(values.len() - 1);
    let p99_idx = ((0.99 * (values.len() as f64 - 1.0)).round() as usize).min(values.len() - 1);

    Ok((values[p95_idx].round() as i64, values[p99_idx].round() as i64))
}

pub fn routes_count(
    pool: &DbPool,
    project_id: Option<i64>,
    since: &str,
    method_filter: Option<&str>,
    search: Option<&str>,
) -> anyhow::Result<i64> {
    let conn = pool.get()?;

    let count: i64 = conn.query_row(
        r#"
        SELECT COUNT(DISTINCT path || method)
        FROM requests
        WHERE happened_at >= ?1
          AND (?2 IS NULL OR project_id = ?2)
          AND (?3 IS NULL OR method = ?3)
          AND (?4 IS NULL OR path LIKE '%' || ?4 || '%')
        "#,
        rusqlite::params![since, project_id, method_filter, search],
        |row| row.get(0),
    )?;

    Ok(count)
}

pub fn delete_before(pool: &DbPool, project_id: Option<i64>, before: &str) -> anyhow::Result<usize> {
    let conn = pool.get()?;
    let deleted = conn.execute(
        "DELETE FROM requests WHERE happened_at < ?1 AND (?2 IS NULL OR project_id = ?2)",
        rusqlite::params![before, project_id],
    )?;
    Ok(deleted)
}

/// Display-friendly request with rounded ms values and formatted timestamp
#[derive(Debug, Clone)]
pub struct RequestDisplay {
    pub method: String,
    pub path: String,
    pub status: i32,
    pub total_ms: i64,
    pub db_ms: i64,
    pub view_ms: i64,
    pub happened_at: String,
}

pub fn slow_display(pool: &DbPool, project_id: Option<i64>, threshold_ms: f64, limit: i64) -> anyhow::Result<Vec<RequestDisplay>> {
    slow_display_filtered(pool, project_id, threshold_ms, None, "total", limit)
}

pub fn slow_display_filtered(
    pool: &DbPool,
    project_id: Option<i64>,
    threshold_ms: f64,
    since: Option<&str>,
    sort_by: &str,
    limit: i64,
) -> anyhow::Result<Vec<RequestDisplay>> {
    slow_display_paginated(pool, project_id, threshold_ms, since, None, sort_by, limit, 0)
}

pub fn slow_display_paginated(
    pool: &DbPool,
    project_id: Option<i64>,
    threshold_ms: f64,
    since: Option<&str>,
    route_filter: Option<&str>,
    sort_by: &str,
    limit: i64,
    offset: i64,
) -> anyhow::Result<Vec<RequestDisplay>> {
    let conn = pool.get()?;

    let order_clause = match sort_by {
        "db" => "db_ms DESC",
        "view" => "view_ms DESC",
        "recent" => "happened_at DESC",
        _ => "total_ms DESC", // default: total
    };

    let sql = format!(
        r#"
        SELECT method, path, status,
               ROUND(total_ms) as total_ms,
               ROUND(db_ms) as db_ms,
               ROUND(view_ms) as view_ms,
               strftime('%Y-%m-%d %H:%M', happened_at) as happened_at
        FROM requests
        WHERE total_ms >= ?1
          AND (?2 IS NULL OR project_id = ?2)
          AND (?3 IS NULL OR happened_at >= ?3)
          AND (?4 IS NULL OR path LIKE '%' || ?4 || '%')
        ORDER BY {}
        LIMIT ?5 OFFSET ?6
        "#,
        order_clause
    );

    let mut stmt = conn.prepare(&sql)?;
    let requests = stmt
        .query_map(rusqlite::params![threshold_ms, project_id, since, route_filter, limit, offset], |row| {
            Ok(RequestDisplay {
                method: row.get(0)?,
                path: row.get(1)?,
                status: row.get(2)?,
                total_ms: row.get::<_, f64>(3)? as i64,
                db_ms: row.get::<_, f64>(4)? as i64,
                view_ms: row.get::<_, f64>(5)? as i64,
                happened_at: row.get(6)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(requests)
}

pub fn slow_count(
    pool: &DbPool,
    project_id: Option<i64>,
    threshold_ms: f64,
    since: Option<&str>,
    route_filter: Option<&str>,
) -> anyhow::Result<i64> {
    let conn = pool.get()?;

    let count: i64 = conn.query_row(
        r#"
        SELECT COUNT(*)
        FROM requests
        WHERE total_ms >= ?1
          AND (?2 IS NULL OR project_id = ?2)
          AND (?3 IS NULL OR happened_at >= ?3)
          AND (?4 IS NULL OR path LIKE '%' || ?4 || '%')
        "#,
        rusqlite::params![threshold_ms, project_id, since, route_filter],
        |row| row.get(0),
    )?;

    Ok(count)
}

/// Calculate percentile from a sorted slice of values (helper for testing)
pub fn calculate_percentile(sorted_values: &[f64], percentile: f64) -> f64 {
    if sorted_values.is_empty() {
        return 0.0;
    }
    let index = ((percentile / 100.0) * (sorted_values.len() as f64 - 1.0)).round() as usize;
    let index = index.min(sorted_values.len() - 1);
    sorted_values[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_percentile_p50() {
        let values = vec![10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0];
        let p50 = calculate_percentile(&values, 50.0);
        // Index = round(0.5 * 9) = round(4.5) = 5 -> values[5] = 60
        assert_eq!(p50, 60.0);
    }

    #[test]
    fn test_calculate_percentile_p95() {
        let values = vec![10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0];
        let p95 = calculate_percentile(&values, 95.0);
        // Index = round(0.95 * 9) = round(8.55) = 9 -> values[9] = 100
        assert_eq!(p95, 100.0);
    }

    #[test]
    fn test_calculate_percentile_p99() {
        let values: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        let p99 = calculate_percentile(&values, 99.0);
        // Index = round(0.99 * 99) = round(98.01) = 98 -> values[98] = 99
        assert_eq!(p99, 99.0);
    }

    #[test]
    fn test_calculate_percentile_single_value() {
        let values = vec![42.0];
        assert_eq!(calculate_percentile(&values, 50.0), 42.0);
        assert_eq!(calculate_percentile(&values, 95.0), 42.0);
        assert_eq!(calculate_percentile(&values, 99.0), 42.0);
    }

    #[test]
    fn test_calculate_percentile_empty() {
        let values: Vec<f64> = vec![];
        assert_eq!(calculate_percentile(&values, 50.0), 0.0);
    }

    #[test]
    fn test_calculate_percentile_two_values() {
        let values = vec![10.0, 100.0];
        // p50: index = round(0.5 * 1) = 1 -> 100
        assert_eq!(calculate_percentile(&values, 50.0), 100.0);
        // p0: index = round(0 * 1) = 0 -> 10
        assert_eq!(calculate_percentile(&values, 0.0), 10.0);
        // p100: index = round(1 * 1) = 1 -> 100
        assert_eq!(calculate_percentile(&values, 100.0), 100.0);
    }

    #[test]
    fn test_latency_stats_structure() {
        let stats = LatencyStats {
            avg_ms: 50,
            p95_ms: 95,
            p99_ms: 99,
        };
        assert_eq!(stats.avg_ms, 50);
        assert_eq!(stats.p95_ms, 95);
        assert_eq!(stats.p99_ms, 99);
    }

    #[test]
    fn test_time_series_point_structure() {
        let point = TimeSeriesPoint {
            label: "10:00".to_string(),
            requests: 1000,
            avg_ms: 45,
        };
        assert_eq!(point.label, "10:00");
        assert_eq!(point.requests, 1000);
        assert_eq!(point.avg_ms, 45);
    }

    #[test]
    fn test_route_summary_structure() {
        let summary = RouteSummary {
            path: "/users".to_string(),
            method: "GET".to_string(),
            request_count: 100,
            avg_ms: 50,
            p95_ms: 95,
            p99_ms: 120,
            max_ms: 500,
            min_ms: 5,
            avg_db_ms: 20,
            avg_db_count: 3,
            error_count: 2,
            error_rate: 2.0,
        };
        assert_eq!(summary.path, "/users");
        assert_eq!(summary.p95_ms, 95);
        assert_eq!(summary.p99_ms, 120);
        assert_eq!(summary.error_rate, 2.0);
    }
}
