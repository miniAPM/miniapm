use crate::DbPool;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// OTLP/HTTP JSON Ingestion Types (matching OTLP protobuf JSON mapping)
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OtlpTraceRequest {
    pub resource_spans: Vec<ResourceSpans>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceSpans {
    pub resource: Option<Resource>,
    pub scope_spans: Option<Vec<ScopeSpans>>,
}

#[derive(Debug, Deserialize)]
pub struct Resource {
    pub attributes: Option<Vec<KeyValue>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeSpans {
    pub scope: Option<InstrumentationScope>,
    pub spans: Vec<OtlpSpan>,
}

#[derive(Debug, Deserialize)]
pub struct InstrumentationScope {
    pub name: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OtlpSpan {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub kind: Option<i32>,
    pub start_time_unix_nano: String,
    pub end_time_unix_nano: String,
    pub attributes: Option<Vec<KeyValue>>,
    pub events: Option<Vec<SpanEvent>>,
    pub status: Option<SpanStatus>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeyValue {
    pub key: String,
    pub value: AttributeValue,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributeValue {
    pub string_value: Option<String>,
    pub int_value: Option<String>,
    pub double_value: Option<f64>,
    pub bool_value: Option<bool>,
    pub array_value: Option<ArrayValue>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ArrayValue {
    pub values: Option<Vec<AttributeValue>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpanEvent {
    pub name: String,
    pub time_unix_nano: Option<String>,
    pub attributes: Option<Vec<KeyValue>>,
}

#[derive(Debug, Deserialize)]
pub struct SpanStatus {
    pub code: Option<i32>,
    pub message: Option<String>,
}

// ============================================================================
// Internal Types
// ============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SpanCategory {
    HttpServer,
    HttpClient,
    Db,
    View,
    Search,
    Job,
    Rake,
    Internal,
}

impl SpanCategory {
    pub fn from_attributes(name: &str, kind: i32, attributes: &HashMap<String, String>) -> Self {
        // Check for database spans first
        if attributes.contains_key("db.system") || attributes.contains_key("db.statement") {
            let db_system = attributes.get("db.system").map(|s| s.as_str()).unwrap_or("");
            if db_system == "elasticsearch" || db_system == "opensearch" {
                return SpanCategory::Search;
            }
            return SpanCategory::Db;
        }

        // Check for HTTP spans
        let has_http = attributes.contains_key("http.url")
            || attributes.contains_key("http.method")
            || attributes.contains_key("url.full")
            || attributes.contains_key("http.request.method");

        if has_http {
            // kind: 2 = SERVER, 3 = CLIENT
            if kind == 3 {
                return SpanCategory::HttpClient;
            }
            if kind == 2 {
                return SpanCategory::HttpServer;
            }
        }

        // Check for view rendering
        if name.starts_with("render_template")
            || name.starts_with("render_partial")
            || name.starts_with("render_collection")
            || name.contains(".erb")
            || name.contains(".haml")
            || name.contains(".slim")
            || name.contains("ActionView")
        {
            return SpanCategory::View;
        }

        // Check for messaging/job spans
        // kind: 4 = PRODUCER, 5 = CONSUMER
        if kind == 4 || kind == 5 {
            return SpanCategory::Job;
        }
        if attributes.contains_key("messaging.system")
            || attributes.contains_key("messaging.destination.name")
        {
            return SpanCategory::Job;
        }

        // Check by name patterns
        let name_lower = name.to_lowercase();
        if name_lower.contains("sidekiq")
            || name_lower.contains("activejob")
            || name_lower.contains("active_job")
            || name_lower.contains("perform")
        {
            return SpanCategory::Job;
        }

        if name_lower.starts_with("rake:")
            || name_lower.starts_with("rake ")
            || name_lower.contains("rake::task")
        {
            return SpanCategory::Rake;
        }

        SpanCategory::Internal
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SpanCategory::HttpServer => "http_server",
            SpanCategory::HttpClient => "http_client",
            SpanCategory::Db => "db",
            SpanCategory::View => "view",
            SpanCategory::Search => "search",
            SpanCategory::Job => "job",
            SpanCategory::Rake => "rake",
            SpanCategory::Internal => "internal",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "http_server" => SpanCategory::HttpServer,
            "http_client" => SpanCategory::HttpClient,
            "db" => SpanCategory::Db,
            "view" => SpanCategory::View,
            "search" => SpanCategory::Search,
            "job" => SpanCategory::Job,
            "rake" => SpanCategory::Rake,
            _ => SpanCategory::Internal,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RootSpanType {
    Web,
    Job,
    Rake,
}

impl RootSpanType {
    pub fn from_category(category: SpanCategory) -> Option<Self> {
        match category {
            SpanCategory::HttpServer => Some(RootSpanType::Web),
            SpanCategory::Job => Some(RootSpanType::Job),
            SpanCategory::Rake => Some(RootSpanType::Rake),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RootSpanType::Web => "web",
            RootSpanType::Job => "job",
            RootSpanType::Rake => "rake",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "web" => Some(RootSpanType::Web),
            "job" => Some(RootSpanType::Job),
            "rake" => Some(RootSpanType::Rake),
            _ => None,
        }
    }
}

// ============================================================================
// Display Types for UI
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct TraceSummary {
    pub trace_id: String,
    pub root_span_name: String,
    pub root_span_type: Option<RootSpanType>,
    pub duration_ms: f64,
    pub span_count: i64,
    pub status_code: i32,
    pub service_name: Option<String>,
    pub http_method: Option<String>,
    pub http_url: Option<String>,
    pub http_status_code: Option<i32>,
    pub happened_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceDetail {
    pub trace_id: String,
    pub spans: Vec<SpanDisplay>,
    pub total_duration_ms: f64,
    pub root_span: Option<SpanDisplay>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpanDisplay {
    pub id: i64,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub category: SpanCategory,
    pub duration_ms: f64,
    pub offset_ms: f64,
    pub offset_percent: f64,
    pub width_percent: f64,
    pub depth: i32,
    pub status_code: i32,
    pub http_method: Option<String>,
    pub http_status_code: Option<i32>,
    pub db_operation: Option<String>,
    pub db_system: Option<String>,
    pub db_statement: Option<String>,
}

// ============================================================================
// Helper Functions
// ============================================================================

fn parse_attributes(attrs: &Option<Vec<KeyValue>>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(attrs) = attrs {
        for kv in attrs {
            let value = if let Some(ref v) = kv.value.string_value {
                v.clone()
            } else if let Some(ref v) = kv.value.int_value {
                v.clone()
            } else if let Some(v) = kv.value.double_value {
                v.to_string()
            } else if let Some(v) = kv.value.bool_value {
                v.to_string()
            } else {
                continue;
            };
            map.insert(kv.key.clone(), value);
        }
    }
    map
}

fn decode_id(s: &str) -> String {
    // OTLP can send IDs as base64 - try to decode
    if let Ok(bytes) = STANDARD.decode(s) {
        hex::encode(bytes)
    } else {
        // Already hex or some other format
        s.to_string()
    }
}

// ============================================================================
// Database Operations
// ============================================================================

pub fn insert_otlp_batch(
    pool: &DbPool,
    request: &OtlpTraceRequest,
    project_id: Option<i64>,
) -> anyhow::Result<usize> {
    let conn = pool.get()?;
    let mut count = 0;

    for resource_span in &request.resource_spans {
        let resource_attrs =
            parse_attributes(&resource_span.resource.as_ref().and_then(|r| r.attributes.clone()));
        let service_name = resource_attrs.get("service.name").cloned();
        let resource_json = serde_json::to_string(&resource_attrs)?;

        let scope_spans = match &resource_span.scope_spans {
            Some(ss) => ss,
            None => continue,
        };

        for scope_span in scope_spans {
            for otlp_span in &scope_span.spans {
                let attrs = parse_attributes(&otlp_span.attributes);
                let kind = otlp_span.kind.unwrap_or(0);
                let category = SpanCategory::from_attributes(&otlp_span.name, kind, &attrs);

                let is_root = otlp_span.parent_span_id.is_none()
                    || otlp_span
                        .parent_span_id
                        .as_ref()
                        .map(|s| s.is_empty())
                        .unwrap_or(true);
                let root_span_type = if is_root {
                    RootSpanType::from_category(category)
                } else {
                    None
                };

                let trace_id = decode_id(&otlp_span.trace_id);
                let span_id = decode_id(&otlp_span.span_id);
                let parent_span_id = otlp_span
                    .parent_span_id
                    .as_ref()
                    .filter(|s| !s.is_empty())
                    .map(|s| decode_id(s));

                let start_nano: i64 = otlp_span.start_time_unix_nano.parse()?;
                let end_nano: i64 = otlp_span.end_time_unix_nano.parse()?;
                let duration_ms = (end_nano - start_nano) as f64 / 1_000_000.0;

                let happened_at = DateTime::from_timestamp_nanos(start_nano)
                    .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                    .to_string();

                let status_code = otlp_span
                    .status
                    .as_ref()
                    .and_then(|s| s.code)
                    .unwrap_or(0);
                let status_message = otlp_span.status.as_ref().and_then(|s| s.message.clone());

                // Extract denormalized fields
                let http_method = attrs
                    .get("http.method")
                    .or_else(|| attrs.get("http.request.method"))
                    .cloned();
                let http_url = attrs
                    .get("http.url")
                    .or_else(|| attrs.get("url.full"))
                    .or_else(|| attrs.get("http.target"))
                    .cloned();
                let http_status: Option<i32> = attrs
                    .get("http.status_code")
                    .or_else(|| attrs.get("http.response.status_code"))
                    .and_then(|s| s.parse().ok());
                let db_system = attrs.get("db.system").cloned();
                let db_statement = attrs.get("db.statement").cloned();
                let db_operation = attrs.get("db.operation").cloned();
                let messaging_system = attrs.get("messaging.system").cloned();
                let messaging_operation = attrs
                    .get("messaging.operation")
                    .or_else(|| attrs.get("messaging.destination.name"))
                    .cloned();
                let request_id = attrs
                    .get("http.request_id")
                    .or_else(|| attrs.get("request_id"))
                    .cloned();

                let attrs_json = serde_json::to_string(&attrs)?;
                let events_json = otlp_span
                    .events
                    .as_ref()
                    .map(|e| serde_json::to_string(e))
                    .transpose()?;

                conn.execute(
                    r#"
                    INSERT OR REPLACE INTO spans
                    (project_id, trace_id, span_id, parent_span_id,
                     start_time_unix_nano, end_time_unix_nano, duration_ms, name, kind,
                     status_code, status_message, span_category, root_span_type,
                     service_name, http_method, http_url, http_status_code,
                     db_system, db_statement, db_operation,
                     messaging_system, messaging_operation, request_id,
                     attributes_json, events_json, resource_attributes_json, happened_at)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                            ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23,
                            ?24, ?25, ?26, ?27)
                    "#,
                    rusqlite::params![
                        project_id,
                        trace_id,
                        span_id,
                        parent_span_id,
                        start_nano,
                        end_nano,
                        duration_ms,
                        otlp_span.name,
                        kind,
                        status_code,
                        status_message,
                        category.as_str(),
                        root_span_type.map(|r| r.as_str()),
                        service_name,
                        http_method,
                        http_url,
                        http_status,
                        db_system,
                        db_statement,
                        db_operation,
                        messaging_system,
                        messaging_operation,
                        request_id,
                        attrs_json,
                        events_json,
                        resource_json,
                        happened_at,
                    ],
                )?;
                count += 1;
            }
        }
    }

    Ok(count)
}

pub fn list_traces(
    pool: &DbPool,
    project_id: Option<i64>,
    root_type_filter: Option<RootSpanType>,
    limit: i64,
) -> anyhow::Result<Vec<TraceSummary>> {
    list_traces_filtered(pool, project_id, root_type_filter, None, None, None, "recent", limit)
}

pub fn list_traces_filtered(
    pool: &DbPool,
    project_id: Option<i64>,
    root_type_filter: Option<RootSpanType>,
    since: Option<&str>,
    search: Option<&str>,
    min_duration_ms: Option<f64>,
    sort_by: &str,
    limit: i64,
) -> anyhow::Result<Vec<TraceSummary>> {
    list_traces_paginated(pool, project_id, root_type_filter, since, search, min_duration_ms, sort_by, limit, 0)
}

pub fn list_traces_paginated(
    pool: &DbPool,
    project_id: Option<i64>,
    root_type_filter: Option<RootSpanType>,
    since: Option<&str>,
    search: Option<&str>,
    min_duration_ms: Option<f64>,
    sort_by: &str,
    limit: i64,
    offset: i64,
) -> anyhow::Result<Vec<TraceSummary>> {
    let conn = pool.get()?;

    let order_clause = match sort_by {
        "duration" => "s.duration_ms DESC",
        "spans" => "span_count DESC",
        _ => "s.happened_at DESC", // default: recent
    };

    let sql = format!(
        r#"
        SELECT
            s.trace_id,
            s.name as root_span_name,
            s.root_span_type,
            s.duration_ms,
            (SELECT COUNT(*) FROM spans s2 WHERE s2.trace_id = s.trace_id) as span_count,
            s.status_code,
            s.service_name,
            s.http_method,
            s.http_url,
            s.http_status_code,
            strftime('%Y-%m-%d %H:%M', s.happened_at) as happened_at
        FROM spans s
        WHERE s.parent_span_id IS NULL
          AND (?1 IS NULL OR s.project_id = ?1)
          AND (?2 IS NULL OR s.root_span_type = ?2)
          AND (?3 IS NULL OR s.happened_at >= ?3)
          AND (?4 IS NULL OR s.name LIKE '%' || ?4 || '%' OR s.http_url LIKE '%' || ?4 || '%')
          AND (?5 IS NULL OR s.duration_ms >= ?5)
        ORDER BY {}
        LIMIT ?6 OFFSET ?7
        "#,
        order_clause
    );

    let root_type_str = root_type_filter.map(|r| r.as_str());
    let mut stmt = conn.prepare(&sql)?;
    let traces = stmt
        .query_map(
            rusqlite::params![project_id, root_type_str, since, search, min_duration_ms, limit, offset],
            |row| {
                Ok(TraceSummary {
                    trace_id: row.get(0)?,
                    root_span_name: row.get(1)?,
                    root_span_type: row
                        .get::<_, Option<String>>(2)?
                        .and_then(|s| RootSpanType::from_str(&s)),
                    duration_ms: row.get(3)?,
                    span_count: row.get(4)?,
                    status_code: row.get(5)?,
                    service_name: row.get(6)?,
                    http_method: row.get(7)?,
                    http_url: row.get(8)?,
                    http_status_code: row.get(9)?,
                    happened_at: row.get(10)?,
                })
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(traces)
}

pub fn count_traces_filtered(
    pool: &DbPool,
    project_id: Option<i64>,
    root_type_filter: Option<RootSpanType>,
    since: Option<&str>,
    search: Option<&str>,
    min_duration_ms: Option<f64>,
) -> anyhow::Result<i64> {
    let conn = pool.get()?;

    let root_type_str = root_type_filter.map(|r| r.as_str());
    let count: i64 = conn.query_row(
        r#"
        SELECT COUNT(*)
        FROM spans s
        WHERE s.parent_span_id IS NULL
          AND (?1 IS NULL OR s.project_id = ?1)
          AND (?2 IS NULL OR s.root_span_type = ?2)
          AND (?3 IS NULL OR s.happened_at >= ?3)
          AND (?4 IS NULL OR s.name LIKE '%' || ?4 || '%' OR s.http_url LIKE '%' || ?4 || '%')
          AND (?5 IS NULL OR s.duration_ms >= ?5)
        "#,
        rusqlite::params![project_id, root_type_str, since, search, min_duration_ms],
        |row| row.get(0),
    )?;

    Ok(count)
}

pub fn get_trace(pool: &DbPool, trace_id: &str) -> anyhow::Result<Option<TraceDetail>> {
    let conn = pool.get()?;

    let mut stmt = conn.prepare(
        r#"
        SELECT id, span_id, parent_span_id, name, span_category,
               duration_ms, start_time_unix_nano, status_code,
               http_method, http_status_code, db_operation, db_system, db_statement
        FROM spans
        WHERE trace_id = ?1
        ORDER BY start_time_unix_nano ASC
        "#,
    )?;

    let spans: Vec<(
        i64,
        String,
        Option<String>,
        String,
        String,
        f64,
        i64,
        i32,
        Option<String>,
        Option<i32>,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = stmt
        .query_map([trace_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
                row.get(10)?,
                row.get(11)?,
                row.get(12)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    if spans.is_empty() {
        return Ok(None);
    }

    // Find trace start time and total duration
    let trace_start = spans.iter().map(|s| s.6).min().unwrap_or(0);
    let trace_end = spans
        .iter()
        .map(|s| s.6 + (s.5 * 1_000_000.0) as i64)
        .max()
        .unwrap_or(0);
    let total_duration_ms = (trace_end - trace_start) as f64 / 1_000_000.0;

    // Build span hierarchy for depth calculation
    let parent_map: HashMap<String, Option<String>> =
        spans.iter().map(|s| (s.1.clone(), s.2.clone())).collect();

    fn compute_depth(
        span_id: &str,
        parent_map: &HashMap<String, Option<String>>,
        depth_cache: &mut HashMap<String, i32>,
    ) -> i32 {
        if let Some(&cached) = depth_cache.get(span_id) {
            return cached;
        }
        let depth = match parent_map.get(span_id).and_then(|p| p.as_ref()) {
            Some(parent_id) => compute_depth(parent_id, parent_map, depth_cache) + 1,
            None => 0,
        };
        depth_cache.insert(span_id.to_string(), depth);
        depth
    }

    let mut depth_cache = HashMap::new();

    let display_spans: Vec<SpanDisplay> = spans
        .iter()
        .map(|s| {
            let offset_ns = s.6 - trace_start;
            let offset_ms = offset_ns as f64 / 1_000_000.0;
            let offset_percent = if total_duration_ms > 0.0 {
                (offset_ms / total_duration_ms) * 100.0
            } else {
                0.0
            };
            let width_percent = if total_duration_ms > 0.0 {
                (s.5 / total_duration_ms) * 100.0
            } else {
                100.0
            };
            let depth = compute_depth(&s.1, &parent_map, &mut depth_cache);

            SpanDisplay {
                id: s.0,
                span_id: s.1.clone(),
                parent_span_id: s.2.clone(),
                name: s.3.clone(),
                category: SpanCategory::from_str(&s.4),
                duration_ms: s.5,
                offset_ms,
                offset_percent,
                width_percent,
                depth,
                status_code: s.7,
                http_method: s.8.clone(),
                http_status_code: s.9,
                db_operation: s.10.clone(),
                db_system: s.11.clone(),
                db_statement: s.12.clone(),
            }
        })
        .collect();

    let root_span = display_spans.iter().find(|s| s.depth == 0).cloned();

    Ok(Some(TraceDetail {
        trace_id: trace_id.to_string(),
        spans: display_spans,
        total_duration_ms,
        root_span,
    }))
}

pub fn delete_before(pool: &DbPool, before: &str) -> anyhow::Result<usize> {
    let conn = pool.get()?;
    let deleted = conn.execute("DELETE FROM spans WHERE happened_at < ?1", [before])?;
    Ok(deleted)
}

pub fn count_since(pool: &DbPool, project_id: Option<i64>, since: &str) -> anyhow::Result<i64> {
    let conn = pool.get()?;
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM spans WHERE (?1 IS NULL OR project_id = ?1) AND happened_at >= ?2",
        rusqlite::params![project_id, since],
        |row| row.get(0),
    )?;
    Ok(count)
}

// ============================================================================
// N+1 Query Detection
// ============================================================================

const N_PLUS_1_THRESHOLD: usize = 5;

/// Normalize a SQL statement by replacing literal values with placeholders
/// This helps group similar queries together
fn normalize_sql(sql: &str) -> String {
    let mut result = String::new();
    let mut chars = sql.chars().peekable();
    let mut in_string = false;
    let mut string_char = ' ';

    while let Some(c) = chars.next() {
        if in_string {
            // Skip until end of string
            if c == string_char && chars.peek() != Some(&string_char) {
                result.push_str("?");
                in_string = false;
            } else if c == string_char && chars.peek() == Some(&string_char) {
                // Escaped quote
                chars.next();
            }
        } else if c == '\'' || c == '"' {
            in_string = true;
            string_char = c;
        } else if c.is_ascii_digit() && (result.ends_with(' ') || result.ends_with('=') || result.ends_with('(') || result.ends_with(',') || result.is_empty()) {
            // Skip numbers that appear to be values
            while chars.peek().map(|ch| ch.is_ascii_digit() || *ch == '.').unwrap_or(false) {
                chars.next();
            }
            result.push('?');
        } else {
            result.push(c);
        }
    }

    // Normalize whitespace
    result.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[derive(Debug, Clone, Serialize)]
pub struct NPlus1Issue {
    pub pattern: String,
    pub count: usize,
    pub total_duration_ms: f64,
    pub span_ids: Vec<String>,
}

/// Detect N+1 query patterns in a trace
pub fn detect_n_plus_1(spans: &[SpanDisplay]) -> Vec<NPlus1Issue> {
    let mut pattern_counts: HashMap<String, (usize, f64, Vec<String>)> = HashMap::new();

    for span in spans {
        if span.category == SpanCategory::Db {
            if let Some(ref statement) = span.db_statement {
                let pattern = normalize_sql(statement);
                let entry = pattern_counts.entry(pattern).or_insert((0, 0.0, Vec::new()));
                entry.0 += 1;
                entry.1 += span.duration_ms;
                entry.2.push(span.span_id.clone());
            }
        }
    }

    let mut issues: Vec<NPlus1Issue> = pattern_counts
        .into_iter()
        .filter(|(_, (count, _, _))| *count >= N_PLUS_1_THRESHOLD)
        .map(|(pattern, (count, total_duration_ms, span_ids))| NPlus1Issue {
            pattern,
            count,
            total_duration_ms,
            span_ids,
        })
        .collect();

    // Sort by count descending
    issues.sort_by(|a, b| b.count.cmp(&a.count));
    issues
}

/// Check if a trace has N+1 issues (for list view)
pub fn has_n_plus_1(pool: &DbPool, trace_id: &str) -> bool {
    let conn = match pool.get() {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Count DB spans grouped by normalized statement pattern
    let result: Result<i64, _> = conn.query_row(
        r#"
        SELECT COUNT(*) FROM (
            SELECT db_statement, COUNT(*) as cnt
            FROM spans
            WHERE trace_id = ?1 AND span_category = 'db' AND db_statement IS NOT NULL
            GROUP BY db_statement
            HAVING cnt >= ?2
        )
        "#,
        rusqlite::params![trace_id, N_PLUS_1_THRESHOLD as i64],
        |row| row.get(0),
    );

    result.unwrap_or(0) > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_sql_strings() {
        let sql = "SELECT * FROM users WHERE name = 'John'";
        assert_eq!(normalize_sql(sql), "SELECT * FROM users WHERE name = ?");
    }

    #[test]
    fn test_normalize_sql_numbers() {
        let sql = "SELECT * FROM users WHERE id = 123";
        assert_eq!(normalize_sql(sql), "SELECT * FROM users WHERE id = ?");
    }

    #[test]
    fn test_normalize_sql_mixed() {
        let sql = "SELECT * FROM orders WHERE user_id = 42 AND status = 'pending'";
        assert_eq!(normalize_sql(sql), "SELECT * FROM orders WHERE user_id = ? AND status = ?");
    }

    #[test]
    fn test_normalize_sql_in_clause() {
        let sql = "SELECT * FROM users WHERE id IN (1, 2, 3)";
        assert_eq!(normalize_sql(sql), "SELECT * FROM users WHERE id IN (?, ?, ?)");
    }
}
