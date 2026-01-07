use crate::DbPool;
use base64::{Engine as _, engine::general_purpose::STANDARD};
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
    Command,
    Internal,
}

impl SpanCategory {
    pub fn from_attributes(name: &str, kind: i32, attributes: &HashMap<String, String>) -> Self {
        // Check for database spans first
        if attributes.contains_key("db.system") || attributes.contains_key("db.statement") {
            let db_system = attributes
                .get("db.system")
                .map(|s| s.as_str())
                .unwrap_or("");
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

        // Command runners: rake, thor, make, etc.
        if name_lower.starts_with("rake:")
            || name_lower.starts_with("rake ")
            || name_lower.contains("rake::task")
            || name_lower.starts_with("thor:")
            || name_lower.starts_with("make:")
        {
            return SpanCategory::Command;
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
            SpanCategory::Command => "command",
            SpanCategory::Internal => "internal",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "http_server" => SpanCategory::HttpServer,
            "http_client" => SpanCategory::HttpClient,
            "db" => SpanCategory::Db,
            "view" => SpanCategory::View,
            "search" => SpanCategory::Search,
            "job" => SpanCategory::Job,
            "command" => SpanCategory::Command,
            _ => SpanCategory::Internal,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RootSpanType {
    Web,
    Job,
    Command,
}

impl RootSpanType {
    pub fn from_category(category: SpanCategory) -> Option<Self> {
        match category {
            SpanCategory::HttpServer => Some(RootSpanType::Web),
            SpanCategory::Job => Some(RootSpanType::Job),
            SpanCategory::Command => Some(RootSpanType::Command),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RootSpanType::Web => "web",
            RootSpanType::Job => "job",
            RootSpanType::Command => "command",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "web" => Some(RootSpanType::Web),
            "job" => Some(RootSpanType::Job),
            "command" => Some(RootSpanType::Command),
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

impl TraceSummary {
    /// Returns a clean, human-readable name for the trace
    pub fn display_name(&self) -> String {
        // For web requests, show "METHOD /path"
        if let Some(ref method) = self.http_method {
            // Extract just the path from the URL if present
            let path = self
                .http_url
                .as_ref()
                .and_then(|url| {
                    // Parse URL to get just the path
                    if let Some(pos) = url.find("://") {
                        let after_scheme = &url[pos + 3..];
                        after_scheme.find('/').map(|p| &after_scheme[p..])
                    } else if url.starts_with('/') {
                        Some(url.as_str())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| {
                    // Fallback: extract path from span name if it starts with method
                    let name = &self.root_span_name;
                    if name.starts_with(method) {
                        name[method.len()..].trim()
                    } else {
                        name.as_str()
                    }
                });

            format!("{} {}", method, path)
        } else {
            // For jobs/rake tasks, just use the span name as-is
            self.root_span_name.clone()
        }
    }

    /// Returns a CSS class for the status
    pub fn status_class(&self) -> &'static str {
        if let Some(code) = self.http_status_code {
            if code >= 500 {
                "status-error"
            } else if code >= 400 {
                "status-warning"
            } else {
                "status-ok"
            }
        } else if self.status_code == 2 {
            "status-error"
        } else {
            "status-ok"
        }
    }

    /// Returns a human-readable status label
    pub fn status_label(&self) -> String {
        if let Some(code) = self.http_status_code {
            code.to_string()
        } else if self.status_code == 2 {
            "Error".to_string()
        } else {
            "OK".to_string()
        }
    }

    /// Returns duration in ms rounded to nearest integer
    pub fn duration_ms_rounded(&self) -> i64 {
        self.duration_ms.round() as i64
    }
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

use crate::models::error as app_error;
use sha2::{Digest, Sha256};

/// Backfill errors from existing spans that have exception events
/// This is useful for extracting errors from spans that were ingested before error extraction was added
pub fn backfill_errors_from_spans(pool: &DbPool) -> anyhow::Result<usize> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        r#"
        SELECT project_id, trace_id, events_json, happened_at
        FROM spans
        WHERE events_json IS NOT NULL
          AND events_json != '[]'
          AND events_json LIKE '%exception%'
        "#,
    )?;

    let mut count = 0;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;

    for row in rows {
        let (project_id, trace_id, events_json, happened_at) = row?;
        if let Ok(events) = serde_json::from_str::<Vec<SpanEvent>>(&events_json) {
            let events_opt = Some(events);
            extract_and_insert_errors(pool, &events_opt, &trace_id, &happened_at, project_id);
            count += 1;
        }
    }

    Ok(count)
}

/// Extract exception events from OTLP span and insert as errors
fn extract_and_insert_errors(
    pool: &DbPool,
    events: &Option<Vec<SpanEvent>>,
    trace_id: &str,
    happened_at: &str,
    project_id: Option<i64>,
) {
    let events = match events {
        Some(e) => e,
        None => return,
    };

    for event in events {
        if event.name != "exception" {
            continue;
        }

        let attrs = parse_attributes(&event.attributes);
        let exception_type = match attrs.get("exception.type") {
            Some(t) => t.clone(),
            None => continue,
        };
        let message = attrs.get("exception.message").cloned().unwrap_or_default();
        let stacktrace = attrs
            .get("exception.stacktrace")
            .cloned()
            .unwrap_or_default();
        let backtrace: Vec<String> = stacktrace.lines().map(|s| s.to_string()).collect();

        // Generate fingerprint from exception type + first backtrace line
        let first_line = backtrace.first().map(|s| s.as_str()).unwrap_or("");
        let mut hasher = Sha256::new();
        hasher.update(format!("{}:{}", exception_type, first_line));
        let fingerprint = format!("{:x}", hasher.finalize());

        let incoming_error = app_error::IncomingError {
            exception_class: exception_type,
            message,
            backtrace,
            fingerprint,
            request_id: Some(trace_id.to_string()),
            user_id: None,
            params: None,
            timestamp: Some(happened_at.to_string()),
            source_context: None,
        };

        if let Err(e) = app_error::insert(pool, &incoming_error, project_id) {
            tracing::warn!("Failed to insert error from span event: {}", e);
        }
    }
}

pub fn insert_otlp_batch(
    pool: &DbPool,
    request: &OtlpTraceRequest,
    project_id: Option<i64>,
) -> anyhow::Result<usize> {
    let conn = pool.get()?;
    let mut count = 0;

    for resource_span in &request.resource_spans {
        let resource_attrs = parse_attributes(
            &resource_span
                .resource
                .as_ref()
                .and_then(|r| r.attributes.clone()),
        );
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

                let status_code = otlp_span.status.as_ref().and_then(|s| s.code).unwrap_or(0);
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
                    .map(serde_json::to_string)
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

                // Extract errors from exception events
                extract_and_insert_errors(
                    pool,
                    &otlp_span.events,
                    &trace_id,
                    &happened_at,
                    project_id,
                );
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
    list_traces_filtered(
        pool,
        project_id,
        root_type_filter,
        None,
        None,
        None,
        "recent",
        limit,
    )
}

#[allow(clippy::too_many_arguments)]
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
    list_traces_paginated(
        pool,
        project_id,
        root_type_filter,
        since,
        search,
        min_duration_ms,
        sort_by,
        limit,
        0,
    )
}

#[allow(clippy::too_many_arguments)]
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
            rusqlite::params![
                project_id,
                root_type_str,
                since,
                search,
                min_duration_ms,
                limit,
                offset
            ],
            |row| {
                Ok(TraceSummary {
                    trace_id: row.get(0)?,
                    root_span_name: row.get(1)?,
                    root_span_type: row
                        .get::<_, Option<String>>(2)?
                        .and_then(|s| RootSpanType::parse(&s)),
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

    #[allow(clippy::type_complexity)]
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
                category: SpanCategory::parse(&s.4),
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
        "SELECT COUNT(*) FROM spans WHERE parent_span_id IS NULL AND (?1 IS NULL OR project_id = ?1) AND happened_at >= ?2",
        rusqlite::params![project_id, since],
        |row| row.get(0),
    )?;
    Ok(count)
}

// ============================================================================
// Dashboard Stats (from root spans)
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct LatencyStats {
    pub avg_ms: i64,
    pub p95_ms: i64,
    pub p99_ms: i64,
}

pub fn latency_stats_since(
    pool: &DbPool,
    project_id: Option<i64>,
    since: &str,
) -> anyhow::Result<LatencyStats> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT duration_ms FROM spans WHERE parent_span_id IS NULL AND happened_at >= ?1 AND (?2 IS NULL OR project_id = ?2) ORDER BY duration_ms ASC",
    )?;

    let values: Vec<f64> = stmt
        .query_map(rusqlite::params![since, project_id], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;

    if values.is_empty() {
        return Ok(LatencyStats {
            avg_ms: 0,
            p95_ms: 0,
            p99_ms: 0,
        });
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

pub fn slow_traces(
    pool: &DbPool,
    project_id: Option<i64>,
    threshold_ms: f64,
    limit: i64,
) -> anyhow::Result<Vec<TraceSummary>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
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
          AND s.duration_ms >= ?1
          AND (?2 IS NULL OR s.project_id = ?2)
        ORDER BY s.duration_ms DESC
        LIMIT ?3
        "#,
    )?;

    let traces = stmt
        .query_map(rusqlite::params![threshold_ms, project_id, limit], |row| {
            Ok(TraceSummary {
                trace_id: row.get(0)?,
                root_span_name: row.get(1)?,
                root_span_type: row
                    .get::<_, Option<String>>(2)?
                    .and_then(|s| RootSpanType::parse(&s)),
                duration_ms: row.get(3)?,
                span_count: row.get(4)?,
                status_code: row.get(5)?,
                service_name: row.get(6)?,
                http_method: row.get(7)?,
                http_url: row.get(8)?,
                http_status_code: row.get(9)?,
                happened_at: row.get(10)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(traces)
}

#[derive(Debug, Clone, Serialize)]
pub struct TimeSeriesPoint {
    pub hour: String,
    pub count: i64,
    pub avg_ms: f64,
    pub error_count: i64,
}

pub fn hourly_stats(
    pool: &DbPool,
    project_id: Option<i64>,
    hours: i64,
) -> anyhow::Result<Vec<TimeSeriesPoint>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        r#"
        SELECT
            strftime('%Y-%m-%d %H:00', happened_at) as hour,
            COUNT(*) as count,
            COALESCE(AVG(duration_ms), 0) as avg_ms,
            SUM(CASE WHEN status_code = 2 OR http_status_code >= 500 THEN 1 ELSE 0 END) as error_count
        FROM spans
        WHERE parent_span_id IS NULL
          AND (?1 IS NULL OR project_id = ?1)
          AND happened_at >= datetime('now', '-' || ?2 || ' hours')
        GROUP BY strftime('%Y-%m-%d %H:00', happened_at)
        ORDER BY hour ASC
        "#,
    )?;

    let data_points: std::collections::HashMap<String, TimeSeriesPoint> = stmt
        .query_map(rusqlite::params![project_id, hours], |row| {
            Ok(TimeSeriesPoint {
                hour: row.get(0)?,
                count: row.get(1)?,
                avg_ms: row.get(2)?,
                error_count: row.get(3)?,
            })
        })?
        .filter_map(|r| r.ok())
        .map(|p| (p.hour.clone(), p))
        .collect();

    // Fill in all hours with zeros for missing data
    let mut points = Vec::with_capacity(hours as usize);
    for i in (0..hours).rev() {
        let hour = chrono::Utc::now() - chrono::Duration::hours(i);
        let hour_key = hour.format("%Y-%m-%d %H:00").to_string();
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

// ============================================================================
// Routes Stats (aggregated by endpoint)
// ============================================================================

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

pub fn routes_summary(
    pool: &DbPool,
    project_id: Option<i64>,
    since: &str,
    search: Option<&str>,
    sort: &str,
    limit: i64,
) -> anyhow::Result<Vec<RouteSummary>> {
    let conn = pool.get()?;

    // Get unique routes with basic stats
    let mut stmt = conn.prepare(
        r#"
        SELECT
            COALESCE(name, http_url, 'unknown') as path,
            COALESCE(http_method, 'GET') as method,
            COUNT(*) as request_count,
            AVG(duration_ms) as avg_ms,
            MAX(duration_ms) as max_ms,
            MIN(duration_ms) as min_ms,
            SUM(CASE WHEN status_code = 2 OR http_status_code >= 500 THEN 1 ELSE 0 END) as error_count
        FROM spans
        WHERE parent_span_id IS NULL
          AND root_span_type = 'web'
          AND (?1 IS NULL OR project_id = ?1)
          AND happened_at >= ?2
          AND (?3 IS NULL OR name LIKE '%' || ?3 || '%' OR http_url LIKE '%' || ?3 || '%')
        GROUP BY COALESCE(name, http_url, 'unknown'), COALESCE(http_method, 'GET')
        ORDER BY request_count DESC
        LIMIT ?4
        "#,
    )?;

    let routes: Vec<(String, String, i64, f64, f64, f64, i64)> = stmt
        .query_map(rusqlite::params![project_id, since, search, limit], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut result = Vec::new();
    for (path, method, request_count, avg_ms, max_ms, min_ms, error_count) in routes {
        let (p95, p99) = calculate_route_percentiles(&conn, project_id, &path, since)?;
        let (avg_db_ms, avg_db_count) = calculate_route_db_stats(&conn, project_id, &path, since)?;
        let error_rate = if request_count > 0 {
            (error_count as f64 / request_count as f64) * 100.0
        } else {
            0.0
        };
        result.push(RouteSummary {
            path,
            method,
            request_count,
            avg_ms: avg_ms.round() as i64,
            p95_ms: p95,
            p99_ms: p99,
            max_ms: max_ms.round() as i64,
            min_ms: min_ms.round() as i64,
            avg_db_ms,
            avg_db_count,
            error_count,
            error_rate,
        });
    }

    // Sort by requested field
    match sort {
        "avg" => result.sort_by(|a, b| b.avg_ms.cmp(&a.avg_ms)),
        "p95" => result.sort_by(|a, b| b.p95_ms.cmp(&a.p95_ms)),
        "p99" => result.sort_by(|a, b| b.p99_ms.cmp(&a.p99_ms)),
        "max" => result.sort_by(|a, b| b.max_ms.cmp(&a.max_ms)),
        "db" => result.sort_by(|a, b| b.avg_db_ms.cmp(&a.avg_db_ms)),
        "errors" => result.sort_by(|a, b| b.error_count.cmp(&a.error_count)),
        _ => {} // default: already sorted by request_count
    }

    Ok(result)
}

pub fn routes_count(
    pool: &DbPool,
    project_id: Option<i64>,
    since: &str,
    search: Option<&str>,
) -> anyhow::Result<i64> {
    let conn = pool.get()?;
    let count: i64 = conn.query_row(
        r#"
        SELECT COUNT(DISTINCT COALESCE(name, http_url, 'unknown') || COALESCE(http_method, 'GET'))
        FROM spans
        WHERE parent_span_id IS NULL
          AND root_span_type = 'web'
          AND (?1 IS NULL OR project_id = ?1)
          AND happened_at >= ?2
          AND (?3 IS NULL OR name LIKE '%' || ?3 || '%' OR http_url LIKE '%' || ?3 || '%')
        "#,
        rusqlite::params![project_id, since, search],
        |row| row.get(0),
    )?;
    Ok(count)
}

fn calculate_route_percentiles(
    conn: &r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>,
    project_id: Option<i64>,
    path: &str,
    since: &str,
) -> anyhow::Result<(i64, i64)> {
    let mut stmt = conn.prepare(
        r#"
        SELECT duration_ms
        FROM spans
        WHERE parent_span_id IS NULL
          AND COALESCE(name, http_url, 'unknown') = ?1
          AND (?2 IS NULL OR project_id = ?2)
          AND happened_at >= ?3
        ORDER BY duration_ms ASC
        "#,
    )?;

    let values: Vec<f64> = stmt
        .query_map(rusqlite::params![path, project_id, since], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;

    if values.is_empty() {
        return Ok((0, 0));
    }

    let p95_idx = ((0.95 * (values.len() as f64 - 1.0)).round() as usize).min(values.len() - 1);
    let p99_idx = ((0.99 * (values.len() as f64 - 1.0)).round() as usize).min(values.len() - 1);

    Ok((
        values[p95_idx].round() as i64,
        values[p99_idx].round() as i64,
    ))
}

fn calculate_route_db_stats(
    conn: &r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>,
    project_id: Option<i64>,
    path: &str,
    since: &str,
) -> anyhow::Result<(i64, i64)> {
    // Get all trace_ids for this route
    let mut stmt = conn.prepare(
        r#"
        SELECT trace_id
        FROM spans
        WHERE parent_span_id IS NULL
          AND COALESCE(name, http_url, 'unknown') = ?1
          AND (?2 IS NULL OR project_id = ?2)
          AND happened_at >= ?3
        "#,
    )?;

    let trace_ids: Vec<String> = stmt
        .query_map(rusqlite::params![path, project_id, since], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;

    if trace_ids.is_empty() {
        return Ok((0, 0));
    }

    // Calculate average DB time and count across these traces
    let placeholders = trace_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!(
        r#"
        SELECT
            COALESCE(AVG(db_total_ms), 0) as avg_db_ms,
            COALESCE(AVG(db_count), 0) as avg_db_count
        FROM (
            SELECT
                trace_id,
                SUM(duration_ms) as db_total_ms,
                COUNT(*) as db_count
            FROM spans
            WHERE trace_id IN ({})
              AND span_category = 'db'
            GROUP BY trace_id
        )
        "#,
        placeholders
    );

    let mut stmt = conn.prepare(&sql)?;
    let result: (f64, f64) = stmt
        .query_row(rusqlite::params_from_iter(trace_ids.iter()), |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;

    Ok((result.0.round() as i64, result.1.round() as i64))
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
                result.push('?');
                in_string = false;
            } else if c == string_char && chars.peek() == Some(&string_char) {
                // Escaped quote
                chars.next();
            }
        } else if c == '\'' || c == '"' {
            in_string = true;
            string_char = c;
        } else if c.is_ascii_digit()
            && (result.ends_with(' ')
                || result.ends_with('=')
                || result.ends_with('(')
                || result.ends_with(',')
                || result.is_empty())
        {
            // Skip numbers that appear to be values
            while chars
                .peek()
                .map(|ch| ch.is_ascii_digit() || *ch == '.')
                .unwrap_or(false)
            {
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
        if span.category == SpanCategory::Db
            && let Some(ref statement) = span.db_statement
        {
            let pattern = normalize_sql(statement);
            let entry = pattern_counts
                .entry(pattern)
                .or_insert((0, 0.0, Vec::new()));
            entry.0 += 1;
            entry.1 += span.duration_ms;
            entry.2.push(span.span_id.clone());
        }
    }

    let mut issues: Vec<NPlus1Issue> = pattern_counts
        .into_iter()
        .filter(|(_, (count, _, _))| *count >= N_PLUS_1_THRESHOLD)
        .map(
            |(pattern, (count, total_duration_ms, span_ids))| NPlus1Issue {
                pattern,
                count,
                total_duration_ms,
                span_ids,
            },
        )
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
        assert_eq!(
            normalize_sql(sql),
            "SELECT * FROM orders WHERE user_id = ? AND status = ?"
        );
    }

    #[test]
    fn test_normalize_sql_in_clause() {
        let sql = "SELECT * FROM users WHERE id IN (1, 2, 3)";
        assert_eq!(
            normalize_sql(sql),
            "SELECT * FROM users WHERE id IN (?, ?, ?)"
        );
    }

    // SpanCategory tests
    #[test]
    fn test_span_category_db() {
        let mut attrs = HashMap::new();
        attrs.insert("db.system".to_string(), "postgresql".to_string());
        assert_eq!(
            SpanCategory::from_attributes("SELECT users", 0, &attrs),
            SpanCategory::Db
        );
    }

    #[test]
    fn test_span_category_elasticsearch() {
        let mut attrs = HashMap::new();
        attrs.insert("db.system".to_string(), "elasticsearch".to_string());
        assert_eq!(
            SpanCategory::from_attributes("search", 0, &attrs),
            SpanCategory::Search
        );
    }

    #[test]
    fn test_span_category_http_server() {
        let mut attrs = HashMap::new();
        attrs.insert("http.method".to_string(), "GET".to_string());
        assert_eq!(
            SpanCategory::from_attributes("GET /users", 2, &attrs),
            SpanCategory::HttpServer
        );
    }

    #[test]
    fn test_span_category_http_client() {
        let mut attrs = HashMap::new();
        attrs.insert(
            "http.url".to_string(),
            "https://api.example.com".to_string(),
        );
        assert_eq!(
            SpanCategory::from_attributes("HTTP GET", 3, &attrs),
            SpanCategory::HttpClient
        );
    }

    #[test]
    fn test_span_category_job() {
        let mut attrs = HashMap::new();
        attrs.insert("messaging.system".to_string(), "sidekiq".to_string());
        assert_eq!(
            SpanCategory::from_attributes("MyJob.perform", 0, &attrs),
            SpanCategory::Job
        );
    }

    #[test]
    fn test_span_category_command_rake() {
        let attrs = HashMap::new();
        assert_eq!(
            SpanCategory::from_attributes("rake db:migrate", 0, &attrs),
            SpanCategory::Command
        );
        assert_eq!(
            SpanCategory::from_attributes("rake:db:migrate", 0, &attrs),
            SpanCategory::Command
        );
    }

    #[test]
    fn test_span_category_command_thor() {
        let attrs = HashMap::new();
        assert_eq!(
            SpanCategory::from_attributes("thor:generate:model", 0, &attrs),
            SpanCategory::Command
        );
    }

    #[test]
    fn test_span_category_view() {
        let attrs = HashMap::new();
        assert_eq!(
            SpanCategory::from_attributes("render_template users/index.html.erb", 0, &attrs),
            SpanCategory::View
        );
        assert_eq!(
            SpanCategory::from_attributes("render_partial _header.html.erb", 0, &attrs),
            SpanCategory::View
        );
    }

    #[test]
    fn test_span_category_roundtrip() {
        for category in [
            SpanCategory::HttpServer,
            SpanCategory::HttpClient,
            SpanCategory::Db,
            SpanCategory::View,
            SpanCategory::Search,
            SpanCategory::Job,
            SpanCategory::Command,
            SpanCategory::Internal,
        ] {
            assert_eq!(SpanCategory::parse(category.as_str()), category);
        }
    }

    // RootSpanType tests
    #[test]
    fn test_root_span_type_from_category() {
        assert_eq!(
            RootSpanType::from_category(SpanCategory::HttpServer),
            Some(RootSpanType::Web)
        );
        assert_eq!(
            RootSpanType::from_category(SpanCategory::Job),
            Some(RootSpanType::Job)
        );
        assert_eq!(
            RootSpanType::from_category(SpanCategory::Command),
            Some(RootSpanType::Command)
        );
        assert_eq!(RootSpanType::from_category(SpanCategory::Db), None);
        assert_eq!(RootSpanType::from_category(SpanCategory::Internal), None);
    }

    #[test]
    fn test_root_span_type_roundtrip() {
        for root_type in [RootSpanType::Web, RootSpanType::Job, RootSpanType::Command] {
            assert_eq!(RootSpanType::parse(root_type.as_str()), Some(root_type));
        }
        assert_eq!(RootSpanType::parse("invalid"), None);
    }

    // TraceSummary display tests
    fn make_trace_summary(
        root_span_name: &str,
        http_method: Option<&str>,
        http_url: Option<&str>,
        http_status_code: Option<i32>,
        status_code: i32,
    ) -> TraceSummary {
        TraceSummary {
            trace_id: "abc123".to_string(),
            root_span_name: root_span_name.to_string(),
            root_span_type: Some(RootSpanType::Web),
            duration_ms: 100.0,
            span_count: 5,
            status_code,
            service_name: None,
            http_method: http_method.map(|s| s.to_string()),
            http_url: http_url.map(|s| s.to_string()),
            http_status_code,
            happened_at: "2024-01-01 12:00".to_string(),
        }
    }

    #[test]
    fn test_display_name_with_full_url() {
        let trace = make_trace_summary(
            "GET /users",
            Some("GET"),
            Some("https://example.com/users"),
            Some(200),
            1,
        );
        assert_eq!(trace.display_name(), "GET /users");
    }

    #[test]
    fn test_display_name_with_path_only() {
        let trace = make_trace_summary("GET /orders", Some("GET"), Some("/orders"), Some(200), 1);
        assert_eq!(trace.display_name(), "GET /orders");
    }

    #[test]
    fn test_display_name_extracts_from_span_name() {
        let trace = make_trace_summary("POST /api/items", Some("POST"), None, Some(201), 1);
        assert_eq!(trace.display_name(), "POST /api/items");
    }

    #[test]
    fn test_display_name_job_without_http() {
        let trace = TraceSummary {
            trace_id: "abc123".to_string(),
            root_span_name: "OrderMailer.confirmation_email".to_string(),
            root_span_type: Some(RootSpanType::Job),
            duration_ms: 100.0,
            span_count: 5,
            status_code: 1,
            service_name: None,
            http_method: None,
            http_url: None,
            http_status_code: None,
            happened_at: "2024-01-01 12:00".to_string(),
        };
        assert_eq!(trace.display_name(), "OrderMailer.confirmation_email");
    }

    #[test]
    fn test_status_class_success() {
        let trace = make_trace_summary("GET /", Some("GET"), None, Some(200), 1);
        assert_eq!(trace.status_class(), "status-ok");
    }

    #[test]
    fn test_status_class_client_error() {
        let trace = make_trace_summary("GET /", Some("GET"), None, Some(404), 1);
        assert_eq!(trace.status_class(), "status-warning");
    }

    #[test]
    fn test_status_class_server_error() {
        let trace = make_trace_summary("GET /", Some("GET"), None, Some(500), 2);
        assert_eq!(trace.status_class(), "status-error");
    }

    #[test]
    fn test_status_class_otlp_error() {
        let trace = make_trace_summary("process", None, None, None, 2);
        assert_eq!(trace.status_class(), "status-error");
    }

    #[test]
    fn test_status_class_ok_without_http() {
        let trace = make_trace_summary("process", None, None, None, 1);
        assert_eq!(trace.status_class(), "status-ok");
    }

    #[test]
    fn test_status_label_http_code() {
        let trace = make_trace_summary("GET /", Some("GET"), None, Some(201), 1);
        assert_eq!(trace.status_label(), "201");
    }

    #[test]
    fn test_status_label_error() {
        let trace = make_trace_summary("process", None, None, None, 2);
        assert_eq!(trace.status_label(), "Error");
    }

    #[test]
    fn test_status_label_ok() {
        let trace = make_trace_summary("process", None, None, None, 1);
        assert_eq!(trace.status_label(), "OK");
    }
}
