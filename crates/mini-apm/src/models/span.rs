use crate::DbPool;
use crate::time;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use jiff::Timestamp;
use serde::{Deserialize, Deserializer, Serialize};
use sqlx::Row;
use std::collections::HashMap;

mod proto;

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
    #[serde(deserialize_with = "int64")]
    pub start_time_unix_nano: i64,
    #[serde(deserialize_with = "int64")]
    pub end_time_unix_nano: i64,
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
    #[serde(default, deserialize_with = "int64_string")]
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
    #[serde(default, deserialize_with = "int64_string")]
    pub time_unix_nano: Option<String>,
    pub attributes: Option<Vec<KeyValue>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Int64 {
    Number(i64),
    String(String),
}

impl Int64 {
    fn into_i64<E: serde::de::Error>(self) -> Result<i64, E> {
        match self {
            Int64::Number(n) => Ok(n),
            Int64::String(s) => s.parse().map_err(E::custom),
        }
    }
}

fn int64<'de, D: Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
    Int64::deserialize(d)?.into_i64()
}

fn int64_string<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::<Int64>::deserialize(d)?
        .map(|v| v.into_i64().map(|n| n.to_string()))
        .transpose()
}

#[derive(Debug, Deserialize)]
pub struct SpanStatus {
    pub code: Option<i32>,
    pub message: Option<String>,
}

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

/// Map a row with the canonical trace summary column order:
/// trace_id, root_span_name, root_span_type, duration_ms, span_count,
/// status_code, service_name, http_method, http_url, http_status_code, happened_at
fn map_trace_summary_row(row: &sqlx::sqlite::SqliteRow) -> Result<TraceSummary, sqlx::Error> {
    Ok(TraceSummary {
        trace_id: row.try_get(0)?,
        root_span_name: row.try_get(1)?,
        root_span_type: row
            .try_get::<Option<String>, _>(2)?
            .and_then(|s| RootSpanType::parse(&s)),
        duration_ms: row.try_get(3)?,
        span_count: row.try_get(4)?,
        status_code: row.try_get(5)?,
        service_name: row.try_get(6)?,
        http_method: row.try_get(7)?,
        http_url: row.try_get(8)?,
        http_status_code: row.try_get(9)?,
        happened_at: row.try_get(10)?,
    })
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
    if s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        s.to_ascii_lowercase()
    } else if let Ok(bytes) = STANDARD.decode(s) {
        hex::encode(bytes)
    } else {
        s.to_string()
    }
}

use crate::models::error as app_error;
use sha2::{Digest, Sha256};

/// Backfill errors from existing spans that have exception events
/// This is useful for extracting errors from spans that were ingested before error extraction was added
pub async fn backfill_errors_from_spans(pool: &DbPool) -> anyhow::Result<usize> {
    let rows: Vec<(Option<i64>, String, String, String)> = sqlx::query_as(
        r#"
        SELECT project_id, trace_id, events_json, happened_at
        FROM spans
        WHERE events_json IS NOT NULL
          AND events_json != '[]'
          AND events_json LIKE '%exception%'
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut count = 0;
    for (project_id, trace_id, events_json, happened_at) in rows {
        if let Ok(events) = serde_json::from_str::<Vec<SpanEvent>>(&events_json) {
            let events_opt = Some(events);
            extract_and_insert_errors(pool, &events_opt, &trace_id, &happened_at, project_id).await;
            count += 1;
        }
    }

    Ok(count)
}

/// Extract exception events from OTLP span and insert as errors
async fn extract_and_insert_errors(
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
            timestamp: happened_at.parse().ok(),
            source_context: None,
        };

        if let Err(e) = app_error::insert(pool, &incoming_error, project_id).await {
            tracing::warn!("Failed to insert error from span event: {}", e);
        }
    }
}

pub async fn insert_otlp_batch(
    pool: &DbPool,
    request: &OtlpTraceRequest,
    project_id: Option<i64>,
) -> anyhow::Result<usize> {
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

                let start_nano = otlp_span.start_time_unix_nano;
                let end_nano = otlp_span.end_time_unix_nano;
                let duration_ms = (end_nano - start_nano) as f64 / 1_000_000.0;

                let happened_at = Timestamp::from_nanosecond(start_nano.into())?
                    .strftime("%Y-%m-%dT%H:%M:%S%.3fZ")
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

                sqlx::query(
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
                )
                .bind(project_id)
                .bind(&trace_id)
                .bind(&span_id)
                .bind(parent_span_id.as_deref())
                .bind(start_nano)
                .bind(end_nano)
                .bind(duration_ms)
                .bind(&otlp_span.name)
                .bind(kind)
                .bind(status_code)
                .bind(status_message.as_deref())
                .bind(category.as_str())
                .bind(root_span_type.map(|r| r.as_str()))
                .bind(service_name.as_deref())
                .bind(http_method.as_deref())
                .bind(http_url.as_deref())
                .bind(http_status)
                .bind(db_system.as_deref())
                .bind(db_statement.as_deref())
                .bind(db_operation.as_deref())
                .bind(messaging_system.as_deref())
                .bind(messaging_operation.as_deref())
                .bind(request_id.as_deref())
                .bind(&attrs_json)
                .bind(events_json.as_deref())
                .bind(&resource_json)
                .bind(&happened_at)
                .execute(pool)
                .await?;
                count += 1;

                // Extract errors from exception events
                extract_and_insert_errors(
                    pool,
                    &otlp_span.events,
                    &trace_id,
                    &happened_at,
                    project_id,
                )
                .await;
            }
        }
    }

    Ok(count)
}

pub async fn list_traces(
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
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn list_traces_filtered(
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
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn list_traces_paginated(
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
    let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(project_id)
        .bind(root_type_str)
        .bind(since)
        .bind(search)
        .bind(min_duration_ms)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

    let traces = rows
        .iter()
        .map(map_trace_summary_row)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(traces)
}

pub async fn count_traces_filtered(
    pool: &DbPool,
    project_id: Option<i64>,
    root_type_filter: Option<RootSpanType>,
    since: Option<&str>,
    search: Option<&str>,
    min_duration_ms: Option<f64>,
) -> anyhow::Result<i64> {
    let root_type_str = root_type_filter.map(|r| r.as_str());
    let count: i64 = sqlx::query_scalar(
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
    )
    .bind(project_id)
    .bind(root_type_str)
    .bind(since)
    .bind(search)
    .bind(min_duration_ms)
    .fetch_one(pool)
    .await?;

    Ok(count)
}

pub async fn get_trace(pool: &DbPool, trace_id: &str) -> anyhow::Result<Option<TraceDetail>> {
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
    )> = sqlx::query_as(
        r#"
        SELECT id, span_id, parent_span_id, name, span_category,
               duration_ms, start_time_unix_nano, status_code,
               http_method, http_status_code, db_operation, db_system, db_statement
        FROM spans
        WHERE trace_id = ?1
        ORDER BY start_time_unix_nano ASC
        "#,
    )
    .bind(trace_id)
    .fetch_all(pool)
    .await?;

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

pub async fn count_since(
    pool: &DbPool,
    project_id: Option<i64>,
    since: &str,
) -> anyhow::Result<i64> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM spans WHERE parent_span_id IS NULL AND (?1 IS NULL OR project_id = ?1) AND happened_at >= ?2",
    )
    .bind(project_id)
    .bind(since)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// Nearest-rank percentile (0.0-1.0) over `sorted` (ascending), rounded to the
/// nearest ms. `sorted` must be non-empty.
fn percentile_ms(sorted: &[f64], p: f64) -> i64 {
    let idx = ((p * (sorted.len() as f64 - 1.0)).round() as usize).min(sorted.len() - 1);
    sorted[idx].round() as i64
}

#[derive(Debug, Clone, Serialize)]
pub struct LatencyStats {
    pub avg_ms: i64,
    pub p95_ms: i64,
    pub p99_ms: i64,
}

pub async fn latency_stats_since(
    pool: &DbPool,
    project_id: Option<i64>,
    since: &str,
) -> anyhow::Result<LatencyStats> {
    let values: Vec<f64> = sqlx::query_scalar(
        "SELECT duration_ms FROM spans WHERE parent_span_id IS NULL AND happened_at >= ?1 AND (?2 IS NULL OR project_id = ?2) ORDER BY duration_ms ASC",
    )
    .bind(since)
    .bind(project_id)
    .fetch_all(pool)
    .await?;

    if values.is_empty() {
        return Ok(LatencyStats {
            avg_ms: 0,
            p95_ms: 0,
            p99_ms: 0,
        });
    }

    let avg = values.iter().sum::<f64>() / values.len() as f64;

    Ok(LatencyStats {
        avg_ms: avg.round() as i64,
        p95_ms: percentile_ms(&values, 0.95),
        p99_ms: percentile_ms(&values, 0.99),
    })
}

pub async fn slow_traces(
    pool: &DbPool,
    project_id: Option<i64>,
    threshold_ms: f64,
    limit: i64,
) -> anyhow::Result<Vec<TraceSummary>> {
    let rows = sqlx::query(
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
    )
    .bind(threshold_ms)
    .bind(project_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let traces = rows
        .iter()
        .map(map_trace_summary_row)
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
          AND (?1 IS NULL OR project_id = ?1)
          AND happened_at >= datetime('now', '-' || ?2 || ' hours')
        GROUP BY strftime('%Y-%m-%d %H:00', happened_at)
        ORDER BY hour ASC
        "#,
    )
    .bind(project_id)
    .bind(hours)
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
        let hour_key = time::hours_ago(i).strftime("%Y-%m-%d %H:00").to_string();
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

pub async fn routes_summary(
    pool: &DbPool,
    project_id: Option<i64>,
    since: &str,
    search: Option<&str>,
    sort: &str,
    limit: i64,
) -> anyhow::Result<Vec<RouteSummary>> {
    // Get unique routes with basic stats
    let routes: Vec<(String, String, i64, f64, f64, f64, i64)> = sqlx::query_as(
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
    )
    .bind(project_id)
    .bind(since)
    .bind(search)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let paths = serde_json::to_string(&routes.iter().map(|r| &r.0).collect::<Vec<_>>())?;
    let durations = route_durations(pool, project_id, since, &paths).await?;
    let db_stats = route_db_stats(pool, project_id, since, &paths).await?;

    let mut result = Vec::new();
    for (path, method, request_count, avg_ms, max_ms, min_ms, error_count) in routes {
        let (p95, p99) = durations
            .get(&path)
            .map(|d| (percentile_ms(d, 0.95), percentile_ms(d, 0.99)))
            .unwrap_or((0, 0));
        let (avg_db_ms, avg_db_count) = db_stats.get(&path).copied().unwrap_or((0, 0));
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
    use std::cmp::Reverse;
    match sort {
        "avg" => result.sort_by_key(|r| Reverse(r.avg_ms)),
        "p95" => result.sort_by_key(|r| Reverse(r.p95_ms)),
        "p99" => result.sort_by_key(|r| Reverse(r.p99_ms)),
        "max" => result.sort_by_key(|r| Reverse(r.max_ms)),
        "db" => result.sort_by_key(|r| Reverse(r.avg_db_ms)),
        "errors" => result.sort_by_key(|r| Reverse(r.error_count)),
        _ => {} // default: already sorted by request_count
    }

    Ok(result)
}

pub async fn routes_count(
    pool: &DbPool,
    project_id: Option<i64>,
    since: &str,
    search: Option<&str>,
) -> anyhow::Result<i64> {
    let count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(DISTINCT COALESCE(name, http_url, 'unknown') || COALESCE(http_method, 'GET'))
        FROM spans
        WHERE parent_span_id IS NULL
          AND root_span_type = 'web'
          AND (?1 IS NULL OR project_id = ?1)
          AND happened_at >= ?2
          AND (?3 IS NULL OR name LIKE '%' || ?3 || '%' OR http_url LIKE '%' || ?3 || '%')
        "#,
    )
    .bind(project_id)
    .bind(since)
    .bind(search)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

async fn route_durations(
    pool: &DbPool,
    project_id: Option<i64>,
    since: &str,
    paths: &str,
) -> anyhow::Result<HashMap<String, Vec<f64>>> {
    let rows: Vec<(String, f64)> = sqlx::query_as(
        r#"
        SELECT COALESCE(name, http_url, 'unknown') AS path, duration_ms
        FROM spans
        WHERE parent_span_id IS NULL
          AND (?1 IS NULL OR project_id = ?1)
          AND happened_at >= ?2
          AND COALESCE(name, http_url, 'unknown') IN (SELECT value FROM json_each(?3))
        ORDER BY duration_ms ASC
        "#,
    )
    .bind(project_id)
    .bind(since)
    .bind(paths)
    .fetch_all(pool)
    .await?;

    let mut durations: HashMap<String, Vec<f64>> = HashMap::new();
    for (path, duration) in rows {
        durations.entry(path).or_default().push(duration);
    }
    Ok(durations)
}

async fn route_db_stats(
    pool: &DbPool,
    project_id: Option<i64>,
    since: &str,
    paths: &str,
) -> anyhow::Result<HashMap<String, (i64, i64)>> {
    let rows: Vec<(String, f64, f64)> = sqlx::query_as(
        r#"
        WITH roots AS (
            SELECT trace_id, COALESCE(name, http_url, 'unknown') AS path
            FROM spans
            WHERE parent_span_id IS NULL
              AND (?1 IS NULL OR project_id = ?1)
              AND happened_at >= ?2
              AND COALESCE(name, http_url, 'unknown') IN (SELECT value FROM json_each(?3))
        ),
        db AS (
            SELECT s.trace_id, SUM(s.duration_ms) AS db_ms, COUNT(*) AS db_count
            FROM spans s
            JOIN (SELECT DISTINCT trace_id FROM roots) r ON r.trace_id = s.trace_id
            WHERE s.span_category = 'db'
            GROUP BY s.trace_id
        )
        SELECT roots.path, AVG(db.db_ms), AVG(db.db_count)
        FROM roots
        JOIN db ON db.trace_id = roots.trace_id
        GROUP BY roots.path
        "#,
    )
    .bind(project_id)
    .bind(since)
    .bind(paths)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(path, db_ms, db_count)| (path, (db_ms.round() as i64, db_count.round() as i64)))
        .collect())
}

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
    issues.sort_by_key(|i| std::cmp::Reverse(i.count));
    issues
}

/// Check if a trace has N+1 issues (for list view)
pub async fn has_n_plus_1(pool: &DbPool, trace_id: &str) -> bool {
    // Count DB spans grouped by normalized statement pattern
    let result: Result<i64, _> = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM (
            SELECT db_statement, COUNT(*) as cnt
            FROM spans
            WHERE trace_id = ?1 AND span_category = 'db' AND db_statement IS NOT NULL
            GROUP BY db_statement
            HAVING cnt >= ?2
        )
        "#,
    )
    .bind(trace_id)
    .bind(N_PLUS_1_THRESHOLD as i64)
    .fetch_one(pool)
    .await;

    result.unwrap_or(0) > 0
}

#[cfg(test)]
mod tests;
