use crate::DbPool;
use crate::db::{self, DbRow};
use crate::time::Stamp;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use jiff::Timestamp;
use serde::{Deserialize, Deserializer, Serialize};
use sqlx::Row;
use std::borrow::Cow;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

mod proto;

cfg_select! {
    feature = "postgres" => {
        mod postgres;
        use postgres as backend;
    }
    _ => {
        mod sqlite;
        use sqlite as backend;
    }
}

pub use backend::{count_since, hourly_stats, latency_stats_since};

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
            Self::Number(n) => Ok(n),
            Self::String(s) => s.parse().map_err(E::custom),
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
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
    pub fn from_attributes(name: &str, kind: i32, attributes: &Attributes<'_>) -> Self {
        // Check for database spans first
        if attributes.contains_key("db.system") || attributes.contains_key("db.statement") {
            let db_system = attributes.get("db.system").map_or("", |s| s.as_ref());
            if db_system == "elasticsearch" || db_system == "opensearch" {
                return Self::Search;
            }
            return Self::Db;
        }

        // Check for HTTP spans
        let has_http = attributes.contains_key("http.url")
            || attributes.contains_key("http.method")
            || attributes.contains_key("url.full")
            || attributes.contains_key("http.request.method");

        if has_http {
            // kind: 2 = SERVER, 3 = CLIENT
            if kind == 3 {
                return Self::HttpClient;
            }
            if kind == 2 {
                return Self::HttpServer;
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
            return Self::View;
        }

        // Check for messaging/job spans
        // kind: 4 = PRODUCER, 5 = CONSUMER
        if kind == 4 || kind == 5 {
            return Self::Job;
        }
        if attributes.contains_key("messaging.system")
            || attributes.contains_key("messaging.destination.name")
        {
            return Self::Job;
        }

        // Check by name patterns
        let name_lower = name.to_lowercase();
        if name_lower.contains("sidekiq")
            || name_lower.contains("activejob")
            || name_lower.contains("active_job")
            || name_lower.contains("perform")
        {
            return Self::Job;
        }

        // Command runners: rake, thor, make, etc.
        if name_lower.starts_with("rake:")
            || name_lower.starts_with("rake ")
            || name_lower.contains("rake::task")
            || name_lower.starts_with("thor:")
            || name_lower.starts_with("make:")
        {
            return Self::Command;
        }

        Self::Internal
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::HttpServer => "http_server",
            Self::HttpClient => "http_client",
            Self::Db => "db",
            Self::View => "view",
            Self::Search => "search",
            Self::Job => "job",
            Self::Command => "command",
            Self::Internal => "internal",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "http_server" => Self::HttpServer,
            "http_client" => Self::HttpClient,
            "db" => Self::Db,
            "view" => Self::View,
            "search" => Self::Search,
            "job" => Self::Job,
            "command" => Self::Command,
            _ => Self::Internal,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RootSpanType {
    Web,
    Job,
    Command,
}

impl RootSpanType {
    pub const fn from_category(category: SpanCategory) -> Option<Self> {
        match category {
            SpanCategory::HttpServer => Some(Self::Web),
            SpanCategory::Job => Some(Self::Job),
            SpanCategory::Command => Some(Self::Command),
            _ => None,
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Job => "job",
            Self::Command => "command",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "web" => Some(Self::Web),
            "job" => Some(Self::Job),
            "command" => Some(Self::Command),
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
    pub happened_at: Stamp,
}

/// Map a row with the canonical trace summary column order:
/// `trace_id`, `root_span_name`, `root_span_type`, `duration_ms`, `span_count`,
/// `status_code`, `service_name`, `http_method`, `http_url`, `http_status_code`, `happened_at`
fn map_trace_summary_row(row: &DbRow) -> Result<TraceSummary, sqlx::Error> {
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

            format!("{method} {path}")
        } else {
            // For jobs/rake tasks, just use the span name as-is
            self.root_span_name.clone()
        }
    }

    /// Returns a CSS class for the status
    pub const fn status_class(&self) -> &'static str {
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
    pub const fn duration_ms_rounded(&self) -> i64 {
        round_i64(self.duration_ms)
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

/// Attribute values as text, borrowed from the request unless they are numbers
pub type Attributes<'a> = HashMap<&'a str, Cow<'a, str>>;

fn parse_attributes(attrs: Option<&[KeyValue]>) -> Attributes<'_> {
    attrs
        .unwrap_or_default()
        .iter()
        .filter_map(|kv| {
            let value = &kv.value;
            let text = if let Some(v) = &value.string_value {
                Cow::Borrowed(v.as_str())
            } else if let Some(v) = &value.int_value {
                Cow::Borrowed(v.as_str())
            } else if let Some(v) = value.double_value {
                Cow::Owned(v.to_string())
            } else {
                Cow::Borrowed(if value.bool_value? { "true" } else { "false" })
            };
            Some((kv.key.as_str(), text))
        })
        .collect()
}

/// A trace or span id as lowercase hex, whether sent as hex or base64
fn decode_id(s: &str) -> Cow<'_, str> {
    if s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        if s.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(s.to_ascii_lowercase())
        } else {
            Cow::Borrowed(s)
        }
    } else if let Ok(bytes) = STANDARD.decode(s) {
        Cow::Owned(hex::encode(bytes))
    } else {
        Cow::Borrowed(s)
    }
}

use crate::models::error as app_error;
use sha2::{Digest, Sha256};

/// Extract exception events from OTLP span and insert as errors
async fn extract_and_insert_errors(
    pool: &DbPool,
    events: &[SpanEvent],
    trace_id: &str,
    happened_at: Stamp,
    project_id: Option<i64>,
) {
    for event in events {
        if event.name != "exception" {
            continue;
        }

        let mut attrs = parse_attributes(event.attributes.as_deref());
        let Some(exception_type) = attrs.remove("exception.type") else {
            continue;
        };
        let message = attrs.remove("exception.message").unwrap_or_default();
        let backtrace: Vec<String> = attrs
            .get("exception.stacktrace")
            .map_or("", |s| s.as_ref())
            .lines()
            .map(str::to_owned)
            .collect();

        // Generate fingerprint from exception type + first backtrace line
        let mut hasher = Sha256::new();
        hasher.update(exception_type.as_bytes());
        hasher.update(b":");
        hasher.update(backtrace.first().map_or("", String::as_str).as_bytes());
        let fingerprint = hex::encode(hasher.finalize());

        let incoming_error = app_error::IncomingError {
            exception_class: exception_type.into_owned(),
            message: message.into_owned(),
            backtrace,
            fingerprint,
            request_id: Some(trace_id.to_string()),
            user_id: None,
            params: None,
            timestamp: Some(happened_at.0),
            source_context: None,
        };

        if let Err(e) = app_error::insert(pool, &incoming_error, project_id).await {
            tracing::warn!("Failed to insert error from span event: {}", e);
        }
    }
}

/// Columns of `spans` written on ingest after `project_id`, in [`SpanRow`]
/// field order
const SPAN_COLUMNS: [&str; 26] = [
    "trace_id",
    "span_id",
    "parent_span_id",
    "start_time_unix_nano",
    "end_time_unix_nano",
    "duration_ms",
    "name",
    "kind",
    "status_code",
    "status_message",
    "span_category",
    "root_span_type",
    "service_name",
    "http_method",
    "http_url",
    "http_status_code",
    "db_system",
    "db_statement",
    "db_operation",
    "messaging_system",
    "messaging_operation",
    "request_id",
    "attributes_json",
    "events_json",
    "resource_attributes_json",
    "happened_at",
];

/// `ON CONFLICT` clause updating a resent span in place, keeping its id
static SPAN_UPSERT: LazyLock<String> = LazyLock::new(|| {
    let set = std::iter::once("project_id")
        .chain(
            SPAN_COLUMNS
                .into_iter()
                .filter(|c| !backend::SPAN_KEY.contains(c)),
        )
        .map(|c| format!("{c} = excluded.{c}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "ON CONFLICT ({}) DO UPDATE SET {set}",
        backend::SPAN_KEY.join(", ")
    )
});

/// One `spans` row, the [`SPAN_COLUMNS`] after `project_id`, borrowing what
/// it can from the request it was read from
struct SpanRow<'a> {
    trace_id: Cow<'a, str>,
    span_id: Cow<'a, str>,
    parent_span_id: Option<Cow<'a, str>>,
    start_time_unix_nano: i64,
    end_time_unix_nano: i64,
    duration_ms: f64,
    name: &'a str,
    kind: i32,
    status_code: i32,
    status_message: Option<&'a str>,
    span_category: &'static str,
    root_span_type: Option<&'static str>,
    service_name: Option<Cow<'a, str>>,
    http_method: Option<Cow<'a, str>>,
    http_url: Option<Cow<'a, str>>,
    http_status_code: Option<i32>,
    db_system: Option<Cow<'a, str>>,
    db_statement: Option<Cow<'a, str>>,
    db_operation: Option<Cow<'a, str>>,
    messaging_system: Option<Cow<'a, str>>,
    messaging_operation: Option<Cow<'a, str>>,
    request_id: Option<Cow<'a, str>>,
    attributes_json: String,
    events_json: Option<String>,
    resource_attributes_json: Arc<str>,
    happened_at: Stamp,
}

pub async fn insert_otlp_batch(
    pool: &DbPool,
    request: &OtlpTraceRequest,
    project_id: Option<i64>,
) -> anyhow::Result<usize> {
    let mut rows = Vec::new();
    let mut events_by_span = Vec::new();

    for resource_span in &request.resource_spans {
        let resource_attrs = parse_attributes(
            resource_span
                .resource
                .as_ref()
                .and_then(|r| r.attributes.as_deref()),
        );
        let service_name = resource_attrs.get("service.name").cloned();
        let resource_json: Arc<str> = serde_json::to_string(&resource_attrs)?.into();

        let Some(scope_spans) = &resource_span.scope_spans else {
            continue;
        };

        for scope_span in scope_spans {
            for otlp_span in &scope_span.spans {
                let mut attrs = parse_attributes(otlp_span.attributes.as_deref());
                let kind = otlp_span.kind.unwrap_or(0);
                let category = SpanCategory::from_attributes(&otlp_span.name, kind, &attrs);

                let is_root = otlp_span.parent_span_id.is_none()
                    || otlp_span
                        .parent_span_id
                        .as_ref()
                        .is_none_or(std::string::String::is_empty);
                let root_span_type = if is_root {
                    RootSpanType::from_category(category)
                } else {
                    None
                };

                let start_nano = otlp_span.start_time_unix_nano;
                let end_nano = otlp_span.end_time_unix_nano;
                let happened_at = Stamp(Timestamp::from_nanosecond(start_nano.into())?);
                let attributes_json = serde_json::to_string(&attrs)?;
                let mut attr = |keys: &[&str]| keys.iter().find_map(|k| attrs.remove(*k));

                let row = SpanRow {
                    trace_id: decode_id(&otlp_span.trace_id),
                    span_id: decode_id(&otlp_span.span_id),
                    parent_span_id: otlp_span
                        .parent_span_id
                        .as_ref()
                        .filter(|s| !s.is_empty())
                        .map(|s| decode_id(s)),
                    start_time_unix_nano: start_nano,
                    end_time_unix_nano: end_nano,
                    duration_ms: (end_nano - start_nano) as f64 / 1_000_000.0,
                    name: &otlp_span.name,
                    kind,
                    status_code: otlp_span.status.as_ref().and_then(|s| s.code).unwrap_or(0),
                    status_message: otlp_span.status.as_ref().and_then(|s| s.message.as_deref()),
                    span_category: category.as_str(),
                    root_span_type: root_span_type.map(|r| r.as_str()),
                    service_name: service_name.clone(),
                    http_method: attr(&["http.method", "http.request.method"]),
                    http_url: attr(&["http.url", "url.full", "http.target"]),
                    http_status_code: attr(&["http.status_code", "http.response.status_code"])
                        .and_then(|s| s.parse().ok()),
                    db_system: attr(&["db.system"]),
                    db_statement: attr(&["db.statement"]),
                    db_operation: attr(&["db.operation"]),
                    messaging_system: attr(&["messaging.system"]),
                    messaging_operation: attr(&[
                        "messaging.operation",
                        "messaging.destination.name",
                    ]),
                    request_id: attr(&["http.request_id", "request_id"]),
                    attributes_json,
                    events_json: otlp_span
                        .events
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()?,
                    resource_attributes_json: Arc::clone(&resource_json),
                    happened_at,
                };

                if let Some(events) = &otlp_span.events {
                    events_by_span.push((events, row.trace_id.clone(), happened_at));
                }
                rows.push(row);
            }
        }
    }
    let count = rows.len();
    backend::insert_spans(pool, project_id, rows).await?;

    for (events, trace_id, happened_at) in events_by_span {
        extract_and_insert_errors(pool, events, &trace_id, happened_at, project_id).await;
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
    since: Option<Stamp>,
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

/// Root spans matching project `$1`, root type `$2`, happened since `$3`,
/// search `$4` and minimum duration `$5`
const TRACE_FILTER: &str = "
    WHERE s.parent_span_id IS NULL
      AND ($1 IS NULL OR s.project_id = $1)
      AND ($2 IS NULL OR s.root_span_type = $2)
      AND ($3 IS NULL OR s.happened_at >= $3)
      AND ($4 IS NULL OR LOWER(s.name) LIKE '%' || LOWER($4) || '%' OR LOWER(s.http_url) LIKE '%' || LOWER($4) || '%')
      AND ($5 IS NULL OR s.duration_ms >= $5)";

#[allow(clippy::too_many_arguments)]
pub async fn list_traces_paginated(
    pool: &DbPool,
    project_id: Option<i64>,
    root_type_filter: Option<RootSpanType>,
    since: Option<Stamp>,
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
        r"
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
            s.happened_at
        FROM spans s
        {TRACE_FILTER}
        ORDER BY {order_clause}
        LIMIT $6 OFFSET $7
        "
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
    since: Option<Stamp>,
    search: Option<&str>,
    min_duration_ms: Option<f64>,
) -> anyhow::Result<i64> {
    let sql = format!("SELECT COUNT(*) FROM spans s {TRACE_FILTER}");
    Ok(sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .bind(project_id)
        .bind(root_type_filter.map(|r| r.as_str()))
        .bind(since)
        .bind(search)
        .bind(min_duration_ms)
        .fetch_one(pool)
        .await?)
}

/// How deep `span_id` sits below its trace's root, memoized in `depths`
fn compute_depth<'a>(
    span_id: &'a str,
    parents: &HashMap<&'a str, Option<&'a str>>,
    depths: &mut HashMap<&'a str, i32>,
) -> i32 {
    if let Some(&cached) = depths.get(span_id) {
        return cached;
    }
    let depth = match parents.get(span_id).copied().flatten() {
        Some(parent_id) => compute_depth(parent_id, parents, depths) + 1,
        None => 0,
    };
    depths.insert(span_id, depth);
    depth
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
        r"
        SELECT id, span_id, parent_span_id, name, span_category,
               duration_ms, start_time_unix_nano, status_code,
               http_method, http_status_code, db_operation, db_system, db_statement
        FROM spans
        WHERE trace_id = $1
        ORDER BY start_time_unix_nano ASC
        ",
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
        .map(|s| s.6 + round_i64(s.5 * 1_000_000.0))
        .max()
        .unwrap_or(0);
    let total_duration_ms = (trace_end - trace_start) as f64 / 1_000_000.0;

    // Build span hierarchy for depth calculation
    let parents: HashMap<&str, Option<&str>> = spans
        .iter()
        .map(|s| (s.1.as_str(), s.2.as_deref()))
        .collect();

    let mut depths = HashMap::new();
    let span_depths: Vec<i32> = spans
        .iter()
        .map(|s| compute_depth(&s.1, &parents, &mut depths))
        .collect();

    let display_spans: Vec<SpanDisplay> = spans
        .into_iter()
        .zip(span_depths)
        .map(|(s, depth)| {
            let offset_ms = (s.6 - trace_start) as f64 / 1_000_000.0;
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
            SpanDisplay {
                id: s.0,
                span_id: s.1,
                parent_span_id: s.2,
                name: s.3,
                category: SpanCategory::parse(&s.4),
                duration_ms: s.5,
                offset_ms,
                offset_percent,
                width_percent,
                depth,
                status_code: s.7,
                http_method: s.8,
                http_status_code: s.9,
                db_operation: s.10,
                db_system: s.11,
                db_statement: s.12,
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

/// A duration rounded to the nearest whole unit
#[expect(
    clippy::cast_possible_truncation,
    reason = "durations are far inside i64"
)]
pub(crate) const fn round_i64(duration: f64) -> i64 {
    duration.round() as i64
}

#[derive(Debug, Clone, Serialize)]
pub struct LatencyStats {
    pub avg_ms: i64,
    pub p95_ms: i64,
    pub p99_ms: i64,
}

pub async fn slow_traces(
    pool: &DbPool,
    project_id: Option<i64>,
    threshold_ms: f64,
    limit: i64,
) -> anyhow::Result<Vec<TraceSummary>> {
    let rows = sqlx::query(
        r"
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
            s.happened_at
        FROM spans s
        WHERE s.parent_span_id IS NULL
          AND s.duration_ms >= $1
          AND ($2 IS NULL OR s.project_id = $2)
        ORDER BY s.duration_ms DESC
        LIMIT $3
        ",
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

/// Web root spans matching project `$1`, happened since `$2` and search `$3`
const ROUTE_FILTER: &str = "
    WHERE parent_span_id IS NULL
      AND root_span_type = 'web'
      AND ($1 IS NULL OR project_id = $1)
      AND happened_at >= $2
      AND ($3 IS NULL OR LOWER(name) LIKE '%' || LOWER($3) || '%' OR LOWER(http_url) LIKE '%' || LOWER($3) || '%')";

pub async fn routes_summary(
    pool: &DbPool,
    project_id: Option<i64>,
    since: Stamp,
    search: Option<&str>,
    sort: &str,
    limit: i64,
) -> anyhow::Result<Vec<RouteSummary>> {
    // Get unique routes with basic stats
    let routes: Vec<(String, String, i64, f64, f64, f64, i64)> =
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
        r"
        SELECT
            name AS path,
            COALESCE(http_method, 'GET') as method,
            COUNT(*) as request_count,
            AVG(duration_ms) as avg_ms,
            MAX(duration_ms) as max_ms,
            MIN(duration_ms) as min_ms,
            SUM(CASE WHEN status_code = 2 OR http_status_code >= 500 THEN 1 ELSE 0 END) as error_count
        FROM spans
        {ROUTE_FILTER}
        GROUP BY name, COALESCE(http_method, 'GET')
        ORDER BY request_count DESC
        LIMIT $4
        "
    )))
    .bind(project_id)
    .bind(since)
    .bind(search)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let paths: Vec<&str> = routes.iter().map(|r| r.0.as_str()).collect();
    let percentiles = backend::route_percentiles(pool, project_id, since, &paths).await?;
    let db_stats = route_db_stats(pool, project_id, since, &paths).await?;

    let mut result = Vec::new();
    for (path, method, request_count, avg_ms, max_ms, min_ms, error_count) in routes {
        let (p95, p99) = percentiles.get(&path).copied().unwrap_or((0, 0));
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
            avg_ms: round_i64(avg_ms),
            p95_ms: p95,
            p99_ms: p99,
            max_ms: round_i64(max_ms),
            min_ms: round_i64(min_ms),
            avg_db_ms,
            avg_db_count,
            error_count,
            error_rate,
        });
    }

    // Sort by requested field
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
    since: Stamp,
    search: Option<&str>,
) -> anyhow::Result<i64> {
    let sql = format!(
        "SELECT COUNT(DISTINCT name || COALESCE(http_method, 'GET'))
         FROM spans {ROUTE_FILTER}"
    );
    Ok(sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .bind(project_id)
        .bind(since)
        .bind(search)
        .fetch_one(pool)
        .await?)
}

async fn route_db_stats(
    pool: &DbPool,
    project_id: Option<i64>,
    since: Stamp,
    paths: &[&str],
) -> anyhow::Result<HashMap<String, (i64, i64)>> {
    let in_paths = db::in_text_list(3);
    let rows: Vec<(String, f64, f64)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        r"
        WITH roots AS (
            SELECT trace_id, name AS path
            FROM spans
            WHERE parent_span_id IS NULL
              AND ($1 IS NULL OR project_id = $1)
              AND happened_at >= $2
              AND name {in_paths}
        ),
        db AS (
            SELECT s.trace_id, SUM(s.duration_ms) AS db_ms, COUNT(*) AS db_count
            FROM spans s
            JOIN (SELECT DISTINCT trace_id FROM roots) r ON r.trace_id = s.trace_id
            WHERE s.span_category = 'db'
            GROUP BY s.trace_id
        )
        SELECT roots.path, AVG(db.db_ms), AVG(CAST(db.db_count AS DOUBLE PRECISION))
        FROM roots
        JOIN db ON db.trace_id = roots.trace_id
        GROUP BY roots.path
        "
    )))
    .bind(project_id)
    .bind(since)
    .bind(db::text_list(paths))
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(path, db_ms, db_count)| (path, (round_i64(db_ms), round_i64(db_count))))
        .collect())
}

const N_PLUS_1_THRESHOLD: u8 = 5;

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
                .is_some_and(|ch| ch.is_ascii_digit() || *ch == '.')
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
        .filter(|(_, (count, _, _))| *count >= usize::from(N_PLUS_1_THRESHOLD))
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
        r"
        SELECT COUNT(*) FROM (
            SELECT db_statement, COUNT(*) as cnt
            FROM spans
            WHERE trace_id = $1 AND span_category = 'db' AND db_statement IS NOT NULL
            GROUP BY db_statement
            HAVING cnt >= $2
        )
        ",
    )
    .bind(trace_id)
    .bind(i64::from(N_PLUS_1_THRESHOLD))
    .fetch_one(pool)
    .await;

    result.unwrap_or(0) > 0
}

#[cfg(test)]
mod tests;
