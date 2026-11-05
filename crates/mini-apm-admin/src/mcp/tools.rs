#![expect(
    clippy::doc_markdown,
    reason = "doc comments here are the MCP descriptions models read, not rustdoc"
)]

use mcp_host::prelude::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use mini_apm::models::error::{self, AppError, ErrorOccurrence, ErrorStatusEvent};
use mini_apm::models::span::{
    self, NPlus1Issue, RootSpanType, RouteSummary, SpanDisplay, TraceSummary,
};
use mini_apm::models::{Deploy, deploy, project};
use mini_apm::time::Stamp;

use super::MiniApm;
use crate::web::period_start;

const MAX_LIMIT: u32 = 100;

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
enum Period {
    #[serde(rename = "1h")]
    Hour,
    #[serde(rename = "24h")]
    Day,
    #[serde(rename = "7d")]
    Week,
    #[serde(rename = "30d")]
    Month,
}

impl Period {
    fn start(self) -> Option<Stamp> {
        period_start(match self {
            Self::Hour => "1h",
            Self::Day => "24h",
            Self::Week => "7d",
            Self::Month => "30d",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum Action {
    Resolve,
    Ignore,
    Reopen,
}

impl Action {
    const ALL: [Self; 3] = [Self::Resolve, Self::Ignore, Self::Reopen];

    const fn name(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::Ignore => "ignore",
            Self::Reopen => "reopen",
        }
    }

    const fn event(self) -> ErrorStatusEvent {
        match self {
            Self::Resolve => ErrorStatusEvent::Resolve,
            Self::Ignore => ErrorStatusEvent::Ignore,
            Self::Reopen => ErrorStatusEvent::Reopen,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Web,
    Job,
    Command,
}

impl Kind {
    const fn root_type(self) -> RootSpanType {
        match self {
            Self::Web => RootSpanType::Web,
            Self::Job => RootSpanType::Job,
            Self::Command => RootSpanType::Command,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum ErrorSort {
    #[default]
    LastSeen,
    FirstSeen,
    Count,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum TraceSort {
    #[default]
    Recent,
    Duration,
    Spans,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum RouteSort {
    #[default]
    Requests,
    Avg,
    P95,
    P99,
    Max,
    Db,
    Errors,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum Status {
    Open,
    Resolved,
    Ignored,
}

const fn default_limit() -> u32 {
    20
}

const fn default_occurrences() -> u32 {
    3
}

const fn default_max_spans() -> u32 {
    200
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ProjectParams {
    /// Project slug from list_projects; every project when omitted
    project: Option<String>,
    /// How many to return, 1 to 100
    #[serde(default = "default_limit")]
    limit: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ListErrorsParams {
    /// Project slug from list_projects; every project when omitted
    project: Option<String>,
    /// Only errors in this status
    status: Option<Status>,
    /// Case-insensitive match on the exception class or message
    search: Option<String>,
    /// Only errors seen within this window
    period: Option<Period>,
    #[serde(default)]
    sort: ErrorSort,
    /// How many to return, 1 to 100
    #[serde(default = "default_limit")]
    limit: u32,
    /// How many to skip, for paging
    #[serde(default)]
    offset: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ErrorDetailsParams {
    /// Error id from list_errors
    id: i64,
    /// Latest occurrences to include, 0 to 100
    #[serde(default = "default_occurrences")]
    occurrences: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SetErrorStatusParams {
    /// Error id from list_errors
    id: i64,
    /// Status change; error_details lists the ones the error allows
    action: Action,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ListTracesParams {
    /// Project slug from list_projects; every project when omitted
    project: Option<String>,
    /// Only traces rooted in a web request, a background job or a command
    kind: Option<Kind>,
    /// Only traces started within this window
    period: Option<Period>,
    /// Case-insensitive match on the root span name or URL
    search: Option<String>,
    /// Only traces at least this slow
    min_duration_ms: Option<f64>,
    #[serde(default)]
    sort: TraceSort,
    /// How many to return, 1 to 100
    #[serde(default = "default_limit")]
    limit: u32,
    /// How many to skip, for paging
    #[serde(default)]
    offset: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct TraceDetailParams {
    /// Trace id from list_traces
    trace_id: String,
    /// Spans to include in timeline order, 1 to 1000
    #[serde(default = "default_max_spans")]
    max_spans: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SlowRoutesParams {
    /// Project slug from list_projects; every project when omitted
    project: Option<String>,
    /// Window to aggregate over; 24h when omitted
    period: Option<Period>,
    /// Case-insensitive match on the route or URL
    search: Option<String>,
    #[serde(default)]
    sort: RouteSort,
    /// How many to return, 1 to 100
    #[serde(default = "default_limit")]
    limit: u32,
}

#[derive(Serialize)]
struct ProjectSummary {
    name: String,
    slug: String,
    created_at: Stamp,
}

#[derive(Serialize)]
struct ErrorReport {
    error: AppError,
    allowed_actions: Vec<Action>,
    occurrences: Vec<ErrorOccurrence>,
}

#[derive(Serialize)]
struct TraceReport {
    trace_id: String,
    total_duration_ms: f64,
    span_count: usize,
    truncated: bool,
    spans: Vec<SpanDisplay>,
    n_plus_1: Vec<NPlus1Issue>,
}

fn internal(e: &anyhow::Error) -> ToolError {
    tracing::error!("MCP tool failed: {e:#}");
    ToolError::Internal("MiniAPM could not read its database".into())
}

fn within(name: &str, value: u32, range: std::ops::RangeInclusive<u32>) -> Result<u32, ToolError> {
    if range.contains(&value) {
        Ok(value)
    } else {
        Err(ToolError::InvalidArguments(format!(
            "{name} must be between {} and {}",
            range.start(),
            range.end()
        )))
    }
}

fn limit(value: u32) -> Result<i64, ToolError> {
    within("limit", value, 1..=MAX_LIMIT).map(i64::from)
}

fn unreadable(e: ToolError) -> ResourceError {
    match e {
        ToolError::InvalidArguments(message) => ResourceError::NotFound(message),
        other => ResourceError::Internal(other.to_string()),
    }
}

fn json(value: &impl Serialize) -> Result<String, ResourceError> {
    serde_json::to_string_pretty(value).map_err(|e| ResourceError::Internal(e.to_string()))
}

impl MiniApm {
    async fn project_id(&self, slug: Option<&str>) -> Result<Option<i64>, ToolError> {
        let Some(slug) = slug else {
            return Ok(None);
        };
        match project::find_by_slug(&self.pool, slug).await {
            Ok(Some(project)) => Ok(Some(project.id)),
            Ok(None) => Err(ToolError::InvalidArguments(format!(
                "No project '{slug}'; list_projects shows the slugs"
            ))),
            Err(e) => Err(internal(&e)),
        }
    }

    async fn find_error(&self, id: i64) -> Result<AppError, ToolError> {
        error::find(&self.pool, id)
            .await
            .map_err(|e| internal(&e))?
            .ok_or_else(|| ToolError::InvalidArguments(format!("No error {id}")))
    }

    async fn error_report(&self, id: i64, occurrences: u32) -> Result<ErrorReport, ToolError> {
        let occurrences = i64::from(within("occurrences", occurrences, 0..=100)?);
        let error = self.find_error(id).await?;
        let occurrences = error::occurrences(&self.pool, id, occurrences)
            .await
            .map_err(|e| internal(&e))?;
        Ok(ErrorReport {
            allowed_actions: Action::ALL
                .into_iter()
                .filter(|action| error.allows(action.event()))
                .collect(),
            error,
            occurrences,
        })
    }

    async fn trace_report(&self, trace_id: &str, max_spans: u32) -> Result<TraceReport, ToolError> {
        let max_spans = within("max_spans", max_spans, 1..=1000)? as usize;
        let detail = span::get_trace(&self.pool, trace_id)
            .await
            .map_err(|e| internal(&e))?
            .ok_or_else(|| ToolError::InvalidArguments(format!("No trace {trace_id}")))?;
        let n_plus_1 = span::detect_n_plus_1(&detail.spans);
        let span_count = detail.spans.len();
        let mut spans = detail.spans;
        spans.truncate(max_spans);
        Ok(TraceReport {
            trace_id: detail.trace_id,
            total_duration_ms: detail.total_duration_ms,
            span_count,
            truncated: span_count > spans.len(),
            spans,
            n_plus_1,
        })
    }
}

#[mcp_router]
impl MiniApm {
    /// Projects MiniAPM records, by slug. Every list tool takes one to narrow its results.
    #[mcp_tool(name = "list_projects", read_only = true, idempotent = true)]
    async fn list_projects(&self, _ctx: Ctx<'_>, _params: Parameters<()>) -> ToolResult {
        #[derive(Serialize)]
        struct Projects {
            projects: Vec<ProjectSummary>,
        }
        let projects = project::list_all(&self.pool)
            .await
            .map_err(|e| internal(&e))?;
        structured(Projects {
            projects: projects
                .into_iter()
                .map(|p| ProjectSummary {
                    name: p.name,
                    slug: p.slug,
                    created_at: p.created_at,
                })
                .collect(),
        })
    }

    /// Error groups, most recently seen first unless sorted otherwise, with the total matching count.
    #[mcp_tool(name = "list_errors", read_only = true, idempotent = true)]
    async fn list_errors(&self, _ctx: Ctx<'_>, params: Parameters<ListErrorsParams>) -> ToolResult {
        #[derive(Serialize)]
        struct Errors {
            errors: Vec<AppError>,
            total: i64,
        }
        let p = params.0;
        let limit = limit(p.limit)?;
        let project_id = self.project_id(p.project.as_deref()).await?;
        let status = p.status.map(|s| match s {
            Status::Open => "open",
            Status::Resolved => "resolved",
            Status::Ignored => "ignored",
        });
        let sort = match p.sort {
            ErrorSort::LastSeen => "last_seen",
            ErrorSort::FirstSeen => "first_seen",
            ErrorSort::Count => "count",
        };
        let since = p.period.and_then(Period::start);
        let search = p.search.as_deref();
        let errors = error::list_paginated(
            &self.pool,
            project_id,
            status,
            search,
            since,
            sort,
            limit,
            i64::from(p.offset),
        )
        .await
        .map_err(|e| internal(&e))?;
        let total = error::count_filtered(&self.pool, project_id, status, search, since)
            .await
            .map_err(|e| internal(&e))?;
        structured(Errors { errors, total })
    }

    /// One error group with its latest occurrences (backtrace, params, source context)
    /// and the status changes it allows.
    #[mcp_tool(name = "error_details", read_only = true, idempotent = true)]
    async fn error_details(
        &self,
        _ctx: Ctx<'_>,
        params: Parameters<ErrorDetailsParams>,
    ) -> ToolResult {
        structured(self.error_report(params.0.id, params.0.occurrences).await?)
    }

    /// Resolve, ignore or reopen an error group. A resolved error reopens by itself when it happens again.
    #[mcp_tool(name = "set_error_status")]
    async fn set_error_status(
        &self,
        ctx: Ctx<'_>,
        params: Parameters<SetErrorStatusParams>,
    ) -> ToolResult {
        #[derive(Serialize)]
        struct Changed {
            id: i64,
            status: &'static str,
        }
        let SetErrorStatusParams { id, action } = params.0;
        let error = self.find_error(id).await?;
        let refused = || {
            ToolError::InvalidArguments(format!(
                "Error {id} is {}; it cannot {}",
                error.status,
                action.name()
            ))
        };
        let status = error::apply(&self.pool, id, action.event())
            .await
            .map_err(|e| internal(&e))?
            .ok_or_else(refused)?;
        tracing::info!(
            "{} moved error {id} to {status} over MCP",
            ctx.get_state::<String>("username").unwrap_or_default()
        );
        structured(Changed { id, status })
    }

    /// Traces by their root span, newest first unless sorted otherwise, with the total matching count.
    #[mcp_tool(name = "list_traces", read_only = true, idempotent = true)]
    async fn list_traces(&self, _ctx: Ctx<'_>, params: Parameters<ListTracesParams>) -> ToolResult {
        #[derive(Serialize)]
        struct Traces {
            traces: Vec<TraceSummary>,
            total: i64,
        }
        let p = params.0;
        let limit = limit(p.limit)?;
        let project_id = self.project_id(p.project.as_deref()).await?;
        let sort = match p.sort {
            TraceSort::Recent => "recent",
            TraceSort::Duration => "duration",
            TraceSort::Spans => "spans",
        };
        let kind = p.kind.map(Kind::root_type);
        let since = p.period.and_then(Period::start);
        let search = p.search.as_deref();
        let traces = span::list_traces_paginated(
            &self.pool,
            project_id,
            kind,
            since,
            search,
            p.min_duration_ms,
            sort,
            limit,
            i64::from(p.offset),
        )
        .await
        .map_err(|e| internal(&e))?;
        let total = span::count_traces_filtered(
            &self.pool,
            project_id,
            kind,
            since,
            search,
            p.min_duration_ms,
        )
        .await
        .map_err(|e| internal(&e))?;
        structured(Traces { traces, total })
    }

    /// One trace's spans in timeline order with their SQL, plus the N+1 query patterns found in it.
    #[mcp_tool(name = "trace_detail", read_only = true, idempotent = true)]
    async fn trace_detail(
        &self,
        _ctx: Ctx<'_>,
        params: Parameters<TraceDetailParams>,
    ) -> ToolResult {
        structured(
            self.trace_report(&params.0.trace_id, params.0.max_spans)
                .await?,
        )
    }

    /// Web routes with request count, latency percentiles, database time and error rate.
    /// Long-lived idle GET streams are included in request_count and stream_count,
    /// but excluded from latency statistics.
    #[mcp_tool(name = "slow_routes", read_only = true, idempotent = true)]
    async fn slow_routes(&self, _ctx: Ctx<'_>, params: Parameters<SlowRoutesParams>) -> ToolResult {
        #[derive(Serialize)]
        struct Routes {
            routes: Vec<RouteSummary>,
        }
        let p = params.0;
        let limit = limit(p.limit)?;
        let project_id = self.project_id(p.project.as_deref()).await?;
        let since = p
            .period
            .unwrap_or(Period::Day)
            .start()
            .unwrap_or_else(Stamp::now);
        let sort = match p.sort {
            RouteSort::Requests => "requests",
            RouteSort::Avg => "avg",
            RouteSort::P95 => "p95",
            RouteSort::P99 => "p99",
            RouteSort::Max => "max",
            RouteSort::Db => "db",
            RouteSort::Errors => "errors",
        };
        let routes = span::routes_summary(
            &self.pool,
            project_id,
            since,
            p.search.as_deref(),
            sort,
            limit,
        )
        .await
        .map_err(|e| internal(&e))?;
        structured(Routes { routes })
    }

    /// Deploys, newest first, to line up regressions with releases.
    #[mcp_tool(name = "list_deploys", read_only = true, idempotent = true)]
    async fn list_deploys(&self, _ctx: Ctx<'_>, params: Parameters<ProjectParams>) -> ToolResult {
        #[derive(Serialize)]
        struct Deploys {
            deploys: Vec<Deploy>,
        }
        let limit = limit(params.0.limit)?;
        let project_id = self.project_id(params.0.project.as_deref()).await?;
        let deploys = deploy::list(&self.pool, project_id, limit)
            .await
            .map_err(|e| internal(&e))?;
        structured(Deploys { deploys })
    }

    /// An error group with its latest occurrences, as error_details returns it
    #[mcp_resource_template(
        uri_template = "miniapm://errors/{id}",
        name = "error",
        mime_type = "application/json"
    )]
    async fn error_resource(&self, ctx: Ctx<'_>) -> ResourceResult {
        let raw = ctx.get_uri_param("id").unwrap_or_default();
        let id = raw
            .parse()
            .map_err(|_| ResourceError::InvalidUri(format!("'{raw}' is not an error id")))?;
        let report = self
            .error_report(id, default_occurrences())
            .await
            .map_err(unreadable)?;
        let uri = format!("miniapm://errors/{id}");
        Ok(vec![text_resource_with_mime(
            uri,
            json(&report)?,
            "application/json",
        )])
    }

    /// A trace's spans and N+1 patterns, as trace_detail returns them
    #[mcp_resource_template(
        uri_template = "miniapm://traces/{trace_id}",
        name = "trace",
        mime_type = "application/json"
    )]
    async fn trace_resource(&self, ctx: Ctx<'_>) -> ResourceResult {
        let trace_id = ctx.get_uri_param("trace_id").unwrap_or_default();
        let report = self
            .trace_report(trace_id, default_max_spans())
            .await
            .map_err(unreadable)?;
        let uri = format!("miniapm://traces/{trace_id}");
        Ok(vec![text_resource_with_mime(
            uri,
            json(&report)?,
            "application/json",
        )])
    }
}
