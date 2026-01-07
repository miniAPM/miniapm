use askama::Template;
use axum::extract::{Path, Query, State};
use chrono::{Duration, Utc};
use serde::Deserialize;
use tower_cookies::Cookies;

use crate::{DbPool, models};

use super::project_context::{WebProjectContext, get_project_context};

const PAGE_SIZE: i64 = 50;

#[derive(Template)]
#[template(path = "traces/index.html")]
pub struct TracesIndexTemplate {
    pub traces: Vec<models::TraceSummary>,
    pub total_count: i64,
    pub type_filter: Option<String>,
    pub search: Option<String>,
    pub period: String,
    pub min_duration: Option<String>,
    pub sort: String,
    pub page: i64,
    pub total_pages: i64,
    pub ctx: WebProjectContext,
}

#[derive(Deserialize)]
pub struct TracesQuery {
    #[serde(rename = "type")]
    pub root_type: Option<String>,
    pub search: Option<String>,
    pub period: Option<String>,
    pub min_duration: Option<String>,
    pub sort: Option<String>,
    pub page: Option<i64>,
}

pub async fn index(
    State(pool): State<DbPool>,
    cookies: Cookies,
    Query(query): Query<TracesQuery>,
) -> TracesIndexTemplate {
    let ctx = get_project_context(&pool, &cookies);
    let project_id = ctx.project_id();

    let root_type_filter = query
        .root_type
        .as_deref()
        .and_then(models::RootSpanType::parse);

    let period = query.period.unwrap_or_else(|| "all".to_string());
    let sort = query.sort.unwrap_or_else(|| "recent".to_string());
    let search = query.search.clone().filter(|s| !s.is_empty());
    let min_duration = query.min_duration.clone().filter(|s| !s.is_empty());
    let page = query.page.unwrap_or(1).max(1);

    let since = match period.as_str() {
        "1h" => Some(Utc::now() - Duration::hours(1)),
        "24h" => Some(Utc::now() - Duration::hours(24)),
        "7d" => Some(Utc::now() - Duration::days(7)),
        "30d" => Some(Utc::now() - Duration::days(30)),
        _ => None, // "all"
    };

    let since_str = since.map(|s| s.to_rfc3339());
    let min_duration_ms: Option<f64> = min_duration.as_ref().and_then(|s| s.parse().ok());

    let total_count = models::span::count_traces_filtered(
        &pool,
        project_id,
        root_type_filter,
        since_str.as_deref(),
        search.as_deref(),
        min_duration_ms,
    )
    .unwrap_or(0);

    let total_pages = (total_count + PAGE_SIZE - 1) / PAGE_SIZE;
    let offset = (page - 1) * PAGE_SIZE;

    let traces = models::span::list_traces_paginated(
        &pool,
        project_id,
        root_type_filter,
        since_str.as_deref(),
        search.as_deref(),
        min_duration_ms,
        &sort,
        PAGE_SIZE,
        offset,
    )
    .unwrap_or_default();

    TracesIndexTemplate {
        traces,
        total_count,
        type_filter: query.root_type,
        search,
        period,
        min_duration,
        sort,
        page,
        total_pages,
        ctx,
    }
}

#[derive(Template)]
#[template(path = "traces/show.html")]
pub struct TraceShowTemplate {
    pub trace: Option<models::TraceDetail>,
    pub n_plus_1_issues: Vec<models::span::NPlus1Issue>,
    pub ctx: WebProjectContext,
}

pub async fn show(
    State(pool): State<DbPool>,
    cookies: Cookies,
    Path(trace_id): Path<String>,
) -> TraceShowTemplate {
    let ctx = get_project_context(&pool, &cookies);
    let trace = models::span::get_trace(&pool, &trace_id).unwrap_or(None);

    // Detect N+1 issues
    let n_plus_1_issues = if let Some(ref t) = trace {
        models::span::detect_n_plus_1(&t.spans)
    } else {
        vec![]
    };

    TraceShowTemplate {
        trace,
        n_plus_1_issues,
        ctx,
    }
}
