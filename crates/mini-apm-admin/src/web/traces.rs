use askama::Template;
use rama::http::service::web::extract::{Path, Query, State};
use serde::Deserialize;

use crate::template::HtmlTemplate;
use mini_apm::{DbPool, models};

use super::project_context::WebProjectContext;

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
    ctx: WebProjectContext,
    Query(query): Query<TracesQuery>,
) -> HtmlTemplate<TracesIndexTemplate> {
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

    let since = super::period_start(&period);

    let since_str = since.map(mini_apm::time::rfc3339);
    let min_duration_ms: Option<f64> = min_duration.as_ref().and_then(|s| s.parse().ok());

    let total_count = models::span::count_traces_filtered(
        &pool,
        project_id,
        root_type_filter,
        since_str.as_deref(),
        search.as_deref(),
        min_duration_ms,
    )
    .await
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
    .await
    .unwrap_or_default();

    HtmlTemplate(TracesIndexTemplate {
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
    })
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
    ctx: WebProjectContext,
    Path(trace_id): Path<String>,
) -> HtmlTemplate<TraceShowTemplate> {
    let trace = models::span::get_trace(&pool, &trace_id)
        .await
        .unwrap_or(None);

    // Detect N+1 issues
    let n_plus_1_issues = if let Some(ref t) = trace {
        models::span::detect_n_plus_1(&t.spans)
    } else {
        vec![]
    };

    HtmlTemplate(TraceShowTemplate {
        trace,
        n_plus_1_issues,
        ctx,
    })
}
