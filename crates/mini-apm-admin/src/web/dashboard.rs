use askama::Template;
use mini_apm::time;
use rama::http::service::web::extract::State;

use crate::template::HtmlTemplate;
use mini_apm::{
    DbPool,
    models::{self, deploy::Deploy, span},
};

use super::project_context::WebProjectContext;

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub requests_24h: i64,
    pub errors_24h: i64,
    pub avg_ms: i64,
    pub p95_ms: i64,
    pub p99_ms: i64,
    pub recent_errors: Vec<models::AppError>,
    pub slow_requests: Vec<span::TraceSummary>,
    pub hourly_stats: Vec<span::TimeSeriesPoint>,
    pub deploys: Vec<Deploy>,
    pub ctx: WebProjectContext,
}

pub async fn index(
    State(pool): State<DbPool>,
    ctx: WebProjectContext,
) -> HtmlTemplate<DashboardTemplate> {
    let project_id = ctx.project_id();
    let since = time::rfc3339(time::hours_ago(24));

    let requests_24h = span::count_since(&pool, project_id, &since)
        .await
        .inspect_err(|e| tracing::error!("Failed to load requests 24h: {e:#}"))
        .unwrap_or(0);
    let errors_24h = models::error::count_since(&pool, project_id, &since)
        .await
        .inspect_err(|e| tracing::error!("Failed to load errors 24h: {e:#}"))
        .unwrap_or(0);
    let latency_stats = span::latency_stats_since(&pool, project_id, &since)
        .await
        .inspect_err(|e| tracing::error!("Failed to load latency stats: {e:#}"))
        .unwrap_or(span::LatencyStats {
            avg_ms: 0,
            p95_ms: 0,
            p99_ms: 0,
        });
    let recent_errors = models::error::list(&pool, project_id, Some("open"), 5)
        .await
        .inspect_err(|e| tracing::error!("Failed to load recent errors: {e:#}"))
        .unwrap_or_default();
    let slow_requests = span::slow_traces(&pool, project_id, 500.0, 5)
        .await
        .inspect_err(|e| tracing::error!("Failed to load slow requests: {e:#}"))
        .unwrap_or_default();
    let hourly_stats = span::hourly_stats(&pool, project_id, 24)
        .await
        .inspect_err(|e| tracing::error!("Failed to load hourly stats: {e:#}"))
        .unwrap_or_default();
    let deploys = models::deploy::list_since(&pool, project_id, &since)
        .await
        .inspect_err(|e| tracing::error!("Failed to load deploys: {e:#}"))
        .unwrap_or_default();

    HtmlTemplate(DashboardTemplate {
        requests_24h,
        errors_24h,
        avg_ms: latency_stats.avg_ms,
        p95_ms: latency_stats.p95_ms,
        p99_ms: latency_stats.p99_ms,
        recent_errors,
        slow_requests,
        hourly_stats,
        deploys,
        ctx,
    })
}
