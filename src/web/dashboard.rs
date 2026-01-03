use askama::Template;
use axum::extract::State;
use chrono::{Duration, Utc};
use tower_cookies::Cookies;

use crate::{models::{self, deploy::Deploy}, DbPool};

use super::project_context::{get_project_context, WebProjectContext};

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub requests_24h: i64,
    pub errors_24h: i64,
    pub avg_ms: i64,
    pub p95_ms: i64,
    pub p99_ms: i64,
    pub recent_errors: Vec<models::AppError>,
    pub slow_requests: Vec<models::request::RequestDisplay>,
    pub hourly_stats: Vec<models::request::TimeSeriesPoint>,
    pub deploys: Vec<Deploy>,
    pub ctx: WebProjectContext,
}

pub async fn index(State(pool): State<DbPool>, cookies: Cookies) -> DashboardTemplate {
    let ctx = get_project_context(&pool, &cookies);
    let project_id = ctx.project_id();
    let since = (Utc::now() - Duration::hours(24)).to_rfc3339();

    let requests_24h = models::request::count_since(&pool, project_id, &since).unwrap_or(0);
    let errors_24h = models::error::count_since(&pool, project_id, &since).unwrap_or(0);
    let latency_stats = models::request::latency_stats_since(&pool, project_id, &since)
        .unwrap_or(models::request::LatencyStats { avg_ms: 0, p95_ms: 0, p99_ms: 0 });
    let recent_errors = models::error::list(&pool, project_id, Some("open"), 5).unwrap_or_default();
    let slow_requests = models::request::slow_display(&pool, project_id, 500.0, 5).unwrap_or_default();
    let hourly_stats = models::request::hourly_stats(&pool, project_id, 24).unwrap_or_default();
    let deploys = models::deploy::list_since(&pool, project_id, &since).unwrap_or_default();

    DashboardTemplate {
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
    }
}
