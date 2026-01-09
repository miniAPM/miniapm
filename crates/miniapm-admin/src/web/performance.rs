use askama::Template;
use axum::extract::{Query, State};
use chrono::{Duration, Utc};
use serde::Deserialize;
use tower_cookies::Cookies;

use miniapm::{DbPool, models::span};

use super::project_context::{WebProjectContext, get_project_context};

#[derive(Template)]
#[template(path = "performance/index.html")]
pub struct RoutesTemplate {
    pub routes: Vec<span::RouteSummary>,
    pub total_count: i64,
    pub max_requests: i64,
    pub period: String,
    pub search: Option<String>,
    pub sort: String,
    pub ctx: WebProjectContext,
}

#[derive(Deserialize)]
pub struct RoutesQuery {
    pub period: Option<String>,
    pub search: Option<String>,
    pub sort: Option<String>,
}

pub async fn index(
    State(pool): State<DbPool>,
    cookies: Cookies,
    Query(query): Query<RoutesQuery>,
) -> RoutesTemplate {
    let ctx = get_project_context(&pool, &cookies);
    let project_id = ctx.project_id();

    let period = query.period.unwrap_or_else(|| "24h".to_string());
    let sort = query.sort.unwrap_or_else(|| "requests".to_string());
    let search = query.search.clone().filter(|s| !s.is_empty());

    let since = match period.as_str() {
        "1h" => Utc::now() - Duration::hours(1),
        "7d" => Utc::now() - Duration::days(7),
        "30d" => Utc::now() - Duration::days(30),
        _ => Utc::now() - Duration::hours(24),
    };

    let since_str = since.to_rfc3339();

    let routes = span::routes_summary(&pool, project_id, &since_str, search.as_deref(), &sort, 100)
        .unwrap_or_default();

    let total_count =
        span::routes_count(&pool, project_id, &since_str, search.as_deref()).unwrap_or(0);

    let max_requests = routes.iter().map(|r| r.request_count).max().unwrap_or(1);

    RoutesTemplate {
        routes,
        total_count,
        max_requests,
        period,
        search,
        sort,
        ctx,
    }
}
