use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::Redirect;
use chrono::{Duration, Utc};
use serde::Deserialize;
use tower_cookies::Cookies;

use crate::{DbPool, models};

use super::project_context::{WebProjectContext, get_project_context};

const PAGE_SIZE: i64 = 50;

#[derive(Template)]
#[template(path = "errors/index.html")]
pub struct ErrorsIndexTemplate {
    pub errors: Vec<models::AppError>,
    pub total_count: i64,
    pub status: Option<String>,
    pub search: Option<String>,
    pub period: String,
    pub sort: String,
    pub page: i64,
    pub total_pages: i64,
    pub hourly_errors: Vec<models::error::ErrorTrendPoint>,
    pub ctx: WebProjectContext,
}

#[derive(Deserialize)]
pub struct ErrorsQuery {
    pub status: Option<String>,
    pub search: Option<String>,
    pub period: Option<String>,
    pub sort: Option<String>,
    pub page: Option<i64>,
}

pub async fn index(
    State(pool): State<DbPool>,
    cookies: Cookies,
    Query(query): Query<ErrorsQuery>,
) -> ErrorsIndexTemplate {
    let ctx = get_project_context(&pool, &cookies);
    let project_id = ctx.project_id();

    let period = query.period.unwrap_or_else(|| "all".to_string());
    let sort = query.sort.unwrap_or_else(|| "last_seen".to_string());
    let search = query.search.clone().filter(|s| !s.is_empty());
    let page = query.page.unwrap_or(1).max(1);

    let since = match period.as_str() {
        "1h" => Some(Utc::now() - Duration::hours(1)),
        "24h" => Some(Utc::now() - Duration::hours(24)),
        "7d" => Some(Utc::now() - Duration::days(7)),
        "30d" => Some(Utc::now() - Duration::days(30)),
        _ => None, // "all"
    };

    let since_str = since.map(|s| s.to_rfc3339());

    let total_count = models::error::count_filtered(
        &pool,
        project_id,
        query.status.as_deref(),
        search.as_deref(),
        since_str.as_deref(),
    )
    .unwrap_or(0);

    let total_pages = (total_count + PAGE_SIZE - 1) / PAGE_SIZE;
    let offset = (page - 1) * PAGE_SIZE;

    let errors = models::error::list_paginated(
        &pool,
        project_id,
        query.status.as_deref(),
        search.as_deref(),
        since_str.as_deref(),
        &sort,
        PAGE_SIZE,
        offset,
    )
    .unwrap_or_default();

    let hourly_errors =
        models::error::hourly_error_stats(&pool, project_id, 24).unwrap_or_default();

    ErrorsIndexTemplate {
        errors,
        total_count,
        status: query.status,
        search,
        period,
        sort,
        page,
        total_pages,
        hourly_errors,
        ctx,
    }
}

#[derive(Template)]
#[template(path = "errors/show.html")]
pub struct ErrorShowTemplate {
    pub error: Option<models::AppError>,
    pub occurrences: Vec<models::ErrorOccurrence>,
    pub trend_24h: Vec<i64>,
    pub ctx: WebProjectContext,
}

pub async fn show(
    State(pool): State<DbPool>,
    cookies: Cookies,
    Path(id): Path<i64>,
) -> ErrorShowTemplate {
    let ctx = get_project_context(&pool, &cookies);
    let error = models::error::find(&pool, id).unwrap_or(None);
    let occurrences = if error.is_some() {
        models::error::occurrences(&pool, id, 10).unwrap_or_default()
    } else {
        vec![]
    };
    let trend_24h = models::error::error_trend_24h(&pool, id).unwrap_or_default();

    ErrorShowTemplate {
        error,
        occurrences,
        trend_24h,
        ctx,
    }
}

#[derive(Deserialize)]
pub struct UpdateStatusForm {
    pub status: String,
}

pub async fn update_status(
    State(pool): State<DbPool>,
    Path(id): Path<i64>,
    Form(form): Form<UpdateStatusForm>,
) -> Redirect {
    // Validate status
    let valid_statuses = ["open", "resolved", "ignored"];
    if valid_statuses.contains(&form.status.as_str()) {
        let _ = models::error::update_status(&pool, id, &form.status);
    }
    Redirect::to(&format!("/errors/{}", id))
}
