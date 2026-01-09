use askama::Template;
use axum::extract::State;
use axum::http::Request;
use axum::http::header::HOST;
use tower_cookies::Cookies;

use miniapm::{
    DbPool,
    models::{
        deploy::{self, Deploy},
        project,
    },
};

use super::project_context::{WebProjectContext, get_project_context};

#[derive(Template)]
#[template(path = "deploys/index.html")]
pub struct DeploysTemplate {
    pub deploys: Vec<Deploy>,
    pub api_key: String,
    pub base_url: String,
    pub ctx: WebProjectContext,
}

pub async fn index<B>(
    State(pool): State<DbPool>,
    cookies: Cookies,
    request: Request<B>,
) -> DeploysTemplate {
    let ctx = get_project_context(&pool, &cookies);
    let project_id = ctx.project_id();
    let deploys = deploy::list(&pool, project_id, 50).unwrap_or_default();

    let api_key = project::ensure_default_project(&pool)
        .map(|p| p.api_key)
        .unwrap_or_else(|_| "YOUR_API_KEY".to_string());

    // Extract base URL from request
    let host = request
        .headers()
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:3000");

    let scheme = if host.contains("localhost") || host.starts_with("127.") {
        "http"
    } else {
        "https"
    };

    let base_url = format!("{}://{}", scheme, host);

    DeploysTemplate {
        deploys,
        api_key,
        base_url,
        ctx,
    }
}
