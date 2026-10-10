use askama::Template;
use rama::http::Request;
use rama::http::header::HOST;
use rama::http::service::web::extract::State;

use crate::template::HtmlTemplate;
use mini_apm::{
    DbPool,
    models::deploy::{self, Deploy},
};

use super::project_context::WebProjectContext;

#[derive(Template)]
#[template(path = "deploys/index.html")]
pub struct DeploysTemplate {
    pub deploys: Vec<Deploy>,
    pub api_key: String,
    pub base_url: String,
    pub ctx: WebProjectContext,
}

pub async fn index(
    State(pool): State<DbPool>,
    ctx: WebProjectContext,
    request: Request,
) -> HtmlTemplate<DeploysTemplate> {
    let project_id = ctx.project_id();
    let deploys = deploy::list(&pool, project_id, 50)
        .await
        .inspect_err(|e| tracing::error!("Failed to load deploys: {e:#}"))
        .unwrap_or_default();

    let api_key = ctx.api_key("YOUR_API_KEY");

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

    let base_url = format!("{scheme}://{host}");

    HtmlTemplate(DeploysTemplate {
        deploys,
        api_key,
        base_url,
        ctx,
    })
}
