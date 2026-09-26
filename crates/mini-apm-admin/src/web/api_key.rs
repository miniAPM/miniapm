use askama::Template;
use rama::http::service::web::extract::State;
use rama::http::service::web::response::{IntoResponse, Redirect};

use crate::template::HtmlTemplate;
use mini_apm::{DbPool, models::project};

use super::project_context::WebProjectContext;

#[derive(Template)]
#[template(path = "api_key/index.html")]
pub struct ApiKeyTemplate {
    pub api_key: String,
    pub ctx: WebProjectContext,
}

pub async fn index(ctx: WebProjectContext) -> HtmlTemplate<ApiKeyTemplate> {
    let api_key = ctx.api_key("Error loading API key");

    HtmlTemplate(ApiKeyTemplate { api_key, ctx })
}

pub async fn regenerate(State(pool): State<DbPool>, ctx: WebProjectContext) -> impl IntoResponse {
    if let Some(project) = ctx.current_project
        && let Err(e) = project::regenerate_api_key(&pool, project.id).await
    {
        tracing::error!("Failed to regenerate API key: {e:#}");
    }
    Redirect::to("/api-key")
}
