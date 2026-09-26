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
    let api_key = ctx
        .current_project
        .as_ref()
        .map(|p| p.api_key.clone())
        .unwrap_or_else(|| "Error loading API key".to_string());

    HtmlTemplate(ApiKeyTemplate { api_key, ctx })
}

pub async fn regenerate(State(pool): State<DbPool>, ctx: WebProjectContext) -> impl IntoResponse {
    if let Some(project) = ctx.current_project {
        let _ = project::regenerate_api_key(&pool, project.id).await;
    }
    Redirect::to("/api-key")
}
