use askama::Template;
use rama::http::service::web::extract::State;
use rama::http::service::web::response::{IntoResponse, Redirect};

use mini_apm::{DbPool, models::project};
use crate::template::HtmlTemplate;

use super::project_context::WebProjectContext;

#[derive(Template)]
#[template(path = "api_key/index.html")]
pub struct ApiKeyTemplate {
    pub api_key: String,
    pub ctx: WebProjectContext,
}

pub async fn index(State(pool): State<DbPool>) -> HtmlTemplate<ApiKeyTemplate> {
    let ctx = WebProjectContext {
        current_project: None,
        projects: vec![],
        projects_enabled: false,
    };

    // Get the default project's API key
    let api_key = project::ensure_default_project(&pool)
        .map(|p| p.api_key)
        .unwrap_or_else(|_| "Error loading API key".to_string());

    HtmlTemplate(ApiKeyTemplate { api_key, ctx })
}

pub async fn regenerate(State(pool): State<DbPool>) -> impl IntoResponse {
    // Get the default project and regenerate its key
    if let Ok(project) = project::ensure_default_project(&pool) {
        let _ = project::regenerate_api_key(&pool, project.id);
    }
    Redirect::to("/api-key")
}