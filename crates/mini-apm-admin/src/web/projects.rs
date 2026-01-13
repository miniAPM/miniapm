use askama::Template;
use rama::http::service::web::extract::{Query, State, Form};
use rama::http::service::web::response::{IntoResponse, Redirect};
use serde::Deserialize;

use mini_apm::{DbPool, models::project};
use crate::template::HtmlTemplate;
use crate::cookies::set_cookie_header;

use super::project_context::WebProjectContext;

const PROJECT_COOKIE: &str = "miniapm_project";

#[derive(Template)]
#[template(path = "projects/index.html")]
pub struct ProjectsTemplate {
    pub projects: Vec<project::Project>,
    pub message: Option<String>,
    pub ctx: WebProjectContext,
}

#[derive(Deserialize)]
pub struct ProjectsQuery {
    pub message: Option<String>,
}

pub async fn index(
    State(pool): State<DbPool>,
    Query(query): Query<ProjectsQuery>,
) -> HtmlTemplate<ProjectsTemplate> {
    let ctx = WebProjectContext {
        current_project: None,
        projects: vec![],
        projects_enabled: false,
    };
    let projects = project::list_all(&pool).unwrap_or_default();

    HtmlTemplate(ProjectsTemplate {
        projects,
        message: query.message,
        ctx,
    })
}

#[derive(Deserialize)]
pub struct SwitchForm {
    pub slug: String,
}

pub async fn switch_project(Form(form): Form<SwitchForm>) -> impl IntoResponse {
    let cookie_header = set_cookie_header(PROJECT_COOKIE, &form.slug, 365 * 86400);
    rama::http::Response::builder()
        .status(rama::http::StatusCode::TEMPORARY_REDIRECT)
        .header("set-cookie", cookie_header)
        .header("location", "/")
        .body(rama::http::Body::empty())
        .unwrap()
}

#[derive(Deserialize)]
pub struct CreateForm {
    pub name: String,
}

pub async fn create(State(pool): State<DbPool>, Form(form): Form<CreateForm>) -> impl IntoResponse {
    if form.name.trim().is_empty() {
        return Redirect::to("/projects");
    }

    let _ = project::create(&pool, form.name.trim());
    Redirect::to("/projects")
}

#[derive(Deserialize)]
pub struct DeleteForm {
    pub id: i64,
}

pub async fn delete(State(pool): State<DbPool>, Form(form): Form<DeleteForm>) -> impl IntoResponse {
    let _ = project::delete(&pool, form.id);
    Redirect::to("/projects")
}

#[derive(Deserialize)]
pub struct RegenerateKeyForm {
    pub id: i64,
}

pub async fn regenerate_key(
    State(pool): State<DbPool>,
    Form(form): Form<RegenerateKeyForm>,
) -> impl IntoResponse {
    let _ = project::regenerate_api_key(&pool, form.id);
    Redirect::to("/projects")
}
