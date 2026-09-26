use askama::Template;
use rama::http::service::web::extract::{Form, Query, State};
use rama::http::service::web::response::{IntoResponse, Redirect};
use serde::Deserialize;

use crate::cookies::set_cookie_header;
use crate::template::HtmlTemplate;
use mini_apm::{DbPool, models::project};

use super::project_context::{PROJECT_COOKIE, WebProjectContext};

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
    ctx: WebProjectContext,
    Query(query): Query<ProjectsQuery>,
) -> HtmlTemplate<ProjectsTemplate> {
    let projects = project::list_all(&pool).await.unwrap_or_default();

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

    let _ = project::create(&pool, form.name.trim()).await;
    Redirect::to("/projects")
}

#[derive(Deserialize)]
pub struct DeleteForm {
    pub id: i64,
}

pub async fn delete(State(pool): State<DbPool>, Form(form): Form<DeleteForm>) -> impl IntoResponse {
    let _ = project::delete(&pool, form.id).await;
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
    let _ = project::regenerate_api_key(&pool, form.id).await;
    Redirect::to("/projects")
}
