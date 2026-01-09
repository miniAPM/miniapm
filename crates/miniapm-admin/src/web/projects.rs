use askama::Template;
use axum::{
    Form,
    extract::{Query, State},
    response::{IntoResponse, Redirect},
};
use serde::Deserialize;
use tower_cookies::{Cookie, Cookies};

use miniapm::{DbPool, models::project};

use super::project_context::{PROJECT_COOKIE, WebProjectContext, get_project_context};

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
    cookies: Cookies,
    Query(query): Query<ProjectsQuery>,
) -> ProjectsTemplate {
    let ctx = get_project_context(&pool, &cookies);
    let projects = project::list_all(&pool).unwrap_or_default();

    ProjectsTemplate {
        projects,
        message: query.message,
        ctx,
    }
}

#[derive(Deserialize)]
pub struct SwitchForm {
    pub slug: String,
}

pub async fn switch_project(cookies: Cookies, Form(form): Form<SwitchForm>) -> impl IntoResponse {
    let cookie = Cookie::build((PROJECT_COOKIE, form.slug))
        .path("/")
        .http_only(true)
        .build();
    cookies.add(cookie);
    Redirect::to("/")
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
