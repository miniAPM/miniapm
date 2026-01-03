use askama::Template;
use axum::extract::State;
use tower_cookies::Cookies;

use crate::{models::deploy::{self, Deploy}, DbPool};

use super::project_context::{get_project_context, WebProjectContext};

#[derive(Template)]
#[template(path = "deploys/index.html")]
pub struct DeploysTemplate {
    pub deploys: Vec<Deploy>,
    pub ctx: WebProjectContext,
}

pub async fn index(State(pool): State<DbPool>, cookies: Cookies) -> DeploysTemplate {
    let ctx = get_project_context(&pool, &cookies);
    let project_id = ctx.project_id();
    let deploys = deploy::list(&pool, project_id, 50).unwrap_or_default();

    DeploysTemplate { deploys, ctx }
}
