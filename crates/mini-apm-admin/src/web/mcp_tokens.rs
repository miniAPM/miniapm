use askama::Template;
use mcp_host::prelude::HttpTransportSessionHandle;
use rama::http::Response;
use rama::http::StatusCode;
use rama::http::request::Parts;
use rama::http::service::web::extract::{Form, FromPartsStateRefPair, State};
use rama::http::service::web::response::{IntoResponse, Redirect};
use serde::Deserialize;

use mini_apm::models::mcp_token::{self, McpToken};
use mini_apm::{DbPool, models};

use super::auth_middleware::CurrentUser;
use super::project_context::WebProjectContext;
use crate::AppState;
use crate::mcp;
use crate::template::HtmlTemplate;

#[derive(Template)]
#[template(path = "mcp_tokens/index.html")]
pub struct McpTokensTemplate {
    pub tokens: Vec<McpToken>,
    pub endpoint: String,
    pub secret: Option<String>,
    pub error: Option<String>,
    pub ctx: WebProjectContext,
}

#[derive(Deserialize)]
pub struct CreateForm {
    pub name: String,
}

#[derive(Deserialize)]
pub struct RevokeForm {
    pub id: i64,
}

/// The user whose tokens the page manages: the signed-in user, or the first
/// admin while user accounts are off
pub struct TokenOwner(i64);

impl FromPartsStateRefPair<AppState> for TokenOwner {
    type Rejection = StatusCode;

    async fn from_parts_state_ref_pair(
        parts: &Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if let Some(user) = parts.extensions.get_ref::<CurrentUser>() {
            return Ok(Self(user.id));
        }
        match models::user::first_admin(&state.pool).await {
            Ok(Some(admin)) => Ok(Self(admin.id)),
            Ok(None) => {
                tracing::error!("No admin user to own MCP tokens");
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
            Err(e) => {
                tracing::error!("Failed to load the admin user: {e:#}");
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
}

fn endpoint() -> String {
    let base = std::env::var("MINI_APM_URL").unwrap_or_else(|_| "http://localhost:3001".into());
    format!("{}/mcp", base.trim_end_matches('/'))
}

async fn render(
    pool: &DbPool,
    owner: i64,
    secret: Option<String>,
    error: Option<String>,
    ctx: WebProjectContext,
) -> Response {
    let tokens = mcp_token::list_for_user(pool, owner)
        .await
        .inspect_err(|e| tracing::error!("Failed to load MCP tokens: {e:#}"))
        .unwrap_or_default();
    HtmlTemplate(McpTokensTemplate {
        tokens,
        endpoint: endpoint(),
        secret,
        error,
        ctx,
    })
    .into_response()
}

pub async fn index(
    State(pool): State<DbPool>,
    TokenOwner(owner): TokenOwner,
    ctx: WebProjectContext,
) -> Response {
    render(&pool, owner, None, None, ctx).await
}

pub async fn create(
    State(pool): State<DbPool>,
    TokenOwner(owner): TokenOwner,
    ctx: WebProjectContext,
    Form(form): Form<CreateForm>,
) -> Response {
    match mcp_token::create(&pool, owner, &form.name).await {
        Ok((_, secret)) => render(&pool, owner, Some(secret), None, ctx).await,
        Err(e) => {
            tracing::warn!("Failed to create MCP token: {e:#}");
            render(&pool, owner, None, Some(e.to_string()), ctx).await
        }
    }
}

pub async fn revoke(
    State(pool): State<DbPool>,
    State(sessions): State<HttpTransportSessionHandle>,
    TokenOwner(owner): TokenOwner,
    Form(form): Form<RevokeForm>,
) -> Redirect {
    match mcp_token::revoke(&pool, owner, form.id).await {
        Ok(true) => {
            let closed = sessions.terminate_owned_by(&mcp::principal(form.id));
            tracing::info!("Revoked MCP token {}, closing {closed} sessions", form.id);
        }
        Ok(false) => tracing::warn!("MCP token {} is not the user's to revoke", form.id),
        Err(e) => tracing::error!("Failed to revoke MCP token: {e:#}"),
    }
    Redirect::to("/mcp-tokens")
}
