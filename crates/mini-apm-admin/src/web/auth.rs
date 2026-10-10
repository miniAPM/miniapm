use askama::Template;
use rama::http::StatusCode;
use rama::http::service::web::extract::{Form, Path, State};
use rama::http::service::web::response::{Html, IntoResponse, Redirect};
use rama::http::{HeaderValue, Response};
use serde::Deserialize;

use mini_apm::api::extract::Extension;

use crate::cookies::{delete_cookie_header, get_cookie, set_cookie_header};
use crate::template::HtmlTemplate;
use crate::web::auth_middleware::CurrentUser;
use mini_apm::{DbPool, models};

use super::project_context::WebProjectContext;

const SESSION_COOKIE: &str = "miniapm_session";

// Templates

#[derive(Template)]
#[template(path = "auth/login.html")]
pub struct LoginTemplate {
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "auth/change_password.html")]
pub struct ChangePasswordTemplate {
    pub error: Option<String>,
    pub username: String,
}

#[derive(Template)]
#[template(path = "auth/users.html")]
pub struct UsersTemplate {
    pub users: Vec<models::User>,
    pub current_user_id: i64,
    pub error: Option<String>,
    pub success: Option<String>,
    pub invite_url: Option<String>,
    pub ctx: WebProjectContext,
}

#[derive(Template)]
#[template(path = "auth/invite.html")]
pub struct InviteTemplate {
    pub username: String,
    pub error: Option<String>,
}

// Form data

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct ChangePasswordForm {
    #[serde(default)]
    pub current_password: String,
    pub new_password: String,
    pub confirm_password: String,
}

#[derive(Deserialize)]
pub struct CreateUserForm {
    pub username: String,
    pub is_admin: Option<String>,
}

// Helper to get current user from cookies
pub async fn get_current_user(pool: &DbPool, req: &rama::http::Request) -> Option<models::User> {
    let token = get_cookie(req, SESSION_COOKIE)?;
    models::user::get_user_from_session(pool, &token)
        .await
        .inspect_err(|e| tracing::error!("Failed to load session user: {e:#}"))
        .ok()
        .flatten()
}

/// Start a session for `user_id` and redirect to `location` with its cookie
async fn sign_in(pool: &DbPool, user_id: i64, location: &'static str) -> anyhow::Result<Response> {
    let token = models::user::create_session(pool, user_id)
        .await
        .inspect_err(|e| tracing::error!("Failed to create session: {e:#}"))?;
    let mut response = Redirect::to(location).into_response();
    response.headers_mut().insert(
        "set-cookie",
        set_cookie_header(SESSION_COOKIE, &token, 7 * 86400).parse()?,
    );
    Ok(response)
}

// Handlers

pub async fn login_page() -> Response {
    HtmlTemplate(LoginTemplate { error: None }).into_response()
}

pub async fn login_submit(State(pool): State<DbPool>, Form(form): Form<LoginForm>) -> Response {
    let fail = |error: &str| {
        HtmlTemplate(LoginTemplate {
            error: Some(error.to_string()),
        })
        .into_response()
    };

    match models::user::authenticate(&pool, &form.username, &form.password)
        .await
        .inspect_err(|e| tracing::error!("Failed to authenticate: {e:#}"))
    {
        Ok(Some(user)) => {
            let location = if user.must_change_password {
                "/auth/change-password"
            } else {
                "/"
            };
            sign_in(&pool, user.id, location)
                .await
                .unwrap_or_else(|_| fail("Failed to create session"))
        }
        Ok(None) => fail("Invalid username or password"),
        Err(_) => fail("Authentication error"),
    }
}

pub async fn logout() -> Response {
    let delete_header = HeaderValue::try_from(delete_cookie_header(SESSION_COOKIE))
        .expect("the session cookie name is a header-safe constant");
    let mut response = Redirect::to("/auth/login").into_response();
    response.headers_mut().insert("set-cookie", delete_header);
    response
}

pub async fn change_password_page(
    State(pool): State<DbPool>,
    req: rama::http::Request,
) -> Response {
    let Some(user) = get_current_user(&pool, &req).await else {
        return Redirect::to("/auth/login").into_response();
    };

    HtmlTemplate(ChangePasswordTemplate {
        error: None,
        username: user.username,
    })
    .into_response()
}

pub async fn change_password_submit(
    State(pool): State<DbPool>,
    Extension(current_user): Extension<CurrentUser>,
    Form(form): Form<ChangePasswordForm>,
) -> Response {
    let fail = |error: &str| {
        HtmlTemplate(ChangePasswordTemplate {
            error: Some(error.to_string()),
            username: current_user.username.clone(),
        })
        .into_response()
    };

    if form.new_password != form.confirm_password {
        return fail("Passwords do not match");
    }
    if form.new_password.len() < 8 {
        return fail("Password must be at least 8 characters");
    }

    // Verify current password (skip only if must_change_password is set, allowing first-time change)
    if !current_user.must_change_password {
        if form.current_password.is_empty() {
            return fail("Current password is required");
        }
        match models::user::verify_password_for_user(&pool, current_user.id, &form.current_password)
            .await
            .inspect_err(|e| tracing::error!("Failed to verify password: {e:#}"))
        {
            Ok(true) => {}
            Ok(false) => return fail("Current password is incorrect"),
            Err(_) => return fail("Failed to verify current password"),
        }
    }

    match models::user::change_password(&pool, current_user.id, &form.new_password)
        .await
        .inspect_err(|e| tracing::error!("Failed to change password: {e:#}"))
    {
        Ok(_) => Redirect::to("/").into_response(),
        Err(_) => fail("Failed to change password"),
    }
}

// Admin-only handlers

/// Returns a `403 Forbidden` response unless `current_user` is an admin.
fn require_admin(current_user: &CurrentUser) -> Option<Response> {
    if current_user.is_admin {
        None
    } else {
        Some((StatusCode::FORBIDDEN, "Admin access required").into_response())
    }
}

async fn users_error(pool: &DbPool, current_user_id: i64, error: impl Into<String>) -> Response {
    render_users_page(pool, current_user_id, Some(error.into()), None, None).await
}

/// Re-renders the users list with a status message, reloading the user list
/// from the database. Shared by all handlers below that mutate users.
async fn render_users_page(
    pool: &DbPool,
    current_user_id: i64,
    error: Option<String>,
    success: Option<String>,
    invite_url: Option<String>,
) -> Response {
    let users = models::user::list_all(pool)
        .await
        .inspect_err(|e| tracing::error!("Failed to load users: {e:#}"))
        .unwrap_or_default();
    let ctx = WebProjectContext {
        current_project: None,
        projects: vec![],
        projects_enabled: false,
        accounts_enabled: true,
    };

    HtmlTemplate(UsersTemplate {
        users,
        current_user_id,
        error,
        success,
        invite_url,
        ctx,
    })
    .into_response()
}

pub async fn users_page(
    State(pool): State<DbPool>,
    Extension(current_user): Extension<CurrentUser>,
) -> Response {
    if let Some(forbidden) = require_admin(&current_user) {
        return forbidden;
    }

    render_users_page(&pool, current_user.id, None, None, None).await
}

pub async fn create_user(
    State(pool): State<DbPool>,
    Extension(current_user): Extension<CurrentUser>,
    Form(form): Form<CreateUserForm>,
) -> Response {
    if let Some(forbidden) = require_admin(&current_user) {
        return forbidden;
    }

    // Validate username
    if let Err(validation_error) = models::user::validate_username(&form.username) {
        return users_error(&pool, current_user.id, validation_error.to_string()).await;
    }

    let is_admin = form.is_admin.as_deref() == Some("on");

    match models::user::create_with_invite(&pool, &form.username, is_admin)
        .await
        .inspect_err(|e| tracing::warn!("Failed to create user: {e:#}"))
    {
        Ok(invite_token) => {
            let base_url = std::env::var("MINI_APM_URL")
                .unwrap_or_else(|_| "http://localhost:3000".to_string());
            let invite_url = format!(
                "{}/auth/invite/{}",
                base_url.trim_end_matches('/'),
                invite_token
            );
            render_users_page(
                &pool,
                current_user.id,
                None,
                Some(format!("User '{}' created", form.username)),
                Some(invite_url),
            )
            .await
        }
        Err(_) => {
            users_error(
                &pool,
                current_user.id,
                "Failed to create user (username may already exist)",
            )
            .await
        }
    }
}

#[derive(Deserialize)]
pub struct DeleteUserForm {
    pub user_id: i64,
}

pub async fn delete_user(
    State(pool): State<DbPool>,
    Extension(current_user): Extension<CurrentUser>,
    Form(form): Form<DeleteUserForm>,
) -> Response {
    if let Some(forbidden) = require_admin(&current_user) {
        return forbidden;
    }

    if form.user_id == current_user.id {
        return users_error(&pool, current_user.id, "Cannot delete yourself").await;
    }

    match models::user::delete(&pool, form.user_id)
        .await
        .inspect_err(|e| tracing::error!("Failed to delete user: {e:#}"))
    {
        Ok(_) => {
            render_users_page(
                &pool,
                current_user.id,
                None,
                Some("User deleted".to_string()),
                None,
            )
            .await
        }
        Err(_) => users_error(&pool, current_user.id, "Failed to delete user").await,
    }
}

// Invite handlers

#[derive(Deserialize)]
pub struct InviteForm {
    pub password: String,
    pub confirm_password: String,
}

/// Rendered when an invite token is missing, unknown, or expired.
fn invalid_invite_response() -> Response {
    (
        StatusCode::NOT_FOUND,
        Html(
            "<h1>Invalid or expired invite link</h1><p><a href=\"/auth/login\">Go to login</a></p>",
        ),
    )
        .into_response()
}

async fn find_invited(pool: &DbPool, token: &str) -> Option<models::User> {
    models::user::find_by_invite_token(pool, token)
        .await
        .inspect_err(|e| tracing::error!("Failed to look up invite: {e:#}"))
        .ok()
        .flatten()
}

pub async fn invite_page(State(pool): State<DbPool>, Path(token): Path<String>) -> Response {
    match find_invited(&pool, &token).await {
        Some(user) => HtmlTemplate(InviteTemplate {
            username: user.username,
            error: None,
        })
        .into_response(),
        None => invalid_invite_response(),
    }
}

pub async fn invite_submit(
    State(pool): State<DbPool>,
    Path(token): Path<String>,
    Form(form): Form<InviteForm>,
) -> Response {
    let Some(user) = find_invited(&pool, &token).await else {
        return invalid_invite_response();
    };

    let fail = |error: &str| {
        HtmlTemplate(InviteTemplate {
            username: user.username.clone(),
            error: Some(error.to_string()),
        })
        .into_response()
    };

    if form.password != form.confirm_password {
        return fail("Passwords do not match");
    }
    if form.password.len() < 8 {
        return fail("Password must be at least 8 characters");
    }
    if models::user::accept_invite(&pool, user.id, &form.password)
        .await
        .inspect_err(|e| tracing::error!("Failed to accept invite: {e:#}"))
        .is_err()
    {
        return fail("Failed to set password");
    }

    sign_in(&pool, user.id, "/")
        .await
        .unwrap_or_else(|_| Redirect::to("/auth/login").into_response())
}

#[cfg(test)]
mod tests;
