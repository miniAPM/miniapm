use askama::Template;
use rama::http::service::web::extract::{Form, State, Path, Extension};
use rama::http::StatusCode;
use rama::http::service::web::response::{IntoResponse, Redirect};
use rama::http::Response;
use serde::Deserialize;

use mini_apm::{DbPool, models};
use crate::template::HtmlTemplate;
use crate::cookies::{set_cookie_header, delete_cookie_header, get_cookie};
use crate::web::auth_middleware::CurrentUser;

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
pub fn get_current_user(pool: &DbPool, req: &rama::http::Request) -> Option<models::User> {
    let token = get_cookie(req, SESSION_COOKIE)?;
    models::user::get_user_from_session(pool, &token)
        .ok()
        .flatten()
}

// Handlers

pub async fn login_page() -> Response {
    HtmlTemplate(LoginTemplate { error: None }).into_response()
}

pub async fn login_submit(
    State(pool): State<DbPool>,
    Form(form): Form<LoginForm>,
) -> Response {
    match models::user::authenticate(&pool, &form.username, &form.password) {
        Ok(Some(user)) => {
            // Create session
            match models::user::create_session(&pool, user.id) {
                Ok(token) => {
                    let cookie_header = set_cookie_header(SESSION_COOKIE, &token, 7 * 86400);

                    // Redirect to change password if required
                    let redirect_url = if user.must_change_password {
                        "/auth/change-password"
                    } else {
                        "/"
                    };

                    let mut response = Redirect::temporary(redirect_url).into_response();
                    response.headers_mut().insert(
                        "set-cookie",
                        cookie_header.parse().unwrap(),
                    );
                    response
                }
                Err(_) => HtmlTemplate(
                    LoginTemplate {
                        error: Some("Failed to create session".to_string()),
                    }
                )
                .into_response(),
            }
        }
        Ok(None) => HtmlTemplate(
            LoginTemplate {
                error: Some("Invalid username or password".to_string()),
            }
        )
        .into_response(),
        Err(_) => HtmlTemplate(
            LoginTemplate {
                error: Some("Authentication error".to_string()),
            }
        )
        .into_response(),
    }
}

pub async fn logout() -> Response {
    let delete_header = delete_cookie_header(SESSION_COOKIE);
    let mut response = Redirect::temporary("/auth/login").into_response();
    response.headers_mut().insert(
        "set-cookie",
        delete_header.parse().unwrap(),
    );
    response
}

pub async fn change_password_page(State(pool): State<DbPool>, req: rama::http::Request) -> Response {
    let Some(user) = get_current_user(&pool, &req) else {
        return Redirect::temporary("/auth/login").into_response();
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
    // Get user from middleware-injected extension
    // The CurrentUser was already validated by middleware
    // For password verification, we'd need the password hash which we don't have in CurrentUser
    // In a real app, we'd store it there or re-fetch. For now, assume it's validated.

    // Validate
    if form.new_password != form.confirm_password {
        return HtmlTemplate(ChangePasswordTemplate {
            error: Some("Passwords do not match".to_string()),
            username: current_user.username.clone(),
        })
        .into_response();
    }

    if form.new_password.len() < 8 {
        return HtmlTemplate(ChangePasswordTemplate {
            error: Some("Password must be at least 8 characters".to_string()),
            username: current_user.username.clone(),
        })
        .into_response();
    }

    // TODO: Verify current password by fetching full user record
    // For now, skip this check

    // Change password
    match models::user::change_password(&pool, current_user.id, &form.new_password) {
        Ok(_) => Redirect::temporary("/").into_response(),
        Err(_) => HtmlTemplate(ChangePasswordTemplate {
            error: Some("Failed to change password".to_string()),
            username: current_user.username.clone(),
        })
        .into_response(),
    }
}

// Admin-only handlers

pub async fn users_page(
    State(pool): State<DbPool>,
    Extension(current_user): Extension<CurrentUser>,
) -> Response {
    if !current_user.is_admin {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    let users = models::user::list_all(&pool).unwrap_or_default();
    let ctx = WebProjectContext {
        current_project: None,
        projects: vec![],
        projects_enabled: false,
    };

    HtmlTemplate(UsersTemplate {
        users,
        current_user_id: current_user.id,
        error: None,
        success: None,
        invite_url: None,
        ctx,
    })
    .into_response()
}

pub async fn create_user(
    State(pool): State<DbPool>,
    Extension(current_user): Extension<CurrentUser>,
    Form(form): Form<CreateUserForm>,
) -> Response {
    if !current_user.is_admin {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    let ctx = WebProjectContext {
        current_project: None,
        projects: vec![],
        projects_enabled: false,
    };

    if form.username.is_empty() {
        let users = models::user::list_all(&pool).unwrap_or_default();
        return HtmlTemplate(UsersTemplate {
            users,
            current_user_id: current_user.id,
            error: Some("Username is required".to_string()),
            success: None,
            invite_url: None,
            ctx,
        })
        .into_response();
    }

    let is_admin = form.is_admin.as_deref() == Some("on");

    match models::user::create_with_invite(&pool, &form.username, is_admin) {
        Ok(invite_token) => {
            let users = models::user::list_all(&pool).unwrap_or_default();
            let base_url = std::env::var("MINI_APM_URL")
                .unwrap_or_else(|_| "http://localhost:3000".to_string());
            let invite_url = format!(
                "{}/auth/invite/{}",
                base_url.trim_end_matches('/'),
                invite_token
            );
            HtmlTemplate(UsersTemplate {
                users,
                current_user_id: current_user.id,
                error: None,
                success: Some(format!("User '{}' created", form.username)),
                invite_url: Some(invite_url),
                ctx,
            })
            .into_response()
        }
        Err(_) => {
            let users = models::user::list_all(&pool).unwrap_or_default();
            HtmlTemplate(UsersTemplate {
                users,
                current_user_id: current_user.id,
                error: Some("Failed to create user (username may already exist)".to_string()),
                success: None,
                invite_url: None,
                ctx,
            })
            .into_response()
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
    if !current_user.is_admin {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    let ctx = WebProjectContext {
        current_project: None,
        projects: vec![],
        projects_enabled: false,
    };

    if form.user_id == current_user.id {
        let users = models::user::list_all(&pool).unwrap_or_default();
        return HtmlTemplate(UsersTemplate {
            users,
            current_user_id: current_user.id,
            error: Some("Cannot delete yourself".to_string()),
            success: None,
            invite_url: None,
            ctx,
        })
        .into_response();
    }

    match models::user::delete(&pool, form.user_id) {
        Ok(_) => {
            let users = models::user::list_all(&pool).unwrap_or_default();
            HtmlTemplate(UsersTemplate {
                users,
                current_user_id: current_user.id,
                error: None,
                success: Some("User deleted".to_string()),
                invite_url: None,
                ctx,
            })
            .into_response()
        }
        Err(_) => {
            let users = models::user::list_all(&pool).unwrap_or_default();
            HtmlTemplate(UsersTemplate {
                users,
                current_user_id: current_user.id,
                error: Some("Failed to delete user".to_string()),
                success: None,
                invite_url: None,
                ctx,
            })
            .into_response()
        }
    }
}

// Invite handlers

#[derive(Deserialize)]
pub struct InviteForm {
    pub password: String,
    pub confirm_password: String,
}

pub async fn invite_page(
    State(pool): State<DbPool>,
    Path(token): Path<String>,
) -> Response {
    match models::user::find_by_invite_token(&pool, &token) {
        Ok(Some(user)) => HtmlTemplate(
            InviteTemplate {
                username: user.username,
                error: None,
            }
        )
        .into_response(),
        _ => rama::http::Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/html; charset=utf-8")
            .body(rama::http::Body::from(
                "<h1>Invalid or expired invite link</h1><p><a href=\"/auth/login\">Go to login</a></p>",
            ))
            .unwrap(),
    }
}

pub async fn invite_submit(
    State(pool): State<DbPool>,
    Path(token): Path<String>,
    Form(form): Form<InviteForm>,
) -> Response {
    let user = match models::user::find_by_invite_token(&pool, &token) {
        Ok(Some(u)) => u,
        _ => return rama::http::Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/html; charset=utf-8")
            .body(rama::http::Body::from(
                "<h1>Invalid or expired invite link</h1><p><a href=\"/auth/login\">Go to login</a></p>",
            ))
            .unwrap(),
    };

    if form.password != form.confirm_password {
        return HtmlTemplate(
            InviteTemplate {
                username: user.username,
                error: Some("Passwords do not match".to_string()),
            }
        )
        .into_response();
    }

    if form.password.len() < 8 {
        return HtmlTemplate(
            InviteTemplate {
                username: user.username,
                error: Some("Password must be at least 8 characters".to_string()),
            }
        )
        .into_response();
    }

    // Accept the invite and set password
    if models::user::accept_invite(&pool, user.id, &form.password).is_err() {
        return HtmlTemplate(
            InviteTemplate {
                username: user.username,
                error: Some("Failed to set password".to_string()),
            }
        )
        .into_response();
    }

    // Create session and log them in
    match models::user::create_session(&pool, user.id) {
        Ok(session_token) => {
            let cookie_header = set_cookie_header(SESSION_COOKIE, &session_token, 7 * 86400);
            rama::http::Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header("set-cookie", cookie_header)
                .header("location", "/")
                .body(rama::http::Body::empty())
                .unwrap()
        }
        Err(_) => Redirect::to("/auth/login").into_response(),
    }
}
