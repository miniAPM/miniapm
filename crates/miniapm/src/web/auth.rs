use askama::Template;
use axum::{
    extract::{Form, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::Deserialize;
use time::Duration;

use crate::{DbPool, config::Config, models};

use super::project_context::{WebProjectContext, get_project_context};

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
pub fn get_current_user(pool: &DbPool, jar: &CookieJar) -> Option<models::User> {
    let token = jar.get(SESSION_COOKIE)?.value();
    models::user::get_user_from_session(pool, token)
        .ok()
        .flatten()
}

// Handlers

pub async fn login_page(State(pool): State<DbPool>, jar: CookieJar) -> Response {
    // If already logged in, redirect to home
    if get_current_user(&pool, &jar).is_some() {
        return Redirect::to("/").into_response();
    }

    Html(LoginTemplate { error: None }.render().unwrap_or_default()).into_response()
}

pub async fn login_submit(
    State(pool): State<DbPool>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Response {
    match models::user::authenticate(&pool, &form.username, &form.password) {
        Ok(Some(user)) => {
            // Create session
            match models::user::create_session(&pool, user.id) {
                Ok(token) => {
                    let cookie = Cookie::build((SESSION_COOKIE, token))
                        .path("/")
                        .http_only(true)
                        .secure(true)
                        .same_site(axum_extra::extract::cookie::SameSite::Lax)
                        .max_age(Duration::days(7))
                        .build();

                    let jar = jar.add(cookie);

                    // Redirect to change password if required
                    if user.must_change_password {
                        (jar, Redirect::to("/auth/change-password")).into_response()
                    } else {
                        (jar, Redirect::to("/")).into_response()
                    }
                }
                Err(_) => Html(
                    LoginTemplate {
                        error: Some("Failed to create session".to_string()),
                    }
                    .render()
                    .unwrap_or_default(),
                )
                .into_response(),
            }
        }
        Ok(None) => Html(
            LoginTemplate {
                error: Some("Invalid username or password".to_string()),
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response(),
        Err(_) => Html(
            LoginTemplate {
                error: Some("Authentication error".to_string()),
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response(),
    }
}

pub async fn logout(State(pool): State<DbPool>, jar: CookieJar) -> Response {
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        let _ = models::user::delete_session(&pool, cookie.value());
    }

    let jar = jar.remove(Cookie::from(SESSION_COOKIE));
    (jar, Redirect::to("/auth/login")).into_response()
}

pub async fn change_password_page(State(pool): State<DbPool>, jar: CookieJar) -> Response {
    let Some(user) = get_current_user(&pool, &jar) else {
        return Redirect::to("/auth/login").into_response();
    };

    Html(
        ChangePasswordTemplate {
            error: None,
            username: user.username,
        }
        .render()
        .unwrap_or_default(),
    )
    .into_response()
}

pub async fn change_password_submit(
    State(pool): State<DbPool>,
    jar: CookieJar,
    Form(form): Form<ChangePasswordForm>,
) -> Response {
    let Some(user) = get_current_user(&pool, &jar) else {
        return Redirect::to("/auth/login").into_response();
    };

    // Validate
    if form.new_password != form.confirm_password {
        return Html(
            ChangePasswordTemplate {
                error: Some("Passwords do not match".to_string()),
                username: user.username,
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response();
    }

    if form.new_password.len() < 8 {
        return Html(
            ChangePasswordTemplate {
                error: Some("Password must be at least 8 characters".to_string()),
                username: user.username,
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response();
    }

    // Verify current password
    let password_valid = user
        .password_hash
        .as_ref()
        .is_some_and(|h| models::user::verify_password(&form.current_password, h));
    if !password_valid {
        return Html(
            ChangePasswordTemplate {
                error: Some("Current password is incorrect".to_string()),
                username: user.username,
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response();
    }

    // Change password
    match models::user::change_password(&pool, user.id, &form.new_password) {
        Ok(_) => Redirect::to("/").into_response(),
        Err(_) => Html(
            ChangePasswordTemplate {
                error: Some("Failed to change password".to_string()),
                username: user.username,
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response(),
    }
}

// Admin-only handlers

pub async fn users_page(
    State(pool): State<DbPool>,
    jar: CookieJar,
    cookies: tower_cookies::Cookies,
) -> Response {
    let Some(user) = get_current_user(&pool, &jar) else {
        return Redirect::to("/auth/login").into_response();
    };

    if !user.is_admin {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    let users = models::user::list_all(&pool).unwrap_or_default();
    let ctx = get_project_context(&pool, &cookies);

    Html(
        UsersTemplate {
            users,
            current_user_id: user.id,
            error: None,
            success: None,
            invite_url: None,
            ctx,
        }
        .render()
        .unwrap_or_default(),
    )
    .into_response()
}

pub async fn create_user(
    State(pool): State<DbPool>,
    jar: CookieJar,
    cookies: tower_cookies::Cookies,
    Form(form): Form<CreateUserForm>,
) -> Response {
    let Some(user) = get_current_user(&pool, &jar) else {
        return Redirect::to("/auth/login").into_response();
    };

    if !user.is_admin {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    let ctx = get_project_context(&pool, &cookies);

    if form.username.is_empty() {
        let users = models::user::list_all(&pool).unwrap_or_default();
        return Html(
            UsersTemplate {
                users,
                current_user_id: user.id,
                error: Some("Username is required".to_string()),
                success: None,
                invite_url: None,
                ctx,
            }
            .render()
            .unwrap_or_default(),
        )
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
            Html(
                UsersTemplate {
                    users,
                    current_user_id: user.id,
                    error: None,
                    success: Some(format!("User '{}' created", form.username)),
                    invite_url: Some(invite_url),
                    ctx,
                }
                .render()
                .unwrap_or_default(),
            )
            .into_response()
        }
        Err(_) => {
            let users = models::user::list_all(&pool).unwrap_or_default();
            Html(
                UsersTemplate {
                    users,
                    current_user_id: user.id,
                    error: Some("Failed to create user (username may already exist)".to_string()),
                    success: None,
                    invite_url: None,
                    ctx,
                }
                .render()
                .unwrap_or_default(),
            )
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
    jar: CookieJar,
    cookies: tower_cookies::Cookies,
    Form(form): Form<DeleteUserForm>,
) -> Response {
    let Some(user) = get_current_user(&pool, &jar) else {
        return Redirect::to("/auth/login").into_response();
    };

    if !user.is_admin {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    let ctx = get_project_context(&pool, &cookies);

    if form.user_id == user.id {
        let users = models::user::list_all(&pool).unwrap_or_default();
        return Html(
            UsersTemplate {
                users,
                current_user_id: user.id,
                error: Some("Cannot delete yourself".to_string()),
                success: None,
                invite_url: None,
                ctx,
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response();
    }

    match models::user::delete(&pool, form.user_id) {
        Ok(_) => {
            let users = models::user::list_all(&pool).unwrap_or_default();
            Html(
                UsersTemplate {
                    users,
                    current_user_id: user.id,
                    error: None,
                    success: Some("User deleted".to_string()),
                    invite_url: None,
                    ctx,
                }
                .render()
                .unwrap_or_default(),
            )
            .into_response()
        }
        Err(_) => {
            let users = models::user::list_all(&pool).unwrap_or_default();
            Html(
                UsersTemplate {
                    users,
                    current_user_id: user.id,
                    error: Some("Failed to delete user".to_string()),
                    success: None,
                    invite_url: None,
                    ctx,
                }
                .render()
                .unwrap_or_default(),
            )
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
    axum::extract::Path(token): axum::extract::Path<String>,
) -> Response {
    match models::user::find_by_invite_token(&pool, &token) {
        Ok(Some(user)) => Html(
            InviteTemplate {
                username: user.username,
                error: None,
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response(),
        _ => Html(
            "<h1>Invalid or expired invite link</h1><p><a href=\"/auth/login\">Go to login</a></p>",
        )
        .into_response(),
    }
}

pub async fn invite_submit(
    State(pool): State<DbPool>,
    jar: CookieJar,
    axum::extract::Path(token): axum::extract::Path<String>,
    Form(form): Form<InviteForm>,
) -> Response {
    let user = match models::user::find_by_invite_token(&pool, &token) {
        Ok(Some(u)) => u,
        _ => return Html(
            "<h1>Invalid or expired invite link</h1><p><a href=\"/auth/login\">Go to login</a></p>",
        )
        .into_response(),
    };

    if form.password != form.confirm_password {
        return Html(
            InviteTemplate {
                username: user.username,
                error: Some("Passwords do not match".to_string()),
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response();
    }

    if form.password.len() < 8 {
        return Html(
            InviteTemplate {
                username: user.username,
                error: Some("Password must be at least 8 characters".to_string()),
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response();
    }

    // Accept the invite and set password
    if models::user::accept_invite(&pool, user.id, &form.password).is_err() {
        return Html(
            InviteTemplate {
                username: user.username,
                error: Some("Failed to set password".to_string()),
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response();
    }

    // Create session and log them in
    match models::user::create_session(&pool, user.id) {
        Ok(session_token) => {
            let cookie = Cookie::build((SESSION_COOKIE, session_token))
                .path("/")
                .http_only(true)
                .secure(true)
                .same_site(axum_extra::extract::cookie::SameSite::Lax)
                .max_age(Duration::days(7))
                .build();

            (jar.add(cookie), Redirect::to("/")).into_response()
        }
        Err(_) => Redirect::to("/auth/login").into_response(),
    }
}

// Middleware helper - check if request is authenticated
pub async fn require_auth(
    pool: &DbPool,
    config: &Config,
    jar: &CookieJar,
) -> Result<Option<models::User>, Redirect> {
    // If user accounts are disabled, allow access
    if !config.enable_user_accounts {
        return Ok(None);
    }

    // Check for valid session
    match get_current_user(pool, jar) {
        Some(user) => {
            // Force password change if required
            if user.must_change_password {
                Err(Redirect::to("/auth/change-password"))
            } else {
                Ok(Some(user))
            }
        }
        None => Err(Redirect::to("/auth/login")),
    }
}
