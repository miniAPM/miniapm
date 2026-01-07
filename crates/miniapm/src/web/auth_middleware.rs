use axum::{
    body::Body,
    extract::State,
    http::Request,
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use std::env;

use crate::{DbPool, models};

const SESSION_COOKIE: &str = "miniapm_session";

/// Middleware that checks authentication when ENABLE_USER_ACCOUNTS is set
pub async fn web_auth_middleware(
    State(pool): State<DbPool>,
    jar: CookieJar,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Check if user accounts are enabled
    let enabled = env::var("ENABLE_USER_ACCOUNTS")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);

    if !enabled {
        // User accounts disabled, allow access
        return next.run(request).await;
    }

    // Get session token from cookie
    let token = match jar.get(SESSION_COOKIE) {
        Some(cookie) => cookie.value().to_string(),
        None => return Redirect::to("/auth/login").into_response(),
    };

    // Validate session
    match models::user::get_user_from_session(&pool, &token) {
        Ok(Some(user)) => {
            // Check if password change is required
            if user.must_change_password {
                // Allow access to change-password page
                let path = request.uri().path();
                if path == "/auth/change-password" || path.starts_with("/static") {
                    return next.run(request).await;
                }
                return Redirect::to("/auth/change-password").into_response();
            }
            // User authenticated, proceed
            next.run(request).await
        }
        _ => Redirect::to("/auth/login").into_response(),
    }
}
