use std::future::Future;

use rama::http::{Request, Response};
use rama::http::service::web::response::Redirect;
use rama::http::service::web::response::IntoResponse;
use rama::extensions::ExtensionsMut;
use rama::Layer;
use rama::service::Service;

use mini_apm::models;
use crate::cookies::get_cookie;
use crate::AppState;

const SESSION_COOKIE: &str = "miniapm_session";

/// User information extracted from session
#[derive(Clone, Debug)]
pub struct CurrentUser {
    pub id: i64,
    pub username: String,
    pub is_admin: bool,
    pub must_change_password: bool,
}

/// Layer that applies web session authentication
#[derive(Clone)]
pub struct WebAuthMiddleware {
    state: AppState,
}

impl WebAuthMiddleware {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

impl<S> Layer<S> for WebAuthMiddleware {
    type Service = WebAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        WebAuthService {
            inner,
            state: self.state.clone(),
        }
    }
}

/// Service that validates web sessions
pub struct WebAuthService<S> {
    inner: S,
    state: AppState,
}

impl<S> Service<Request> for WebAuthService<S>
where
    S: Service<Request, Output = Response, Error = std::convert::Infallible> + Send + Sync + 'static,
{
    type Output = Response;
    type Error = std::convert::Infallible;

    fn serve(&self, mut req: Request) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        let pool = self.state.pool.clone();
        let enable_user_accounts = std::env::var("ENABLE_USER_ACCOUNTS")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        async move {
            let path = req.uri().path();

            // Skip protection for unprotected routes
            let is_unprotected = path == "/health"
                || path.starts_with("/auth/login")
                || path.starts_with("/auth/logout")
                || path.starts_with("/auth/invite/")
                || path.starts_with("/ingest/")
                || path.starts_with("/static/");
            let is_protected = !is_unprotected;

            // If not a protected route or user accounts disabled, allow access
            if !is_protected || !enable_user_accounts {
                return self.inner.serve(req).await;
            }

            // Get session token from cookie
            let token = match get_cookie(&req, SESSION_COOKIE) {
                Some(token) => token,
                None => return Ok(Redirect::temporary("/auth/login").into_response()),
            };

            // Validate session
            match models::user::get_user_from_session(&pool, &token) {
                Ok(Some(user)) => {
                    // Check if password change is required
                    if user.must_change_password {
                        // Allow access to change-password page and static files
                        if path == "/auth/change-password" || path.starts_with("/static") {
                            req.extensions_mut().insert(CurrentUser {
                                id: user.id,
                                username: user.username.clone(),
                                is_admin: user.is_admin,
                                must_change_password: user.must_change_password,
                            });
                            return self.inner.serve(req).await;
                        }
                        return Ok(Redirect::temporary("/auth/change-password").into_response());
                    }

                    // User authenticated, inject CurrentUser and proceed
                    req.extensions_mut().insert(CurrentUser {
                        id: user.id,
                        username: user.username.clone(),
                        is_admin: user.is_admin,
                        must_change_password: user.must_change_password,
                    });
                    self.inner.serve(req).await
                }
                _ => Ok(Redirect::temporary("/auth/login").into_response()),
            }
        }
    }
}
