pub mod web;

mod cookies;
mod template;

#[cfg(test)]
mod tests;

use std::convert::Infallible;
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rama::Layer;
use rama::conversion::FromRef;
use rama::error::BoxError;
use rama::extensions::ExtensionsRef;
use rama::http::headers::HeaderMapExt;
use rama::http::headers::forwarded::XForwardedFor;
use rama::http::layer::error_handling::ErrorHandlerLayer;
use rama::http::service::web::response::IntoResponse;
use rama::http::service::web::{Router, response::Html};
use rama::http::{Request, Response, StatusCode};
use rama::layer::LimitLayer;
use rama::layer::limit::policy::RateLimitReached;
use rama::net::rate::KeyedRatePolicy;
use rama::net::stream::SocketInfo;
use rama::service::Service;
use rama::utils::rate::Rate;

use mini_apm::DbPool;

/// Combined state for routes that need pool
#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
}

// Allow extracting DbPool from AppState
impl FromRef<AppState> for DbPool {
    fn from_ref(state: &AppState) -> Self {
        state.pool.clone()
    }
}

pub fn make_app(
    pool: DbPool,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    let state = AppState { pool };

    let app = Router::new_with_state(state.clone())
        // Health check (no auth)
        .with_get("/health", mini_apm::api::health_handler)
        // Auth routes (no auth middleware needed)
        .with_get("/auth/login", web::auth::login_page)
        .with_post("/auth/login", web::auth::login_submit)
        .with_post("/auth/logout", web::auth::logout)
        .with_get("/auth/invite/{token}", web::auth::invite_page)
        .with_post("/auth/invite/{token}", web::auth::invite_submit)
        .with_get("/auth/change-password", web::auth::change_password_page)
        .with_post("/auth/change-password", web::auth::change_password_submit)
        .with_get("/auth/users", web::auth::users_page)
        .with_post("/auth/users/create", web::auth::create_user)
        .with_post("/auth/users/delete", web::auth::delete_user)
        // Protected Web UI routes
        .with_get("/", web::dashboard::index)
        .with_get("/errors", web::errors::index)
        .with_get("/errors/{id}", web::errors::show)
        .with_post("/errors/{id}/status", web::errors::update_status)
        .with_get("/traces", web::traces::index)
        .with_get("/traces/{trace_id}", web::traces::show)
        .with_get("/performance", web::performance::index)
        .with_get("/deploys", web::deploys::index)
        .with_post("/projects/switch", web::projects::switch_project)
        .with_get("/projects", web::projects::index)
        .with_post("/projects/create", web::projects::create)
        .with_post("/projects/delete", web::projects::delete)
        .with_post("/projects/regenerate-key", web::projects::regenerate_key)
        .with_get("/api-key", web::api_key::index)
        .with_post("/api-key/regenerate", web::api_key::regenerate)
        // Static files
        .with_endpoint_service(
            "/static",
            rama::http::service::fs::ServeDir::new(static_dir()),
        )
        // 404 handler
        .with_not_found((
            StatusCode::NOT_FOUND,
            Html("<h1>404 Not Found</h1>".to_owned()),
        ));

    // Apply middleware layers (outermost first)
    // Router errors (e.g. bad path params) become responses so the
    // service error type is Infallible as the middlewares require
    let app = ErrorHandlerLayer::new().into_layer(app);

    // Auth middleware checks authentication
    let auth_layer = web::auth_middleware::WebAuthMiddleware::new(state.clone());
    let with_auth = auth_layer.layer(app);

    // Security headers middleware adds security headers to all responses
    let security_layer = web::security_headers::SecurityHeadersMiddleware::new();
    let with_security = security_layer.layer(with_auth);

    // Rate limiting (100 requests per minute per client IP)
    let rate_limit = LimitLayer::new(Arc::new(KeyedRatePolicy::abort(
        client_rate_key,
        Rate::new(100, Duration::from_secs(60)),
    )))
    .with_error_into_response_fn(|err: BoxError| {
        Ok::<_, Infallible>(match err.downcast::<RateLimitReached>() {
            Ok(reached) => reached.into_response(),
            Err(err) => {
                tracing::warn!("Rate limiter rejected request: {}", err);
                StatusCode::SERVICE_UNAVAILABLE.into_response()
            }
        })
    });
    Arc::new(rate_limit.into_layer(with_security))
}

/// Admin UI assets: `./static` when deployed (see Dockerfile), else the
/// crate's own copy so running from source works from any directory
fn static_dir() -> PathBuf {
    let deployed = Path::new("./static");
    if deployed.is_dir() {
        deployed.to_path_buf()
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("static")
    }
}

/// Rate limit key: the socket peer, unless that peer is a reverse proxy on
/// the local network, then the client address the proxy appended to
/// X-Forwarded-For. Earlier entries are client-supplied and ignored.
/// IPv6 clients share a bucket per /64 so they cannot rotate addresses.
fn client_rate_key(req: &Request) -> Result<Option<IpAddr>, BoxError> {
    let Some(peer) = req
        .extensions()
        .get_ref::<SocketInfo>()
        .map(|info| info.peer_addr().ip_addr.to_canonical())
    else {
        return Ok(None);
    };

    let forwarded = req
        .headers()
        .typed_get::<XForwardedFor>()
        .and_then(|xff| xff.iter().last().copied());
    let client = match forwarded {
        Some(ip) if is_local(peer) => ip.to_canonical(),
        _ => peer,
    };

    Ok(Some(match client {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from_bits(v6.to_bits() & !(u64::MAX as u128))),
        v4 => v4,
    }))
}

fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local(),
    }
}
