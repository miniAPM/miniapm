pub mod api_key;
pub mod auth;
pub mod auth_middleware;
pub mod dashboard;
pub mod deploys;
pub mod errors;
pub mod performance;
pub mod project_context;
pub mod projects;
pub mod security_headers;
pub mod traces;

pub use auth_middleware::WebAuthMiddleware;
pub use project_context::WebProjectContext;
pub use security_headers::SecurityHeadersMiddleware;

use jiff::Timestamp;
use mini_apm::time;

/// Parse a dashboard period filter into a lower time bound.
/// Anything other than "1h", "24h", "7d", "30d" means "all" (no bound).
pub fn period_start(period: &str) -> Option<Timestamp> {
    match period {
        "1h" => Some(time::hours_ago(1)),
        "24h" => Some(time::hours_ago(24)),
        "7d" => Some(time::days_ago(7)),
        "30d" => Some(time::days_ago(30)),
        _ => None,
    }
}
