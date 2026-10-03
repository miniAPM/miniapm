//! Health check endpoint

use rama::http::StatusCode;
use rama::http::service::web::extract::State;
use rama::http::service::web::response::Json;
use serde::Serialize;
use std::time::Instant;

use crate::DbPool;

static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

pub fn init_start_time() {
    START_TIME.get_or_init(Instant::now);
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub uptime_seconds: u64,
    pub db_ok: bool,
}

pub async fn health_handler(State(pool): State<DbPool>) -> (StatusCode, Json<HealthResponse>) {
    let uptime_seconds = START_TIME.get().map(|t| t.elapsed().as_secs()).unwrap_or(0);

    // Actually verify database connectivity
    let db_ok = sqlx::query("SELECT 1").execute(&pool).await.is_ok();

    if db_ok {
        (
            StatusCode::OK,
            Json(HealthResponse {
                status: "ok".to_string(),
                error: None,
                uptime_seconds,
                db_ok: true,
            }),
        )
    } else {
        tracing::error!("Health check failed: database unreachable");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "unhealthy".to_string(),
                error: Some("Database unreachable".to_string()),
                uptime_seconds,
                db_ok: false,
            }),
        )
    }
}
