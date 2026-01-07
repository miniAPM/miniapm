use axum::{Json, extract::State, http::StatusCode};
use serde::Serialize;
use std::time::Instant;

use crate::{DbPool, db};

static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

pub fn init_start_time() {
    START_TIME.get_or_init(Instant::now);
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub db_size_mb: f64,
    pub uptime_seconds: u64,
    pub db_ok: bool,
}

pub async fn health_handler(State(pool): State<DbPool>) -> (StatusCode, Json<HealthResponse>) {
    let uptime_seconds = START_TIME.get().map(|t| t.elapsed().as_secs()).unwrap_or(0);

    // Actually verify database connectivity
    let db_ok = match pool.get() {
        Ok(conn) => conn.query_row("SELECT 1", [], |_| Ok(())).is_ok(),
        Err(_) => false,
    };

    if db_ok {
        let db_size_mb = db::get_db_size(&pool).unwrap_or(0.0);
        (
            StatusCode::OK,
            Json(HealthResponse {
                status: "ok".to_string(),
                error: None,
                db_size_mb,
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
                db_size_mb: 0.0,
                uptime_seconds,
                db_ok: false,
            }),
        )
    }
}
