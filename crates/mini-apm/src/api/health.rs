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
    let db_ok = match pool.get() {
        Ok(conn) => conn.query_row("SELECT 1", [], |_| Ok(())).is_ok(),
        Err(_) => false,
    };

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db;

    fn test_pool() -> DbPool {
        let config = Config::default();
        db::init(&config).expect("Failed to create test database")
    }

    #[tokio::test]
    async fn test_health_handler_ok() {
        init_start_time();
        let pool = test_pool();

        let (status, Json(response)) = health_handler(State(pool)).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(response.status, "ok");
        assert!(response.db_ok);
        assert!(response.error.is_none());
    }

    #[tokio::test]
    async fn test_health_response_serialization() {
        let response = HealthResponse {
            status: "ok".to_string(),
            error: None,
            uptime_seconds: 100,
            db_ok: true,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"db_ok\":true"));
        // error should be skipped when None
        assert!(!json.contains("\"error\""));
        // db_size_mb should no longer be exposed
        assert!(!json.contains("db_size"));
    }

    #[tokio::test]
    async fn test_health_response_with_error_serialization() {
        let response = HealthResponse {
            status: "unhealthy".to_string(),
            error: Some("Database error".to_string()),
            uptime_seconds: 50,
            db_ok: false,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"unhealthy\""));
        assert!(json.contains("\"error\":\"Database error\""));
        assert!(json.contains("\"db_ok\":false"));
    }
}
