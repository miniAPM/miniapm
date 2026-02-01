//! API ingestion handlers
//!
//! Handles incoming telemetry data: spans, deploys, errors.

use rama::http::StatusCode;
use rama::http::service::web::extract::{Extension, Json, State};
use serde::Deserialize;

use crate::api::auth::ProjectContext;
use crate::{
    DbPool,
    models::{deploy, error as app_error, span},
};

#[derive(Debug, Deserialize)]
pub struct IncomingErrorBatch {
    pub errors: Vec<app_error::IncomingError>,
}

pub async fn ingest_spans(
    State(pool): State<DbPool>,
    Extension(ctx): Extension<ProjectContext>,
    Json(otlp_request): Json<span::OtlpTraceRequest>,
) -> StatusCode {
    match span::insert_otlp_batch(&pool, &otlp_request, ctx.project_id) {
        Ok(count) => {
            tracing::debug!("Ingested {} spans (project_id={:?})", count, ctx.project_id);
            StatusCode::ACCEPTED
        }
        Err(e) => {
            tracing::error!("Failed to ingest spans: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

pub async fn ingest_deploys(
    State(pool): State<DbPool>,
    Extension(ctx): Extension<ProjectContext>,
    Json(incoming): Json<deploy::IncomingDeploy>,
) -> StatusCode {
    match deploy::insert(&pool, &incoming, ctx.project_id) {
        Ok(id) => {
            tracing::info!(
                "Recorded deploy id={} git_sha={} (project_id={:?})",
                id,
                incoming.git_sha,
                ctx.project_id
            );
            StatusCode::ACCEPTED
        }
        Err(e) => {
            tracing::error!("Failed to record deploy: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

pub async fn ingest_errors(
    State(pool): State<DbPool>,
    Extension(ctx): Extension<ProjectContext>,
    Json(incoming): Json<app_error::IncomingError>,
) -> StatusCode {
    match app_error::insert(&pool, &incoming, ctx.project_id) {
        Ok(id) => {
            tracing::debug!(
                "Recorded error id={} class={} (project_id={:?})",
                id,
                incoming.exception_class,
                ctx.project_id
            );
            StatusCode::ACCEPTED
        }
        Err(e) => {
            tracing::error!("Failed to record error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

pub async fn ingest_errors_batch(
    State(pool): State<DbPool>,
    Extension(ctx): Extension<ProjectContext>,
    Json(batch): Json<IncomingErrorBatch>,
) -> StatusCode {
    let mut success_count = 0;
    let mut error_count = 0;

    for error in batch.errors {
        match app_error::insert(&pool, &error, ctx.project_id) {
            Ok(_) => success_count += 1,
            Err(e) => {
                tracing::warn!("Failed to record error: {}", e);
                error_count += 1;
            }
        }
    }

    tracing::debug!(
        "Ingested {} errors, {} failed (project_id={:?})",
        success_count,
        error_count,
        ctx.project_id
    );

    if error_count > 0 && success_count == 0 {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::ACCEPTED
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db;
    use crate::models::project;

    fn test_pool() -> DbPool {
        let config = Config::default();
        db::init(&config).expect("Failed to create test database")
    }

    fn project_context(project_id: Option<i64>) -> ProjectContext {
        ProjectContext { project_id }
    }

    #[tokio::test]
    async fn test_ingest_spans_success() {
        let pool = test_pool();
        let proj = project::ensure_default_project(&pool).unwrap();
        let ctx = project_context(Some(proj.id));

        let otlp_request = span::OtlpTraceRequest {
            resource_spans: vec![span::ResourceSpans {
                resource: Some(span::Resource {
                    attributes: Some(vec![span::KeyValue {
                        key: "service.name".to_string(),
                        value: span::AttributeValue {
                            string_value: Some("test-service".to_string()),
                            int_value: None,
                            double_value: None,
                            bool_value: None,
                            array_value: None,
                        },
                    }]),
                }),
                scope_spans: Some(vec![span::ScopeSpans {
                    scope: Some(span::InstrumentationScope {
                        name: Some("test".to_string()),
                        version: Some("1.0".to_string()),
                    }),
                    spans: vec![span::OtlpSpan {
                        trace_id: "0af7651916cd43dd8448eb211c80319c".to_string(),
                        span_id: "b7ad6b7169203331".to_string(),
                        parent_span_id: None,
                        name: "test-span".to_string(),
                        kind: Some(1),
                        start_time_unix_nano: "1000000000".to_string(),
                        end_time_unix_nano: "2000000000".to_string(),
                        attributes: None,
                        events: None,
                        status: None,
                    }],
                }]),
            }],
        };

        let status =
            ingest_spans(State(pool.clone()), Extension(ctx), Json(otlp_request)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_ingest_spans_empty() {
        let pool = test_pool();
        let proj = project::ensure_default_project(&pool).unwrap();
        let ctx = project_context(Some(proj.id));

        let otlp_request = span::OtlpTraceRequest {
            resource_spans: vec![],
        };

        let status =
            ingest_spans(State(pool.clone()), Extension(ctx), Json(otlp_request)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_ingest_error_success() {
        let pool = test_pool();
        let proj = project::ensure_default_project(&pool).unwrap();
        let ctx = project_context(Some(proj.id));

        let incoming = app_error::IncomingError {
            exception_class: "RuntimeError".to_string(),
            message: "Something went wrong".to_string(),
            backtrace: vec!["app/models/user.rb:42:in `validate'".to_string()],
            fingerprint: "test_fingerprint_123".to_string(),
            request_id: Some("req-123".to_string()),
            user_id: Some("user-456".to_string()),
            params: None,
            timestamp: None,
            source_context: None,
        };

        let status = ingest_errors(State(pool.clone()), Extension(ctx), Json(incoming)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_ingest_error_with_source_context() {
        let pool = test_pool();
        let proj = project::ensure_default_project(&pool).unwrap();
        let ctx = project_context(Some(proj.id));

        let incoming = app_error::IncomingError {
            exception_class: "NoMethodError".to_string(),
            message: "undefined method 'foo'".to_string(),
            backtrace: vec!["app/controllers/users_controller.rb:15:in `show'".to_string()],
            fingerprint: "source_context_test".to_string(),
            request_id: None,
            user_id: None,
            params: None,
            timestamp: None,
            source_context: Some(app_error::IncomingSourceContext {
                file: "/app/controllers/users_controller.rb".to_string(),
                lineno: 15,
                pre_context: Some(vec![
                    "  def show".to_string(),
                    "    @user = User.find(params[:id])".to_string(),
                ]),
                context_line: "    @user.foo".to_string(),
                post_context: Some(vec!["  end".to_string(), "".to_string()]),
            }),
        };

        let status = ingest_errors(State(pool.clone()), Extension(ctx), Json(incoming)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_ingest_errors_batch_success() {
        let pool = test_pool();
        let proj = project::ensure_default_project(&pool).unwrap();
        let ctx = project_context(Some(proj.id));

        let batch = IncomingErrorBatch {
            errors: vec![
                app_error::IncomingError {
                    exception_class: "Error1".to_string(),
                    message: "First error".to_string(),
                    backtrace: vec!["line1".to_string()],
                    fingerprint: "batch_fp1".to_string(),
                    request_id: None,
                    user_id: None,
                    params: None,
                    timestamp: None,
                    source_context: None,
                },
                app_error::IncomingError {
                    exception_class: "Error2".to_string(),
                    message: "Second error".to_string(),
                    backtrace: vec!["line2".to_string()],
                    fingerprint: "batch_fp2".to_string(),
                    request_id: None,
                    user_id: None,
                    params: None,
                    timestamp: None,
                    source_context: None,
                },
            ],
        };

        let status =
            ingest_errors_batch(State(pool.clone()), Extension(ctx), Json(batch)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_ingest_errors_batch_empty() {
        let pool = test_pool();
        let proj = project::ensure_default_project(&pool).unwrap();
        let ctx = project_context(Some(proj.id));

        let batch = IncomingErrorBatch { errors: vec![] };

        let status =
            ingest_errors_batch(State(pool.clone()), Extension(ctx), Json(batch)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_ingest_deploy_success() {
        let pool = test_pool();
        let proj = project::ensure_default_project(&pool).unwrap();
        let ctx = project_context(Some(proj.id));

        let incoming = deploy::IncomingDeploy {
            git_sha: "abc123def456".to_string(),
            version: Some("v1.0.0".to_string()),
            env: Some("production".to_string()),
            description: Some("Initial release".to_string()),
            deployer: Some("ci".to_string()),
            timestamp: None,
        };

        let status = ingest_deploys(State(pool.clone()), Extension(ctx), Json(incoming)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_ingest_deploy_minimal() {
        let pool = test_pool();
        let proj = project::ensure_default_project(&pool).unwrap();
        let ctx = project_context(Some(proj.id));

        let incoming = deploy::IncomingDeploy {
            git_sha: "abc123".to_string(),
            version: None,
            env: None,
            description: None,
            deployer: None,
            timestamp: None,
        };

        let status = ingest_deploys(State(pool.clone()), Extension(ctx), Json(incoming)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_ingest_without_project_id() {
        let pool = test_pool();
        let _proj = project::ensure_default_project(&pool).unwrap();
        let ctx = project_context(None); // No project_id

        let incoming = deploy::IncomingDeploy {
            git_sha: "no_project".to_string(),
            version: None,
            env: None,
            description: None,
            deployer: None,
            timestamp: None,
        };

        let status = ingest_deploys(State(pool.clone()), Extension(ctx), Json(incoming)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }
}
