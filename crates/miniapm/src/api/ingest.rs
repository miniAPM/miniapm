use axum::{Extension, Json, extract::State, http::StatusCode};
use serde::Deserialize;

use crate::{
    DbPool,
    api::auth::ProjectContext,
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
