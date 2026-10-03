//! API ingestion handlers
//!
//! Handles incoming telemetry data: spans, deploys, errors.

use rama::extensions::ExtensionsRef;
use rama::http::StatusCode;
use rama::http::grpc;
use rama::http::grpc::protobuf::prost::Message;
use rama::http::grpc::service::opentelemetry::proto::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse, trace_service_server::TraceService,
};
use rama::http::service::web::extract::{Bytes, Json, State};
use serde::Deserialize;

use crate::api::auth::ProjectContext;
use crate::api::extract::Extension;
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
    if store_spans(&pool, &otlp_request, ctx.project_id).await {
        StatusCode::ACCEPTED
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

async fn store_spans(
    pool: &DbPool,
    request: &span::OtlpTraceRequest,
    project_id: Option<i64>,
) -> bool {
    match span::insert_otlp_batch(pool, request, project_id).await {
        Ok(count) => {
            tracing::debug!("Ingested {} spans (project_id={:?})", count, project_id);
            true
        }
        Err(e) => {
            tracing::error!("Failed to ingest spans: {}", e);
            false
        }
    }
}

pub struct OtlpTraceService {
    pool: DbPool,
}

impl OtlpTraceService {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl TraceService for OtlpTraceService {
    async fn export(
        &self,
        request: grpc::Request<ExportTraceServiceRequest>,
    ) -> Result<grpc::Response<ExportTraceServiceResponse>, grpc::Status> {
        let Some(ctx) = request.extensions().get_ref::<ProjectContext>().cloned() else {
            return Err(grpc::Status::unauthenticated("missing project"));
        };
        if !store_spans(&self.pool, &request.into_inner().into(), ctx.project_id).await {
            return Err(grpc::Status::internal("failed to ingest spans"));
        }
        Ok(grpc::Response::new(ExportTraceServiceResponse::default()))
    }
}

pub async fn ingest_spans_protobuf(
    State(pool): State<DbPool>,
    Extension(ctx): Extension<ProjectContext>,
    Bytes(body): Bytes,
) -> StatusCode {
    match ExportTraceServiceRequest::decode(body) {
        Ok(request) => ingest_spans(State(pool), Extension(ctx), Json(request.into())).await,
        Err(e) => {
            tracing::warn!("Invalid OTLP protobuf payload: {}", e);
            StatusCode::BAD_REQUEST
        }
    }
}

pub async fn ingest_deploys(
    State(pool): State<DbPool>,
    Extension(ctx): Extension<ProjectContext>,
    Json(incoming): Json<deploy::IncomingDeploy>,
) -> StatusCode {
    match deploy::insert(&pool, &incoming, ctx.project_id).await {
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
    match app_error::insert(&pool, &incoming, ctx.project_id).await {
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
        match app_error::insert(&pool, &error, ctx.project_id).await {
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
