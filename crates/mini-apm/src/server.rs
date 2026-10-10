use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use rama::Layer;
use rama::Service;
use rama::conversion::FromRef;
use rama::graceful::Shutdown;
use rama::http::grpc::service::opentelemetry::proto::collector::trace::v1::trace_service_server::TraceServiceServer;
use rama::http::header::CONTENT_TYPE;
use rama::http::layer::body_limit::BodyLimitLayer;
use rama::http::layer::error_handling::ErrorHandlerLayer;
use rama::http::matcher::HttpMatcher;
use rama::http::server::HttpServer;
use rama::http::service::web::response::IntoResponse;
use rama::http::service::web::{Router, response::Html};
use rama::http::{HeaderValue, Request, Response, StatusCode};
use rama::rt::Executor;

use crate::self_monitor::{SelfMonitor, SelfMonitorLayer};
use crate::{DbPool, api, config::Config, jobs, models};

/// Combined state for routes that need both pool and config
#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub config: Config,
}

// Allow extracting DbPool from AppState
impl FromRef<AppState> for DbPool {
    fn from_ref(state: &AppState) -> Self {
        state.pool.clone()
    }
}

// Allow extracting Config from AppState
impl FromRef<AppState> for Config {
    fn from_ref(state: &AppState) -> Self {
        state.config.clone()
    }
}

/// Maximum request body size (10 MB)
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

pub async fn run(pool: DbPool, config: Config, port: u16) -> anyhow::Result<()> {
    // Initialize start time for uptime tracking
    api::health::init_start_time();

    // Always ensure default project exists (collector only)
    let default_project = models::project::ensure_default_project(&pool).await?;

    if !config.enable_projects {
        tracing::info!("Single-project mode - API key: {}", default_project.api_key);
    }

    match crate::repair::otlp_ids(&pool).await {
        Ok(0) => {}
        Ok(n) => tracing::info!("Repaired {} spans stored with mangled ids", n),
        Err(e) => tracing::error!("Failed to repair mangled span ids: {:#}", e),
    }

    // MiniAPM records its own requests and errors into the `self` project
    let self_project = models::project::ensure_self_project(&pool).await?;
    SelfMonitor::start(pool.clone(), self_project.id, "miniapm").install();

    // Start background jobs
    jobs::start(pool.clone(), config.clone());

    let app = make_app(AppState { pool, config });

    let addr = format!("0.0.0.0:{port}");
    tracing::info!("MiniAPM collector listening on http://{} (API only)", addr);

    serve_with_graceful_shutdown(addr, app).await
}

pub fn make_app(
    state: AppState,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    // Ingestion API (API key auth required)
    let ingest = Router::new_with_state(state.clone())
        .with_post("/deploys", api::ingest_deploys)
        .with_match_route(
            "/v1/traces",
            HttpMatcher::method_post().and_header(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-protobuf"),
            ),
            api::ingest_spans_protobuf,
        )
        .with_post("/v1/traces", api::ingest_spans)
        .with_post("/errors", api::ingest_errors)
        .with_post("/errors/batch", api::ingest_errors_batch);
    let ingest = BodyLimitLayer::new(MAX_BODY_SIZE).into_layer(ingest);
    let ingest = api::ProjectKeyAuthorizer::layer(state.pool.clone()).into_layer(ingest);

    let otlp_grpc = TraceServiceServer::new(api::OtlpTraceService::new(state.pool.clone()))
        .with_max_decoding_message_size(MAX_BODY_SIZE);
    let otlp_grpc = api::ProjectKeyAuthorizer::layer(state.pool.clone()).into_layer(otlp_grpc);

    // Build router with API routes only
    let app = Router::new_with_state(state)
        // Health check (no auth)
        .with_get("/health", api::health_handler)
        .with_sub_service("/ingest", ingest)
        .with_match_route(
            "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
            HttpMatcher::method_post(),
            otlp_grpc,
        )
        // 404 handler
        .with_not_found((
            StatusCode::NOT_FOUND,
            Html("<h1>404 - Collector API Only</h1>".to_owned()),
        ));

    let app = ErrorHandlerLayer::new().into_layer(app);
    Arc::new(SelfMonitorLayer::global().into_layer(app))
}

/// Run an HTTP server on `addr` until Ctrl+C/SIGTERM, then drain in-flight
/// connections (up to 30s) before returning.
pub async fn serve_with_graceful_shutdown<S, Resp>(addr: String, app: S) -> anyhow::Result<()>
where
    S: Service<Request, Output = Resp, Error = Infallible> + Clone + 'static,
    Resp: IntoResponse + Send + 'static,
{
    let graceful = Shutdown::default();

    graceful.spawn_task_fn(move |guard| async move {
        let exec = Executor::graceful(guard);

        if let Err(e) = HttpServer::auto(exec).listen(&addr, app).await {
            tracing::error!("Server error: {}", e);
        }
    });

    // Wait for shutdown signal
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received Ctrl+C, starting graceful shutdown...");
        }
        () = async {
            #[cfg(unix)]
            {
                let mut sigterm = tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::terminate()
                ).expect("Failed to install SIGTERM handler");
                sigterm.recv().await;
            }
            #[cfg(not(unix))]
            {
                std::future::pending::<()>().await;
            }
        } => {
            tracing::info!("Received SIGTERM, starting graceful shutdown...");
        }
    }

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .map_err(|e| anyhow::anyhow!("Graceful shutdown failed: {e:?}"))?;

    tracing::info!("Server shutdown complete");
    Ok(())
}

#[cfg(test)]
mod tests;
