use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use rama::Layer;
use rama::Service;
use rama::conversion::FromRef;
use rama::extensions::Extension;
use rama::graceful::{Shutdown, WeakShutdownGuard};
use rama::http::grpc::service::opentelemetry::proto::collector::trace::v1::trace_service_server::TraceServiceServer;
use rama::http::header::CONTENT_TYPE;
use rama::http::layer::body_limit::BodyLimitLayer;
use rama::http::layer::error_handling::ErrorHandlerLayer;
use rama::http::matcher::HttpMatcher;
use rama::http::server::HttpServer;
use rama::http::service::web::response::IntoResponse;
use rama::http::service::web::{Router, response::Html};
use rama::http::{HeaderValue, Request, Response, StatusCode};
use rama::layer::AddInputExtensionLayer;
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
    let (monitor, writer) = SelfMonitor::start(pool.clone(), self_project.id, "miniapm");
    monitor.install();

    // Start background jobs
    let jobs = jobs::start(pool.clone(), config.clone());

    let app = make_app(AppState {
        pool: pool.clone(),
        config,
    });

    let addr = format!("0.0.0.0:{port}");
    tracing::info!("MiniAPM collector listening on http://{} (API only)", addr);

    let result = serve_with_jobs(addr, app, Some(jobs)).await;
    if let Err(error) = writer.shutdown().await {
        tracing::warn!(%error, "Self-monitor shutdown incomplete");
    }
    // Maintenance tasks have finished or been cancelled and joined, even when
    // HTTP draining failed. Close sessions only after releasing their guards.
    pool.close().await;
    result
}

pub fn make_app(
    state: AppState,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    // Ingestion API (API key auth required)
    let admission = api::admission::Admission::new(
        state.config.ingest_admission.as_ref(),
        state.config.ingest_max_in_flight,
    );
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
    let ingest = admission.wrap(ingest, api::admission::Transport::Http);
    let ingest = api::ProjectKeyAuthorizer::layer(state.pool.clone()).into_layer(ingest);

    let otlp_grpc = TraceServiceServer::new(api::OtlpTraceService::new(state.pool.clone()))
        .with_max_decoding_message_size(MAX_BODY_SIZE);
    let otlp_grpc = admission.wrap(otlp_grpc, api::admission::Transport::Grpc);
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

/// Request extension that resolves once shutdown starts, without holding
/// it back, so endless responses such as SSE streams can end in time
#[derive(Debug, Clone)]
pub struct ShutdownSignal(pub WeakShutdownGuard);

impl Extension for ShutdownSignal {}

impl ShutdownSignal {
    pub async fn triggered(&self) {
        self.0.cancelled().await;
    }
}

/// Run an HTTP server on `addr` until Ctrl+C/SIGTERM, then drain in-flight
/// connections (up to 30s) before returning.
/// Listener failures are returned instead of waiting for a shutdown signal.
pub async fn serve_with_graceful_shutdown<S, Resp>(addr: String, app: S) -> anyhow::Result<()>
where
    S: Service<Request, Output = Resp, Error = Infallible> + Clone + 'static,
    Resp: IntoResponse + Send + 'static,
{
    serve_with_jobs(addr, app, None).await
}

async fn serve_with_jobs<S, Resp>(
    addr: String,
    app: S,
    jobs: Option<jobs::Jobs>,
) -> anyhow::Result<()>
where
    S: Service<Request, Output = Resp, Error = Infallible> + Clone + 'static,
    Resp: IntoResponse + Send + 'static,
{
    serve_until(addr, app, jobs, shutdown_signal()).await
}

async fn serve_until<S, Resp>(
    addr: String,
    app: S,
    jobs: Option<jobs::Jobs>,
    stop: impl Future<Output = anyhow::Result<()>> + Send,
) -> anyhow::Result<()>
where
    S: Service<Request, Output = Resp, Error = Infallible> + Clone + 'static,
    Resp: IntoResponse + Send + 'static,
{
    // Signals are handled below, once, for both HTTP and maintenance tasks.
    let (shutdown, signal) = tokio::sync::oneshot::channel::<()>();
    let graceful = Shutdown::new(signal);

    let mut listener = graceful.spawn_task_fn(move |guard| async move {
        let app = AddInputExtensionLayer::new(ShutdownSignal(guard.clone_weak())).into_layer(app);
        let exec = Executor::graceful(guard);

        HttpServer::auto(exec)
            .listen(&addr, app)
            .await
            .map_err(|error| anyhow::anyhow!("HTTP listener on {addr} failed: {error}"))
    });

    // A failed listener must not leave a headless collector running jobs.
    let (listener_result, signal_result) = tokio::select! {
        result = &mut listener => (Some(match result {
            Ok(Err(error)) => Err(error),
            Ok(Ok(())) => Err(anyhow::anyhow!("HTTP listener stopped unexpectedly")),
            Err(error) => Err(anyhow::anyhow!("HTTP listener task failed: {error}")),
        }), Ok(())),
        result = stop => (None, result.context("Shutdown signal failed")),
    };

    if shutdown.send(()).is_err() {
        tracing::warn!("HTTP shutdown signal receiver already closed");
    }
    // A failed listener or signal source requires immediate cleanup.
    let grace = if listener_result.is_some() || signal_result.is_err() {
        Duration::ZERO
    } else {
        Duration::from_secs(30)
    };
    let drained = drain(graceful, jobs, grace).await;
    let served = if let Some(result) = listener_result {
        result
    } else {
        // Do not detach the listener on HTTP-drain timeout. Joining after abort
        // also handles the small race between guard release and task completion.
        listener.abort();
        match listener.await {
            Ok(result) => result,
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(anyhow::anyhow!("HTTP listener task failed: {error}")),
        }
    };
    if let Err(error) = &drained {
        tracing::error!(%error, "HTTP draining failed");
    }
    signal_result.and(served).and(drained)?;

    tracing::info!("Server shutdown complete");
    Ok(())
}

async fn shutdown_signal() -> anyhow::Result<()> {
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.context("Could not receive Ctrl+C")?;
            tracing::info!("Received Ctrl+C, starting graceful shutdown...");
        }
        result = async {
            #[cfg(unix)]
            {
                let mut sigterm = tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::terminate(),
                ).context("Could not install SIGTERM handler")?;
                sigterm.recv().await.context("SIGTERM signal stream closed")
            }
            #[cfg(not(unix))]
            {
                std::future::pending::<anyhow::Result<()>>().await
            }
        } => {
            result?;
            tracing::info!("Received SIGTERM, starting graceful shutdown...");
        }
    }
    Ok(())
}

pub(crate) async fn drain(
    graceful: Shutdown,
    jobs: Option<jobs::Jobs>,
    grace: Duration,
) -> anyhow::Result<()> {
    if let Some(jobs) = &jobs {
        jobs.stop();
    }
    // Both drains run even if HTTP times out; never detach maintenance jobs on
    // an early error. Their grace runs concurrently, not after HTTP's grace.
    let (http, ()) = tokio::join!(graceful.shutdown_with_limit(grace), async move {
        if let Some(jobs) = jobs {
            jobs.shutdown(grace).await;
        }
    });
    http.map(|_| ())
        .map_err(|e| anyhow::anyhow!("Graceful shutdown failed: {e:?}"))
}

#[cfg(test)]
mod tests;
