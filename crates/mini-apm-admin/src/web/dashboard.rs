use std::time::Duration;

use askama::Template;
use mini_apm::server::ShutdownSignal;
use mini_apm::time;
use rama::error::BoxError;
use rama::extensions::Extensions;
use rama::futures::{FutureExt, Stream, StreamExt, future, stream};
use rama::http::service::web::extract::State;
use rama::http::service::web::response::Sse;
use rama::http::sse::datastar::{DatastarEvent, PatchElements};
use tokio::time::MissedTickBehavior;

use crate::template::HtmlTemplate;
use mini_apm::{
    DbPool,
    models::{self, span},
};

use super::project_context::WebProjectContext;

const LIVE_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub live: DashboardLive,
    pub ctx: WebProjectContext,
}

/// The part of the dashboard the live stream re-renders
#[derive(Template)]
#[template(path = "dashboard/live.html")]
pub struct DashboardLive {
    pub requests_24h: i64,
    pub errors_24h: i64,
    pub avg_ms: i64,
    pub p95_ms: i64,
    pub p99_ms: i64,
    pub recent_errors: Vec<models::AppError>,
    pub slow_requests: Vec<span::TraceSummary>,
    pub hourly_stats: Vec<span::TimeSeriesPoint>,
    pub deploy_hours: Vec<String>,
}

impl DashboardLive {
    async fn load(pool: &DbPool, project_id: Option<i64>) -> Self {
        let since = time::hours_ago(24);

        let requests_24h = span::count_since(pool, project_id, since)
            .await
            .inspect_err(|e| tracing::error!("Failed to load requests 24h: {e:#}"))
            .unwrap_or(0);
        let errors_24h = models::error::count_since(pool, project_id, since)
            .await
            .inspect_err(|e| tracing::error!("Failed to load errors 24h: {e:#}"))
            .unwrap_or(0);
        let latency_stats = span::latency_stats_since(pool, project_id, since)
            .await
            .inspect_err(|e| tracing::error!("Failed to load latency stats: {e:#}"))
            .unwrap_or(span::LatencyStats {
                avg_ms: 0,
                p95_ms: 0,
                p99_ms: 0,
            });
        let recent_errors = models::error::list(pool, project_id, Some("open"), 5)
            .await
            .inspect_err(|e| tracing::error!("Failed to load recent errors: {e:#}"))
            .unwrap_or_default();
        let slow_requests = span::slow_traces(pool, project_id, 500.0, 5)
            .await
            .inspect_err(|e| tracing::error!("Failed to load slow requests: {e:#}"))
            .unwrap_or_default();
        let hourly_stats = span::hourly_stats(pool, project_id, 24)
            .await
            .inspect_err(|e| tracing::error!("Failed to load hourly stats: {e:#}"))
            .unwrap_or_default();
        let deploy_hours = models::deploy::list_since(pool, project_id, since)
            .await
            .inspect_err(|e| tracing::error!("Failed to load deploys: {e:#}"))
            .unwrap_or_default()
            .into_iter()
            .map(|deploy| deploy.deployed_at.hour_label())
            .collect();

        Self {
            requests_24h,
            errors_24h,
            avg_ms: latency_stats.avg_ms,
            p95_ms: latency_stats.p95_ms,
            p99_ms: latency_stats.p99_ms,
            recent_errors,
            slow_requests,
            hourly_stats,
            deploy_hours,
        }
    }

    fn into_event(self) -> Result<DatastarEvent, BoxError> {
        let elements = self.render()?.try_into()?;
        Ok(PatchElements::new(elements).try_into_datastar_event()?)
    }
}

pub async fn index(
    State(pool): State<DbPool>,
    ctx: WebProjectContext,
) -> HtmlTemplate<DashboardTemplate> {
    let live = DashboardLive::load(&pool, ctx.project_id()).await;
    HtmlTemplate(DashboardTemplate { live, ctx })
}

/// Datastar stream patching the live dashboard right away, then every
/// `LIVE_INTERVAL`, until the client leaves or the server shuts down
pub async fn live(
    State(pool): State<DbPool>,
    ctx: WebProjectContext,
    extensions: Extensions,
) -> Sse<impl Stream<Item = Result<DatastarEvent, BoxError>>> {
    let project_id = ctx.project_id();
    let mut ticks = tokio::time::interval(LIVE_INTERVAL);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let updates = stream::unfold((pool, ticks), move |(pool, mut ticks)| async move {
        ticks.tick().await;
        let event = DashboardLive::load(&pool, project_id).await.into_event();
        Some((event, (pool, ticks)))
    });

    let shutdown = match extensions.get_arc::<ShutdownSignal>() {
        Some(signal) => async move { signal.triggered().await }.boxed(),
        None => future::pending().boxed(),
    };
    Sse::new(updates.take_until(shutdown))
}
