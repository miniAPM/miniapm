mod retention;

use crate::{DbPool, config::Config, db, models, self_monitor};
use std::future::Future;
use std::time::Duration;
use tokio::time::interval;

const HOUR: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_secs(86400);

pub fn start(pool: DbPool, config: Config) {
    let p = pool.clone();
    every(pool.clone(), "sessions.cleanup", HOUR, move || {
        let p = p.clone();
        async move {
            let count = models::user::delete_expired_sessions(&p).await?;
            if count > 0 {
                tracing::info!("Cleaned up {} expired sessions", count);
            }
            Ok(())
        }
    });

    let p = pool.clone();
    every(pool, "retention", DAY, move || {
        let (p, c) = (p.clone(), config.clone());
        async move { retention::cleanup(&p, &c).await }
    });

    tracing::info!("Background jobs started");
}

/// Run `job` every `period`, skipping a turn while another instance runs it
fn every<F, Fut>(pool: DbPool, name: &'static str, period: Duration, job: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send,
{
    tokio::spawn(async move {
        let mut interval = interval(period);
        loop {
            interval.tick().await;
            match self_monitor::trace_job(name, db::exclusively(&pool, name, job())).await {
                Ok(true) => {}
                Ok(false) => tracing::debug!("Job {name} skipped: another instance runs it"),
                Err(e) => tracing::error!("Job {} failed: {:#}", name, e),
            }
        }
    });
}
