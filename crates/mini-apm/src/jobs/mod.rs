mod retention;

use crate::{DbPool, config::Config, models, self_monitor};
use std::future::Future;
use std::time::Duration;
use tokio::time::interval;

const HOUR: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_secs(86400);

pub fn start(pool: DbPool, config: Config) {
    let p = pool.clone();
    every("sessions.cleanup", HOUR, move || {
        let p = p.clone();
        async move {
            let count = models::user::delete_expired_sessions(&p).await?;
            if count > 0 {
                tracing::info!("Cleaned up {} expired sessions", count);
            }
            Ok(())
        }
    });

    every("retention", DAY, move || {
        let (p, c) = (pool.clone(), config.clone());
        async move { retention::cleanup(&p, &c).await }
    });

    tracing::info!("Background jobs started");
}

fn every<F, Fut>(name: &'static str, period: Duration, job: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send,
{
    tokio::spawn(async move {
        let mut interval = interval(period);
        loop {
            interval.tick().await;
            if let Err(e) = self_monitor::trace_job(name, job()).await {
                tracing::error!("Job {} failed: {:#}", name, e);
            }
        }
    });
}
