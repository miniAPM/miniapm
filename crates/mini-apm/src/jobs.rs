mod retention;
mod sessions;

use crate::{DbPool, config::Config, db, self_monitor};
use std::future::Future;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::interval;

const HOUR: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_hours(24);

/// Owned maintenance tasks. Dropping the owner aborts any remaining tasks.
#[derive(Debug)]
#[must_use = "keep the job owner alive and call shutdown before closing the database"]
pub struct Jobs {
    stopping: watch::Sender<bool>,
    tasks: JoinSet<()>,
}

pub fn start(pool: DbPool, config: Config) -> Jobs {
    let mut jobs = Jobs::new();
    let p = pool.clone();
    jobs.every(pool.clone(), "sessions.cleanup", HOUR, move || {
        let p = p.clone();
        async move { sessions::cleanup(&p).await }
    });

    let p = pool.clone();
    jobs.every(pool, "retention", DAY, move || {
        let (p, c) = (p.clone(), config.clone());
        async move { retention::cleanup(&p, &c).await }
    });

    tracing::info!("Background jobs started");
    jobs
}

impl Jobs {
    fn new() -> Self {
        let (stopping, _) = watch::channel(false);
        Self {
            stopping,
            tasks: JoinSet::new(),
        }
    }

    /// Stop scheduling immediately, without interrupting the current runs.
    pub(crate) fn stop(&self) {
        self.stopping.send_replace(true);
    }

    /// Allow current runs to finish within `grace`, then abort and join them.
    /// Joining ensures job futures (including advisory-lock guards) are dropped.
    pub async fn shutdown(mut self, grace: Duration) {
        self.stop();
        if tokio::time::timeout(grace, self.join()).await.is_err() {
            tracing::warn!("Background job shutdown grace expired; cancelling remaining jobs");
            self.tasks.abort_all();
            self.join().await;
        }
    }

    async fn join(&mut self) {
        while let Some(result) = self.tasks.join_next().await {
            if let Err(error) = result
                && !error.is_cancelled()
            {
                tracing::error!(%error, "Background job task failed");
            }
        }
    }

    /// Run `job` every `period`, skipping a turn while another instance runs it.
    fn every<F, Fut>(&mut self, pool: DbPool, name: &'static str, period: Duration, job: F)
    where
        F: Fn() -> Fut + Send + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send,
    {
        let mut stopping = self.stopping.subscribe();
        self.tasks.spawn(async move {
            let mut interval = interval(period);
            loop {
                tokio::select! {
                    biased;
                    _ = stopping.wait_for(|stopping| *stopping) => break,
                    _ = interval.tick() => {}
                }
                // A running job, including its retries, gets the shutdown grace.
                match self_monitor::trace_job(name, db::exclusively(&pool, name, job())).await {
                    Ok(true) => {}
                    Ok(false) => tracing::debug!("Job {name} skipped: another instance runs it"),
                    Err(e) => tracing::error!("Job {} failed: {:#}", name, e),
                }
            }
        });
    }
}

#[cfg(test)]
mod tests;
