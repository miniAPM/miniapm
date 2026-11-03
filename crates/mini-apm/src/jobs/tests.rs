use super::*;
use rama::graceful::Shutdown;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;

#[tokio::test]
async fn stop_prevents_the_first_scheduled_run() {
    let pool = db::test_pool().await;
    let mut jobs = Jobs::new();
    let runs = Arc::new(AtomicUsize::new(0));
    jobs.every(pool.clone(), "shutdown.not_started", HOUR, {
        let runs = runs.clone();
        move || {
            runs.fetch_add(1, Ordering::SeqCst);
            async { Ok(()) }
        }
    });
    // No yield between scheduling and stopping: the first interval tick is ready.
    jobs.shutdown(Duration::from_secs(5)).await;
    assert_eq!(runs.load(Ordering::SeqCst), 0);
    pool.close().await;
}

async fn probe_pool() -> DbPool {
    let pool = db::test_pool().await;
    sqlx::query("CREATE TABLE shutdown_probe (value INTEGER NOT NULL)")
        .execute(&pool)
        .await
        .unwrap();
    pool
}

#[tokio::test]
async fn running_job_can_commit_during_grace_without_another_run() -> anyhow::Result<()> {
    let pool = probe_pool().await;
    let started = Arc::new(Notify::new());
    let finish = Arc::new(Notify::new());
    let mut jobs = Jobs::new();
    jobs.every(pool.clone(), "shutdown.commit", HOUR, {
        let pool = pool.clone();
        let started = started.clone();
        let finish = finish.clone();
        move || {
            let pool = pool.clone();
            let started = started.clone();
            let finish = finish.clone();
            async move {
                started.notify_one();
                finish.notified().await;
                sqlx::query("INSERT INTO shutdown_probe VALUES (1)")
                    .execute(&pool)
                    .await?;
                Ok(())
            }
        }
    });
    tokio::time::timeout(Duration::from_secs(5), started.notified()).await?;
    let mut shutdown = Box::pin(jobs.shutdown(Duration::from_secs(5)));
    tokio::select! {
        biased;
        () = &mut shutdown => panic!("shutdown did not wait for the running job"),
        () = std::future::ready(()) => {}
    }
    finish.notify_one();
    shutdown.await;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM shutdown_probe")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 1);
    pool.close().await;
    Ok(())
}

#[tokio::test]
async fn http_timeout_still_cancels_and_joins_the_running_job() -> anyhow::Result<()> {
    let pool = probe_pool().await;
    let started = Arc::new(Notify::new());
    let mut jobs = Jobs::new();
    jobs.every(pool.clone(), "shutdown.cancel", HOUR, {
        let pool = pool.clone();
        let started = started.clone();
        move || {
            let pool = pool.clone();
            let started = started.clone();
            async move {
                let mut transaction = db::begin_write(&pool).await?;
                sqlx::query("INSERT INTO shutdown_probe VALUES (1)")
                    .execute(&mut *transaction)
                    .await?;
                started.notify_one();
                std::future::pending::<()>().await;
                transaction.commit().await?;
                Ok(())
            }
        }
    });
    tokio::time::timeout(Duration::from_secs(5), started.notified()).await?;
    let http = Shutdown::no_signal();
    let connection = http.guard(); // Deliberately prevent HTTP from draining.
    let result = crate::server::drain(http, Some(jobs), Duration::ZERO).await;
    assert!(result.is_err());
    drop(connection);
    // No task may retain the transaction after draining, including the HTTP
    // error path. Its uncommitted work must not survive cancellation.
    let count: i64 = tokio::time::timeout(
        Duration::from_secs(5),
        sqlx::query_scalar("SELECT COUNT(*) FROM shutdown_probe").fetch_one(&pool),
    )
    .await??;
    assert_eq!(count, 0);

    #[cfg(feature = "postgres")]
    {
        // Keep the original pool alive to expose any pooled advisory-lock leak.
        let observer = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with((*pool.connect_options()).clone())
            .await?;
        let mut session = observer.acquire().await?;
        tokio::time::timeout(
            Duration::from_secs(5),
            sqlx::query(
                "SELECT pg_advisory_lock(hashtext('miniapm'), hashtext('shutdown.cancel'))",
            )
            .execute(&mut *session),
        )
        .await??;
        let unlocked: bool = sqlx::query_scalar(
            "SELECT pg_advisory_unlock(hashtext('miniapm'), hashtext('shutdown.cancel'))",
        )
        .fetch_one(&mut *session)
        .await?;
        assert!(unlocked);
        drop(session);
        observer.close().await;
    }
    tokio::time::timeout(Duration::from_secs(5), pool.close()).await?;
    Ok(())
}
