use super::*;
use crate::models::project;
use crate::time;

#[tokio::test]
async fn migrations_create_schema_and_preserve_data_when_reapplied() -> anyhow::Result<()> {
    let pool = test_pool().await;
    let created = project::create(&pool, "Survives restart").await?;

    sqlx::migrate!("./migrations/postgres").run(&pool).await?;

    let stored = project::find(&pool, created.id)
        .await?
        .expect("project preserved");
    assert_eq!(stored.api_key, created.api_key);

    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p')
           AND NOT c.relispartition AND c.relname <> '_sqlx_migrations'
         ORDER BY 1",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        tables,
        [
            "deploys",
            "error_occurrences",
            "errors",
            "mcp_tokens",
            "projects",
            "sessions",
            "settings",
            "span_rollups",
            "spans",
            "users"
        ]
    );
    Ok(())
}

#[tokio::test]
async fn day_partitions_take_over_default_rows_and_expire_whole_days() -> anyhow::Result<()> {
    let pool = test_pool().await;
    for (span_id, days) in [("old", 10), ("mid", 3), ("new", 0)] {
        sqlx::query(
            "INSERT INTO spans (trace_id, span_id, name, start_time_unix_nano, end_time_unix_nano,
                span_category, happened_at)
             VALUES ('trace', $1, 'x', 0, 1, 'internal', $2)",
        )
        .bind(span_id)
        .bind(time::days_ago(days))
        .execute(&pool)
        .await?;
    }
    for days in [10, 3] {
        sqlx::query("SELECT create_day_partition('spans', ($1 AT TIME ZONE 'UTC')::date)")
            .bind(time::days_ago(days))
            .execute(&pool)
            .await?;
    }
    maintain(&pool).await?;
    let placed: Vec<(String, String)> =
        sqlx::query_as("SELECT span_id, tableoid::regclass::text FROM spans ORDER BY span_id")
            .fetch_all(&pool)
            .await?;
    assert!(
        placed.iter().all(|(_, table)| table.starts_with("spans_p")),
        "{placed:?}"
    );
    let rolled_up = || {
        sqlx::query_scalar::<_, i64>("SELECT COALESCE(SUM(requests), 0)::bigint FROM span_rollups")
            .fetch_one(&pool)
    };
    assert_eq!(rolled_up().await?, 3, "moved rows are counted once");

    expire(&pool, "spans", "happened_at", time::days_ago(5)).await?;
    let left: Vec<String> = sqlx::query_scalar("SELECT span_id FROM spans ORDER BY span_id")
        .fetch_all(&pool)
        .await?;
    assert_eq!(left, ["mid", "new"]);
    assert_eq!(
        rolled_up().await?,
        2,
        "expired days take their rollups along"
    );
    Ok(())
}

#[tokio::test]
async fn jobs_skip_while_another_instance_holds_them() -> anyhow::Result<()> {
    let pool = test_pool().await;
    let lock = "SELECT pg_advisory_lock(hashtext('miniapm'), hashtext('test.lock'))";
    let unlock = "SELECT pg_advisory_unlock(hashtext('miniapm'), hashtext('test.lock'))";
    let mut other_instance = pool.acquire().await?;
    sqlx::query(lock).execute(&mut *other_instance).await?;

    let ran = std::sync::atomic::AtomicBool::new(false);
    let job = async {
        ran.store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    };
    assert!(!exclusively(&pool, "test.lock", job).await?);
    assert!(!ran.load(std::sync::atomic::Ordering::Relaxed));

    sqlx::query(unlock).execute(&mut *other_instance).await?;
    let pid_before: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&pool)
        .await?;
    let failing = async { Err::<(), _>(anyhow::anyhow!("boom")) };
    assert_eq!(
        exclusively(&pool, "test.lock", failing)
            .await
            .unwrap_err()
            .to_string(),
        "boom"
    );
    let available: bool = sqlx::query_scalar(
        "SELECT pg_try_advisory_lock(hashtext('miniapm'), hashtext('test.lock'))",
    )
    .fetch_one(&mut *other_instance)
    .await?;
    assert!(
        available,
        "a failed run releases the lock for a different session"
    );
    sqlx::query(unlock).execute(&mut *other_instance).await?;
    assert!(
        exclusively(&pool, "test.lock", async { Ok(()) }).await?,
        "a successful run can acquire the released lock"
    );
    let pid_after: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&pool)
        .await?;
    assert_eq!(
        pid_after, pid_before,
        "normal completion must keep the healthy session reusable"
    );
    Ok(())
}

#[tokio::test]
async fn cancelled_jobs_release_their_session_lock() -> anyhow::Result<()> {
    use std::time::Duration;
    use tokio::sync::oneshot;

    let pool = test_pool().await;
    let observer = PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*pool.connect_options()).clone())
        .await?;
    let schema: String = sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(&pool)
        .await?;
    let name = format!("{schema}.cancelled");
    let (started, running) = oneshot::channel();
    let worker = tokio::spawn({
        let pool = pool.clone();
        let name = name.clone();
        async move {
            exclusively(&pool, &name, async {
                started.send(()).expect("job observer alive");
                std::future::pending::<anyhow::Result<()>>().await
            })
            .await
        }
    });
    tokio::time::timeout(Duration::from_secs(5), running).await??;
    assert!(
        !exclusively(&observer, &name, async { Ok(()) }).await?,
        "another collector must skip while the job runs"
    );
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());

    // Keep the original pool alive: closing the whole pool would hide a leaked lock.
    let mut observer_session = observer.acquire().await?;
    tokio::time::timeout(
        Duration::from_secs(5),
        sqlx::query("SELECT pg_advisory_lock(hashtext('miniapm'), hashtext($1))")
            .bind(&name)
            .execute(&mut *observer_session),
    )
    .await
    .context("cancelled job left its advisory lock held")??;
    let unlocked: bool =
        sqlx::query_scalar("SELECT pg_advisory_unlock(hashtext('miniapm'), hashtext($1))")
            .bind(&name)
            .fetch_one(&mut *observer_session)
            .await?;
    assert!(
        unlocked,
        "the other collector acquired and released the lock"
    );
    drop(observer_session);
    // The lock connection must also give its pool slot back. The test pool has
    // two slots: one for the next lock holder and one for its database work.
    assert!(
        tokio::time::timeout(
            Duration::from_secs(5),
            exclusively(&pool, &name, async {
                let value: i32 = sqlx::query_scalar("SELECT 1").fetch_one(&pool).await?;
                assert_eq!(value, 1);
                Ok(())
            })
        )
        .await??
    );
    observer.close().await;
    pool.close().await;
    Ok(())
}

#[tokio::test]
async fn connections_use_utc_and_plan_with_their_parameters() -> anyhow::Result<()> {
    let pool = test_pool().await;
    let settings: (String, String) =
        sqlx::query_as("SELECT current_setting('timezone'), current_setting('plan_cache_mode')")
            .fetch_one(&pool)
            .await?;
    assert_eq!(settings, ("UTC".into(), "force_custom_plan".into()));
    Ok(())
}
