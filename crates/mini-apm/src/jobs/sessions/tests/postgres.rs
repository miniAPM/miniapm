use super::*;
use std::sync::Arc;
use tokio::sync::Notify;

async fn reject_cleanup(pool: &DbPool, failures: u32, code: &str) -> anyhow::Result<()> {
    // Sequence increments survive statement rollback, unlike updates to a counter table.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE SEQUENCE cleanup_attempts;
         CREATE FUNCTION fail_cleanup() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
           IF nextval('cleanup_attempts') <= {failures} THEN
             RAISE EXCEPTION USING ERRCODE = '{code}', MESSAGE = 'cleanup failed';
           END IF;
           RETURN NULL;
         END $$;
         CREATE TRIGGER fail_cleanup BEFORE DELETE ON sessions
           FOR EACH STATEMENT EXECUTE FUNCTION fail_cleanup();"
    )))
    .execute(pool)
    .await?;
    Ok(())
}

#[tokio::test]
async fn cleanup_recovers_or_stops_for_classified_database_errors() -> anyhow::Result<()> {
    for (code, failures, deleted) in [
        ("40001", 2, 1),
        ("40P01", 1, 1),
        ("55P03", 1, 1),
        ("40001", 10, 0),
        ("23505", 1, 0),
        ("42501", 1, 0),
        ("57014", 1, 0),
        ("08006", 1, 0),
    ] {
        let pool = crate::db::test_pool().await;
        let cutoff = seed(&pool).await?;
        reject_cleanup(&pool, failures, code).await?;
        let result = delete_with_retry(&pool, cutoff, |_| std::future::ready(())).await;
        if deleted == 1 {
            let outcome = result?;
            assert_eq!(outcome.into_inner(), 1);
            assert_eq!(tokens(&pool).await?, ["active", "boundary"]);
        } else {
            let error = result.unwrap_err();
            assert_eq!(
                error
                    .cause()
                    .as_database_error()
                    .and_then(sqlx::error::DatabaseError::code),
                Some(code.into()),
                "cleanup must propagate its database failure"
            );
            assert_eq!(tokens(&pool).await?, ["active", "boundary", "expired"]);
        }
        pool.close().await;
    }
    Ok(())
}

#[tokio::test]
async fn cleanup_holds_its_job_lock_during_backoff_and_releases_it_on_cancellation()
-> anyhow::Result<()> {
    let pool = crate::db::test_pool().await;
    let cutoff = seed(&pool).await?;
    reject_cleanup(&pool, 10, "40001").await?;
    let observer = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*pool.connect_options()).clone())
        .await?;
    let schema: String = sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(&pool)
        .await?;
    let name = format!("{schema}.sessions.cleanup");
    let sleeping = Arc::new(Notify::new());
    let worker = tokio::spawn({
        let pool = pool.clone();
        let name = name.clone();
        let sleeping = sleeping.clone();
        async move {
            crate::db::exclusively(&pool, &name, async {
                delete_with_retry(&pool, cutoff, |_| {
                    sleeping.notify_one();
                    std::future::pending::<()>()
                })
                .await?;
                Ok(())
            })
            .await
        }
    });
    tokio::time::timeout(Duration::from_secs(5), sleeping.notified()).await?;
    assert!(
        !crate::db::exclusively(&observer, &name, async {
            panic!("another collector must not execute cleanup during backoff");
        })
        .await?
    );
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    let mut connection = observer.acquire().await?;
    tokio::time::timeout(
        Duration::from_secs(5),
        sqlx::query("SELECT pg_advisory_lock(hashtext('miniapm'), hashtext($1))")
            .bind(&name)
            .execute(&mut *connection),
    )
    .await??;
    let unlocked: bool =
        sqlx::query_scalar("SELECT pg_advisory_unlock(hashtext('miniapm'), hashtext($1))")
            .bind(&name)
            .fetch_one(&mut *connection)
            .await?;
    assert!(unlocked);
    drop(connection);
    assert_eq!(tokens(&pool).await?, ["active", "boundary", "expired"]);
    sqlx::query("DROP TRIGGER fail_cleanup ON sessions")
        .execute(&pool)
        .await?;
    cleanup(&pool).await?;
    assert_eq!(tokens(&pool).await?, ["active"]);
    observer.close().await;
    pool.close().await;
    Ok(())
}
