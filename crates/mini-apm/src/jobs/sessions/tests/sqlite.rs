use super::*;
use std::sync::Arc;
use tokio::sync::Mutex;

async fn file_pool() -> anyhow::Result<(DbPool, tempfile::TempDir)> {
    let directory = tempfile::tempdir()?;
    let seed = crate::db::init(&crate::config::Config {
        sqlite_path: directory
            .path()
            .join("sessions.sqlite3")
            .to_string_lossy()
            .into_owned(),
        ..crate::config::Config::default()
    })
    .await?;
    let options = (*seed.connect_options())
        .clone()
        .busy_timeout(Duration::ZERO);
    seed.close().await;
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await?;
    Ok((pool, directory))
}

#[tokio::test]
async fn busy_cleanup_recovers_without_deleting_the_cutoff_boundary() -> anyhow::Result<()> {
    let (pool, _directory) = file_pool().await?;
    let cutoff = seed(&pool).await?;
    let blocker = Arc::new(Mutex::new(Some(crate::db::begin_write(&pool).await?)));
    let outcome = delete_with_retry(&pool, cutoff, |_| {
        let blocker = blocker.clone();
        async move {
            let transaction = blocker.lock().await.take();
            if let Some(transaction) = transaction {
                transaction.rollback().await.unwrap();
            }
        }
    })
    .await?;
    assert_eq!(outcome.into_inner(), 1);
    assert_eq!(tokens(&pool).await?, ["active", "boundary"]);
    pool.close().await;
    Ok(())
}

#[tokio::test]
async fn persistent_contention_preserves_sessions() -> anyhow::Result<()> {
    let (pool, _directory) = file_pool().await?;
    let cutoff = seed(&pool).await?;
    let blocker = crate::db::begin_write(&pool).await?;
    let error = delete_with_retry(&pool, cutoff, |_| std::future::ready(()))
        .await
        .unwrap_err();
    assert!(retryable(error.cause()));
    blocker.rollback().await?;
    assert_eq!(tokens(&pool).await?, ["active", "boundary", "expired"]);
    pool.close().await;
    Ok(())
}

#[tokio::test]
async fn permanent_storage_failure_preserves_sessions() -> anyhow::Result<()> {
    let pool = crate::db::test_pool().await;
    let cutoff = seed(&pool).await?;
    sqlx::raw_sql(
        "CREATE TRIGGER reject_cleanup BEFORE DELETE ON sessions
         BEGIN SELECT RAISE(ABORT, 'cleanup rejected'); END;",
    )
    .execute(&pool)
    .await?;
    let error = delete_with_retry(&pool, cutoff, |_| std::future::ready(()))
        .await
        .unwrap_err();
    assert!(!retryable(error.cause()));
    assert_eq!(tokens(&pool).await?, ["active", "boundary", "expired"]);
    Ok(())
}
