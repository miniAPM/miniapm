use super::*;
use crate::{db, models::project};
use rama::http::Body;
use rama::service::service_fn;
use tracing_subscriber::Layer as _;
use tracing_subscriber::layer::SubscriberExt;

#[test]
fn test_route_of_collapses_ids() {
    for (path, route) in [
        ("/errors", "/errors"),
        ("/errors/42", "/errors/{id}"),
        ("/traces/0af7651916cd43dd8448eb211c80319c", "/traces/{id}"),
        ("/ingest/v1/traces", "/ingest/v1/traces"),
    ] {
        assert_eq!(route_of(path), route);
    }
}

#[tokio::test]
async fn test_records_requests_jobs_queries_and_errors() {
    let pool = db::test_pool().await;
    let project = project::ensure_self_project(&pool).await.unwrap();
    let (monitor, writer) = SelfMonitor::start(pool.clone(), project.id, "test");

    let lock: &'static OnceLock<SelfMonitor> = Box::leak(Box::new(OnceLock::from(monitor.clone())));
    let layer = CaptureLayer { monitor: lock }.with_filter(CaptureLayer::filter());
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(layer)).unwrap();

    let handler_pool = pool.clone();
    let handler = service_fn(move |_: Request| {
        let pool = handler_pool.clone();
        async move {
            sqlx::query("SELECT 1").execute(&pool).await.unwrap();
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }
    });
    let app = SelfMonitorLayer::new(Some(monitor.clone())).into_layer(handler);
    for path in ["/errors/42", "/health"] {
        let req = Request::builder().uri(path).body(Body::empty()).unwrap();
        app.serve(req).await.unwrap();
    }
    monitor
        .trace_job("test.job", async {
            sqlx::query("SELECT 2").execute(&pool).await?;
            Ok(())
        })
        .await
        .unwrap();
    tracing::warn!("not an error");
    tracing::error!(disk = "sda", "disk full");

    // Sender clones stay alive in the app and subscriber. Shutdown must close
    // admission and flush explicitly, rather than waiting for those to drop.
    writer.shutdown().await.unwrap();
    assert!(monitor.tx.is_closed());
    let recorded_traces: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT r.name, r.root_span_type, c.db_statement FROM spans r
             JOIN spans c ON c.trace_id = r.trace_id AND c.parent_span_id = r.span_id
             WHERE r.project_id = $1 AND r.parent_span_id IS NULL ORDER BY r.name",
    )
    .bind(project.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    let recorded_errors: Vec<String> = sqlx::query_scalar(
        "SELECT message FROM errors WHERE project_id = $1 AND exception_class = $2",
    )
    .bind(project.id)
    .bind(module_path!())
    .fetch_all(&pool)
    .await
    .unwrap();

    let traces = vec![
        (
            "GET /errors/{id}".to_string(),
            "web".to_string(),
            "SELECT 1".to_string(),
        ),
        (
            "test.job".to_string(),
            "job".to_string(),
            "SELECT 2".to_string(),
        ),
    ];
    let errors = vec!["disk full disk=\"sda\"".to_string()];
    assert_eq!((recorded_traces, recorded_errors), (traces, errors));
    pool.close().await;
}

#[tokio::test]
async fn shutdown_flushes_multiple_batches_and_rejects_late_records() -> anyhow::Result<()> {
    let pool = db::test_pool().await;
    let project = project::ensure_self_project(&pool).await?;
    let (monitor, writer) = SelfMonitor::start(pool.clone(), project.id, "flush-test");
    let clone = monitor.clone();
    for _ in 0..BATCH + 3 {
        monitor.trace_job("buffered", async { Ok(()) }).await?;
    }
    writer.shutdown().await?;
    clone.trace_job("late", async { Ok(()) }).await?;
    assert!(clone.tx.is_closed());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM spans WHERE project_id = $1")
        .bind(project.id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, i64::try_from(BATCH + 3)?);
    pool.close().await;
    Ok(())
}

#[tokio::test]
async fn stalled_writer_is_cancelled_and_joined_at_the_flush_deadline() -> anyhow::Result<()> {
    let pool = db::test_pool().await;
    let project = project::ensure_self_project(&pool).await?;
    let mut connections = Vec::new();
    for _ in 0..pool.options().get_max_connections() {
        connections.push(pool.acquire().await?);
    }
    let (monitor, writer) = SelfMonitor::start(pool.clone(), project.id, "stalled-test");
    monitor.trace_job("blocked", async { Ok(()) }).await?;
    let error = writer.drain(Duration::ZERO).await.unwrap_err();
    assert!(error.to_string().contains("remaining records discarded"));
    assert!(monitor.tx.is_closed());
    drop(connections);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM spans WHERE project_id = $1")
        .bind(project.id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 0);
    tokio::time::timeout(Duration::from_secs(5), pool.close()).await?;
    Ok(())
}
