use super::*;
use crate::{db, models::project};
use rama::http::Body;
use rama::service::service_fn;
use std::time::Duration;
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
    let monitor = SelfMonitor::start(pool.clone(), project.id, "test");

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

    let mut recorded = (vec![], vec![]);
    for _ in 0..100 {
        let traces: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT r.name, r.root_span_type, c.db_statement FROM spans r
             JOIN spans c ON c.trace_id = r.trace_id AND c.parent_span_id = r.span_id
             WHERE r.project_id = $1 AND r.parent_span_id IS NULL ORDER BY r.name",
        )
        .bind(project.id)
        .fetch_all(&pool)
        .await
        .unwrap();
        let errors: Vec<String> = sqlx::query_scalar(
            "SELECT message FROM errors WHERE project_id = $1 AND exception_class = $2",
        )
        .bind(project.id)
        .bind(module_path!())
        .fetch_all(&pool)
        .await
        .unwrap();
        recorded = (traces, errors);
        if recorded.0.len() == 2 && !recorded.1.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

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
    assert_eq!(recorded, (traces, errors));
}
