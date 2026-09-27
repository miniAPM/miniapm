use super::*;
use crate::{db, models::project};
use rama::http::Body;
use rama::service::service_fn;
use std::time::Duration;
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
async fn test_records_requests_and_errors_into_self_project() {
    let pool = db::test_pool().await;
    let project = project::ensure_self_project(&pool).await.unwrap();
    let monitor = SelfMonitor::start(pool.clone(), project.id, "test");

    let ok = service_fn(async |_: Request| Ok::<_, Infallible>(Response::new(Body::empty())));
    let app = SelfMonitorLayer::new(Some(monitor.clone())).into_layer(ok);
    for path in ["/errors/42", "/health", "/static/style.css"] {
        let req = Request::builder().uri(path).body(Body::empty()).unwrap();
        app.serve(req).await.unwrap();
    }

    let monitor: &'static OnceLock<SelfMonitor> = Box::leak(Box::new(OnceLock::from(monitor)));
    let subscriber = tracing_subscriber::registry().with(ErrorCaptureLayer { monitor });
    tracing::subscriber::with_default(subscriber, || {
        tracing::warn!("not an error");
        tracing::error!(disk = "sda", "disk full");
    });

    let mut recorded = (vec![], vec![]);
    for _ in 0..100 {
        let spans: Vec<(String, String)> =
            sqlx::query_as("SELECT name, service_name FROM spans WHERE project_id = ?1")
                .bind(project.id)
                .fetch_all(&pool)
                .await
                .unwrap();
        let errors: Vec<(String, String)> =
            sqlx::query_as("SELECT exception_class, message FROM errors WHERE project_id = ?1")
                .bind(project.id)
                .fetch_all(&pool)
                .await
                .unwrap();
        recorded = (spans, errors);
        if !recorded.0.is_empty() && !recorded.1.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let spans = vec![("GET /errors/{id}".to_string(), "test".to_string())];
    let errors = vec![(
        module_path!().to_string(),
        "disk full disk=\"sda\"".to_string(),
    )];
    assert_eq!(recorded, (spans, errors));
}
