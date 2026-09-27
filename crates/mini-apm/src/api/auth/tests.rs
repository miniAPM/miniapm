use super::*;
use crate::{db, models::project::Project};
use rama::Layer;
use rama::extensions::ExtensionsRef;
use rama::http::body::util::BodyExt;
use rama::http::{Body, Request, Response, StatusCode};
use rama::service::{Service, service_fn};
use std::convert::Infallible;

/// Serves one request through the auth layer to a handler echoing the project id
async fn serve(authorization: impl FnOnce(&Project) -> Option<String>) -> (Response, Project) {
    let pool = db::test_pool().await;
    let project = crate::models::project::ensure_default_project(&pool)
        .await
        .unwrap();

    let echo = service_fn(|req: Request| async move {
        let id = req
            .extensions()
            .get_ref::<ProjectContext>()
            .and_then(|c| c.project_id);
        Ok::<_, Infallible>(Response::new(Body::from(format!("{id:?}"))))
    });

    let mut req = Request::builder().uri("/");
    if let Some(value) = authorization(&project) {
        req = req.header("Authorization", value);
    }
    let res = ProjectKeyAuthorizer::layer(pool)
        .into_layer(echo)
        .serve(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    (res, project)
}

#[tokio::test]
async fn test_rejects_missing_or_invalid_credentials() {
    for auth in [None, Some("Basic eHl6OnB3"), Some("Bearer wrong_key")] {
        let (res, _) = serve(|_| auth.map(String::from)).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{auth:?}");
    }
}

#[tokio::test]
async fn test_accepts_valid_key_and_injects_project() {
    let (res, project) = serve(|p| Some(format!("Bearer {}", p.api_key))).await;
    assert_eq!(res.status(), StatusCode::OK);

    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, format!("{:?}", Some(project.id)));
}
