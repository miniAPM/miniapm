use super::*;
use rama::http::Body;
use rama::http::header::RETRY_AFTER;
use rama::net::address::SocketAddress;

fn request(uri: &str, peer: &str, forwarded_for: Option<&str>) -> Request {
    let mut req = Request::builder().uri(uri);
    if let Some(chain) = forwarded_for {
        req = req.header("X-Forwarded-For", chain);
    }
    let req = req.body(Body::empty()).unwrap();
    let peer: IpAddr = peer.parse().unwrap();
    req.extensions()
        .insert(SocketInfo::new(None, SocketAddress::new(peer, 40000)));
    req
}

async fn app() -> impl Service<Request, Output = Response, Error = Infallible> {
    let config = mini_apm::config::Config::default();
    make_app(mini_apm::db::init(&config).await.unwrap())
}

#[tokio::test]
async fn test_health_and_not_found() {
    let app = app().await;
    for (uri, expected) in [
        ("/health", StatusCode::OK),
        ("/nope", StatusCode::NOT_FOUND),
        ("/auth/users", StatusCode::NOT_FOUND),
        ("/auth/change-password", StatusCode::NOT_FOUND),
    ] {
        let res = app.serve(request(uri, "203.0.113.1", None)).await.unwrap();
        assert_eq!(res.status(), expected, "{uri}");
    }
}

#[tokio::test]
async fn test_rate_limits_per_client_ip() {
    let app = app().await;

    for _ in 0..100 {
        let res = app
            .serve(request("/nope", "203.0.113.1", None))
            .await
            .unwrap();
        assert_ne!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    }
    let res = app
        .serve(request("/nope", "203.0.113.1", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(res.headers().contains_key(RETRY_AFTER));

    // X-Forwarded-For only counts from a local proxy, and only its last hop
    for (peer, forwarded, limited) in [
        ("203.0.113.2", None, false),
        ("203.0.113.1", Some("198.51.100.7"), true),
        ("10.0.0.2", Some("198.51.100.7, 203.0.113.1"), true),
        ("10.0.0.2", Some("203.0.113.1, 198.51.100.7"), false),
    ] {
        let res = app.serve(request("/nope", peer, forwarded)).await.unwrap();
        let got = res.status() == StatusCode::TOO_MANY_REQUESTS;
        assert_eq!(got, limited, "{peer} {forwarded:?}");
    }
}

#[tokio::test]
async fn test_pages_follow_selected_project() {
    use mini_apm::models::{error, project};
    use rama::http::body::util::BodyExt;

    let config = mini_apm::config::Config::default();
    let pool = mini_apm::db::init(&config).await.unwrap();
    let default = project::ensure_default_project(&pool).await.unwrap();
    let other = project::create(&pool, "Other").await.unwrap();
    let only_in_other = error::IncomingError {
        exception_class: "OnlyInOtherError".into(),
        message: "boom".into(),
        backtrace: vec![],
        fingerprint: "fp".into(),
        request_id: None,
        user_id: None,
        params: None,
        timestamp: None,
        source_context: None,
    };
    error::insert(&pool, &only_in_other, Some(other.id))
        .await
        .unwrap();
    let app = make_app(pool);

    let page = async |uri: &str, cookie: Option<&str>| {
        let mut req = request(uri, "203.0.113.1", None);
        if let Some(slug) = cookie {
            let value = format!("miniapm_project={slug}").parse().unwrap();
            req.headers_mut().insert("cookie", value);
        }
        let body = app.serve(req).await.unwrap().into_body();
        String::from_utf8(body.collect().await.unwrap().to_bytes().to_vec()).unwrap()
    };

    for (cookie, api_key, sees_error) in [
        (None, &default.api_key, false),
        (Some("other"), &other.api_key, true),
    ] {
        let api_page = page("/api-key", cookie).await;
        assert!(api_page.contains(api_key.as_str()), "{cookie:?}");
        assert!(api_page.contains("project-selector"), "{cookie:?}");
        assert!(!api_page.contains("/auth/users"), "{cookie:?}");
        let errors_page = page("/errors", cookie).await;
        assert_eq!(
            errors_page.contains("OnlyInOtherError"),
            sees_error,
            "{cookie:?}"
        );
    }
}

#[tokio::test]
async fn test_form_posts_redirect_with_see_other() {
    let app = app().await;
    for (uri, form) in [
        ("/projects/switch", "slug=default"),
        ("/errors/1/status", "status=resolved"),
        ("/auth/logout", ""),
    ] {
        let mut req = request(uri, "203.0.113.1", None);
        *req.method_mut() = rama::http::Method::POST;
        req.headers_mut().insert(
            "content-type",
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        *req.body_mut() = Body::from(form);
        let res = app.serve(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER, "{uri}");
    }
}
