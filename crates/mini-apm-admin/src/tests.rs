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
    make_app(mini_apm::db::test_pool().await)
}

async fn html(
    app: &impl Service<Request, Output = Response, Error = Infallible>,
    uri: &str,
) -> String {
    use rama::http::body::util::BodyExt;

    let res = app.serve(request(uri, "203.0.113.1", None)).await.unwrap();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(body.to_vec()).unwrap()
}

#[tokio::test]
async fn test_health_and_not_found() {
    let app = app().await;
    for (uri, expected) in [
        ("/health", StatusCode::OK),
        ("/nope", StatusCode::NOT_FOUND),
        ("/auth/users", StatusCode::NOT_FOUND),
        ("/auth/change-password", StatusCode::NOT_FOUND),
        ("/auth/invite/bogus", StatusCode::NOT_FOUND),
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

    let pool = mini_apm::db::test_pool().await;
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
            let value = format!("unrelated=abc=123; miniapm_project={slug}; other=xyz")
                .parse()
                .unwrap();
            req.headers_mut().insert("cookie", value);
        }
        let body = app.serve(req).await.unwrap().into_body();
        String::from_utf8(body.collect().await.unwrap().to_bytes().to_vec()).unwrap()
    };

    for (cookie, api_key, sees_error) in [
        (None, &default.api_key, false),
        (Some("other"), &other.api_key, true),
        (Some("missing-project"), &default.api_key, false),
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
async fn test_form_posts_redirect_with_see_other_and_reject_malformed_input() {
    let app = app().await;
    for (uri, form, expected) in [
        ("/projects/switch", "slug=default", StatusCode::SEE_OTHER),
        ("/errors/1/status", "status=resolved", StatusCode::SEE_OTHER),
        ("/auth/logout", "", StatusCode::SEE_OTHER),
        (
            "/projects/switch",
            "slug=bad%0Aslug",
            StatusCode::BAD_REQUEST,
        ),
        (
            "/projects/switch",
            "slug=x%3B%20Domain%3Devil",
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let mut req = request(uri, "203.0.113.1", None);
        *req.method_mut() = rama::http::Method::POST;
        req.headers_mut().insert(
            "content-type",
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        *req.body_mut() = Body::from(form);
        let res = app.serve(req).await.unwrap();
        assert_eq!(res.status(), expected, "{uri} {form}");
        if expected == StatusCode::BAD_REQUEST {
            assert!(res.headers().get("set-cookie").is_none(), "{form}");
        } else if uri == "/projects/switch" {
            assert_eq!(res.headers().get("location").unwrap(), "/");
            assert_eq!(
                res.headers().get("set-cookie").unwrap(),
                "miniapm_project=default; Max-Age=31536000; Path=/; HttpOnly; SameSite=Lax"
            );
        } else if uri == "/auth/logout" {
            assert_eq!(res.headers().get("location").unwrap(), "/auth/login");
            assert_eq!(
                res.headers().get("set-cookie").unwrap(),
                "miniapm_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
            );
        }
    }
}

#[tokio::test]
async fn test_filter_links_carry_query_values_intact() {
    let app = app().await;
    for path in ["/errors", "/traces", "/performance"] {
        let html = html(&app, &format!("{path}?search=a%26b%20%23c%2B&sort=x%3Dy")).await;
        assert!(html.contains("search=a%26b%20%23c%2B"), "{path}");
        assert!(html.contains("sort=x%3Dy"), "{path}");
    }
}

#[tokio::test]
async fn test_dashboard_marks_deploys_on_their_chart_hour() {
    use mini_apm::models::{deploy, project};
    use mini_apm::time::Stamp;

    let pool = mini_apm::db::test_pool().await;
    let project = project::ensure_default_project(&pool).await.unwrap();
    let at = Stamp::now();
    sqlx::query(
        "INSERT INTO spans (project_id, trace_id, span_id, start_time_unix_nano,
            end_time_unix_nano, duration_ms, name, span_category, root_span_type, happened_at)
         VALUES ($1, 'trace', 'span', 0, 1, 1.0, 'GET /', 'http_server', 'web', $2)",
    )
    .bind(project.id)
    .bind(at)
    .execute(&pool)
    .await
    .unwrap();
    let incoming = deploy::IncomingDeploy {
        git_sha: "abc1234".into(),
        version: None,
        env: None,
        description: None,
        deployer: None,
        timestamp: Some(at.0),
    };
    deploy::insert(&pool, &incoming, Some(project.id))
        .await
        .unwrap();

    let html = html(&make_app(pool), "/").await;
    let hour = at.hour_label();
    assert!(html.contains(&format!(r#""hour":"{hour}""#)));
    assert!(html.contains(&format!(r#"data-signals:_deploys='["{hour}"]'"#)));
}

#[tokio::test]
async fn test_dashboard_streams_live_patches_until_shutdown() {
    use mini_apm::server::ShutdownSignal;
    use rama::graceful::Shutdown;
    use rama::http::body::util::BodyExt;

    let app = app().await;
    let page = html(&app, "/").await;
    assert!(page.contains("@get('/dashboard/live'"));
    assert!(page.contains(r#"src="/static/datastar.js""#));
    let script = app
        .serve(request("/static/datastar.js", "203.0.113.1", None))
        .await
        .unwrap();
    assert_eq!(script.status(), StatusCode::OK);

    let (trigger, signal) = tokio::sync::oneshot::channel::<()>();
    let shutdown = Shutdown::new(signal);
    let req = request("/dashboard/live", "203.0.113.1", None);
    req.extensions()
        .insert(ShutdownSignal(shutdown.guard_weak()));
    let res = app.serve(req).await.unwrap();
    assert_eq!(res.headers()["content-type"], "text/event-stream");

    let mut body = res.into_body();
    let frame = body.frame().await.unwrap().unwrap().into_data().unwrap();
    let event = String::from_utf8(frame.to_vec()).unwrap();
    assert!(
        event.starts_with(
            "event: datastar-patch-elements\ndata: elements <div id=\"dashboard-live\""
        ),
        "{event}"
    );

    trigger.send(()).unwrap();
    let rest = tokio::time::timeout(Duration::from_secs(5), body.collect()).await;
    assert!(rest.unwrap().unwrap().to_bytes().is_empty());
}

#[tokio::test]
async fn test_error_page_offers_only_allowed_status_changes() {
    use mini_apm::models::error::{self, ErrorStatusEvent::*};

    let pool = mini_apm::db::test_pool().await;
    let incoming = error::IncomingError {
        exception_class: "BoomError".into(),
        message: "boom".into(),
        backtrace: vec![],
        fingerprint: "fp".into(),
        request_id: None,
        user_id: None,
        params: None,
        timestamp: None,
        source_context: None,
    };
    let id = error::insert(&pool, &incoming, None).await.unwrap();
    let app = make_app(pool.clone());

    for (event, offered) in [
        (None, ["resolved", "ignored"]),
        (Some(Resolve), ["ignored", "open"]),
        (Some(Ignore), ["resolved", "open"]),
    ] {
        let label = format!("{event:?}");
        if let Some(event) = event {
            error::apply(&pool, id, event).await.unwrap();
        }
        let page = html(&app, &format!("/errors/{id}")).await;
        for status in ["resolved", "ignored", "open"] {
            let button = format!(r#"name="status" value="{status}""#);
            assert_eq!(
                page.contains(&button),
                offered.contains(&status),
                "{label} {status}"
            );
        }
    }
}
