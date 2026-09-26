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
