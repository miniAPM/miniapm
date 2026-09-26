use super::*;
use rama::extensions::ExtensionsRef;
use rama::http::Body;
use rama::http::header::RETRY_AFTER;
use rama::net::address::SocketAddress;
use rama::net::stream::SocketInfo;
use std::net::IpAddr;

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

    // Other clients keep their own budget, by socket peer or forwarded IP
    for (peer, forwarded) in [("203.0.113.2", None), ("203.0.113.1", Some("198.51.100.7"))] {
        let res = app.serve(request("/nope", peer, forwarded)).await.unwrap();
        assert_ne!(
            res.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "{peer} {forwarded:?}"
        );
    }
}
