use super::*;
use rama::extensions::ExtensionsRef;
use rama::http::Body;
use rama::http::header::RETRY_AFTER;
use rama::net::address::SocketAddress;
use rama::net::stream::SocketInfo;
use std::net::IpAddr;

fn request(peer: &str, forwarded_for: Option<&str>) -> Request {
    let mut req = Request::builder().uri("/nope");
    if let Some(ip) = forwarded_for {
        req = req.header("X-Forwarded-For", ip);
    }
    let req = req.body(Body::empty()).unwrap();
    let peer: IpAddr = peer.parse().unwrap();
    req.extensions()
        .insert(SocketInfo::new(None, SocketAddress::new(peer, 40000)));
    req
}

#[tokio::test]
async fn test_rate_limits_per_client_ip() {
    let config = mini_apm::config::Config::default();
    let app = make_app(mini_apm::db::init(&config).await.unwrap());

    for _ in 0..100 {
        let res = app.serve(request("203.0.113.1", None)).await.unwrap();
        assert_ne!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    }
    let res = app.serve(request("203.0.113.1", None)).await.unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(res.headers().contains_key(RETRY_AFTER));

    // Other clients keep their own budget, by socket peer or forwarded IP
    for (peer, forwarded) in [("203.0.113.2", None), ("203.0.113.1", Some("198.51.100.7"))] {
        let res = app.serve(request(peer, forwarded)).await.unwrap();
        assert_ne!(
            res.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "{peer} {forwarded:?}"
        );
    }
}
