use super::*;
use rama::http::body::util::BodyExt;
use rama::http::{Body, StatusCode};
use rama::service::service_fn;
use std::convert::Infallible;

#[tokio::test]
async fn secures_responses_without_overwriting_explicit_cache_policy() -> anyhow::Result<()> {
    for cache_control in [None, Some("public, max-age=3600")] {
        let handler = service_fn(move |_: Request| async move {
            let mut response = Response::builder().status(StatusCode::CREATED);
            if let Some(value) = cache_control {
                response = response.header("Cache-Control", value);
            }
            Ok::<_, Infallible>(response.body(Body::from("unchanged")).unwrap())
        });
        let service = SecurityHeadersMiddleware::new().layer(handler);
        let response = service.serve(Request::new(Body::empty())).await?;

        assert_eq!(response.status(), StatusCode::CREATED);
        for (name, value) in [
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("X-XSS-Protection", "1; mode=block"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            (
                "Content-Security-Policy",
                "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'",
            ),
            (
                "Cache-Control",
                cache_control.unwrap_or("no-store, no-cache, must-revalidate"),
            ),
        ] {
            assert_eq!(response.headers().get(name).expect(name), value, "{name}");
        }
        assert_eq!(
            response.into_body().collect().await?.to_bytes(),
            "unchanged"
        );
    }
    Ok(())
}
