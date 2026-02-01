//! Rate limiting middleware for protecting API endpoints
//!
//! This module provides a simple in-memory rate limiter that tracks
//! requests per IP address and returns 429 Too Many Requests when
//! the limit is exceeded.

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use rama::Layer;
use rama::http::{Body, Request, Response, StatusCode};
use rama::service::Service;

/// Configuration for rate limiting
#[derive(Clone)]
pub struct RateLimitConfig {
    /// Maximum requests allowed per window
    pub max_requests: u32,
    /// Time window duration
    pub window: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window: Duration::from_secs(60),
        }
    }
}

/// Entry tracking requests for a single IP
struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

/// Shared state for rate limiting
type RateLimitState = Arc<RwLock<HashMap<IpAddr, RateLimitEntry>>>;

/// Layer that applies rate limiting
#[derive(Clone)]
pub struct RateLimitMiddleware {
    config: RateLimitConfig,
    state: RateLimitState,
}

impl RateLimitMiddleware {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create with default configuration (100 requests per minute)
    pub fn with_defaults() -> Self {
        Self::new(RateLimitConfig::default())
    }
}

impl<S> Layer<S> for RateLimitMiddleware {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            config: self.config.clone(),
            state: self.state.clone(),
        }
    }
}

/// Service that enforces rate limits
pub struct RateLimitService<S> {
    inner: S,
    config: RateLimitConfig,
    state: RateLimitState,
}

impl<S> RateLimitService<S> {
    /// Check if request should be allowed and update counters
    fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let now = Instant::now();

        let mut state = self.state.write().unwrap();

        // Clean up old entries periodically (every 1000 entries)
        if state.len() > 1000 {
            state.retain(|_, entry| now.duration_since(entry.window_start) < self.config.window);
        }

        let entry = state.entry(ip).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });

        // Check if window has expired
        if now.duration_since(entry.window_start) >= self.config.window {
            // Reset window
            entry.count = 1;
            entry.window_start = now;
            return true;
        }

        // Check if under limit
        if entry.count < self.config.max_requests {
            entry.count += 1;
            return true;
        }

        false
    }
}

impl<S> Service<Request> for RateLimitService<S>
where
    S: Service<Request, Output = Response, Error = std::convert::Infallible> + Send + Sync + 'static,
{
    type Output = Response;
    type Error = std::convert::Infallible;

    fn serve(
        &self,
        req: Request,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        async move {
            // Extract IP from X-Forwarded-For header or use a default
            let ip = req
                .headers()
                .get("X-Forwarded-For")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .and_then(|s| s.trim().parse::<IpAddr>().ok())
                .unwrap_or_else(|| "127.0.0.1".parse().unwrap());

            // Check rate limit
            if !self.check_rate_limit(ip) {
                let response = Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .header("Retry-After", "60")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"error":"Rate limit exceeded. Please try again later."}"#))
                    .unwrap();
                return Ok(response);
            }

            // Proceed with request
            self.inner.serve(req).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    struct DummyService;

    impl Service<Request> for DummyService {
        type Output = Response;
        type Error = Infallible;

        fn serve(
            &self,
            _req: Request,
        ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
            async move {
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::empty())
                    .unwrap())
            }
        }
    }

    fn make_request_with_ip(ip: &str) -> Request {
        Request::builder()
            .uri("/test")
            .header("X-Forwarded-For", ip)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn test_allows_requests_under_limit() {
        let config = RateLimitConfig {
            max_requests: 5,
            window: Duration::from_secs(60),
        };
        let middleware = RateLimitMiddleware::new(config);
        let service = middleware.layer(DummyService);

        for _ in 0..5 {
            let req = make_request_with_ip("192.168.1.1");
            let response = service.serve(req).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn test_blocks_requests_over_limit() {
        let config = RateLimitConfig {
            max_requests: 3,
            window: Duration::from_secs(60),
        };
        let middleware = RateLimitMiddleware::new(config);
        let service = middleware.layer(DummyService);

        // First 3 requests should succeed
        for _ in 0..3 {
            let req = make_request_with_ip("192.168.1.2");
            let response = service.serve(req).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        // 4th request should be rate limited
        let req = make_request_with_ip("192.168.1.2");
        let response = service.serve(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_different_ips_have_separate_limits() {
        let config = RateLimitConfig {
            max_requests: 2,
            window: Duration::from_secs(60),
        };
        let middleware = RateLimitMiddleware::new(config);
        let service = middleware.layer(DummyService);

        // IP 1: Use up limit
        for _ in 0..2 {
            let req = make_request_with_ip("10.0.0.1");
            let response = service.serve(req).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        // IP 1 should be blocked
        let req = make_request_with_ip("10.0.0.1");
        let response = service.serve(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        // IP 2 should still work
        let req = make_request_with_ip("10.0.0.2");
        let response = service.serve(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_retry_after_header() {
        let config = RateLimitConfig {
            max_requests: 1,
            window: Duration::from_secs(60),
        };
        let middleware = RateLimitMiddleware::new(config);
        let service = middleware.layer(DummyService);

        // Use up limit
        let req = make_request_with_ip("10.0.0.3");
        let _ = service.serve(req).await.unwrap();

        // Check rate limited response has Retry-After header
        let req = make_request_with_ip("10.0.0.3");
        let response = service.serve(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().contains_key("Retry-After"));
    }

    #[tokio::test]
    async fn test_default_config() {
        let middleware = RateLimitMiddleware::with_defaults();
        let service = middleware.layer(DummyService);

        // Should allow at least one request
        let req = make_request_with_ip("192.168.1.100");
        let response = service.serve(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
