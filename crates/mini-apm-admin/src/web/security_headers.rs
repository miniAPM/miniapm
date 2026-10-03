use rama::Layer;
use rama::http::{Request, Response};
use rama::service::Service;

/// Layer that adds security headers to all responses
#[derive(Clone, Default)]
pub struct SecurityHeadersMiddleware;

impl SecurityHeadersMiddleware {
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for SecurityHeadersMiddleware {
    type Service = SecurityHeadersService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersService { inner }
    }
}

/// Service that adds security headers to responses
pub struct SecurityHeadersService<S> {
    inner: S,
}

impl<S> Service<Request> for SecurityHeadersService<S>
where
    S: Service<Request, Output = Response, Error = std::convert::Infallible>
        + Send
        + Sync
        + 'static,
{
    type Output = Response;
    type Error = std::convert::Infallible;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        let mut response = self.inner.serve(req).await?;

        // Check if Cache-Control is already set before getting mutable reference
        let has_cache_control = response.headers().contains_key("Cache-Control");

        // Add security headers
        let headers = response.headers_mut();

        // Prevent MIME type sniffing
        headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());

        // Prevent clickjacking
        headers.insert("X-Frame-Options", "DENY".parse().unwrap());

        // XSS protection (legacy but still useful)
        headers.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());

        // Control referrer information
        headers.insert(
            "Referrer-Policy",
            "strict-origin-when-cross-origin".parse().unwrap(),
        );

        // Content Security Policy
        // Allow 'unsafe-inline' for styles and scripts since we use inline styles in templates
        headers.insert(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'".parse().unwrap(),
        );

        // Prevent caching of sensitive pages
        if !has_cache_control {
            headers.insert(
                "Cache-Control",
                "no-store, no-cache, must-revalidate".parse().unwrap(),
            );
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests;
