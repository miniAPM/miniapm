//! Template rendering helpers for rama + askama integration
//!
//! Provides an HtmlTemplate wrapper that implements IntoResponse
//! to replace askama_axum functionality.

use askama::Template;
use rama::http::service::web::response::IntoResponse;
use rama::http::{Body, Response, StatusCode};

/// Wrapper for askama templates that implements rama's IntoResponse
pub struct HtmlTemplate<T: Template>(pub T);

impl<T: Template> IntoResponse for HtmlTemplate<T> {
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/html; charset=utf-8")
                .body(Body::from(html))
                .unwrap(),
            Err(e) => {
                tracing::error!("Template render error: {}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header("content-type", "text/plain")
                    .body(Body::from("Template error"))
                    .unwrap()
            }
        }
    }
}
