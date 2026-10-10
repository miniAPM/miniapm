//! Template rendering helpers for rama + askama integration
//!
//! Provides an `HtmlTemplate` wrapper that implements `IntoResponse`
//! to replace `askama_axum` functionality.

use askama::Template;
use rama::http::service::web::response::{Html, IntoResponse};
use rama::http::{Response, StatusCode};

/// Wrapper for askama templates that implements rama's `IntoResponse`
pub struct HtmlTemplate<T: Template>(pub T);

impl<T: Template> IntoResponse for HtmlTemplate<T> {
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(e) => {
                tracing::error!("Template render error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
            }
        }
    }
}
