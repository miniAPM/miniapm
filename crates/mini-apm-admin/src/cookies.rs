//! Cookie parsing and setting utilities for rama
//!
//! Rama doesn't have built-in cookie middleware, so we provide
//! simple helpers for parsing and setting cookies manually.

use rama::http::{HeaderMap, Request};

/// Extract a cookie value from a request by name
pub fn get_cookie<B>(req: &Request<B>, name: &str) -> Option<String> {
    get_cookie_from_headers(req.headers(), name)
}

/// Extract a cookie value from request headers by name
pub fn get_cookie_from_headers(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get("cookie")
        .and_then(|h| h.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let mut parts = cookie.trim().splitn(2, '=');
                match (parts.next(), parts.next()) {
                    (Some(key), Some(value)) if key == name => Some(value.to_string()),
                    _ => None,
                }
            })
        })
}

/// Generate a Set-Cookie header value
pub fn set_cookie_header(name: &str, value: &str, max_age: i64) -> String {
    format!("{name}={value}; Max-Age={max_age}; Path=/; HttpOnly; SameSite=Lax")
}

/// Generate a Set-Cookie header to delete a cookie
pub fn delete_cookie_header(name: &str) -> String {
    format!("{name}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax")
}
