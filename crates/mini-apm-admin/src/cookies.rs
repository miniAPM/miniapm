//! Cookie parsing and setting utilities for rama
//!
//! Rama doesn't have built-in cookie middleware, so we provide
//! simple helpers for parsing and setting cookies manually.

use rama::http::Request;

/// Extract a cookie value from a request by name
pub fn get_cookie<B>(req: &Request<B>, name: &str) -> Option<String> {
    req.headers()
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
    format!(
        "{}={}; Max-Age={}; Path=/; HttpOnly; SameSite=Lax",
        name, value, max_age
    )
}

/// Generate a Set-Cookie header to delete a cookie
pub fn delete_cookie_header(name: &str) -> String {
    format!("{}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax", name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::http::Request;

    #[test]
    fn test_get_cookie_found() {
        let req = Request::builder()
            .header("cookie", "session=abc123; other=xyz")
            .body(())
            .unwrap();

        assert_eq!(get_cookie(&req, "session"), Some("abc123".to_string()));
        assert_eq!(get_cookie(&req, "other"), Some("xyz".to_string()));
    }

    #[test]
    fn test_get_cookie_not_found() {
        let req = Request::builder()
            .header("cookie", "session=abc123")
            .body(())
            .unwrap();

        assert_eq!(get_cookie(&req, "missing"), None);
    }

    #[test]
    fn test_get_cookie_no_header() {
        let req = Request::builder().body(()).unwrap();
        assert_eq!(get_cookie(&req, "session"), None);
    }

    #[test]
    fn test_set_cookie_header() {
        let header = set_cookie_header("session", "abc123", 86400);
        assert!(header.contains("session=abc123"));
        assert!(header.contains("Max-Age=86400"));
        assert!(header.contains("HttpOnly"));
    }

    #[test]
    fn test_delete_cookie_header() {
        let header = delete_cookie_header("session");
        assert!(header.contains("session="));
        assert!(header.contains("Max-Age=0"));
    }
}
