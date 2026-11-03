use mcp_host::prelude::*;
use mcp_host::transport::http::{
    HttpAuthFuture, HttpAuthOutcome, HttpAuthRequest, HttpAuthenticator,
};
use serde_json::json;

use mini_apm::{DbPool, models::mcp_token};

const SOURCE: &str = "mcp-token";

/// The principal every session opened with token `token_id` is pinned to
pub fn principal(token_id: i64) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal::new(SOURCE, token_id.to_string())
}

/// Checks the bearer token of every request against the stored MCP tokens,
/// so a revoked token fails on its next request
#[derive(Debug)]
pub struct TokenAuthenticator(pub DbPool);

impl HttpAuthenticator for TokenAuthenticator {
    fn authenticate<'a>(&'a self, request: HttpAuthRequest<'a>) -> HttpAuthFuture<'a> {
        Box::pin(async move {
            let secret = request
                .authorization
                .and_then(|value| value.split_once(' '))
                .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
                .map(|(_, secret)| secret.trim())
                .ok_or(HttpTransportError::Unauthorized)?;
            let bearer = mcp_token::authenticate(&self.0, secret)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to look up MCP token: {e:#}");
                    HttpTransportError::Internal("token lookup failed".into())
                })?
                .ok_or(HttpTransportError::Unauthorized)?;
            Ok(HttpAuthOutcome::new(principal(bearer.token_id))
                .with_state("username", json!(bearer.username)))
        })
    }
}
