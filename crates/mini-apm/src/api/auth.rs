//! API key authentication for the ingest API
//!
//! A database-backed [`Authorizer`] for rama's
//! `ValidateRequestHeaderLayer::auth`, which parses the Bearer token,
//! rejects with 401 + `WWW-Authenticate`, and merges the returned
//! [`ProjectContext`] into the request extensions for downstream handlers.

use rama::extensions::Extensions;
use rama::http::layer::auth::HttpAuthorizer;
use rama::http::layer::validate_request::ValidateRequestHeaderLayer;
use rama::net::user::Bearer;
use rama::net::user::authority::{AuthorizeResult, Authorizer, Unauthorized};

use crate::DbPool;
use crate::models::project::SELF_SLUG;

/// Holds project information extracted from API key authentication
#[derive(Clone, Debug)]
pub struct ProjectContext {
    pub project_id: Option<i64>,
}

impl rama::extensions::Extension for ProjectContext {}

/// Resolves a Bearer API key to the project that owns it
#[derive(Clone)]
pub struct ProjectKeyAuthorizer {
    pool: DbPool,
}

impl ProjectKeyAuthorizer {
    pub const fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Layer requiring a valid project API key on every request
    pub fn layer(pool: DbPool) -> ValidateRequestHeaderLayer<HttpAuthorizer<Self, Bearer>> {
        ValidateRequestHeaderLayer::auth(HttpAuthorizer::new(Self::new(pool)))
    }
}

impl Authorizer<Bearer> for ProjectKeyAuthorizer {
    type Error = Unauthorized;

    async fn authorize(&self, credentials: Bearer) -> AuthorizeResult<Bearer, Self::Error> {
        let result =
            match crate::models::project::find_by_api_key(&self.pool, credentials.token()).await {
                Ok(Some(project)) if project.slug != SELF_SLUG => {
                    let extensions = Extensions::new();
                    extensions.insert(ProjectContext {
                        project_id: Some(project.id),
                    });
                    Ok(Some(extensions))
                }
                // Unknown key, or the `self` project that only records in-process
                Ok(_) => Err(Unauthorized::new()),
                Err(e) => {
                    tracing::error!("Database error validating API key: {}", e);
                    Err(Unauthorized::new())
                }
            };

        AuthorizeResult {
            credentials,
            result,
        }
    }
}

#[cfg(test)]
mod tests;
