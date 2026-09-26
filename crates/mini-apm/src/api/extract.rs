//! Extractors for rama web endpoints.

use rama::http::StatusCode;
use rama::http::request::Parts;
use rama::http::service::web::extract::FromPartsStateRefPair;

/// Extractor that clones a typed value out of the request extensions.
///
/// Replacement for the `Extension` extractor that rama 0.3.0 removed:
/// extensions are inserted by middleware (e.g. API key auth) and read
/// here from the request parts. Missing extension rejects with 500.
pub struct Extension<T>(pub T);

impl<T, S> FromPartsStateRefPair<S> for Extension<T>
where
    T: rama::extensions::Extension + Clone,
    S: Send + Sync + 'static,
{
    type Rejection = StatusCode;

    async fn from_parts_state_ref_pair(parts: &Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get_ref::<T>()
            .cloned()
            .map(Self)
            .ok_or_else(|| {
                tracing::error!(
                    "Missing request extension {} (is its middleware applied?)",
                    std::any::type_name::<T>()
                );
                StatusCode::INTERNAL_SERVER_ERROR
            })
    }
}
