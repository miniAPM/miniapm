//! Process-local admission, after authentication and before reading ingestion bodies.

use std::sync::Arc;
use std::time::Duration;

use rama::Service;
use rama::extensions::ExtensionsRef;
use rama::http::service::web::response::IntoResponse;
use rama::http::{Request, Response, StatusCode};
use throttle_machines::{GcraParams, KeyedGcra};

use super::ProjectContext;

/// Validated per-project, per-collector request budget.
#[derive(Clone, Debug)]
pub struct AdmissionConfig {
    params: GcraParams,
    max_keys_per_shard: usize,
}

impl AdmissionConfig {
    pub fn new(rate: f64, burst: u32, max_keys_per_shard: usize) -> anyhow::Result<Self> {
        anyhow::ensure!(
            rate.is_finite() && (0.000_001..=1_000_000.0).contains(&rate),
            "INGEST_REQUESTS_PER_SECOND must be finite and between 0.000001 and 1000000"
        );
        anyhow::ensure!(
            (1..=1_000_000).contains(&burst),
            "INGEST_BURST must be between 1 and 1000000"
        );
        anyhow::ensure!(
            (1..=65_536).contains(&max_keys_per_shard),
            "INGEST_MAX_KEYS_PER_SHARD must be between 1 and 65536"
        );
        Ok(Self {
            params: GcraParams::from_rate(rate, burst),
            max_keys_per_shard,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Admission {
    limiter: Option<Arc<KeyedGcra<i64>>>,
}

impl Admission {
    pub(crate) fn new(config: Option<&AdmissionConfig>) -> Self {
        Self {
            limiter: config.map(|config| {
                Arc::new(
                    KeyedGcra::new(config.params).max_keys_per_shard(config.max_keys_per_shard),
                )
            }),
        }
    }

    pub(crate) fn wrap<S>(&self, inner: S, transport: Transport) -> Admitted<S> {
        Admitted {
            inner,
            admission: self.clone(),
            transport,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Transport {
    Http,
    Grpc,
}

#[derive(Clone, Debug)]
pub(crate) struct Admitted<S> {
    inner: S,
    admission: Admission,
    transport: Transport,
}

impl<S> Service<Request> for Admitted<S>
where
    S: Service<Request, Output = Response>,
{
    type Output = Response;
    type Error = S::Error;

    async fn serve(&self, req: Request) -> Result<Response, Self::Error> {
        if let Some(limiter) = &self.admission.limiter {
            // A missing context is a wiring error: never admit unauthenticated work.
            let Some(project_id) = req
                .extensions()
                .get_ref::<ProjectContext>()
                .and_then(|p| p.project_id)
            else {
                return Ok(StatusCode::UNAUTHORIZED.into_response());
            };
            let decision = limiter.check(&project_id);
            if !decision.allowed {
                return Ok(refusal(self.transport, decision.retry_after));
            }
        }
        self.inner.serve(req).await
    }
}

fn refusal(transport: Transport, retry_after: f64) -> Response {
    match transport {
        Transport::Http => {
            // The validated bounds keep the library's finite retry hint representable.
            let seconds = Duration::from_secs_f64(retry_after.ceil().max(1.0)).as_secs();
            (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", seconds.to_string())],
                "Ingestion admission limit reached",
            )
                .into_response()
        }
        Transport::Grpc => {
            rama::http::grpc::Status::unavailable("Ingestion admission limit reached")
                .try_into_http()
                .expect("static gRPC status contains valid headers")
        }
    }
}

#[cfg(test)]
mod tests;
