//! Process-local admission, after authentication and before reading ingestion bodies.

use std::sync::Arc;
use std::time::Duration;

use rama::Service;
use rama::extensions::ExtensionsRef;
use rama::http::service::web::response::IntoResponse;
use rama::http::{Request, Response, StatusCode};
use throttle_machines::{GcraParams, KeyedGcra};
use tokio::sync::Semaphore;

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

/// Maximum simultaneous ingestion handlers in one collector (not a queue).
///
/// The ceiling leaves headroom in the normal ten-connection database pool.
#[derive(Clone, Copy, Debug)]
pub struct InFlightLimit(usize);

impl InFlightLimit {
    pub fn new(limit: usize) -> anyhow::Result<Self> {
        anyhow::ensure!(
            (1..=8).contains(&limit),
            "INGEST_MAX_IN_FLIGHT must be between 1 and 8"
        );
        Ok(Self(limit))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Admission {
    limiter: Option<Arc<KeyedGcra<i64>>>,
    capacity: Option<Arc<Semaphore>>,
}

impl Admission {
    pub(crate) fn new(config: Option<&AdmissionConfig>, in_flight: Option<InFlightLimit>) -> Self {
        Self {
            limiter: config.map(|config| {
                Arc::new(
                    KeyedGcra::new(config.params).max_keys_per_shard(config.max_keys_per_shard),
                )
            }),
            capacity: in_flight.map(|limit| Arc::new(Semaphore::new(limit.0))),
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
        // Acquire before spending rate budget; rejected work does not queue or consume quota.
        // The guard spans body reads and persistence and drops on every return/cancellation.
        let _permit = if let Some(capacity) = &self.admission.capacity {
            match capacity.try_acquire() {
                Ok(permit) => Some(permit),
                Err(_) => return Ok(refusal(self.transport, Refusal::Capacity)),
            }
        } else {
            None
        };
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
                return Ok(refusal(self.transport, Refusal::Rate(decision.retry_after)));
            }
        }
        self.inner.serve(req).await
    }
}

#[derive(Clone, Copy, Debug)]
enum Refusal {
    Capacity,
    Rate(f64),
}

fn refusal(transport: Transport, reason: Refusal) -> Response {
    let (status, retry_after, message) = match reason {
        Refusal::Capacity => (
            StatusCode::SERVICE_UNAVAILABLE,
            1.0,
            "Ingestion concurrency limit reached",
        ),
        Refusal::Rate(delay) => (
            StatusCode::TOO_MANY_REQUESTS,
            delay,
            "Ingestion admission limit reached",
        ),
    };
    match transport {
        Transport::Http => {
            // The validated bounds keep the library's finite retry hint representable.
            let seconds = Duration::from_secs_f64(retry_after.ceil().max(1.0)).as_secs();
            (status, [("retry-after", seconds.to_string())], message).into_response()
        }
        Transport::Grpc => rama::http::grpc::Status::unavailable(message)
            .try_into_http()
            .expect("static gRPC status contains valid headers"),
    }
}

#[cfg(test)]
mod tests;
