//! MCP endpoint: errors, traces, routes and deploys for remote MCP clients,
//! authenticated with per-user MCP tokens

mod auth;
mod tools;
mod triage;

#[cfg(test)]
mod tests;

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use mcp_host::prelude::*;
use rama::Service;
use rama::extensions::ExtensionsRef;
use rama::futures::StreamExt;
use rama::http::header::CONTENT_TYPE;
use rama::http::{Body, Request, Response};

use mini_apm::DbPool;
use mini_apm::server::ShutdownSignal;

pub use auth::principal;

const INSTRUCTIONS: &str = "MiniAPM collects errors and traces from instrumented apps. \
Errors are grouped; each group is open, resolved or ignored, and a resolved error \
reopens when it happens again. Start with list_errors or slow_routes, drill into one \
with error_details or trace_detail, and use triage_error to walk the user through \
changing an error's status. Pass a project slug from list_projects to narrow any list.";

pub struct MiniApm {
    pool: DbPool,
}

/// The MCP endpoint. Its event streams end when the server starts shutting
/// down, so open sessions do not hold the graceful drain.
#[derive(Clone)]
pub struct Endpoint(McpHttpService);

impl Endpoint {
    pub fn new(pool: DbPool) -> anyhow::Result<Self> {
        let server = Server::builder("miniapm", env!("CARGO_PKG_VERSION"))
            .with_title("MiniAPM")
            .with_instructions(INSTRUCTIONS)
            .with_logging()
            .with_circuit_breaker(ToolBreakerConfig {
                failure_threshold: 5,
                failure_window_secs: 60.0,
                half_open_timeout_secs: 30.0,
                success_threshold: 2,
                call_timeout_secs: triage::BUDGET.as_secs_f64(),
            })
            .with_rate_limit(50.0, 100)?
            .with_session_rate_limit(10.0, 30)?
            .with_runtime_config(ServerRuntimeConfig {
                max_client_request_timeout: Duration::from_mins(3),
                ..ServerRuntimeConfig::default()
            })
            .build();
        server.register_router(MiniApm::router()?, Arc::new(MiniApm { pool: pool.clone() }))?;
        server.tool_registry().register(triage::tool()?)?;

        let config = HttpTransportConfig {
            localhost_only: false,
            authenticator: Some(Arc::new(auth::TokenAuthenticator(pool))),
            ..HttpTransportConfig::default()
        };
        Ok(Self(McpHttpService::new(Arc::new(server), config)?))
    }

    pub fn sessions(&self) -> HttpTransportSessionHandle {
        self.0.session_handle()
    }
}

impl Service<Request> for Endpoint {
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, req: Request) -> Result<Response, Infallible> {
        let shutdown = req.extensions().get_ref::<ShutdownSignal>().cloned();
        let res = self.0.handle(req).await;
        let streaming = res
            .headers()
            .get(CONTENT_TYPE)
            .is_some_and(|value| value == "text/event-stream");
        Ok(match shutdown {
            Some(signal) if streaming => {
                let (parts, body) = res.into_parts();
                let body = body
                    .into_data_stream()
                    .take_until(async move { signal.triggered().await });
                Response::from_parts(parts, Body::from_stream(body))
            }
            _ => res,
        })
    }
}
