//! MiniAPM monitoring itself. Requests and errors of the collector and the
//! admin are recorded into the `self` project through the regular ingest
//! code, handed over in-process instead of over HTTP.

use std::convert::Infallible;
use std::fmt;
use std::sync::OnceLock;

use jiff::Timestamp;
use rama::http::{Request, Response};
use rama::{Layer, Service};
use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;

use crate::DbPool;
use crate::models::error::{self, IncomingError};
use crate::models::span;

#[cfg(test)]
mod tests;

/// Records buffered for the writer; beyond this, new records are dropped
const QUEUE: usize = 1024;
/// Most spans written in one batch
const BATCH: usize = 256;

static GLOBAL: OnceLock<SelfMonitor> = OnceLock::new();

tokio::task_local! {
    /// Set while the writer runs, so errors it logs are not recorded again
    static WRITING: ();
}

enum Record {
    Span(span::OtlpSpan),
    Error(IncomingError),
}

/// Handle for recording into the `self` project. Recording never waits:
/// when the writer falls behind, records are dropped.
#[derive(Clone)]
pub struct SelfMonitor {
    tx: mpsc::Sender<Record>,
}

impl SelfMonitor {
    /// Start the background writer for `project_id`, reporting as `service`
    pub fn start(pool: DbPool, project_id: i64, service: &'static str) -> Self {
        let (tx, rx) = mpsc::channel(QUEUE);
        tokio::spawn(WRITING.scope((), write(pool, project_id, service, rx)));
        Self { tx }
    }

    /// Make this the process-wide monitor behind [`ErrorCaptureLayer`] and
    /// [`SelfMonitorLayer::global`]
    pub fn install(self) {
        if GLOBAL.set(self).is_err() {
            tracing::warn!("Self monitor already installed");
        }
    }

    pub fn global() -> Option<&'static SelfMonitor> {
        GLOBAL.get()
    }

    fn record(&self, record: Record) {
        let _ = self.tx.try_send(record);
    }

    /// Record a served request as a root server span
    pub fn record_request(
        &self,
        method: &str,
        path: &str,
        status: u16,
        start: Timestamp,
        end: Timestamp,
    ) {
        self.record(Record::Span(span::OtlpSpan {
            trace_id: format!("{:032x}", rand::random::<u128>()),
            span_id: format!("{:016x}", rand::random::<u64>()),
            parent_span_id: None,
            name: format!("{method} {}", route_of(path)),
            kind: Some(2),
            start_time_unix_nano: start.as_nanosecond() as i64,
            end_time_unix_nano: end.as_nanosecond() as i64,
            attributes: Some(vec![
                attribute("http.method", method),
                attribute("http.target", path),
                attribute("http.status_code", &status.to_string()),
            ]),
            events: None,
            status: Some(span::SpanStatus {
                code: Some(if status >= 500 { 2 } else { 1 }),
                message: None,
            }),
        }));
    }
}

/// Collapse ids and tokens in a path so requests group by route
fn route_of(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            let id = !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit());
            let token = segment.len() >= 16
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            if id || token { "{id}" } else { segment }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn attribute(key: &str, value: &str) -> span::KeyValue {
    span::KeyValue {
        key: key.to_string(),
        value: span::AttributeValue {
            string_value: Some(value.to_string()),
            int_value: None,
            double_value: None,
            bool_value: None,
            array_value: None,
        },
    }
}

async fn write(pool: DbPool, project_id: i64, service: &str, mut rx: mpsc::Receiver<Record>) {
    while let Some(first) = rx.recv().await {
        let (mut spans, mut errors) = (Vec::new(), Vec::new());
        let mut next = Some(first);
        while let Some(record) = next {
            match record {
                Record::Span(s) => spans.push(s),
                Record::Error(e) => errors.push(e),
            }
            next = if spans.len() < BATCH {
                rx.try_recv().ok()
            } else {
                None
            };
        }

        if !spans.is_empty() {
            let batch = span::OtlpTraceRequest {
                resource_spans: vec![span::ResourceSpans {
                    resource: Some(span::Resource {
                        attributes: Some(vec![attribute("service.name", service)]),
                    }),
                    scope_spans: Some(vec![span::ScopeSpans { scope: None, spans }]),
                }],
            };
            if let Err(e) = span::insert_otlp_batch(&pool, &batch, Some(project_id)).await {
                tracing::warn!("Failed to record own spans: {}", e);
            }
        }
        for e in errors {
            if let Err(e) = error::insert(&pool, &e, Some(project_id)).await {
                tracing::warn!("Failed to record own error: {}", e);
            }
        }
    }
}

/// Records every served request, except health checks and static assets
#[derive(Clone)]
pub struct SelfMonitorLayer {
    monitor: Option<SelfMonitor>,
}

impl SelfMonitorLayer {
    pub fn new(monitor: Option<SelfMonitor>) -> Self {
        Self { monitor }
    }

    /// Records into the installed monitor, or does nothing without one
    pub fn global() -> Self {
        Self::new(SelfMonitor::global().cloned())
    }
}

impl<S> Layer<S> for SelfMonitorLayer {
    type Service = SelfMonitorService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SelfMonitorService {
            inner,
            monitor: self.monitor.clone(),
        }
    }
}

#[derive(Clone)]
pub struct SelfMonitorService<S> {
    inner: S,
    monitor: Option<SelfMonitor>,
}

impl<S> Service<Request> for SelfMonitorService<S>
where
    S: Service<Request, Output = Response, Error = Infallible> + Send + Sync + 'static,
{
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, req: Request) -> Result<Response, Infallible> {
        let Some(monitor) = &self.monitor else {
            return self.inner.serve(req).await;
        };
        let path = req
            .uri()
            .path()
            .unwrap_or_default()
            .as_encoded_str()
            .into_owned();
        if path == "/health" || path.starts_with("/static/") {
            return self.inner.serve(req).await;
        }

        let method = req.method().as_str().to_owned();
        let start = Timestamp::now();
        let res = self.inner.serve(req).await?;
        monitor.record_request(
            &method,
            &path,
            res.status().as_u16(),
            start,
            Timestamp::now(),
        );
        Ok(res)
    }
}

/// `tracing` layer recording ERROR events as errors of the `self` project,
/// grouped by the file and line that logged them
pub struct ErrorCaptureLayer {
    monitor: &'static OnceLock<SelfMonitor>,
}

impl ErrorCaptureLayer {
    /// Records into the process-wide monitor, once one is installed
    pub fn global() -> Self {
        Self { monitor: &GLOBAL }
    }
}

impl<S: Subscriber> tracing_subscriber::Layer<S> for ErrorCaptureLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        if *meta.level() != Level::ERROR || WRITING.try_with(|_| ()).is_ok() {
            return;
        }
        let Some(monitor) = self.monitor.get() else {
            return;
        };

        let mut message = MessageVisitor::default();
        event.record(&mut message);
        let location = format!(
            "{}:{}",
            meta.file().unwrap_or("unknown"),
            meta.line().unwrap_or(0)
        );
        monitor.record(Record::Error(IncomingError {
            exception_class: meta.target().to_string(),
            message: message.0,
            backtrace: vec![format!("{location}:in `{}'", meta.target())],
            fingerprint: format!("{}:{location}", meta.target()),
            request_id: None,
            user_id: None,
            params: None,
            timestamp: None,
            source_context: None,
        }));
    }
}

/// The event's message, followed by its other fields as `key=value`
#[derive(Default)]
struct MessageVisitor(String);

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let separator = if self.0.is_empty() { "" } else { " " };
        if field.name() == "message" {
            self.0 = format!("{value:?}{separator}{}", self.0);
        } else {
            self.0 = format!("{}{separator}{}={value:?}", self.0, field.name());
        }
    }
}
