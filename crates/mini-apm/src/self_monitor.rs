//! MiniAPM monitoring itself. Requests and errors of the collector and the
//! admin are recorded into the `self` project through the regular ingest
//! code, handed over in-process instead of over HTTP.

use std::convert::Infallible;
use std::fmt::{self, Write as _};
use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock};

use jiff::{SignedDuration, Timestamp};
use rama::http::{Request, Response};
use rama::{Layer, Service};
use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing::{Event, Instrument, Level, Subscriber};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::{LookupSpan, Registry};

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
    Spans(Vec<span::OtlpSpan>),
    Error(Box<IncomingError>),
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

    /// Make this the process-wide monitor behind [`CaptureLayer`] and
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

    pub async fn trace_job<F, T>(&self, name: &str, job: F) -> anyhow::Result<T>
    where
        F: Future<Output = anyhow::Result<T>>,
    {
        let trace = Trace::start();
        let result = job.instrument(trace.span.clone()).await;
        self.record_trace(trace, name.to_string(), 5, vec![], result.is_err());
        result
    }

    fn record_trace(
        &self,
        trace: Trace,
        name: String,
        kind: i32,
        attributes: Vec<span::KeyValue>,
        failed: bool,
    ) {
        let trace_id = format!("{:032x}", rand::random::<u128>());
        let root_id = format!("{:016x}", rand::random::<u64>());
        let queries = trace.queries.take().into_iter().map(|q| span::OtlpSpan {
            trace_id: trace_id.clone(),
            span_id: format!("{:016x}", rand::random::<u64>()),
            parent_span_id: Some(root_id.clone()),
            name: q.summary,
            kind: Some(3),
            start_time_unix_nano: nanos(q.start),
            end_time_unix_nano: nanos(q.end),
            attributes: Some(vec![
                attribute("db.system", "sqlite"),
                attribute("db.statement", q.statement),
            ]),
            events: None,
            status: None,
        });
        let root = span::OtlpSpan {
            trace_id: trace_id.clone(),
            span_id: root_id.clone(),
            parent_span_id: None,
            name,
            kind: Some(kind),
            start_time_unix_nano: nanos(trace.start),
            end_time_unix_nano: nanos(Timestamp::now()),
            attributes: Some(attributes),
            events: None,
            status: Some(span::SpanStatus {
                code: Some(if failed { 2 } else { 1 }),
                message: None,
            }),
        };
        self.record(Record::Spans(
            std::iter::once(root).chain(queries).collect(),
        ));
    }
}

pub async fn trace_job<F, T>(name: &str, job: F) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>>,
{
    match SelfMonitor::global() {
        Some(monitor) => monitor.trace_job(name, job).await,
        None => job.await,
    }
}

struct Trace {
    span: tracing::Span,
    queries: QueryLog,
    start: Timestamp,
}

impl Trace {
    fn start() -> Self {
        let span = tracing::debug_span!("self_monitor");
        let queries = QueryLog::default();
        span.with_subscriber(|(id, dispatch)| {
            if let Some(span) = dispatch.downcast_ref::<Registry>().and_then(|r| r.span(id)) {
                span.extensions_mut().insert(queries.clone());
            }
        });
        Self {
            span,
            queries,
            start: Timestamp::now(),
        }
    }
}

#[derive(Clone, Default)]
struct QueryLog(Arc<Mutex<Vec<Query>>>);

impl QueryLog {
    fn push(&self, query: Query) {
        if let Ok(mut queries) = self.0.lock() {
            queries.push(query);
        }
    }

    fn take(&self) -> Vec<Query> {
        self.0
            .lock()
            .map(|mut queries| std::mem::take(&mut *queries))
            .unwrap_or_default()
    }
}

struct Query {
    summary: String,
    statement: String,
    start: Timestamp,
    end: Timestamp,
}

fn nanos(ts: Timestamp) -> i64 {
    ts.as_nanosecond() as i64
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

fn attribute(key: &str, value: impl Into<String>) -> span::KeyValue {
    span::KeyValue {
        key: key.to_string(),
        value: span::AttributeValue {
            string_value: Some(value.into()),
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
                Record::Spans(s) => spans.extend(s),
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
        let trace = Trace::start();
        let res = self.inner.serve(req).instrument(trace.span.clone()).await?;
        let status = res.status().as_u16();
        monitor.record_trace(
            trace,
            format!("{method} {}", route_of(&path)),
            2,
            vec![
                attribute("http.method", method),
                attribute("http.target", path),
                attribute("http.status_code", status.to_string()),
            ],
            status >= 500,
        );
        Ok(res)
    }
}

/// `tracing` layer feeding the `self` project: ERROR events become errors
/// grouped by the file and line that logged them, and sqlx queries become
/// child spans of the request or job they ran in
pub struct CaptureLayer {
    monitor: &'static OnceLock<SelfMonitor>,
}

impl CaptureLayer {
    pub fn global() -> Self {
        Self { monitor: &GLOBAL }
    }

    pub fn filter() -> Targets {
        Targets::new()
            .with_default(Level::ERROR)
            .with_target("sqlx::query", Level::DEBUG)
            .with_target(module_path!(), Level::DEBUG)
    }
}

impl<S> tracing_subscriber::Layer<S> for CaptureLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let meta = event.metadata();
        if meta.target() == "sqlx::query" {
            let log = ctx
                .event_scope(event)
                .into_iter()
                .flatten()
                .find_map(|span| span.extensions().get::<QueryLog>().cloned());
            if let Some(log) = log {
                let mut query = QueryVisitor::default();
                event.record(&mut query);
                let end = Timestamp::now();
                let elapsed =
                    SignedDuration::try_from_secs_f64(query.elapsed_secs).unwrap_or_default();
                let statement = match query.statement.trim() {
                    "" => query.summary.clone(),
                    sql => sql.to_string(),
                };
                log.push(Query {
                    summary: query.summary,
                    statement,
                    start: end - elapsed,
                    end,
                });
            }
            return;
        }
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
        monitor.record(Record::Error(Box::new(IncomingError {
            exception_class: meta.target().to_string(),
            message: message.0,
            backtrace: vec![format!("{location}:in `{}'", meta.target())],
            fingerprint: format!("{}:{location}", meta.target()),
            request_id: None,
            user_id: None,
            params: None,
            timestamp: None,
            source_context: None,
        })));
    }
}

#[derive(Default)]
struct QueryVisitor {
    summary: String,
    statement: String,
    elapsed_secs: f64,
}

impl Visit for QueryVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "summary" => self.summary = value.to_string(),
            "db.statement" => self.statement = value.to_string(),
            _ => {}
        }
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        if field.name() == "elapsed_secs" {
            self.elapsed_secs = value;
        }
    }

    fn record_debug(&mut self, _field: &Field, _value: &dyn fmt::Debug) {}
}

/// The event's message, followed by its other fields as `key=value`
#[derive(Default)]
struct MessageVisitor(String);

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let separator = if self.0.is_empty() { "" } else { " " };
        // A Debug impl that errors leaves the message cut short rather than
        // panicking inside the tracing layer
        if field.name() == "message" {
            let fields = std::mem::take(&mut self.0);
            write!(self.0, "{value:?}{separator}{fields}").ok();
        } else {
            write!(self.0, "{separator}{}={value:?}", field.name()).ok();
        }
    }
}
