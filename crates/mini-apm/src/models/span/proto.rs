use rama::http::grpc::service::opentelemetry::proto::collector::trace::v1::ExportTraceServiceRequest;
use rama::http::grpc::service::opentelemetry::proto::common::v1::{
    self as common, any_value::Value,
};
use rama::http::grpc::service::opentelemetry::proto::trace::v1 as trace;

use super::{
    ArrayValue, AttributeValue, InstrumentationScope, KeyValue, OtlpSpan, OtlpTraceRequest,
    Resource, ResourceSpans, ScopeSpans, SpanEvent, SpanStatus,
};

impl From<ExportTraceServiceRequest> for OtlpTraceRequest {
    fn from(request: ExportTraceServiceRequest) -> Self {
        Self {
            resource_spans: request
                .resource_spans
                .into_iter()
                .map(|rs| ResourceSpans {
                    resource: rs.resource.map(|r| Resource {
                        attributes: Some(attributes(r.attributes)),
                    }),
                    scope_spans: Some(
                        rs.scope_spans
                            .into_iter()
                            .map(|ss| ScopeSpans {
                                scope: ss.scope.map(|s| InstrumentationScope {
                                    name: Some(s.name),
                                    version: Some(s.version),
                                }),
                                spans: ss.spans.into_iter().map(span).collect(),
                            })
                            .collect(),
                    ),
                })
                .collect(),
        }
    }
}

fn span(s: trace::Span) -> OtlpSpan {
    OtlpSpan {
        trace_id: hex::encode(s.trace_id),
        span_id: hex::encode(s.span_id),
        parent_span_id: (!s.parent_span_id.is_empty()).then(|| hex::encode(s.parent_span_id)),
        name: s.name,
        kind: Some(s.kind),
        start_time_unix_nano: s.start_time_unix_nano as i64,
        end_time_unix_nano: s.end_time_unix_nano as i64,
        attributes: Some(attributes(s.attributes)),
        events: Some(
            s.events
                .into_iter()
                .map(|e| SpanEvent {
                    name: e.name,
                    time_unix_nano: Some(e.time_unix_nano.to_string()),
                    attributes: Some(attributes(e.attributes)),
                })
                .collect(),
        ),
        status: s.status.map(|st| SpanStatus {
            code: Some(st.code),
            message: Some(st.message).filter(|m| !m.is_empty()),
        }),
    }
}

fn attributes(kvs: Vec<common::KeyValue>) -> Vec<KeyValue> {
    kvs.into_iter()
        .map(|kv| KeyValue {
            key: kv.key,
            value: value(kv.value),
        })
        .collect()
}

fn value(v: Option<common::AnyValue>) -> AttributeValue {
    let mut out = AttributeValue {
        string_value: None,
        int_value: None,
        double_value: None,
        bool_value: None,
        array_value: None,
    };
    match v.and_then(|v| v.value) {
        Some(Value::StringValue(s)) => out.string_value = Some(s),
        Some(Value::BoolValue(b)) => out.bool_value = Some(b),
        Some(Value::IntValue(i)) => out.int_value = Some(i.to_string()),
        Some(Value::DoubleValue(d)) => out.double_value = Some(d),
        Some(Value::BytesValue(b)) => out.string_value = Some(hex::encode(b)),
        Some(Value::ArrayValue(a)) => {
            out.array_value = Some(ArrayValue {
                values: Some(a.values.into_iter().map(|v| value(Some(v))).collect()),
            })
        }
        Some(Value::KvlistValue(_) | Value::StringValueStrindex(_)) | None => {}
    }
    out
}
