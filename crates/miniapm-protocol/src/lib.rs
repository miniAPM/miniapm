//! Wire types for the `MiniAPM` ingest API.
//!
//! Requests carry `Authorization: Bearer <project api key>` and a JSON body.
//! Paths are relative to the collector's base URL.

#![cfg_attr(test, allow(dead_code_pub_in_binary))]

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `POST` an [`IncomingError`].
pub const ERRORS_PATH: &str = "/ingest/errors";
/// `POST` an [`IncomingErrorBatch`].
pub const ERRORS_BATCH_PATH: &str = "/ingest/errors/batch";
/// `POST` an [`IncomingDeploy`].
pub const DEPLOYS_PATH: &str = "/ingest/deploys";
/// `POST` an OTLP `ExportTraceServiceRequest`, protobuf or JSON.
pub const TRACES_PATH: &str = "/ingest/v1/traces";

/// One error occurrence. Occurrences with the same `fingerprint` group together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncomingError {
    pub exception_class: String,
    pub message: String,
    pub backtrace: Vec<String>,
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    /// When it happened; the collector uses its receive time when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_context: Option<IncomingSourceContext>,
}

/// Source lines around the line that raised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncomingSourceContext {
    pub file: String,
    pub lineno: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_context: Option<Vec<String>>,
    pub context_line: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_context: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncomingErrorBatch {
    pub errors: Vec<IncomingError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncomingDeploy {
    pub git_sha: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployer: Option<String>,
    /// When it happened; the collector uses its receive time when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<Timestamp>,
}

#[cfg(test)]
mod tests;
