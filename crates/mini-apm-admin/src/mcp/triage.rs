use std::time::Duration;

use mcp_host::bt::{Ask, Call, Check, Node, Sample, TreeTool};
use mcp_host::protocol::elicitation::ElicitationSchema;
use serde_json::{Value, json};

/// Time any tool call may take; the triage tree waits on a person within it
pub const BUDGET: Duration = Duration::from_mins(5);
const ASK_TIMEOUT: Duration = Duration::from_mins(3);
const SAMPLE_TIMEOUT: Duration = Duration::from_mins(1);
const BACKTRACE_LINES: usize = 15;

const ASSESSOR: &str = "You triage errors reported by an application performance monitor. \
In at most three sentences, name the likely cause and say whether the error should be \
resolved, ignored, or kept open.";

/// `triage_error`: load an error, have the client's model assess it when it
/// can sample, then ask the user how to change its status. Declining, or a
/// client that cannot ask, leaves the error as it is.
pub fn tool() -> anyhow::Result<TreeTool> {
    let decision = ElicitationSchema::builder()
        .required_enum("action", ["resolve", "ignore", "reopen"])
        .description("Pick a status change, or decline to leave the error as it is")
        .build()
        .map_err(anyhow::Error::msg)?;

    let decide = Node::sequence([
        Node::from(
            Ask::message_from(question)
                .with_schema(decision)
                .store_as("decision"),
        )
        .timeout(ASK_TIMEOUT),
        Call::new("set_error_status")
            .try_args_from(|board| {
                let action = board["decision"]["action"]
                    .as_str()
                    .ok_or_else(|| "no action was chosen".to_owned())?;
                Ok(json!({ "id": board["input"]["id"], "action": action }))
            })
            .store_as("status")
            .into(),
    ]);
    let root = Node::sequence([
        Call::new("error_details")
            .args_from(|board| json!({ "id": board["input"]["id"], "occurrences": 1 }))
            .store_as("error")
            .into(),
        Node::from(
            Sample::prompt_from(assessment_prompt)
                .with_system(ASSESSOR)
                .with_max_tokens(300)
                .store_as("assessment"),
        )
        .timeout(SAMPLE_TIMEOUT)
        .force_success(),
        Node::fallback([
            decide,
            Check::new("left unchanged", |board| board["decision"].is_null()).into(),
        ]),
    ]);

    Ok(TreeTool::new("triage_error", root)?
        .with_description(
            "Walk the user through one error group: load it, assess it with the client's \
             model when sampling is available, then ask whether to resolve, ignore or reopen \
             it. Declining leaves it unchanged; changing it needs form elicitation.",
        )
        .with_input_schema(json!({
            "type": "object",
            "properties": {
                "id": { "type": "integer", "description": "Error id from list_errors" }
            },
            "required": ["id"]
        })))
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or("unknown")
}

fn question(board: &Value) -> String {
    let report = &board["error"];
    let error = &report["error"];
    let allowed: Vec<&str> = report["allowed_actions"]
        .as_array()
        .map(|actions| actions.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    format!(
        "{}: {}\nStatus {}, seen {} times, last at {}.\nAssessment: {}\nAllowed changes: {}.",
        text(&error["exception_class"]),
        text(&error["message"]),
        text(&error["status"]),
        error["occurrence_count"],
        text(&error["last_seen_at"]),
        board["assessment"].as_str().unwrap_or("none"),
        allowed.join(", "),
    )
}

fn assessment_prompt(board: &Value) -> String {
    let report = &board["error"];
    let error = &report["error"];
    let occurrence = &report["occurrences"][0];
    let backtrace: Vec<&str> = occurrence["backtrace"]
        .as_array()
        .map(|lines| {
            lines
                .iter()
                .filter_map(Value::as_str)
                .take(BACKTRACE_LINES)
                .collect()
        })
        .unwrap_or_default();
    let source = &occurrence["source_context"];
    format!(
        "{}: {}\nStatus {}, {} occurrences between {} and {}.\n\nBacktrace:\n{}\n\nFailing line {}:{}: {}",
        text(&error["exception_class"]),
        text(&error["message"]),
        text(&error["status"]),
        error["occurrence_count"],
        text(&error["first_seen_at"]),
        text(&error["last_seen_at"]),
        backtrace.join("\n"),
        text(&source["file"]),
        source["lineno"],
        text(&source["context_line"]),
    )
}
