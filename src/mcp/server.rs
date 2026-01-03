use crate::{models, DbPool};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};

#[derive(Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    id: serde_json::Value,
    method: String,
    params: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

#[derive(Serialize)]
struct ToolInfo {
    name: String,
    description: String,
    input_schema: serde_json::Value,
}

pub async fn run(pool: DbPool) -> anyhow::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let response = JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: serde_json::Value::Null,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32700,
                        message: format!("Parse error: {}", e),
                    }),
                };
                writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
                stdout.flush()?;
                continue;
            }
        };

        let response = handle_request(&pool, request)?;
        writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
        stdout.flush()?;
    }

    Ok(())
}

fn handle_request(pool: &DbPool, request: JsonRpcRequest) -> anyhow::Result<JsonRpcResponse> {
    let result = match request.method.as_str() {
        "initialize" => handle_initialize(),
        "tools/list" => handle_list_tools(),
        "tools/call" => handle_tool_call(pool, request.params),
        _ => Err(anyhow::anyhow!("Unknown method: {}", request.method)),
    };

    match result {
        Ok(value) => Ok(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: request.id,
            result: Some(value),
            error: None,
        }),
        Err(e) => Ok(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: request.id,
            result: None,
            error: Some(JsonRpcError {
                code: -32603,
                message: e.to_string(),
            }),
        }),
    }
}

fn handle_initialize() -> anyhow::Result<serde_json::Value> {
    Ok(serde_json::json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": "miniapm",
            "version": "0.1.0"
        }
    }))
}

fn handle_list_tools() -> anyhow::Result<serde_json::Value> {
    let tools = vec![
        ToolInfo {
            name: "list_errors".to_string(),
            description: "List recent errors grouped by fingerprint".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "status": {"type": "string", "enum": ["open", "resolved", "ignored"]},
                    "limit": {"type": "integer", "default": 10}
                }
            }),
        },
        ToolInfo {
            name: "error_details".to_string(),
            description: "Get full details for a specific error".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "id": {"type": "integer"}
                },
                "required": ["id"]
            }),
        },
        ToolInfo {
            name: "slow_routes".to_string(),
            description: "Get slowest routes by average latency".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "period": {"type": "string", "enum": ["24h", "7d", "30d"], "default": "24h"},
                    "limit": {"type": "integer", "default": 10}
                }
            }),
        },
        ToolInfo {
            name: "system_status".to_string(),
            description: "Get overall system health".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        },
    ];

    Ok(serde_json::json!({ "tools": tools }))
}

fn handle_tool_call(pool: &DbPool, params: Option<serde_json::Value>) -> anyhow::Result<serde_json::Value> {
    let params = params.ok_or_else(|| anyhow::anyhow!("Missing params"))?;
    let tool_name = params["name"].as_str().ok_or_else(|| anyhow::anyhow!("Missing tool name"))?;
    let args = &params["arguments"];

    // MCP shows data across all projects (project_id = None)
    let result = match tool_name {
        "list_errors" => {
            let status = args["status"].as_str();
            let limit = args["limit"].as_i64().unwrap_or(10);
            let errors = models::error::list(pool, None, status, limit)?;
            serde_json::to_value(errors)?
        }
        "error_details" => {
            let id = args["id"].as_i64().ok_or_else(|| anyhow::anyhow!("Missing id"))?;
            let error = models::error::find(pool, id)?;
            let occurrences = if error.is_some() {
                models::error::occurrences(pool, id, 5)?
            } else {
                vec![]
            };
            serde_json::json!({
                "error": error,
                "occurrences": occurrences
            })
        }
        "slow_routes" => {
            let period = args["period"].as_str().unwrap_or("24h");
            let limit = args["limit"].as_i64().unwrap_or(10);
            let since = match period {
                "7d" => Utc::now() - Duration::days(7),
                "30d" => Utc::now() - Duration::days(30),
                _ => Utc::now() - Duration::hours(24),
            };
            let routes = models::request::routes_summary(pool, None, &since.to_rfc3339(), limit)?;
            serde_json::to_value(routes)?
        }
        "system_status" => {
            let since_24h = (Utc::now() - Duration::hours(24)).to_rfc3339();
            let requests_24h = models::request::count_since(pool, None, &since_24h)?;
            let errors_24h = models::error::count_since(pool, None, &since_24h)?;
            let avg_ms = models::request::avg_ms_since(pool, None, &since_24h)?;
            let db_size = crate::db::get_db_size(pool)?;

            serde_json::json!({
                "requests_24h": requests_24h,
                "errors_24h": errors_24h,
                "error_rate": if requests_24h > 0 { errors_24h as f64 / requests_24h as f64 } else { 0.0 },
                "avg_response_ms": avg_ms,
                "db_size_mb": db_size
            })
        }
        _ => return Err(anyhow::anyhow!("Unknown tool: {}", tool_name)),
    };

    Ok(serde_json::json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&result)?
        }]
    }))
}
