use rand::Rng;
use serde_json::{json, Value};

use super::routes::Route;

/// Generate a complete trace for a web request with realistic child spans
pub fn generate_web_trace(route: &Route, total_ms: f64, db_ms: f64, view_ms: f64) -> Value {
    let mut rng = rand::thread_rng();

    // Generate IDs
    let trace_id = format!("{:032x}", rng.gen::<u128>());
    let root_span_id = format!("{:016x}", rng.gen::<u64>());

    // Timestamps in nanoseconds
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64;
    let start_ns = now_ns - (total_ms * 1_000_000.0) as i64;
    let end_ns = now_ns;

    let mut spans = Vec::new();

    // Root span (HTTP server)
    let status_code = if rng.gen::<f64>() < 0.05 { 500 } else { 200 };
    spans.push(json!({
        "traceId": trace_id,
        "spanId": root_span_id,
        "name": format!("{} {}", route.method, route.path),
        "kind": 2, // SERVER
        "startTimeUnixNano": start_ns.to_string(),
        "endTimeUnixNano": end_ns.to_string(),
        "attributes": [
            {"key": "http.method", "value": {"stringValue": route.method}},
            {"key": "http.url", "value": {"stringValue": format!("https://shop.example.com{}", route.path)}},
            {"key": "http.status_code", "value": {"intValue": status_code.to_string()}},
            {"key": "http.route", "value": {"stringValue": route.path}},
            {"key": "rails.controller", "value": {"stringValue": route.controller}},
            {"key": "rails.action", "value": {"stringValue": route.action}}
        ],
        "status": {"code": if status_code >= 400 { 2 } else { 1 }}
    }));

    let mut current_offset = 0.0;

    // Generate ActiveRecord spans
    let db_queries = route.db_queries.max(1);
    let avg_query_ms = db_ms / db_queries as f64;

    for i in 0..db_queries {
        let span_id = format!("{:016x}", rng.gen::<u64>());
        let query_ms = avg_query_ms * (0.5 + rng.gen::<f64>());
        let query_start = start_ns + (current_offset * 1_000_000.0) as i64;
        let query_end = query_start + (query_ms * 1_000_000.0) as i64;

        let (table, operation) = pick_query_type(&mut rng, route);
        let query = generate_sql_query(operation, table);

        spans.push(json!({
            "traceId": trace_id,
            "spanId": span_id,
            "parentSpanId": root_span_id,
            "name": format!("{} {}", operation, table),
            "kind": 3, // CLIENT
            "startTimeUnixNano": query_start.to_string(),
            "endTimeUnixNano": query_end.to_string(),
            "attributes": [
                {"key": "db.system", "value": {"stringValue": "postgresql"}},
                {"key": "db.name", "value": {"stringValue": "shop_production"}},
                {"key": "db.operation", "value": {"stringValue": operation}},
                {"key": "db.sql.table", "value": {"stringValue": table}},
                {"key": "db.statement", "value": {"stringValue": query}}
            ],
            "status": {"code": 1}
        }));

        current_offset += query_ms * 0.8; // Some overlap

        // Occasionally add an Elasticsearch query for search routes
        if route.path.contains("search") && i == 0 {
            let es_span_id = format!("{:016x}", rng.gen::<u64>());
            let es_ms = 20.0 + rng.gen::<f64>() * 80.0;
            let es_start = query_end;
            let es_end = es_start + (es_ms * 1_000_000.0) as i64;

            spans.push(json!({
                "traceId": trace_id,
                "spanId": es_span_id,
                "parentSpanId": root_span_id,
                "name": "POST products/_search",
                "kind": 3, // CLIENT
                "startTimeUnixNano": es_start.to_string(),
                "endTimeUnixNano": es_end.to_string(),
                "attributes": [
                    {"key": "db.system", "value": {"stringValue": "elasticsearch"}},
                    {"key": "db.operation", "value": {"stringValue": "search"}},
                    {"key": "db.statement", "value": {"stringValue": r#"{"query":{"multi_match":{"query":"...","fields":["name^10","description"]}}}"#}}
                ],
                "status": {"code": 1}
            }));
            current_offset += es_ms;
        }
    }

    // Generate view rendering spans
    if view_ms > 0.0 {
        let view_span_id = format!("{:016x}", rng.gen::<u64>());
        let view_start = end_ns - (view_ms * 1_000_000.0) as i64;

        let template = match route.action {
            "index" => format!("{}/index.html.erb", route.controller.to_lowercase().replace("::", "/")),
            "show" => format!("{}/show.html.erb", route.controller.to_lowercase().replace("::", "/")),
            _ => format!("{}/{}.html.erb", route.controller.to_lowercase().replace("::", "/"), route.action),
        };

        spans.push(json!({
            "traceId": trace_id,
            "spanId": view_span_id,
            "parentSpanId": root_span_id,
            "name": format!("render_template {}", template),
            "kind": 0, // INTERNAL
            "startTimeUnixNano": view_start.to_string(),
            "endTimeUnixNano": end_ns.to_string(),
            "attributes": [
                {"key": "rails.template", "value": {"stringValue": template}}
            ],
            "status": {"code": 1}
        }));

        // Add partial renders
        let partials = pick_partials(&mut rng, route);
        let partial_ms = view_ms / (partials.len() + 1) as f64;
        let mut partial_offset = view_start;

        for partial in partials {
            let partial_span_id = format!("{:016x}", rng.gen::<u64>());
            let partial_end = partial_offset + (partial_ms * 1_000_000.0) as i64;

            spans.push(json!({
                "traceId": trace_id,
                "spanId": partial_span_id,
                "parentSpanId": view_span_id,
                "name": format!("render_partial {}", partial),
                "kind": 0, // INTERNAL
                "startTimeUnixNano": partial_offset.to_string(),
                "endTimeUnixNano": partial_end.to_string(),
                "attributes": [
                    {"key": "rails.template", "value": {"stringValue": partial}}
                ],
                "status": {"code": 1}
            }));
            partial_offset = partial_end;
        }
    }

    // Occasionally add HTTP client call (external API)
    if rng.gen::<f64>() < 0.15 {
        let http_span_id = format!("{:016x}", rng.gen::<u64>());
        let http_ms = 30.0 + rng.gen::<f64>() * 150.0;
        let http_start = start_ns + ((total_ms * 0.3) * 1_000_000.0) as i64;
        let http_end = http_start + (http_ms * 1_000_000.0) as i64;

        let (url, service) = pick_external_service(&mut rng);

        spans.push(json!({
            "traceId": trace_id,
            "spanId": http_span_id,
            "parentSpanId": root_span_id,
            "name": format!("GET {}", url),
            "kind": 3, // CLIENT
            "startTimeUnixNano": http_start.to_string(),
            "endTimeUnixNano": http_end.to_string(),
            "attributes": [
                {"key": "http.method", "value": {"stringValue": "GET"}},
                {"key": "http.url", "value": {"stringValue": url}},
                {"key": "http.status_code", "value": {"intValue": "200"}},
                {"key": "peer.service", "value": {"stringValue": service}}
            ],
            "status": {"code": 1}
        }));
    }

    json!({
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    {"key": "service.name", "value": {"stringValue": "shop-rails"}},
                    {"key": "service.version", "value": {"stringValue": "1.2.3"}},
                    {"key": "deployment.environment", "value": {"stringValue": "production"}}
                ]
            },
            "scopeSpans": [{
                "scope": {
                    "name": "opentelemetry-instrumentation-rails",
                    "version": "0.28.0"
                },
                "spans": spans
            }]
        }]
    })
}

/// Generate a background job trace
pub fn generate_job_trace() -> Value {
    let mut rng = rand::thread_rng();

    let trace_id = format!("{:032x}", rng.gen::<u128>());
    let root_span_id = format!("{:016x}", rng.gen::<u64>());

    let jobs = [
        ("OrderMailer", "confirmation_email", 150.0, 3),
        ("InventoryUpdateJob", "perform", 80.0, 5),
        ("ReportGeneratorJob", "perform", 500.0, 20),
        ("ImageProcessorJob", "perform", 300.0, 2),
        ("WebhookDeliveryJob", "perform", 200.0, 1),
        ("SearchIndexJob", "perform", 100.0, 8),
    ];

    let (job_class, method, base_ms, db_queries) = jobs[rng.gen_range(0..jobs.len())];
    let total_ms = base_ms * (0.7 + rng.gen::<f64>() * 0.6);

    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64;
    let start_ns = now_ns - (total_ms * 1_000_000.0) as i64;
    let end_ns = now_ns;

    let mut spans = Vec::new();

    // Root job span
    spans.push(json!({
        "traceId": trace_id,
        "spanId": root_span_id,
        "name": format!("{}.{}", job_class, method),
        "kind": 5, // CONSUMER
        "startTimeUnixNano": start_ns.to_string(),
        "endTimeUnixNano": end_ns.to_string(),
        "attributes": [
            {"key": "messaging.system", "value": {"stringValue": "sidekiq"}},
            {"key": "messaging.destination.name", "value": {"stringValue": "default"}},
            {"key": "messaging.operation", "value": {"stringValue": "process"}},
            {"key": "sidekiq.job_class", "value": {"stringValue": job_class}}
        ],
        "status": {"code": 1}
    }));

    // Add some DB queries
    let avg_query_ms = (total_ms * 0.4) / db_queries as f64;
    let mut offset = 0.0;

    for _ in 0..db_queries {
        let span_id = format!("{:016x}", rng.gen::<u64>());
        let query_ms = avg_query_ms * (0.5 + rng.gen::<f64>());
        let query_start = start_ns + (offset * 1_000_000.0) as i64;
        let query_end = query_start + (query_ms * 1_000_000.0) as i64;

        let tables = ["orders", "users", "products", "inventory_items", "emails"];
        let table = tables[rng.gen_range(0..tables.len())];
        let ops = ["SELECT", "UPDATE", "INSERT"];
        let op = ops[rng.gen_range(0..ops.len())];

        spans.push(json!({
            "traceId": trace_id,
            "spanId": span_id,
            "parentSpanId": root_span_id,
            "name": format!("{} {}", op, table),
            "kind": 3,
            "startTimeUnixNano": query_start.to_string(),
            "endTimeUnixNano": query_end.to_string(),
            "attributes": [
                {"key": "db.system", "value": {"stringValue": "postgresql"}},
                {"key": "db.operation", "value": {"stringValue": op}},
                {"key": "db.sql.table", "value": {"stringValue": table}}
            ],
            "status": {"code": 1}
        }));

        offset += query_ms;
    }

    // HTTP client call for mailer/webhook jobs
    if job_class.contains("Mailer") || job_class.contains("Webhook") {
        let span_id = format!("{:016x}", rng.gen::<u64>());
        let http_ms = 50.0 + rng.gen::<f64>() * 100.0;
        let http_start = start_ns + ((total_ms * 0.5) * 1_000_000.0) as i64;
        let http_end = http_start + (http_ms * 1_000_000.0) as i64;

        let (url, kind) = if job_class.contains("Mailer") {
            ("https://api.sendgrid.com/v3/mail/send", "POST")
        } else {
            ("https://webhooks.example.com/events", "POST")
        };

        spans.push(json!({
            "traceId": trace_id,
            "spanId": span_id,
            "parentSpanId": root_span_id,
            "name": format!("{} {}", kind, url),
            "kind": 3,
            "startTimeUnixNano": http_start.to_string(),
            "endTimeUnixNano": http_end.to_string(),
            "attributes": [
                {"key": "http.method", "value": {"stringValue": kind}},
                {"key": "http.url", "value": {"stringValue": url}},
                {"key": "http.status_code", "value": {"intValue": "200"}}
            ],
            "status": {"code": 1}
        }));
    }

    json!({
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    {"key": "service.name", "value": {"stringValue": "shop-rails"}},
                    {"key": "service.version", "value": {"stringValue": "1.2.3"}}
                ]
            },
            "scopeSpans": [{
                "scope": {"name": "opentelemetry-instrumentation-sidekiq"},
                "spans": spans
            }]
        }]
    })
}

/// Generate a rake task trace
pub fn generate_rake_trace() -> Value {
    let mut rng = rand::thread_rng();

    let trace_id = format!("{:032x}", rng.gen::<u128>());
    let root_span_id = format!("{:016x}", rng.gen::<u64>());

    let tasks = [
        ("db:migrate", 2000.0, 15),
        ("assets:precompile", 5000.0, 2),
        ("cache:clear", 100.0, 3),
        ("reports:daily", 3000.0, 50),
        ("cleanup:old_sessions", 500.0, 10),
    ];

    let (task_name, base_ms, db_queries) = tasks[rng.gen_range(0..tasks.len())];
    let total_ms = base_ms * (0.8 + rng.gen::<f64>() * 0.4);

    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64;
    let start_ns = now_ns - (total_ms * 1_000_000.0) as i64;
    let end_ns = now_ns;

    let mut spans = Vec::new();

    spans.push(json!({
        "traceId": trace_id,
        "spanId": root_span_id,
        "name": format!("rake {}", task_name),
        "kind": 0, // INTERNAL
        "startTimeUnixNano": start_ns.to_string(),
        "endTimeUnixNano": end_ns.to_string(),
        "attributes": [
            {"key": "rake.task", "value": {"stringValue": task_name}}
        ],
        "status": {"code": 1}
    }));

    // DB queries for rake tasks
    let avg_query_ms = (total_ms * 0.6) / db_queries as f64;
    let mut offset = 0.0;

    for _ in 0..db_queries {
        let span_id = format!("{:016x}", rng.gen::<u64>());
        let query_ms = avg_query_ms * (0.3 + rng.gen::<f64>() * 1.4);
        let query_start = start_ns + (offset * 1_000_000.0) as i64;
        let query_end = query_start + (query_ms * 1_000_000.0) as i64;

        let op = if task_name.contains("migrate") {
            ["ALTER TABLE", "CREATE INDEX", "DROP TABLE"][rng.gen_range(0..3)]
        } else {
            ["SELECT", "DELETE", "UPDATE"][rng.gen_range(0..3)]
        };

        spans.push(json!({
            "traceId": trace_id,
            "spanId": span_id,
            "parentSpanId": root_span_id,
            "name": op,
            "kind": 3,
            "startTimeUnixNano": query_start.to_string(),
            "endTimeUnixNano": query_end.to_string(),
            "attributes": [
                {"key": "db.system", "value": {"stringValue": "postgresql"}},
                {"key": "db.operation", "value": {"stringValue": op.split_whitespace().next().unwrap_or(op)}}
            ],
            "status": {"code": 1}
        }));

        offset += query_ms * 0.9;
    }

    json!({
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    {"key": "service.name", "value": {"stringValue": "shop-rails"}}
                ]
            },
            "scopeSpans": [{
                "scope": {"name": "opentelemetry-instrumentation-rake"},
                "spans": spans
            }]
        }]
    })
}

fn pick_query_type<R: Rng>(rng: &mut R, route: &Route) -> (&'static str, &'static str) {
    let tables = match route.controller {
        "ProductsController" | "Api::V1::ProductsController" => &["products", "categories", "product_images"][..],
        "CartController" | "CartItemsController" => &["carts", "cart_items", "products"][..],
        "CheckoutController" => &["orders", "order_items", "payments", "addresses"][..],
        "OrdersController" => &["orders", "order_items", "users"][..],
        "SearchController" => &["products", "categories"][..],
        _ => &["users", "sessions", "products"][..],
    };

    let ops = ["SELECT", "SELECT", "SELECT", "INSERT", "UPDATE"];
    let table = tables[rng.gen_range(0..tables.len())];
    let op = ops[rng.gen_range(0..ops.len())];

    (table, op)
}

fn generate_sql_query(operation: &str, table: &str) -> String {
    match operation {
        "SELECT" => format!("SELECT \"{}\".*  FROM \"{}\" WHERE \"{}\"...", table, table, table),
        "INSERT" => format!("INSERT INTO \"{}\" (...) VALUES (...)", table),
        "UPDATE" => format!("UPDATE \"{}\" SET ... WHERE ...", table),
        _ => format!("{} on {}", operation, table),
    }
}

fn pick_partials<R: Rng>(rng: &mut R, route: &Route) -> Vec<String> {
    let base = route.controller.to_lowercase().replace("::", "/");
    let mut partials = Vec::new();

    if rng.gen::<f64>() < 0.7 {
        partials.push("shared/_header.html.erb".to_string());
    }
    if rng.gen::<f64>() < 0.8 {
        partials.push("shared/_navigation.html.erb".to_string());
    }
    if route.action == "index" && rng.gen::<f64>() < 0.9 {
        partials.push(format!("{}/_item.html.erb", base));
    }
    if route.action == "show" && rng.gen::<f64>() < 0.6 {
        partials.push(format!("{}/_details.html.erb", base));
    }
    if rng.gen::<f64>() < 0.5 {
        partials.push("shared/_footer.html.erb".to_string());
    }

    partials
}

fn pick_external_service<R: Rng>(rng: &mut R) -> (&'static str, &'static str) {
    let services = [
        ("https://api.stripe.com/v1/charges", "stripe"),
        ("https://api.sendgrid.com/v3/mail/send", "sendgrid"),
        ("https://api.twilio.com/2010-04-01/Messages", "twilio"),
        ("https://maps.googleapis.com/maps/api/geocode/json", "google-maps"),
    ];
    services[rng.gen_range(0..services.len())]
}
