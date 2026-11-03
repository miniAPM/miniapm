use std::sync::atomic::{AtomicU64, Ordering};

use rama::http::body::util::BodyExt;
use rama::http::{Request, StatusCode};
use serde_json::{Value, json};

use super::*;
use crate::make_app;
use mini_apm::models::{error, mcp_token, project, user};

const PROTOCOL: &str = "2025-11-25";

fn post(token: Option<&str>, session: Option<&str>, body: &Value) -> Request {
    let mut req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", PROTOCOL);
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    if let Some(session) = session {
        req = req.header("mcp-session-id", session);
    }
    req.body(Body::from(body.to_string())).unwrap()
}

fn form(uri: &str, body: &str) -> Request {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn initialize() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL,
            "capabilities": {},
            "clientInfo": { "name": "miniapm-tests", "version": "1" }
        }
    })
}

async fn reply(res: Response, id: u64) -> Value {
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8(body.to_vec()).unwrap();
    text.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|data| serde_json::from_str::<Value>(data.trim()).ok())
        .find(|message| message["id"] == id)
        .unwrap_or_else(|| panic!("no reply to {id} in {text:?}"))
}

struct Client<S> {
    app: S,
    token: String,
    session: String,
    ids: AtomicU64,
}

impl<S: Service<Request, Output = Response, Error = Infallible>> Client<S> {
    async fn connect(app: S, token: String) -> Self {
        let res = app
            .serve(post(Some(&token), None, &initialize()))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let session = res.headers()["mcp-session-id"].to_str().unwrap().to_owned();
        let init = reply(res, 0).await;
        assert_eq!(init["result"]["serverInfo"]["name"], "miniapm");

        let initialized = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        let res = app
            .serve(post(Some(&token), Some(&session), &initialized))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        Self {
            app,
            token,
            session,
            ids: AtomicU64::new(1),
        }
    }

    async fn request(&self, method: &str, params: Value) -> Value {
        let id = self.ids.fetch_add(1, Ordering::Relaxed);
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let res = self
            .app
            .serve(post(Some(&self.token), Some(&self.session), &body))
            .await
            .unwrap();
        let message = reply(res, id).await;
        message
            .get("result")
            .cloned()
            .unwrap_or_else(|| panic!("{method} failed: {message}"))
    }

    async fn tool(&self, name: &str, arguments: Value) -> Value {
        self.request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        )
        .await
    }

    fn sse(&self) -> Request {
        Request::builder()
            .method("GET")
            .uri("/mcp")
            .header("accept", "text/event-stream")
            .header("mcp-protocol-version", PROTOCOL)
            .header("authorization", format!("Bearer {}", self.token))
            .header("mcp-session-id", &self.session)
            .body(Body::empty())
            .unwrap()
    }
}

struct Fixture {
    pool: DbPool,
    admin: i64,
    token_id: i64,
    secret: String,
    error_id: i64,
}

async fn fixture() -> Fixture {
    let pool = mini_apm::db::test_pool().await;
    let admin = user::create(&pool, "admin", "admin-password", true)
        .await
        .unwrap();
    let (token, secret) = mcp_token::create(&pool, admin, "tests").await.unwrap();
    let project = project::ensure_default_project(&pool).await.unwrap();
    let incoming = error::IncomingError {
        exception_class: "NoMethodError".into(),
        message: "undefined method `total' for nil".into(),
        backtrace: vec!["app/models/order.rb:12:in `total'".into()],
        fingerprint: "fp".into(),
        request_id: None,
        user_id: None,
        params: None,
        timestamp: None,
        source_context: None,
    };
    let error_id = error::insert(&pool, &incoming, Some(project.id))
        .await
        .unwrap();
    for (span_id, parent, name, category, root_type) in [
        ("root", None, "GET /orders", "http_server", Some("web")),
        ("child", Some("root"), "SELECT orders", "db", None),
    ] {
        sqlx::query(
            "INSERT INTO spans (project_id, trace_id, span_id, parent_span_id, start_time_unix_nano,
                end_time_unix_nano, duration_ms, name, span_category, root_span_type, happened_at)
             VALUES ($1, 'trace-1', $2, $3, 0, 1, 1.0, $4, $5, $6, $7)",
        )
        .bind(project.id)
        .bind(span_id)
        .bind(parent)
        .bind(name)
        .bind(category)
        .bind(root_type)
        .bind(mini_apm::time::Stamp::now())
        .execute(&pool)
        .await
        .unwrap();
    }
    Fixture {
        pool,
        admin,
        token_id: token.id,
        secret,
        error_id,
    }
}

#[tokio::test]
async fn requests_need_a_live_token_and_no_browser_origin() {
    let f = fixture().await;
    let (token, revoked) = mcp_token::create(&f.pool, f.admin, "revoked")
        .await
        .unwrap();
    mcp_token::revoke(&f.pool, f.admin, token.id).await.unwrap();
    let app = make_app(f.pool).unwrap();

    for (authorization, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (
            Some("Bearer mcp_bogus".to_owned()),
            StatusCode::UNAUTHORIZED,
        ),
        (
            Some(format!("Basic {}", f.secret)),
            StatusCode::UNAUTHORIZED,
        ),
        (Some(format!("Bearer {revoked}")), StatusCode::UNAUTHORIZED),
        (Some(format!("bearer {}", f.secret)), StatusCode::OK),
    ] {
        let mut req = post(None, None, &initialize());
        if let Some(value) = &authorization {
            req.headers_mut()
                .insert("authorization", value.parse().unwrap());
        }
        let res = app.serve(req).await.unwrap();
        assert_eq!(res.status(), expected, "{authorization:?}");
    }

    let mut req = post(Some(&f.secret), None, &initialize());
    req.headers_mut()
        .insert("origin", "https://evil.example".parse().unwrap());
    assert_eq!(
        app.serve(req).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn tools_and_resources_read_and_triage_the_collected_data() {
    let f = fixture().await;
    let client = Client::connect(make_app(f.pool.clone()).unwrap(), f.secret).await;
    let id = f.error_id;

    let tools = client.request("tools/list", json!({})).await;
    let mut names: Vec<&str> = tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "error_details",
            "list_deploys",
            "list_errors",
            "list_projects",
            "list_traces",
            "set_error_status",
            "slow_routes",
            "trace_detail",
            "triage_error",
        ]
    );

    let projects = client.tool("list_projects", json!({})).await;
    assert!(!projects.to_string().contains("api_key"), "{projects}");

    let errors = client
        .tool("list_errors", json!({ "project": "default" }))
        .await;
    assert_eq!(errors["structuredContent"]["total"], 1);
    assert_eq!(errors["structuredContent"]["errors"][0]["id"], id);
    for (arguments, message) in [
        (json!({ "project": "nope" }), "No project 'nope'"),
        (json!({ "limit": 0 }), "limit must be between 1 and 100"),
        (json!({ "status": "closed" }), "closed"),
    ] {
        let refused = client.tool("list_errors", arguments.clone()).await;
        assert_eq!(refused["isError"], true, "{arguments}");
        assert!(
            refused.to_string().contains(message),
            "{arguments}: {refused}"
        );
    }

    let details = client.tool("error_details", json!({ "id": id })).await;
    assert_eq!(
        details["structuredContent"]["allowed_actions"],
        json!(["resolve", "ignore"])
    );

    let triage = client.tool("triage_error", json!({ "id": id })).await;
    assert_ne!(triage["isError"], true, "{triage}");
    let steps = &triage["structuredContent"]["steps"];
    assert_eq!(
        steps.as_array().unwrap().last().unwrap()["check"],
        "left unchanged"
    );
    assert_eq!(
        client.tool("triage_error", json!({})).await["isError"],
        true
    );

    let resolved = client
        .tool("set_error_status", json!({ "id": id, "action": "resolve" }))
        .await;
    assert_eq!(resolved["structuredContent"]["status"], "resolved");
    let again = client
        .tool("set_error_status", json!({ "id": id, "action": "resolve" }))
        .await;
    assert_eq!(again["isError"], true);
    assert!(again.to_string().contains("is resolved"), "{again}");

    let trace = client
        .tool(
            "trace_detail",
            json!({ "trace_id": "trace-1", "max_spans": 1 }),
        )
        .await;
    assert_eq!(trace["structuredContent"]["span_count"], 2);
    assert_eq!(trace["structuredContent"]["truncated"], true);
    let routes = client.tool("slow_routes", json!({})).await;
    assert_eq!(
        routes["structuredContent"]["routes"][0]["path"],
        "GET /orders"
    );

    let templates = client.request("resources/templates/list", json!({})).await;
    assert_eq!(templates["resourceTemplates"].as_array().unwrap().len(), 2);
    let read = client
        .request(
            "resources/read",
            json!({ "uri": format!("miniapm://errors/{id}") }),
        )
        .await;
    let report: Value =
        serde_json::from_str(read["contents"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(report["error"]["status"], "resolved");
    assert_eq!(report["allowed_actions"], json!(["ignore", "reopen"]));
}

#[tokio::test]
async fn event_streams_end_on_revocation_and_shutdown() {
    use mini_apm::server::ShutdownSignal;
    use rama::graceful::Shutdown;

    let f = fixture().await;
    let app = make_app(f.pool.clone()).unwrap();
    let ended = async |res: Response| {
        assert_eq!(res.headers()["content-type"], "text/event-stream");
        let rest = tokio::time::timeout(Duration::from_secs(5), res.into_body().collect()).await;
        assert!(rest.is_ok(), "stream still open");
    };

    let client = Client::connect(app.clone(), f.secret.clone()).await;
    let (trigger, signal) = tokio::sync::oneshot::channel::<()>();
    let shutdown = Shutdown::new(signal);
    let req = client.sse();
    req.extensions()
        .insert(ShutdownSignal(shutdown.guard_weak()));
    let stream = app.serve(req).await.unwrap();
    trigger.send(()).unwrap();
    ended(stream).await;

    let client = Client::connect(app.clone(), f.secret).await;
    let stream = app.serve(client.sse()).await.unwrap();
    let revoke = form("/mcp-tokens/revoke", &format!("id={}", f.token_id));
    assert_eq!(
        app.serve(revoke).await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
    ended(stream).await;
    let res = app
        .serve(post(
            Some(&client.token),
            Some(&client.session),
            &initialize(),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_page_shows_a_new_secret_once() {
    let f = fixture().await;
    let app = make_app(f.pool.clone()).unwrap();
    let page = async |req: Request| {
        let res = app.serve(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(body.to_vec()).unwrap()
    };
    let create = |name: &str| form("/mcp-tokens/create", &format!("name={name}"));

    let created = page(create("laptop")).await;
    let secret = created
        .split("<code class=\"api-key\">")
        .nth(1)
        .and_then(|rest| rest.split('<').next())
        .expect("new secret on the page")
        .to_owned();
    assert!(created.contains("http://localhost:3001/mcp"));
    assert!(
        mcp_token::authenticate(&f.pool, &secret)
            .await
            .unwrap()
            .is_some()
    );

    let listed = page(Request::get("/mcp-tokens").body(Body::empty()).unwrap()).await;
    assert!(listed.contains("laptop") && listed.contains("tests"));
    assert!(!listed.contains(&secret));
    assert!(page(create("")).await.contains("Token name is required"));
}
