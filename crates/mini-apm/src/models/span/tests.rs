use super::*;

#[test]
fn sql_normalization_groups_queries_that_differ_only_in_literals() {
    for (sql, expected) in [
        (
            "SELECT * FROM users WHERE name = 'John'",
            "SELECT * FROM users WHERE name = ?",
        ),
        (
            "SELECT * FROM users WHERE id = 123",
            "SELECT * FROM users WHERE id = ?",
        ),
        (
            "SELECT * FROM orders WHERE user_id = 42 AND status = 'pending'",
            "SELECT * FROM orders WHERE user_id = ? AND status = ?",
        ),
        (
            "SELECT * FROM users WHERE id IN (1, 2, 3)",
            "SELECT * FROM users WHERE id IN (?, ?, ?)",
        ),
        (
            "SELECT 'O''Reilly', 3.14 FROM users2 WHERE id=42",
            "SELECT ?, ? FROM users2 WHERE id=?",
        ),
        (
            " SELECT  *\n FROM users WHERE name = \"Jane\" ",
            "SELECT * FROM users WHERE name = ?",
        ),
    ] {
        assert_eq!(normalize_sql(sql), expected, "{sql}");
        assert_eq!(
            normalize_sql(expected),
            expected,
            "normalization is idempotent"
        );
    }
}

#[test]
fn trace_names_resolve_http_paths_with_span_name_fallbacks() {
    for (name, method, url, expected) in [
        (
            "request",
            Some("GET"),
            Some("https://example.com/users"),
            "GET /users",
        ),
        ("request", Some("GET"), Some("/orders"), "GET /orders"),
        ("POST /api/items", Some("POST"), None, "POST /api/items"),
        (
            "GET /fallback",
            Some("GET"),
            Some("https://example.com"),
            "GET /fallback",
        ),
        (
            "custom-operation",
            Some("GET"),
            None,
            "GET custom-operation",
        ),
        (
            "OrderMailer.confirmation_email",
            None,
            None,
            "OrderMailer.confirmation_email",
        ),
    ] {
        let trace = TraceSummary {
            trace_id: "trace".into(),
            root_span_name: name.into(),
            root_span_type: None,
            duration_ms: 100.0,
            span_count: 1,
            status_code: 1,
            service_name: None,
            http_method: method.map(str::to_string),
            http_url: url.map(str::to_string),
            http_status_code: None,
            happened_at: Stamp(Timestamp::UNIX_EPOCH),
        };
        assert_eq!(trace.display_name(), expected, "{name}: {url:?}");
    }
}

#[test]
fn classification_respects_attribute_precedence_and_name_fallbacks() {
    use SpanCategory::*;
    for (name, kind, attributes, expected) in [
        ("SELECT users", 0, vec![("db.system", "postgresql")], Db),
        ("search", 0, vec![("db.system", "elasticsearch")], Search),
        ("search", 0, vec![("db.system", "opensearch")], Search),
        // Database attributes take priority even if HTTP attributes/kind are present.
        (
            "HTTP GET",
            3,
            vec![("db.statement", "SELECT 1"), ("http.method", "GET")],
            Db,
        ),
        ("GET /users", 2, vec![("http.method", "GET")], HttpServer),
        (
            "GET /users",
            2,
            vec![("http.request.method", "GET")],
            HttpServer,
        ),
        (
            "HTTP GET",
            3,
            vec![("http.url", "https://example.com")],
            HttpClient,
        ),
        (
            "HTTP GET",
            3,
            vec![("url.full", "https://example.com")],
            HttpClient,
        ),
        ("send", 0, vec![("messaging.system", "sidekiq")], Job),
        ("consume", 5, vec![], Job),
        ("produce", 4, vec![], Job),
        ("MyJob.perform", 0, vec![], Job),
        ("rake db:migrate", 0, vec![], Command),
        ("rake:db:migrate", 0, vec![], Command),
        ("thor:generate:model", 0, vec![], Command),
        ("render_template users/index.html.erb", 0, vec![], View),
        ("render_partial _header.html.erb", 0, vec![], View),
        ("work", 0, vec![], Internal),
    ] {
        let attributes = attributes
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        assert_eq!(
            SpanCategory::from_attributes(name, kind, &attributes),
            expected,
            "{name}"
        );
    }
}

#[tokio::test]
async fn batches_are_atomic_and_resent_spans_update_in_place() -> anyhow::Result<()> {
    let pool = crate::db::test_pool().await;
    crate::db::reject_inserts(&pool, "spans", "name", "poison").await?;
    let batch = |names: &[&str]| -> serde_json::Result<OtlpTraceRequest> {
        let spans: Vec<_> = names
            .iter()
            .enumerate()
            .map(|(i, name)| {
                serde_json::json!({
                    "traceId": "0af7651916cd43dd8448eb211c80319c",
                    "spanId": format!("{i:016x}"),
                    "name": name,
                    "startTimeUnixNano": 1_000_000_000,
                    "endTimeUnixNano": 2_000_000_000,
                    "events": [{"name": "exception", "attributes": [
                        {"key": "exception.type", "value": {"stringValue": format!("{name}Error")}}
                    ]}],
                })
            })
            .collect();
        serde_json::from_value(
            serde_json::json!({"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]}),
        )
    };

    let mut ids = Vec::new();
    for (names, inserted, spans, errors) in [
        (&["ok", "poison"][..], None, 0, 0),
        (&["ok", "fine"][..], Some(2), 2, 2),
        (&["ok", "renamed"][..], Some(2), 2, 3),
    ] {
        assert_eq!(
            insert_otlp_batch(&pool, &batch(names)?, None).await.ok(),
            inserted,
            "{names:?}"
        );
        for (query, expected) in [
            ("SELECT COUNT(*) FROM spans", spans),
            ("SELECT COUNT(*) FROM errors", errors),
        ] {
            let count: i64 = sqlx::query_scalar(query).fetch_one(&pool).await?;
            assert_eq!(count, expected, "{query} after {names:?}");
        }
        ids.push(
            sqlx::query_scalar::<_, i64>("SELECT id FROM spans ORDER BY span_id")
                .fetch_all(&pool)
                .await?,
        );
    }
    assert_eq!(ids[1], ids[2], "resent spans keep their ids");
    let names: Vec<String> = sqlx::query_scalar("SELECT name FROM spans ORDER BY span_id")
        .fetch_all(&pool)
        .await?;
    assert_eq!(names, ["ok", "renamed"]);
    Ok(())
}
