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
            .map(|(k, v)| (k, Cow::Borrowed(v)))
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
    let batch = |spans: &[(u32, &str)]| -> serde_json::Result<OtlpTraceRequest> {
        let spans: Vec<_> = spans
            .iter()
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
        (&[(0, "ok"), (1, "poison")][..], None, 0, 0),
        (&[(0, "ok"), (1, "fine")][..], Some(2), 2, 2),
        (&[(0, "ok"), (1, "renamed")][..], Some(2), 2, 3),
        (&[(1, "first"), (1, "last")][..], Some(2), 2, 5),
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
    assert_eq!(
        (&ids[2], &ids[3]),
        (&ids[1], &ids[1]),
        "resent spans keep their ids"
    );
    let names: Vec<String> = sqlx::query_scalar("SELECT name FROM spans ORDER BY span_id")
        .fetch_all(&pool)
        .await?;
    assert_eq!(names, ["ok", "last"]);
    Ok(())
}

async fn insert_span(
    pool: &DbPool,
    id: usize,
    parent: Option<&str>,
    duration_ms: f64,
    status_code: i32,
    at: Stamp,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO spans (trace_id, span_id, parent_span_id, start_time_unix_nano,
            end_time_unix_nano, duration_ms, name, status_code, span_category, root_span_type,
            happened_at)
         VALUES ('trace', $1, $2, 0, 1, $3, 'GET /', $4, 'http_server',
            CASE WHEN $2 IS NULL THEN 'web' END, $5)",
    )
    .bind(format!("{id:016x}"))
    .bind(parent)
    .bind(duration_ms)
    .bind(status_code)
    .bind(at)
    .execute(pool)
    .await?;
    Ok(())
}

#[tokio::test]
async fn hourly_stats_bucket_root_spans_inside_the_window() -> anyhow::Result<()> {
    let pool = crate::db::test_pool().await;
    for (i, (hours, duration_ms, status_code, parent)) in [
        (0, 10.0, 0, None),
        (2, 20.0, 0, None),
        (2, 30.0, 2, None),
        (2, 99.0, 0, Some("0000000000000001")),
        (30, 99.0, 0, None),
    ]
    .into_iter()
    .enumerate()
    {
        let at = crate::time::hours_ago(hours);
        insert_span(&pool, i, parent, duration_ms, status_code, at).await?;
    }
    let label = |hours| crate::time::hours_ago(hours).hour_label();

    let points = hourly_stats(&pool, None, 24).await?;
    let by_hour: HashMap<_, _> = points
        .iter()
        .map(|p| (p.hour.clone(), (p.count, p.avg_ms, p.error_count)))
        .collect();
    assert_eq!(points.len(), 24);
    assert_eq!(by_hour[&label(0)], (1, 10.0, 0));
    assert_eq!(by_hour[&label(2)], (2, 25.0, 1));
    assert_eq!(points.iter().map(|p| p.count).sum::<i64>(), 3);

    for statement in [
        "UPDATE spans SET status_code = 2, duration_ms = 50.0 WHERE span_id = '0000000000000000'",
        "DELETE FROM spans WHERE span_id = '0000000000000002'",
    ] {
        sqlx::query(statement).execute(&pool).await?;
    }
    let points = hourly_stats(&pool, None, 24).await?;
    let by_hour: HashMap<_, _> = points
        .iter()
        .map(|p| (p.hour.clone(), (p.count, p.avg_ms, p.error_count)))
        .collect();
    assert_eq!(by_hour[&label(0)], (1, 50.0, 1));
    assert_eq!(by_hour[&label(2)], (1, 20.0, 0));
    Ok(())
}

#[tokio::test]
async fn root_spans_count_from_the_exact_instant() -> anyhow::Result<()> {
    let pool = crate::db::test_pool().await;
    let since = crate::time::hours_ago(2);
    let at = |offset_secs: i64| Stamp(since.0 + jiff::SignedDuration::from_secs(offset_secs));
    for (i, offset, parent) in [
        (0, -60, None),
        (1, 60, None),
        (2, 3_660, None),
        (3, 7_000, None),
        (4, 7_000, Some("0000000000000003")),
    ] {
        insert_span(&pool, i, parent, 1.0, 0, at(offset)).await?;
    }
    assert_eq!(count_since(&pool, None, since).await?, 3);
    Ok(())
}

#[tokio::test]
async fn latency_percentiles_use_the_nearest_rank() -> anyhow::Result<()> {
    let pool = crate::db::test_pool().await;
    for i in 1..=32 {
        insert_span(&pool, i, None, i as f64, 0, Stamp::now()).await?;
    }
    let since = crate::time::hours_ago(1);

    let stats = latency_stats_since(&pool, None, since).await?;
    assert_eq!((stats.avg_ms, stats.p95_ms, stats.p99_ms), (17, 31, 32));
    let routes = routes_summary(&pool, None, since, None, "requests", 10).await?;
    let percentiles: Vec<_> = routes
        .iter()
        .map(|r| (r.path.as_str(), r.p95_ms, r.p99_ms))
        .collect();
    assert_eq!(percentiles, [("GET /", 31, 32)]);
    Ok(())
}
