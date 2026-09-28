use super::*;
use crate::db::test_pool;

fn mangle(hex: &str) -> String {
    hex::encode(STANDARD.decode(hex).unwrap())
}

#[tokio::test]
async fn test_restores_mangled_ids_once() {
    let pool = test_pool().await;
    let trace = "0af7651916cd43dd8448eb211c80319c";
    let (root, child) = ("b7ad6b7169203331", "00f067aa0ba902b7");
    let clean = ("4bf92f3577b34da6a3ce929d0e0e4736", "53995c3f42cd8ad8");
    let insert = "INSERT INTO spans (trace_id, span_id, parent_span_id, start_time_unix_nano,
        end_time_unix_nano, name, span_category, happened_at) VALUES (?1, ?2, ?3, 0, 1, 'x', 'internal', '')";
    for (t, s, p) in [
        (mangle(trace), mangle(root), None),
        (mangle(trace), mangle(child), Some(mangle(root))),
        (clean.0.to_string(), clean.1.to_string(), None),
    ] {
        sqlx::query(insert)
            .bind(t)
            .bind(s)
            .bind(p)
            .execute(&pool)
            .await
            .unwrap();
    }

    assert_eq!(otlp_ids(&pool).await.unwrap(), 2);
    assert_eq!(otlp_ids(&pool).await.unwrap(), 0);

    let spans: Vec<(String, String, Option<String>)> =
        sqlx::query_as("SELECT trace_id, span_id, parent_span_id FROM spans ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        spans,
        [
            (trace.into(), root.into(), None),
            (trace.into(), child.into(), Some(root.into())),
            (clean.0.into(), clean.1.into(), None),
        ]
    );
}
