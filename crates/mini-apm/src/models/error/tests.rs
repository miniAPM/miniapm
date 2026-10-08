use super::*;
use crate::time::hours_ago;
use crate::{db::test_pool, models::project};

fn incoming(exception_class: &str, hours: i64) -> IncomingError {
    IncomingError {
        exception_class: exception_class.into(),
        message: "boom".into(),
        backtrace: vec![],
        fingerprint: exception_class.into(),
        request_id: None,
        user_id: None,
        params: None,
        timestamp: Some(hours_ago(hours).0),
        source_context: None,
    }
}

#[test]
fn similarity_normalizes_words_and_handles_empty_inputs() {
    for (left, right, expected) in [
        ("hello world", "hello world", 1.0),
        ("hello world", "foo bar baz", 0.0),
        ("Hello World", "hello world", 1.0),
        ("can't find user_id!", "can t find user id", 1.0),
        (
            "undefined method foo for nil",
            "undefined method bar for nil",
            4.0 / 6.0,
        ),
        ("hello hello world", "hello world", 1.0),
        ("", "", 1.0),
        ("hello", "", 0.0),
        ("", "hello", 0.0),
    ] {
        let actual = text_similarity(left, right);
        assert!(
            (actual - expected).abs() < f64::EPSILON,
            "{left:?} / {right:?}: {actual}"
        );
        assert_eq!(
            actual,
            text_similarity(right, left),
            "similarity is symmetric"
        );
    }
}

#[test]
fn error_location_prefers_application_frames_and_falls_back_to_dependencies() {
    for (frames, expected) in [
        (
            vec![
                "/usr/local/lib/ruby/gems/activerecord/lib/base.rb:123:in `find'",
                "/app/models/user.rb:42:in `authenticate'",
                "/app/controllers/sessions_controller.rb:15:in `create'",
            ],
            Some("/app/models/user.rb:42"),
        ),
        (
            vec![
                "/gems/rack/lib/handler.rb:10:in `call'",
                "/vendor/bundle/gems/rails/lib/rails.rb:5:in `run'",
                "app/services/payment.rb:88:in `process'",
            ],
            Some("app/services/payment.rb:88"),
        ),
        (
            vec![
                "/gems/activerecord/lib/base.rb:123:in `find'",
                "/vendor/bundle/gems/rails/lib/rails.rb:5:in `run'",
            ],
            Some("/gems/activerecord/lib/base.rb:123"),
        ),
        (vec![], None),
    ] {
        let backtrace = frames.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            extract_error_location(&backtrace).as_deref(),
            expected,
            "{frames:?}"
        );
    }
}

#[tokio::test]
async fn grouping_preserves_occurrences_and_isolates_projects_and_locations() -> anyhow::Result<()>
{
    let pool = test_pool().await;
    let first = project::create(&pool, "First").await?;
    let second = project::create(&pool, "Second").await?;
    let incoming = |message: &str, line: i32| IncomingError {
        exception_class: "RecordNotFound".into(),
        message: message.into(),
        backtrace: vec![format!("app/models/user.rb:{line}:in `find'")],
        fingerprint: format!("{message}:{line}"),
        request_id: None,
        user_id: None,
        params: None,
        timestamp: None,
        source_context: None,
    };
    let id = insert(
        &pool,
        &incoming("Couldn't find User with 'id'=123", 42),
        Some(first.id),
    )
    .await?;
    assert_eq!(
        insert(
            &pool,
            &incoming("Couldn't find User with 'id'=456", 42),
            Some(first.id)
        )
        .await?,
        id
    );
    let other_project = insert(
        &pool,
        &incoming("Couldn't find User with 'id'=123", 42),
        Some(second.id),
    )
    .await?;
    let other_location = insert(
        &pool,
        &incoming("Couldn't find User with 'id'=123", 99),
        Some(first.id),
    )
    .await?;
    assert_ne!(other_project, id);
    assert_ne!(other_location, id);
    assert_eq!(
        find(&pool, id)
            .await?
            .expect("error group")
            .occurrence_count,
        2
    );
    assert_eq!(occurrences(&pool, id, 10).await?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn hourly_counts_bucket_occurrences_inside_the_window() -> anyhow::Result<()> {
    let pool = test_pool().await;
    let project = project::create(&pool, "Hourly").await?;
    let mut error_id = 0;
    for hours in [0, 2, 2, 30] {
        error_id = insert(&pool, &incoming("TimeoutError", hours), Some(project.id)).await?;
    }
    let label = |hours| hours_ago(hours).hour_label();

    let points = hourly_error_stats(&pool, Some(project.id), 24).await?;
    let counts: std::collections::HashMap<_, _> =
        points.iter().map(|p| (p.hour.clone(), p.count)).collect();
    assert_eq!(points.len(), 24);
    assert_eq!((counts[&label(0)], counts[&label(2)]), (1, 2));
    assert_eq!(points.iter().map(|p| p.count).sum::<i64>(), 3);

    let trend = error_trend_24h(&pool, error_id).await?;
    assert_eq!(trend.len(), 24);
    assert_eq!(trend.iter().sum::<i64>(), 3);
    Ok(())
}

#[tokio::test]
async fn filtered_error_lists_agree_with_their_counts() -> anyhow::Result<()> {
    let pool = test_pool().await;
    let project = project::create(&pool, "Filters").await?;
    let timeout = insert(&pool, &incoming("TimeoutError", 0), Some(project.id)).await?;
    insert(&pool, &incoming("NoMethodError", 5), Some(project.id)).await?;
    apply(&pool, timeout, ErrorStatusEvent::Resolve).await?;

    for (status, search, since, expected) in [
        (None, None, None, 2),
        (Some("open"), None, None, 1),
        (Some("resolved"), None, None, 1),
        (None, Some("TIMEOUT"), None, 1),
        (None, None, Some(hours_ago(1)), 1),
        (Some("open"), None, Some(hours_ago(1)), 0),
    ] {
        let listed = list_paginated(
            &pool,
            Some(project.id),
            status,
            search,
            since,
            "last_seen",
            10,
            0,
        )
        .await?;
        let count = count_filtered(&pool, Some(project.id), status, search, since).await?;
        assert_eq!(
            (listed.len() as i64, count),
            (expected, expected),
            "{status:?} {search:?} {since:?}"
        );
    }
    Ok(())
}
