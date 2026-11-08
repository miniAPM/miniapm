use super::*;
use serde_json::json;

fn error() -> IncomingError {
    IncomingError {
        exception_class: "RuntimeError".into(),
        message: "boom".into(),
        backtrace: vec!["app/models/user.rb:42:in `validate'".into()],
        fingerprint: "RuntimeError:app/models/user.rb:42".into(),
        request_id: None,
        user_id: None,
        params: None,
        timestamp: None,
        source_context: None,
    }
}

#[test]
fn absent_optionals_stay_off_the_wire() {
    let deploy = IncomingDeploy {
        git_sha: "abc1234".into(),
        version: None,
        env: None,
        description: None,
        deployer: None,
        timestamp: None,
    };
    for (value, expected) in [
        (
            serde_json::to_value(error()).unwrap(),
            json!({
                "exception_class": "RuntimeError",
                "message": "boom",
                "backtrace": ["app/models/user.rb:42:in `validate'"],
                "fingerprint": "RuntimeError:app/models/user.rb:42",
            }),
        ),
        (
            serde_json::to_value(deploy).unwrap(),
            json!({"git_sha": "abc1234"}),
        ),
    ] {
        assert_eq!(value, expected);
    }
}

#[test]
fn full_error_round_trips() {
    let full = IncomingError {
        request_id: Some("req-1".into()),
        user_id: Some("42".into()),
        params: Some(json!({"id": 7})),
        timestamp: Some("2026-11-08T12:00:00Z".parse().unwrap()),
        source_context: Some(IncomingSourceContext {
            file: "app/models/user.rb".into(),
            lineno: 42,
            pre_context: Some(vec!["def validate".into()]),
            context_line: "  raise \"boom\"".into(),
            post_context: None,
        }),
        ..error()
    };
    let batch = IncomingErrorBatch { errors: vec![full] };
    let wire = serde_json::to_string(&batch).unwrap();
    assert_eq!(
        serde_json::from_str::<IncomingErrorBatch>(&wire).unwrap(),
        batch
    );
}
