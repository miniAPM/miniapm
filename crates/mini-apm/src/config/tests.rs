use super::Config;

#[test]
fn validation_reports_all_configuration_errors() {
    let config = Config {
        mini_apm_url: "invalid".into(),
        retention_days_errors: -1,
        retention_days_spans: 0,
        slow_request_threshold_ms: -100.0,
        enable_user_accounts: true,
        session_secret: "short".into(),
        ..Config::default()
    };

    let error = config
        .validate()
        .expect_err("invalid configuration")
        .to_string();
    for setting in [
        "MINI_APM_URL",
        "RETENTION_DAYS_ERRORS",
        "RETENTION_DAYS_SPANS",
        "SLOW_REQUEST_THRESHOLD_MS",
        "SESSION_SECRET",
    ] {
        assert!(error.contains(setting), "missing {setting}: {error}");
    }
    assert_eq!(error.lines().count(), 6);
}

#[test]
fn session_secret_requirement_depends_on_account_mode() {
    for (accounts, secret, valid) in [
        (false, "short".to_string(), true),
        (true, "x".repeat(31), false),
        (true, "x".repeat(32), true),
    ] {
        let config = Config {
            enable_user_accounts: accounts,
            session_secret: secret,
            ..Config::default()
        };
        assert_eq!(config.validate().is_ok(), valid, "accounts={accounts}");
    }
}

#[test]
fn validation_accepts_supported_urls_and_positive_boundaries() -> anyhow::Result<()> {
    for url in ["http://localhost:3000", "https://miniapm.example.com"] {
        Config {
            mini_apm_url: url.into(),
            retention_days_errors: 1,
            retention_days_spans: 1,
            slow_request_threshold_ms: 0.1,
            ..Config::default()
        }
        .validate()?;
    }
    Ok(())
}
