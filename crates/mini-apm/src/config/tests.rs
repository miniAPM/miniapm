use super::*;

#[test]
fn text_settings_preserve_explicit_values_and_reject_invalid_present_values() {
    for name in ["SQLITE_PATH", "DATABASE_URL", "MINI_APM_URL"] {
        assert!(
            parse_optional_text(name, Err(env::VarError::NotPresent))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            parse_optional_text(name, Ok("configured value".into()))
                .unwrap()
                .as_deref(),
            Some("configured value")
        );
        for value in ["", "   "] {
            assert!(
                parse_optional_text(name, Ok(value.into()))
                    .unwrap_err()
                    .to_string()
                    .contains(name)
            );
        }
        let error =
            parse_optional_text(name, Err(env::VarError::NotUnicode("private-value".into())))
                .unwrap_err();
        assert!(error.to_string().contains(name));
        assert!(!format!("{error:#}").contains("private-value"));
    }
    let error = Config {
        sqlite_path: String::new(),
        database_url: Some(String::new()),
        ..Config::default()
    }
    .validate()
    .unwrap_err()
    .to_string();
    assert!(error.contains("SQLITE_PATH"));
    assert!(error.contains("DATABASE_URL"));
}

#[cfg(all(feature = "sqlite", not(feature = "postgres")))]
#[test]
fn sqlite_build_rejects_a_postgres_database_url() {
    let config = Config {
        database_url: Some("postgres://localhost/miniapm".into()),
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("built with SQLite"));
    assert!(error.contains("--features postgres"));
}

#[test]
fn session_secrets_distinguish_absence_from_invalid_values() {
    assert!(parse_session_secret(Err(env::VarError::NotPresent), true).is_err());
    assert_ne!(
        parse_session_secret(Err(env::VarError::NotPresent), false).unwrap(),
        ""
    );
    for accounts in [false, true] {
        for value in ["", "   "] {
            assert!(parse_session_secret(Ok(value.into()), accounts).is_err());
        }
        let error = parse_session_secret(
            Err(env::VarError::NotUnicode("private-value".into())),
            accounts,
        )
        .unwrap_err();
        assert!(error.to_string().contains("SESSION_SECRET"));
        assert!(!format!("{error:#}").contains("private-value"));
    }
    assert!(parse_session_secret(Ok("short".into()), true).is_err());
    assert_eq!(
        parse_session_secret(Ok("development".into()), false).unwrap(),
        "development"
    );
    assert_eq!(
        parse_session_secret(Ok("x".repeat(32)), true).unwrap(),
        "x".repeat(32)
    );
}

#[test]
fn configuration_debug_output_redacts_credentials() {
    let config = Config {
        session_secret: "private-session-value".into(),
        database_url: Some("postgres://user:private-password@localhost/miniapm".into()),
        ..Config::default()
    };
    let debug = format!("{config:?}");
    assert!(!debug.contains("private-session-value"));
    assert!(!debug.contains("private-password"));
    assert!(debug.contains("[REDACTED]"));
    assert!(debug.contains("retention_days_errors"));
}

#[test]
fn slow_thresholds_default_only_when_absent_and_require_finite_positive_values() {
    assert_eq!(
        parse_threshold(Err(env::VarError::NotPresent)).unwrap(),
        500.0
    );
    assert_eq!(parse_threshold(Ok("12.5".into())).unwrap(), 12.5);
    for value in ["", "invalid", "0", "-1", "NaN", "inf", "-inf"] {
        assert!(
            parse_threshold(Ok(value.into()))
                .unwrap_err()
                .to_string()
                .contains("SLOW_REQUEST_THRESHOLD_MS")
        );
    }
    assert!(parse_threshold(Err(env::VarError::NotUnicode("invalid".into()))).is_err());
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 0.0] {
        let config = Config {
            slow_request_threshold_ms: value,
            ..Config::default()
        };
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("SLOW_REQUEST_THRESHOLD_MS")
        );
    }
}

#[test]
fn retention_defaults_only_when_absent_and_rejects_unsafe_cutoffs() {
    for (name, default) in [("RETENTION_DAYS_ERRORS", 30), ("RETENTION_DAYS_SPANS", 7)] {
        assert_eq!(
            parse_retention(name, Err(env::VarError::NotPresent), default).unwrap(),
            default
        );
        assert_eq!(parse_retention(name, Ok("90".into()), default).unwrap(), 90);
        for value in ["", "invalid", "0", "-1", "9223372036854775807"] {
            assert!(
                parse_retention(name, Ok(value.into()), default)
                    .unwrap_err()
                    .to_string()
                    .contains(name)
            );
        }
        assert!(
            parse_retention(
                name,
                Err(env::VarError::NotUnicode("invalid".into())),
                default
            )
            .is_err()
        );
    }
    let invalid = Config {
        retention_days_errors: i64::MAX,
        retention_days_spans: i64::MAX,
        ..Config::default()
    }
    .validate()
    .unwrap_err()
    .to_string();
    assert!(invalid.contains("RETENTION_DAYS_ERRORS"));
    assert!(invalid.contains("RETENTION_DAYS_SPANS"));
}

#[test]
fn feature_flags_default_only_when_absent_and_reject_typos() {
    for name in ["ENABLE_USER_ACCOUNTS", "ENABLE_PROJECTS"] {
        assert!(!parse_flag(name, Err(env::VarError::NotPresent)).unwrap());
        for (value, expected) in [
            ("true", true),
            ("TRUE", true),
            ("1", true),
            ("false", false),
            ("FALSE", false),
            ("0", false),
        ] {
            assert_eq!(parse_flag(name, Ok(value.into())).unwrap(), expected);
        }
        for value in ["", "treu", "yes"] {
            assert!(
                parse_flag(name, Ok(value.into()))
                    .unwrap_err()
                    .to_string()
                    .contains(name)
            );
        }
        assert!(parse_flag(name, Err(env::VarError::NotUnicode("invalid".into()))).is_err());
    }
}

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
        (false, String::new(), false),
        (true, " ".repeat(32), false),
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
#[test]
fn ingestion_environment_settings_are_strict_and_opt_in() {
    let absent = || Err(std::env::VarError::NotPresent);
    assert!(
        super::parse_ingest_admission(absent(), absent(), absent())
            .unwrap()
            .is_none()
    );
    assert!(
        super::parse_ingest_admission(Ok("100".into()), absent(), absent())
            .unwrap()
            .is_some()
    );
    for rate in ["", "invalid", "NaN", "inf", "0", "-1"] {
        assert!(
            super::parse_ingest_admission(Ok(rate.into()), absent(), absent()).is_err(),
            "{rate}"
        );
    }
    for burst in ["0", "-1", "1000001", "invalid"] {
        assert!(super::parse_ingest_admission(Ok("1".into()), Ok(burst.into()), absent()).is_err());
    }
    for keys in ["0", "-1", "65537", "invalid"] {
        assert!(super::parse_ingest_admission(Ok("1".into()), absent(), Ok(keys.into())).is_err());
    }
    assert!(super::parse_ingest_admission(absent(), Ok("1".into()), absent()).is_err());
    assert!(super::parse_ingest_admission(absent(), absent(), Ok("1".into())).is_err());
}
#[test]
fn ingestion_concurrency_is_independent_and_bounded() {
    assert!(
        super::parse_in_flight(Err(std::env::VarError::NotPresent))
            .unwrap()
            .is_none()
    );
    for value in ["1", "4", "8"] {
        assert!(super::parse_in_flight(Ok(value.into())).unwrap().is_some());
    }
    for value in ["", "0", "-1", "9", "NaN", "1.5", "invalid"] {
        assert!(super::parse_in_flight(Ok(value.into())).is_err(), "{value}");
    }
}
