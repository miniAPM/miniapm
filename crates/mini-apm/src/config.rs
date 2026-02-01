use std::env;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct Config {
    pub sqlite_path: String,
    pub api_key: Option<String>,
    pub retention_days_errors: i64,
    pub retention_days_hourly_rollups: i64,
    pub retention_days_spans: i64,
    pub slow_request_threshold_ms: f64,
    pub mini_apm_url: String,
    pub enable_user_accounts: bool,
    pub enable_projects: bool,
    pub session_secret: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        // SESSION_SECRET is required when user accounts are enabled
        let enable_user_accounts = env::var("ENABLE_USER_ACCOUNTS")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        let session_secret = env::var("SESSION_SECRET").ok();

        if enable_user_accounts && session_secret.is_none() {
            anyhow::bail!(
                "SESSION_SECRET environment variable is required when ENABLE_USER_ACCOUNTS=true. \
                Generate one with: openssl rand -hex 32"
            );
        }

        // Warn if using default secret in development
        let session_secret = session_secret.unwrap_or_else(|| {
            if enable_user_accounts {
                // This shouldn't happen due to the check above, but just in case
                panic!("SESSION_SECRET is required");
            }
            // In single-user mode, generate a random secret per run
            use rand::Rng;
            let bytes: [u8; 32] = rand::thread_rng().r#gen();
            hex::encode(bytes)
        });

        Ok(Self {
            sqlite_path: env::var("SQLITE_PATH")
                .unwrap_or_else(|_| "./data/miniapm.db".to_string()),
            api_key: env::var("MINI_APM_API_KEY").ok(),
            retention_days_errors: env::var("RETENTION_DAYS_ERRORS")
                .ok()
                .and_then(|v| v.parse().ok())
                .filter(|&v| v > 0)
                .unwrap_or(30),
            retention_days_hourly_rollups: env::var("RETENTION_DAYS_HOURLY_ROLLUPS")
                .ok()
                .and_then(|v| v.parse().ok())
                .filter(|&v| v > 0)
                .unwrap_or(90),
            retention_days_spans: env::var("RETENTION_DAYS_SPANS")
                .ok()
                .and_then(|v| v.parse().ok())
                .filter(|&v| v > 0)
                .unwrap_or(7),
            slow_request_threshold_ms: env::var("SLOW_REQUEST_THRESHOLD_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .filter(|&v| v > 0.0)
                .unwrap_or(500.0),
            mini_apm_url: env::var("MINI_APM_URL")
                .unwrap_or_else(|_| "http://localhost:3000".to_string()),
            enable_user_accounts,
            enable_projects: env::var("ENABLE_PROJECTS")
                .map(|v| v == "1" || v.to_lowercase() == "true")
                .unwrap_or(false),
            session_secret,
        })
    }

    pub fn api_key_configured(&self) -> bool {
        self.api_key.as_ref().is_some_and(|k| !k.is_empty())
    }

    /// Validates configuration and returns a list of errors.
    /// Returns Ok(()) if all validations pass.
    pub fn validate(&self) -> anyhow::Result<()> {
        let mut errors = Vec::new();

        // Validate MINI_APM_URL is a valid URL
        if !self.mini_apm_url.starts_with("http://") && !self.mini_apm_url.starts_with("https://") {
            errors.push(format!(
                "MINI_APM_URL must start with http:// or https://, got: {}",
                self.mini_apm_url
            ));
        }

        // Validate retention days are positive
        if self.retention_days_errors <= 0 {
            errors.push(format!(
                "RETENTION_DAYS_ERRORS must be positive, got: {}",
                self.retention_days_errors
            ));
        }
        if self.retention_days_hourly_rollups <= 0 {
            errors.push(format!(
                "RETENTION_DAYS_HOURLY_ROLLUPS must be positive, got: {}",
                self.retention_days_hourly_rollups
            ));
        }
        if self.retention_days_spans <= 0 {
            errors.push(format!(
                "RETENTION_DAYS_SPANS must be positive, got: {}",
                self.retention_days_spans
            ));
        }

        // Validate slow request threshold is positive
        if self.slow_request_threshold_ms <= 0.0 {
            errors.push(format!(
                "SLOW_REQUEST_THRESHOLD_MS must be positive, got: {}",
                self.slow_request_threshold_ms
            ));
        }

        // Validate session secret is long enough when user accounts are enabled
        if self.enable_user_accounts && self.session_secret.len() < 32 {
            errors.push(
                "SESSION_SECRET should be at least 32 characters for security".to_string(),
            );
        }

        // Validate sqlite_path parent directory exists or can be created (skip for :memory:)
        if self.sqlite_path != ":memory:"
            && let Some(parent) = Path::new(&self.sqlite_path).parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            // Not an error, just a warning - we'll create it
            tracing::debug!(
                "Database directory {} does not exist, will be created",
                parent.display()
            );
        }

        if errors.is_empty() {
            Ok(())
        } else {
            anyhow::bail!("Configuration errors:\n  - {}", errors.join("\n  - "))
        }
    }

    /// Logs configuration summary at startup
    pub fn log_summary(&self) {
        tracing::info!("Configuration:");
        tracing::info!("  Database: {}", self.sqlite_path);
        tracing::info!("  Base URL: {}", self.mini_apm_url);
        tracing::info!("  User accounts: {}", self.enable_user_accounts);
        tracing::info!("  Multi-project mode: {}", self.enable_projects);
        tracing::info!(
            "  Retention: errors={}d, rollups={}d, spans={}d",
            self.retention_days_errors,
            self.retention_days_hourly_rollups,
            self.retention_days_spans
        );
        tracing::info!(
            "  Slow request threshold: {}ms",
            self.slow_request_threshold_ms
        );
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sqlite_path: ":memory:".to_string(),
            api_key: None,
            retention_days_errors: 30,
            retention_days_hourly_rollups: 90,
            retention_days_spans: 7,
            slow_request_threshold_ms: 500.0,
            mini_apm_url: "http://localhost:3000".to_string(),
            enable_user_accounts: false,
            enable_projects: false,
            session_secret: "test-secret".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_url() {
        let mut config = Config::default();
        config.mini_apm_url = "not-a-url".to_string();

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must start with http://"));
    }

    #[test]
    fn test_validate_https_url() {
        let mut config = Config::default();
        config.mini_apm_url = "https://miniapm.example.com".to_string();

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_negative_retention_days() {
        let mut config = Config::default();
        config.retention_days_errors = -1;

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("RETENTION_DAYS_ERRORS must be positive"));
    }

    #[test]
    fn test_validate_zero_retention_days() {
        let mut config = Config::default();
        config.retention_days_spans = 0;

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("RETENTION_DAYS_SPANS must be positive"));
    }

    #[test]
    fn test_validate_negative_threshold() {
        let mut config = Config::default();
        config.slow_request_threshold_ms = -100.0;

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("SLOW_REQUEST_THRESHOLD_MS must be positive"));
    }

    #[test]
    fn test_validate_short_session_secret_with_user_accounts() {
        let mut config = Config::default();
        config.enable_user_accounts = true;
        config.session_secret = "short".to_string();

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("SESSION_SECRET should be at least 32 characters"));
    }

    #[test]
    fn test_validate_short_session_secret_without_user_accounts() {
        let mut config = Config::default();
        config.enable_user_accounts = false;
        config.session_secret = "short".to_string();

        // Should be OK when user accounts are disabled
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_multiple_errors() {
        let mut config = Config::default();
        config.mini_apm_url = "invalid".to_string();
        config.retention_days_errors = -1;
        config.retention_days_spans = 0;

        let result = config.validate();
        assert!(result.is_err());
        let error = result.unwrap_err().to_string();
        assert!(error.contains("MINI_APM_URL"));
        assert!(error.contains("RETENTION_DAYS_ERRORS"));
        assert!(error.contains("RETENTION_DAYS_SPANS"));
    }

    #[test]
    fn test_api_key_configured_with_key() {
        let mut config = Config::default();
        config.api_key = Some("my-api-key".to_string());

        assert!(config.api_key_configured());
    }

    #[test]
    fn test_api_key_configured_without_key() {
        let config = Config::default();
        assert!(!config.api_key_configured());
    }

    #[test]
    fn test_api_key_configured_empty_key() {
        let mut config = Config::default();
        config.api_key = Some("".to_string());

        assert!(!config.api_key_configured());
    }

    #[test]
    fn test_memory_db_validation() {
        let mut config = Config::default();
        config.sqlite_path = ":memory:".to_string();

        assert!(config.validate().is_ok());
    }
}
