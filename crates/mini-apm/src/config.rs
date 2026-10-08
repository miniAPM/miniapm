use std::env;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct Config {
    pub sqlite_path: String,
    pub database_url: Option<String>,
    pub retention_days_errors: i64,
    pub retention_days_spans: i64,
    pub slow_request_threshold_ms: f64,
    pub mini_apm_url: String,
    pub enable_user_accounts: bool,
    pub enable_projects: bool,
    pub session_secret: String,
}

pub fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn env_positive<T: std::str::FromStr + PartialOrd + Default>(name: &str, default: T) -> T {
    env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > T::default())
        .unwrap_or(default)
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        // SESSION_SECRET is required when user accounts are enabled
        let enable_user_accounts = env_flag("ENABLE_USER_ACCOUNTS");

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
            database_url: env::var("DATABASE_URL").ok(),
            retention_days_errors: env_positive("RETENTION_DAYS_ERRORS", 30),
            retention_days_spans: env_positive("RETENTION_DAYS_SPANS", 7),
            slow_request_threshold_ms: env_positive("SLOW_REQUEST_THRESHOLD_MS", 500.0),
            mini_apm_url: env::var("MINI_APM_URL")
                .unwrap_or_else(|_| "http://localhost:3000".to_string()),
            enable_user_accounts,
            enable_projects: env_flag("ENABLE_PROJECTS"),
            session_secret,
        })
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
            errors.push("SESSION_SECRET should be at least 32 characters for security".to_string());
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
        tracing::info!("  Database: {}", crate::db::describe(self));
        tracing::info!("  Base URL: {}", self.mini_apm_url);
        tracing::info!("  User accounts: {}", self.enable_user_accounts);
        tracing::info!("  Multi-project mode: {}", self.enable_projects);
        tracing::info!(
            "  Retention: errors={}d, spans={}d",
            self.retention_days_errors,
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
            database_url: None,
            retention_days_errors: 30,
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
mod tests;
