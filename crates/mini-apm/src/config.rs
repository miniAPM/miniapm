use std::env;
use std::path::Path;

#[derive(Clone)]
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
    pub ingest_admission: Option<crate::api::admission::AdmissionConfig>,
    pub ingest_max_in_flight: Option<crate::api::admission::InFlightLimit>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Config")
            .field("sqlite_path", &self.sqlite_path)
            .field(
                "database_url",
                &self.database_url.as_ref().map(|_| "[REDACTED]"),
            )
            .field("retention_days_errors", &self.retention_days_errors)
            .field("retention_days_spans", &self.retention_days_spans)
            .field("slow_request_threshold_ms", &self.slow_request_threshold_ms)
            .field("mini_apm_url", &self.mini_apm_url)
            .field("enable_user_accounts", &self.enable_user_accounts)
            .field("enable_projects", &self.enable_projects)
            .field("session_secret", &"[REDACTED]")
            .field("ingest_admission", &self.ingest_admission)
            .field("ingest_max_in_flight", &self.ingest_max_in_flight)
            .finish()
    }
}

fn parse_session_secret(
    value: Result<String, env::VarError>,
    accounts: bool,
) -> anyhow::Result<String> {
    let secret = match value {
        Ok(secret) => secret,
        Err(env::VarError::NotPresent) if !accounts => {
            return Ok(hex::encode(rand::random::<[u8; 32]>()));
        }
        Err(env::VarError::NotPresent) => anyhow::bail!(
            "SESSION_SECRET is required when ENABLE_USER_ACCOUNTS=true. Generate one with: openssl rand -hex 32"
        ),
        Err(_) => anyhow::bail!("SESSION_SECRET must contain valid UTF-8"),
    };
    anyhow::ensure!(
        !secret.trim().is_empty(),
        "SESSION_SECRET must not be blank"
    );
    anyhow::ensure!(
        !accounts || secret.len() >= 32,
        "SESSION_SECRET must be at least 32 characters when user accounts are enabled"
    );
    Ok(secret)
}

fn parse_optional_text(
    name: &str,
    value: Result<String, env::VarError>,
) -> anyhow::Result<Option<String>> {
    match value {
        Err(env::VarError::NotPresent) => Ok(None),
        Err(_) => anyhow::bail!("{name} must contain valid UTF-8"),
        Ok(value) => {
            anyhow::ensure!(!value.trim().is_empty(), "{name} must not be blank");
            Ok(Some(value))
        }
    }
}

pub fn env_flag(name: &str) -> anyhow::Result<bool> {
    parse_flag(name, env::var(name))
}

fn parse_flag(name: &str, value: Result<String, env::VarError>) -> anyhow::Result<bool> {
    match value {
        Err(env::VarError::NotPresent) => Ok(false),
        Ok(value) if value == "1" || value.eq_ignore_ascii_case("true") => Ok(true),
        Ok(value) if value == "0" || value.eq_ignore_ascii_case("false") => Ok(false),
        _ => anyhow::bail!("{name} must be true, false, 1, or 0"),
    }
}

fn parse_threshold(value: Result<String, env::VarError>) -> anyhow::Result<f64> {
    let threshold: f64 = match value {
        Err(env::VarError::NotPresent) => 500.0,
        Ok(value) => value
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid SLOW_REQUEST_THRESHOLD_MS"))?,
        Err(_) => anyhow::bail!("SLOW_REQUEST_THRESHOLD_MS must contain valid UTF-8"),
    };
    anyhow::ensure!(
        threshold.is_finite() && threshold > 0.0,
        "SLOW_REQUEST_THRESHOLD_MS must be finite and positive"
    );
    Ok(threshold)
}

fn retention_supported(days: i64) -> bool {
    days > 0
        && days.checked_mul(86_400).is_some_and(|seconds| {
            jiff::Timestamp::now()
                .checked_sub(jiff::SignedDuration::from_secs(seconds))
                .is_ok()
        })
}

fn parse_retention(
    name: &str,
    value: Result<String, env::VarError>,
    default: i64,
) -> anyhow::Result<i64> {
    let days = match value {
        Err(env::VarError::NotPresent) => default,
        Ok(value) => value
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid {name}"))?,
        Err(_) => anyhow::bail!("{name} must contain valid UTF-8"),
    };
    anyhow::ensure!(
        retention_supported(days),
        "{name} must be positive and within the supported timestamp range"
    );
    Ok(days)
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        // SESSION_SECRET is required when user accounts are enabled
        let enable_user_accounts = env_flag("ENABLE_USER_ACCOUNTS")?;

        let session_secret =
            parse_session_secret(env::var("SESSION_SECRET"), enable_user_accounts)?;

        Ok(Self {
            sqlite_path: parse_optional_text("SQLITE_PATH", env::var("SQLITE_PATH"))?
                .unwrap_or_else(|| "./data/miniapm.db".to_string()),
            database_url: parse_optional_text("DATABASE_URL", env::var("DATABASE_URL"))?,
            retention_days_errors: parse_retention(
                "RETENTION_DAYS_ERRORS",
                env::var("RETENTION_DAYS_ERRORS"),
                30,
            )?,
            retention_days_spans: parse_retention(
                "RETENTION_DAYS_SPANS",
                env::var("RETENTION_DAYS_SPANS"),
                7,
            )?,
            slow_request_threshold_ms: parse_threshold(env::var("SLOW_REQUEST_THRESHOLD_MS"))?,
            mini_apm_url: parse_optional_text("MINI_APM_URL", env::var("MINI_APM_URL"))?
                .unwrap_or_else(|| "http://localhost:3000".to_string()),
            enable_user_accounts,
            enable_projects: env_flag("ENABLE_PROJECTS")?,
            session_secret,
            ingest_admission: ingest_admission_from_env()?,
            ingest_max_in_flight: parse_in_flight(env::var("INGEST_MAX_IN_FLIGHT"))?,
        })
    }

    /// Validates configuration and returns a list of errors.
    /// Returns Ok(()) if all validations pass.
    pub fn validate(&self) -> anyhow::Result<()> {
        let mut errors = Vec::new();
        if self.sqlite_path.trim().is_empty() {
            errors.push("SQLITE_PATH must not be blank".to_string());
        }
        if self
            .database_url
            .as_ref()
            .is_some_and(|url| url.trim().is_empty())
        {
            errors.push("DATABASE_URL must not be blank when supplied".to_string());
        }
        #[cfg(all(feature = "sqlite", not(feature = "postgres")))]
        if self.database_url.is_some() {
            errors.push(
                "DATABASE_URL is set, but this binary was built with SQLite; \
                 rebuild with --no-default-features --features postgres"
                    .to_string(),
            );
        }

        // Validate MINI_APM_URL is a valid URL
        if !self.mini_apm_url.starts_with("http://") && !self.mini_apm_url.starts_with("https://") {
            errors.push(format!(
                "MINI_APM_URL must start with http:// or https://, got: {}",
                self.mini_apm_url
            ));
        }

        // Validate retention days are positive
        if !retention_supported(self.retention_days_errors) {
            errors.push(format!(
                "RETENTION_DAYS_ERRORS must be positive and within the supported timestamp range, got: {}",
                self.retention_days_errors
            ));
        }
        if !retention_supported(self.retention_days_spans) {
            errors.push(format!(
                "RETENTION_DAYS_SPANS must be positive and within the supported timestamp range, got: {}",
                self.retention_days_spans
            ));
        }

        // Validate slow request threshold is positive
        if !self.slow_request_threshold_ms.is_finite() || self.slow_request_threshold_ms <= 0.0 {
            errors.push(format!(
                "SLOW_REQUEST_THRESHOLD_MS must be finite and positive, got: {}",
                self.slow_request_threshold_ms
            ));
        }

        // Validate session secret is long enough when user accounts are enabled
        if self.session_secret.trim().is_empty()
            || (self.enable_user_accounts && self.session_secret.len() < 32)
        {
            errors.push("SESSION_SECRET must be nonblank and at least 32 characters when user accounts are enabled".to_string());
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
        tracing::info!("  Ingestion admission: {:?}", self.ingest_admission);
        tracing::info!("  Ingestion concurrency: {:?}", self.ingest_max_in_flight);
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
            ingest_admission: None,
            ingest_max_in_flight: None,
        }
    }
}

fn ingest_admission_from_env() -> anyhow::Result<Option<crate::api::admission::AdmissionConfig>> {
    parse_ingest_admission(
        env::var("INGEST_REQUESTS_PER_SECOND"),
        env::var("INGEST_BURST"),
        env::var("INGEST_MAX_KEYS_PER_SHARD"),
    )
}

fn parse_ingest_admission(
    rate: Result<String, env::VarError>,
    burst: Result<String, env::VarError>,
    keys: Result<String, env::VarError>,
) -> anyhow::Result<Option<crate::api::admission::AdmissionConfig>> {
    use anyhow::Context;
    if matches!(rate, Err(env::VarError::NotPresent)) {
        anyhow::ensure!(
            matches!(burst, Err(env::VarError::NotPresent))
                && matches!(keys, Err(env::VarError::NotPresent)),
            "INGEST_BURST and INGEST_MAX_KEYS_PER_SHARD require INGEST_REQUESTS_PER_SECOND"
        );
        return Ok(None);
    }
    let rate = rate
        .context("Invalid INGEST_REQUESTS_PER_SECOND")?
        .parse()
        .context("Invalid INGEST_REQUESTS_PER_SECOND")?;
    let parse_optional =
        |value: Result<String, env::VarError>, default, name| -> anyhow::Result<u32> {
            match value {
                Ok(value) => value.parse().with_context(|| format!("Invalid {name}")),
                Err(env::VarError::NotPresent) => Ok(default),
                Err(error) => Err(error).with_context(|| format!("Invalid {name}")),
            }
        };
    let burst = parse_optional(burst, 100, "INGEST_BURST")?;
    let keys = parse_optional(keys, 4096, "INGEST_MAX_KEYS_PER_SHARD")?;
    Ok(Some(crate::api::admission::AdmissionConfig::new(
        rate,
        burst,
        keys as usize,
    )?))
}

fn parse_in_flight(
    value: Result<String, env::VarError>,
) -> anyhow::Result<Option<crate::api::admission::InFlightLimit>> {
    use anyhow::Context;
    match value {
        Err(env::VarError::NotPresent) => Ok(None),
        value => Ok(Some(crate::api::admission::InFlightLimit::new(
            value
                .context("Invalid INGEST_MAX_IN_FLIGHT")?
                .parse()
                .context("Invalid INGEST_MAX_IN_FLIGHT")?,
        )?)),
    }
}

#[cfg(test)]
mod tests;
