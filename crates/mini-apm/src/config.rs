use std::env;

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
}
