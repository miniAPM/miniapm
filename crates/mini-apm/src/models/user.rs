use crate::DbPool;
use crate::time::Stamp;
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use jiff::{SignedDuration, Timestamp};
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    pub is_admin: bool,
    pub must_change_password: bool,
    #[serde(skip_serializing)]
    pub invite_token: Option<String>,
    pub invite_expires_at: Option<Stamp>,
    pub created_at: Stamp,
    pub last_login_at: Option<Stamp>,
}

const USER_COLUMNS: &str = "id, username, password_hash, is_admin, must_change_password, invite_token, invite_expires_at, created_at, last_login_at";

#[derive(Debug, Clone)]
pub struct Session {
    pub id: i64,
    pub token: String,
    pub user_id: i64,
    pub created_at: Stamp,
    pub expires_at: Stamp,
}

/// Validation error for username
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsernameValidationError {
    TooShort,
    TooLong,
    InvalidCharacters,
    Empty,
}

impl std::fmt::Display for UsernameValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "Username must be at least 3 characters"),
            Self::TooLong => write!(f, "Username must be at most 32 characters"),
            Self::InvalidCharacters => {
                write!(
                    f,
                    "Username can only contain letters, numbers, underscores, and dashes"
                )
            }
            Self::Empty => write!(f, "Username cannot be empty"),
        }
    }
}

/// Validate a username
/// Returns Ok(()) if valid, Err with specific error otherwise
pub fn validate_username(username: &str) -> Result<(), UsernameValidationError> {
    let username = username.trim();

    if username.is_empty() {
        return Err(UsernameValidationError::Empty);
    }

    if username.len() < 3 {
        return Err(UsernameValidationError::TooShort);
    }

    if username.len() > 32 {
        return Err(UsernameValidationError::TooLong);
    }

    // Allow alphanumeric, underscore, and dash
    if !username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err(UsernameValidationError::InvalidCharacters);
    }

    Ok(())
}

/// Hash a password using Argon2
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {e}"))?;
    Ok(hash.to_string())
}

/// Verify a password against a hash
pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Generate a random session token
fn generate_token() -> String {
    random_hex::<32>()
}

fn random_hex<const N: usize>() -> String {
    let mut bytes = [0u8; N];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    hex::encode(bytes)
}

/// Generate a random password (16 alphanumeric characters)
fn generate_random_password() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..16)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Create the default admin user if no users exist
pub async fn ensure_default_admin(pool: &DbPool) -> anyhow::Result<()> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;

    if count == 0 {
        let password = generate_random_password();
        let password_hash = hash_password(&password)?;
        let now = Stamp::now();

        sqlx::query(
            "INSERT INTO users (username, password_hash, is_admin, must_change_password, created_at) VALUES ($1, $2, TRUE, TRUE, $3)",
        )
        .bind("admin")
        .bind(&password_hash)
        .bind(now)
        .execute(pool)
        .await?;

        tracing::info!("============================================================");
        tracing::info!("Created default admin user");
        tracing::info!("Username: admin");
        tracing::info!("Password: {}", password);
        tracing::info!("Please change this password after first login!");
        tracing::info!("============================================================");
    }

    Ok(())
}

/// Authenticate a user and return them if successful
pub async fn authenticate(
    pool: &DbPool,
    username: &str,
    password: &str,
) -> anyhow::Result<Option<User>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM users WHERE username = $1");
    let user: Option<User> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(username)
        .fetch_optional(pool)
        .await?;

    match user {
        Some(ref u)
            if u.password_hash
                .as_ref()
                .is_some_and(|h| verify_password(password, h)) =>
        {
            // Update last login time
            if let Err(e) = sqlx::query("UPDATE users SET last_login_at = $1 WHERE id = $2")
                .bind(Stamp::now())
                .bind(u.id)
                .execute(pool)
                .await
            {
                tracing::warn!("Failed to record the login of user {}: {e:#}", u.id);
            }
            Ok(user)
        }
        _ => Ok(None),
    }
}

/// Create a new session for a user
pub async fn create_session(pool: &DbPool, user_id: i64) -> anyhow::Result<String> {
    let token = generate_token();
    let now = Timestamp::now();
    let expires = now + SignedDuration::from_hours(7 * 24);

    sqlx::query(
        "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(&token)
    .bind(user_id)
    .bind(Stamp(now))
    .bind(Stamp(expires))
    .execute(pool)
    .await?;

    Ok(token)
}

/// Get user from session token
pub async fn get_user_from_session(pool: &DbPool, token: &str) -> anyhow::Result<Option<User>> {
    let now = Stamp::now();

    let user: Option<User> = sqlx::query_as(
        r"
        SELECT u.id, u.username, u.password_hash, u.is_admin, u.must_change_password,
               u.invite_token, u.invite_expires_at, u.created_at, u.last_login_at
        FROM users u
        JOIN sessions s ON s.user_id = u.id
        WHERE s.token = $1 AND s.expires_at > $2
        ",
    )
    .bind(token)
    .bind(now)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// Delete a session (logout)
pub async fn delete_session(pool: &DbPool, token: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM sessions WHERE token = $1")
        .bind(token)
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete expired sessions (cleanup)
pub async fn delete_expired_sessions(pool: &DbPool) -> anyhow::Result<u64> {
    let now = Stamp::now();
    let result = sqlx::query("DELETE FROM sessions WHERE expires_at < $1")
        .bind(now)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// List all users (admin only)
pub async fn list_all(pool: &DbPool) -> anyhow::Result<Vec<User>> {
    let users = sqlx::query_as::<_, User>(
        r"SELECT id, username, password_hash, is_admin, must_change_password, invite_token, invite_expires_at,
                  created_at,
                  last_login_at
           FROM users ORDER BY username",
    )
    .fetch_all(pool)
    .await?;

    Ok(users)
}

/// Create a new user (admin only)
pub async fn create(
    pool: &DbPool,
    username: &str,
    password: &str,
    is_admin: bool,
) -> anyhow::Result<i64> {
    let password_hash = hash_password(password)?;
    let now = Stamp::now();

    let id = sqlx::query_scalar(
        "INSERT INTO users (username, password_hash, is_admin, must_change_password, created_at) VALUES ($1, $2, $3, FALSE, $4) RETURNING id",
    )
    .bind(username)
    .bind(&password_hash)
    .bind(is_admin)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(id)
}

/// Delete a user (admin only, cannot delete self)
pub async fn delete(pool: &DbPool, user_id: i64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Verify password for a user by ID
pub async fn verify_password_for_user(
    pool: &DbPool,
    user_id: i64,
    password: &str,
) -> anyhow::Result<bool> {
    let password_hash: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await?
            .flatten();

    match password_hash {
        Some(hash) => Ok(verify_password(password, &hash)),
        None => Ok(false),
    }
}

/// Change password
pub async fn change_password(
    pool: &DbPool,
    user_id: i64,
    new_password: &str,
) -> anyhow::Result<()> {
    let password_hash = hash_password(new_password)?;

    sqlx::query("UPDATE users SET password_hash = $1, must_change_password = FALSE WHERE id = $2")
        .bind(&password_hash)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Reset password by username (for CLI use)
pub async fn reset_password(
    pool: &DbPool,
    username: &str,
    new_password: &str,
) -> anyhow::Result<()> {
    let password_hash = hash_password(new_password)?;

    let result = sqlx::query(
        "UPDATE users SET password_hash = $1, must_change_password = FALSE WHERE username = $2",
    )
    .bind(&password_hash)
    .bind(username)
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        anyhow::bail!("User '{username}' not found");
    }

    Ok(())
}

/// Find user by ID
pub async fn find(pool: &DbPool, id: i64) -> anyhow::Result<Option<User>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM users WHERE id = $1");
    let user: Option<User> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_optional(pool)
        .await?;

    Ok(user)
}

/// Generate an invite token (12 bytes = 24 hex chars, short but secure)
pub fn generate_invite_token() -> String {
    random_hex::<12>()
}

/// Create a new user with an invite token (no password yet)
pub async fn create_with_invite(
    pool: &DbPool,
    username: &str,
    is_admin: bool,
) -> anyhow::Result<String> {
    let invite_token = generate_invite_token();
    let now = Timestamp::now();
    let expires = now + SignedDuration::from_hours(7 * 24);

    sqlx::query(
        "INSERT INTO users (username, is_admin, invite_token, invite_expires_at, created_at) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(username)
    .bind(is_admin)
    .bind(&invite_token)
    .bind(Stamp(expires))
    .bind(Stamp(now))
    .execute(pool)
    .await?;

    Ok(invite_token)
}

/// Find user by invite token
pub async fn find_by_invite_token(pool: &DbPool, token: &str) -> anyhow::Result<Option<User>> {
    let now = Stamp::now();
    let sql = format!(
        "SELECT {USER_COLUMNS} FROM users WHERE invite_token = $1 AND invite_expires_at > $2"
    );

    let user: Option<User> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(token)
        .bind(now)
        .fetch_optional(pool)
        .await?;

    Ok(user)
}

/// Accept an invite - set password and clear invite token
pub async fn accept_invite(pool: &DbPool, user_id: i64, password: &str) -> anyhow::Result<()> {
    let password_hash = hash_password(password)?;

    sqlx::query(
        "UPDATE users SET password_hash = $1, invite_token = NULL, invite_expires_at = NULL WHERE id = $2",
    )
    .bind(&password_hash)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete users with expired invite tokens who never activated their account
pub async fn delete_expired_invites(pool: &DbPool) -> anyhow::Result<u64> {
    let now = Stamp::now();

    let result = sqlx::query(
        "DELETE FROM users WHERE invite_token IS NOT NULL AND invite_expires_at < $1 AND password_hash IS NULL",
    )
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests;
