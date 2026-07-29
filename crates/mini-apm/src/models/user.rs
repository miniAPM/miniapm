use crate::DbPool;
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use chrono::{Duration, Utc};
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
    pub invite_expires_at: Option<String>,
    pub created_at: String,
    pub last_login_at: Option<String>,
}

const USER_COLUMNS: &str = "id, username, password_hash, is_admin, must_change_password, invite_token, invite_expires_at, created_at, last_login_at";

#[derive(Debug, Clone)]
pub struct Session {
    pub id: i64,
    pub token: String,
    pub user_id: i64,
    pub created_at: String,
    pub expires_at: String,
}

/// Validation error for username
#[derive(Debug, Clone, PartialEq)]
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
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;
    Ok(hash.to_string())
}

/// Verify a password against a hash
pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Generate a random session token
fn generate_token() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.r#gen();
    hex::encode(bytes)
}

/// Generate a random password (16 alphanumeric characters)
fn generate_random_password() -> String {
    let mut rng = rand::thread_rng();
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
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
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO users (username, password_hash, is_admin, must_change_password, created_at) VALUES (?1, ?2, 1, 1, ?3)",
        )
        .bind("admin")
        .bind(&password_hash)
        .bind(&now)
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
    let sql = format!("SELECT {USER_COLUMNS} FROM users WHERE username = ?1");
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
            let now = Utc::now().to_rfc3339();
            let _ = sqlx::query("UPDATE users SET last_login_at = ?1 WHERE id = ?2")
                .bind(&now)
                .bind(u.id)
                .execute(pool)
                .await;
            Ok(user)
        }
        _ => Ok(None),
    }
}

/// Create a new session for a user
pub async fn create_session(pool: &DbPool, user_id: i64) -> anyhow::Result<String> {
    let token = generate_token();
    let now = Utc::now();
    let expires = now + Duration::days(7);

    sqlx::query(
        "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(&token)
    .bind(user_id)
    .bind(now.to_rfc3339())
    .bind(expires.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(token)
}

/// Get user from session token
pub async fn get_user_from_session(pool: &DbPool, token: &str) -> anyhow::Result<Option<User>> {
    let now = Utc::now().to_rfc3339();

    let user: Option<User> = sqlx::query_as(
        r#"
        SELECT u.id, u.username, u.password_hash, u.is_admin, u.must_change_password,
               u.invite_token, u.invite_expires_at, u.created_at, u.last_login_at
        FROM users u
        JOIN sessions s ON s.user_id = u.id
        WHERE s.token = ?1 AND s.expires_at > ?2
        "#,
    )
    .bind(token)
    .bind(&now)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// Delete a session (logout)
pub async fn delete_session(pool: &DbPool, token: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM sessions WHERE token = ?1")
        .bind(token)
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete expired sessions (cleanup)
pub async fn delete_expired_sessions(pool: &DbPool) -> anyhow::Result<usize> {
    let now = Utc::now().to_rfc3339();
    let result = sqlx::query("DELETE FROM sessions WHERE expires_at < ?1")
        .bind(&now)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() as usize)
}

/// List all users (admin only)
pub async fn list_all(pool: &DbPool) -> anyhow::Result<Vec<User>> {
    let users = sqlx::query_as::<_, User>(
        r#"SELECT id, username, password_hash, is_admin, must_change_password, invite_token, invite_expires_at,
                  strftime('%Y-%m-%d %H:%M', created_at) AS created_at,
                  CASE WHEN last_login_at IS NOT NULL THEN strftime('%Y-%m-%d %H:%M', last_login_at) ELSE NULL END AS last_login_at
           FROM users ORDER BY username"#,
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
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query(
        "INSERT INTO users (username, password_hash, is_admin, must_change_password, created_at) VALUES (?1, ?2, ?3, 0, ?4)",
    )
    .bind(username)
    .bind(&password_hash)
    .bind(is_admin)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Delete a user (admin only, cannot delete self)
pub async fn delete(pool: &DbPool, user_id: i64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM users WHERE id = ?1")
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
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id = ?1")
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

    sqlx::query("UPDATE users SET password_hash = ?1, must_change_password = 0 WHERE id = ?2")
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
        "UPDATE users SET password_hash = ?1, must_change_password = 0 WHERE username = ?2",
    )
    .bind(&password_hash)
    .bind(username)
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        anyhow::bail!("User '{}' not found", username);
    }

    Ok(())
}

/// Find user by ID
pub async fn find(pool: &DbPool, id: i64) -> anyhow::Result<Option<User>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?1");
    let user: Option<User> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_optional(pool)
        .await?;

    Ok(user)
}

/// Generate an invite token (12 bytes = 24 hex chars, short but secure)
pub fn generate_invite_token() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 12] = rng.r#gen();
    hex::encode(bytes)
}

/// Create a new user with an invite token (no password yet)
pub async fn create_with_invite(
    pool: &DbPool,
    username: &str,
    is_admin: bool,
) -> anyhow::Result<String> {
    let invite_token = generate_invite_token();
    let now = Utc::now();
    let expires = now + Duration::days(7);

    sqlx::query(
        "INSERT INTO users (username, is_admin, invite_token, invite_expires_at, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(username)
    .bind(is_admin)
    .bind(&invite_token)
    .bind(expires.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(invite_token)
}

/// Find user by invite token
pub async fn find_by_invite_token(pool: &DbPool, token: &str) -> anyhow::Result<Option<User>> {
    let now = Utc::now().to_rfc3339();
    let sql =
        format!("SELECT {USER_COLUMNS} FROM users WHERE invite_token = ?1 AND invite_expires_at > ?2");

    let user: Option<User> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(token)
        .bind(&now)
        .fetch_optional(pool)
        .await?;

    Ok(user)
}

/// Accept an invite - set password and clear invite token
pub async fn accept_invite(pool: &DbPool, user_id: i64, password: &str) -> anyhow::Result<()> {
    let password_hash = hash_password(password)?;

    sqlx::query(
        "UPDATE users SET password_hash = ?1, invite_token = NULL, invite_expires_at = NULL WHERE id = ?2",
    )
    .bind(&password_hash)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete users with expired invite tokens who never activated their account
pub async fn delete_expired_invites(pool: &DbPool) -> anyhow::Result<usize> {
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query(
        "DELETE FROM users WHERE invite_token IS NOT NULL AND invite_expires_at < ?1 AND password_hash IS NULL",
    )
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db;

    async fn test_pool() -> DbPool {
        let config = Config::default();
        db::init(&config).await.expect("Failed to create test database")
    }

    #[test]
    fn test_validate_username_valid() {
        assert!(validate_username("alice").is_ok());
        assert!(validate_username("bob123").is_ok());
        assert!(validate_username("user_name").is_ok());
        assert!(validate_username("user-name").is_ok());
        assert!(validate_username("User_Name-123").is_ok());
        assert!(validate_username("abc").is_ok()); // Minimum length
        assert!(validate_username("a".repeat(32).as_str()).is_ok()); // Maximum length
    }

    #[test]
    fn test_validate_username_empty() {
        assert_eq!(validate_username(""), Err(UsernameValidationError::Empty));
        assert_eq!(
            validate_username("   "),
            Err(UsernameValidationError::Empty)
        );
    }

    #[test]
    fn test_validate_username_too_short() {
        assert_eq!(
            validate_username("ab"),
            Err(UsernameValidationError::TooShort)
        );
        assert_eq!(
            validate_username("a"),
            Err(UsernameValidationError::TooShort)
        );
    }

    #[test]
    fn test_validate_username_too_long() {
        let long_name = "a".repeat(33);
        assert_eq!(
            validate_username(&long_name),
            Err(UsernameValidationError::TooLong)
        );
    }

    #[test]
    fn test_validate_username_invalid_chars() {
        assert_eq!(
            validate_username("user@name"),
            Err(UsernameValidationError::InvalidCharacters)
        );
        assert_eq!(
            validate_username("user name"),
            Err(UsernameValidationError::InvalidCharacters)
        );
        assert_eq!(
            validate_username("user.name"),
            Err(UsernameValidationError::InvalidCharacters)
        );
        assert_eq!(
            validate_username("user!name"),
            Err(UsernameValidationError::InvalidCharacters)
        );
    }

    #[test]
    fn test_validate_username_trims_whitespace() {
        // Whitespace is trimmed before validation
        assert!(validate_username("  alice  ").is_ok());
    }

    #[test]
    fn test_hash_and_verify_password() {
        let password = "secret123";
        let hash = hash_password(password).unwrap();

        assert!(verify_password(password, &hash));
        assert!(!verify_password("wrong", &hash));
    }

    #[test]
    fn test_hash_password_unique() {
        let hash1 = hash_password("same").unwrap();
        let hash2 = hash_password("same").unwrap();

        // Hashes should be different due to random salt
        assert_ne!(hash1, hash2);
        // But both should verify
        assert!(verify_password("same", &hash1));
        assert!(verify_password("same", &hash2));
    }

    #[test]
    fn test_verify_invalid_hash() {
        assert!(!verify_password("password", "not-a-valid-hash"));
    }

    #[test]
    fn test_generate_invite_token_format() {
        let token = generate_invite_token();
        assert_eq!(token.len(), 24); // 12 bytes = 24 hex chars
    }

    #[tokio::test]
    async fn test_ensure_default_admin() {
        let pool = test_pool().await;

        ensure_default_admin(&pool).await.unwrap();

        let users = list_all(&pool).await.unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "admin");
        assert!(users[0].is_admin);
        assert!(users[0].must_change_password);
    }

    #[tokio::test]
    async fn test_ensure_default_admin_idempotent() {
        let pool = test_pool().await;

        ensure_default_admin(&pool).await.unwrap();
        ensure_default_admin(&pool).await.unwrap();

        let users = list_all(&pool).await.unwrap();
        assert_eq!(users.len(), 1);
    }

    #[tokio::test]
    async fn test_create_user() {
        let pool = test_pool().await;

        let id = create(&pool, "testuser", "password123", false).await.unwrap();

        let user = find(&pool, id).await.unwrap().unwrap();
        assert_eq!(user.username, "testuser");
        assert!(!user.is_admin);
        assert!(!user.must_change_password);
    }

    #[tokio::test]
    async fn test_create_admin_user() {
        let pool = test_pool().await;

        let id = create(&pool, "admin2", "password", true).await.unwrap();

        let user = find(&pool, id).await.unwrap().unwrap();
        assert!(user.is_admin);
    }

    #[tokio::test]
    async fn test_authenticate_success() {
        let pool = test_pool().await;
        create(&pool, "authuser", "secret", false).await.unwrap();

        let user = authenticate(&pool, "authuser", "secret").await.unwrap();

        assert!(user.is_some());
        assert_eq!(user.unwrap().username, "authuser");
    }

    #[tokio::test]
    async fn test_authenticate_wrong_password() {
        let pool = test_pool().await;
        create(&pool, "authuser2", "secret", false).await.unwrap();

        let user = authenticate(&pool, "authuser2", "wrong").await.unwrap();

        assert!(user.is_none());
    }

    #[tokio::test]
    async fn test_authenticate_nonexistent_user() {
        let pool = test_pool().await;

        let user = authenticate(&pool, "nobody", "password").await.unwrap();

        assert!(user.is_none());
    }

    #[tokio::test]
    async fn test_session_lifecycle() {
        let pool = test_pool().await;
        let user_id = create(&pool, "sessionuser", "pass", false).await.unwrap();

        // Create session
        let token = create_session(&pool, user_id).await.unwrap();
        assert_eq!(token.len(), 64); // 32 bytes = 64 hex chars

        // Get user from session
        let user = get_user_from_session(&pool, &token).await.unwrap();
        assert!(user.is_some());
        assert_eq!(user.unwrap().id, user_id);

        // Delete session
        delete_session(&pool, &token).await.unwrap();

        // Session should be gone
        let user = get_user_from_session(&pool, &token).await.unwrap();
        assert!(user.is_none());
    }

    #[tokio::test]
    async fn test_change_password() {
        let pool = test_pool().await;
        let user_id = create(&pool, "changepass", "old", false).await.unwrap();

        change_password(&pool, user_id, "new").await.unwrap();

        // Old password should fail
        let result = authenticate(&pool, "changepass", "old").await.unwrap();
        assert!(result.is_none());

        // New password should work
        let result = authenticate(&pool, "changepass", "new").await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_delete_user() {
        let pool = test_pool().await;
        let user_id = create(&pool, "deleteme", "pass", false).await.unwrap();

        delete(&pool, user_id).await.unwrap();

        let user = find(&pool, user_id).await.unwrap();
        assert!(user.is_none());
    }

    #[tokio::test]
    async fn test_list_all_users() {
        let pool = test_pool().await;
        create(&pool, "user1", "pass", false).await.unwrap();
        create(&pool, "user2", "pass", true).await.unwrap();

        let users = list_all(&pool).await.unwrap();

        assert_eq!(users.len(), 2);
    }

    #[tokio::test]
    async fn test_verify_password_for_user_success() {
        let pool = test_pool().await;
        let user_id = create(&pool, "verifyuser", "mypassword", false).await.unwrap();

        let result = verify_password_for_user(&pool, user_id, "mypassword")
            .await
            .unwrap();

        assert!(result);
    }

    #[tokio::test]
    async fn test_verify_password_for_user_wrong_password() {
        let pool = test_pool().await;
        let user_id = create(&pool, "verifyuser2", "mypassword", false).await.unwrap();

        let result = verify_password_for_user(&pool, user_id, "wrongpassword")
            .await
            .unwrap();

        assert!(!result);
    }

    #[tokio::test]
    async fn test_verify_password_for_user_nonexistent() {
        let pool = test_pool().await;

        let result = verify_password_for_user(&pool, 99999, "anypassword")
            .await
            .unwrap();

        assert!(!result);
    }

    #[tokio::test]
    async fn test_invite_flow() {
        let pool = test_pool().await;

        // Create user with invite
        let invite_token = create_with_invite(&pool, "invited", false).await.unwrap();

        // Find by invite token
        let user = find_by_invite_token(&pool, &invite_token).await.unwrap();
        assert!(user.is_some());
        let user = user.unwrap();
        assert_eq!(user.username, "invited");
        assert!(user.password_hash.is_none());

        // Accept invite
        accept_invite(&pool, user.id, "newpassword").await.unwrap();

        // Invite token should no longer work
        let user = find_by_invite_token(&pool, &invite_token).await.unwrap();
        assert!(user.is_none());

        // But user can now authenticate
        let user = authenticate(&pool, "invited", "newpassword").await.unwrap();
        assert!(user.is_some());
    }

    #[tokio::test]
    async fn test_delete_expired_invites() {
        let pool = test_pool().await;

        // Create an expired invite (invite_expires_at in the past, no password)
        let expired_time = (Utc::now() - Duration::days(1)).to_rfc3339();
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO users (username, is_admin, invite_token, invite_expires_at, created_at) VALUES (?1, 0, 'expired-token', ?2, ?3)",
        )
        .bind("expired_user")
        .bind(&expired_time)
        .bind(&now)
        .execute(&pool)
        .await
        .unwrap();

        // Create a valid (non-expired) invite
        let future_time = (Utc::now() + Duration::days(1)).to_rfc3339();
        sqlx::query(
            "INSERT INTO users (username, is_admin, invite_token, invite_expires_at, created_at) VALUES (?1, 0, 'valid-token', ?2, ?3)",
        )
        .bind("valid_user")
        .bind(&future_time)
        .bind(&now)
        .execute(&pool)
        .await
        .unwrap();

        // Create an activated user (has password, invite cleared)
        let password_hash = hash_password("password").unwrap();
        sqlx::query(
            "INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?1, ?2, 0, ?3)",
        )
        .bind("active_user")
        .bind(&password_hash)
        .bind(&now)
        .execute(&pool)
        .await
        .unwrap();

        // Run cleanup
        let deleted = delete_expired_invites(&pool).await.unwrap();
        assert_eq!(deleted, 1);

        // Check that only expired invite was deleted
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 2); // valid_user and active_user remain
    }
}
