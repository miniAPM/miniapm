use crate::DbPool;
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use chrono::{Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone)]
pub struct Session {
    pub id: i64,
    pub token: String,
    pub user_id: i64,
    pub created_at: String,
    pub expires_at: String,
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

/// Create the default admin user if no users exist
pub fn ensure_default_admin(pool: &DbPool) -> anyhow::Result<()> {
    let conn = pool.get()?;

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;

    if count == 0 {
        let password_hash = hash_password("admin")?;
        let now = Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO users (username, password_hash, is_admin, must_change_password, created_at) VALUES (?1, ?2, 1, 1, ?3)",
            ("admin", &password_hash, &now),
        )?;

        tracing::info!("Created default admin user (admin/admin) - please change password!");
    }

    Ok(())
}

/// Authenticate a user and return them if successful
pub fn authenticate(pool: &DbPool, username: &str, password: &str) -> anyhow::Result<Option<User>> {
    let conn = pool.get()?;

    let user: Option<User> = conn
        .query_row(
            "SELECT id, username, password_hash, is_admin, must_change_password, invite_token, invite_expires_at, created_at, last_login_at FROM users WHERE username = ?1",
            [username],
            |row| {
                Ok(User {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    password_hash: row.get(2)?,
                    is_admin: row.get::<_, i64>(3)? == 1,
                    must_change_password: row.get::<_, i64>(4)? == 1,
                    invite_token: row.get(5)?,
                    invite_expires_at: row.get(6)?,
                    created_at: row.get(7)?,
                    last_login_at: row.get(8)?,
                })
            },
        )
        .ok();

    match user {
        Some(ref u)
            if u.password_hash
                .as_ref()
                .is_some_and(|h| verify_password(password, h)) =>
        {
            // Update last login time
            let now = Utc::now().to_rfc3339();
            let _ = conn.execute(
                "UPDATE users SET last_login_at = ?1 WHERE id = ?2",
                (&now, u.id),
            );
            Ok(user)
        }
        _ => Ok(None),
    }
}

/// Create a new session for a user
pub fn create_session(pool: &DbPool, user_id: i64) -> anyhow::Result<String> {
    let conn = pool.get()?;
    let token = generate_token();
    let now = Utc::now();
    let expires = now + Duration::days(7);

    conn.execute(
        "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
        (&token, user_id, now.to_rfc3339(), expires.to_rfc3339()),
    )?;

    Ok(token)
}

/// Get user from session token
pub fn get_user_from_session(pool: &DbPool, token: &str) -> anyhow::Result<Option<User>> {
    let conn = pool.get()?;
    let now = Utc::now().to_rfc3339();

    let user: Option<User> = conn
        .query_row(
            r#"
            SELECT u.id, u.username, u.password_hash, u.is_admin, u.must_change_password, u.invite_token, u.invite_expires_at, u.created_at, u.last_login_at
            FROM users u
            JOIN sessions s ON s.user_id = u.id
            WHERE s.token = ?1 AND s.expires_at > ?2
            "#,
            [token, &now],
            |row| {
                Ok(User {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    password_hash: row.get(2)?,
                    is_admin: row.get::<_, i64>(3)? == 1,
                    must_change_password: row.get::<_, i64>(4)? == 1,
                    invite_token: row.get(5)?,
                    invite_expires_at: row.get(6)?,
                    created_at: row.get(7)?,
                    last_login_at: row.get(8)?,
                })
            },
        )
        .ok();

    Ok(user)
}

/// Delete a session (logout)
pub fn delete_session(pool: &DbPool, token: &str) -> anyhow::Result<()> {
    let conn = pool.get()?;
    conn.execute("DELETE FROM sessions WHERE token = ?1", [token])?;
    Ok(())
}

/// Delete expired sessions (cleanup)
pub fn delete_expired_sessions(pool: &DbPool) -> anyhow::Result<usize> {
    let conn = pool.get()?;
    let now = Utc::now().to_rfc3339();
    let deleted = conn.execute("DELETE FROM sessions WHERE expires_at < ?1", [&now])?;
    Ok(deleted)
}

/// List all users (admin only)
pub fn list_all(pool: &DbPool) -> anyhow::Result<Vec<User>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        r#"SELECT id, username, password_hash, is_admin, must_change_password, invite_token, invite_expires_at,
                  strftime('%Y-%m-%d %H:%M', created_at),
                  CASE WHEN last_login_at IS NOT NULL THEN strftime('%Y-%m-%d %H:%M', last_login_at) ELSE NULL END
           FROM users ORDER BY username"#,
    )?;

    let users = stmt
        .query_map([], |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                password_hash: row.get(2)?,
                is_admin: row.get::<_, i64>(3)? == 1,
                must_change_password: row.get::<_, i64>(4)? == 1,
                invite_token: row.get(5)?,
                invite_expires_at: row.get(6)?,
                created_at: row.get(7)?,
                last_login_at: row.get(8)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(users)
}

/// Create a new user (admin only)
pub fn create(
    pool: &DbPool,
    username: &str,
    password: &str,
    is_admin: bool,
) -> anyhow::Result<i64> {
    let conn = pool.get()?;
    let password_hash = hash_password(password)?;
    let now = Utc::now().to_rfc3339();

    conn.execute(
        "INSERT INTO users (username, password_hash, is_admin, must_change_password, created_at) VALUES (?1, ?2, ?3, 0, ?4)",
        (username, &password_hash, if is_admin { 1 } else { 0 }, &now),
    )?;

    Ok(conn.last_insert_rowid())
}

/// Delete a user (admin only, cannot delete self)
pub fn delete(pool: &DbPool, user_id: i64) -> anyhow::Result<()> {
    let conn = pool.get()?;
    conn.execute("DELETE FROM users WHERE id = ?1", [user_id])?;
    Ok(())
}

/// Change password
pub fn change_password(pool: &DbPool, user_id: i64, new_password: &str) -> anyhow::Result<()> {
    let conn = pool.get()?;
    let password_hash = hash_password(new_password)?;

    conn.execute(
        "UPDATE users SET password_hash = ?1, must_change_password = 0 WHERE id = ?2",
        (&password_hash, user_id),
    )?;

    Ok(())
}

/// Find user by ID
pub fn find(pool: &DbPool, id: i64) -> anyhow::Result<Option<User>> {
    let conn = pool.get()?;

    let user: Option<User> = conn
        .query_row(
            "SELECT id, username, password_hash, is_admin, must_change_password, invite_token, invite_expires_at, created_at, last_login_at FROM users WHERE id = ?1",
            [id],
            |row| {
                Ok(User {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    password_hash: row.get(2)?,
                    is_admin: row.get::<_, i64>(3)? == 1,
                    must_change_password: row.get::<_, i64>(4)? == 1,
                    invite_token: row.get(5)?,
                    invite_expires_at: row.get(6)?,
                    created_at: row.get(7)?,
                    last_login_at: row.get(8)?,
                })
            },
        )
        .ok();

    Ok(user)
}

/// Generate an invite token (12 bytes = 24 hex chars, short but secure)
pub fn generate_invite_token() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 12] = rng.r#gen();
    hex::encode(bytes)
}

/// Create a new user with an invite token (no password yet)
pub fn create_with_invite(pool: &DbPool, username: &str, is_admin: bool) -> anyhow::Result<String> {
    let conn = pool.get()?;
    let invite_token = generate_invite_token();
    let now = Utc::now();
    let expires = now + Duration::days(7);

    conn.execute(
        "INSERT INTO users (username, is_admin, invite_token, invite_expires_at, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        (username, if is_admin { 1 } else { 0 }, &invite_token, expires.to_rfc3339(), now.to_rfc3339()),
    )?;

    Ok(invite_token)
}

/// Find user by invite token
pub fn find_by_invite_token(pool: &DbPool, token: &str) -> anyhow::Result<Option<User>> {
    let conn = pool.get()?;
    let now = Utc::now().to_rfc3339();

    let user: Option<User> = conn
        .query_row(
            "SELECT id, username, password_hash, is_admin, must_change_password, invite_token, invite_expires_at, created_at, last_login_at FROM users WHERE invite_token = ?1 AND invite_expires_at > ?2",
            [token, &now],
            |row| {
                Ok(User {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    password_hash: row.get(2)?,
                    is_admin: row.get::<_, i64>(3)? == 1,
                    must_change_password: row.get::<_, i64>(4)? == 1,
                    invite_token: row.get(5)?,
                    invite_expires_at: row.get(6)?,
                    created_at: row.get(7)?,
                    last_login_at: row.get(8)?,
                })
            },
        )
        .ok();

    Ok(user)
}

/// Accept an invite - set password and clear invite token
pub fn accept_invite(pool: &DbPool, user_id: i64, password: &str) -> anyhow::Result<()> {
    let conn = pool.get()?;
    let password_hash = hash_password(password)?;

    conn.execute(
        "UPDATE users SET password_hash = ?1, invite_token = NULL, invite_expires_at = NULL WHERE id = ?2",
        (&password_hash, user_id),
    )?;

    Ok(())
}
