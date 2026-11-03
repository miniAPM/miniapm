use crate::DbPool;
use crate::time::Stamp;
use jiff::{SignedDuration, Timestamp};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[cfg(test)]
mod tests;

const PREFIX: &str = "mcp_";
const MAX_NAME_CHARS: usize = 64;
const TOUCH_INTERVAL: SignedDuration = SignedDuration::from_mins(5);

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct McpToken {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub created_at: Stamp,
    pub last_used_at: Option<Stamp>,
}

/// The user behind a token, as of the request that presented it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bearer {
    pub token_id: i64,
    pub user_id: i64,
    pub username: String,
    pub is_admin: bool,
}

fn digest(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

/// Issue a token for `user_id`. Only its digest is stored, so the returned
/// secret cannot be shown again.
pub async fn create(pool: &DbPool, user_id: i64, name: &str) -> anyhow::Result<(McpToken, String)> {
    let name = name.trim();
    anyhow::ensure!(!name.is_empty(), "Token name is required");
    anyhow::ensure!(
        name.chars().count() <= MAX_NAME_CHARS,
        "Token name must be at most {MAX_NAME_CHARS} characters"
    );

    let secret = format!("{PREFIX}{}", hex::encode(rand::random::<[u8; 32]>()));
    let token = sqlx::query_as(
        "INSERT INTO mcp_tokens (user_id, name, token_hash, created_at) VALUES ($1, $2, $3, $4)
         RETURNING id, user_id, name, created_at, last_used_at",
    )
    .bind(user_id)
    .bind(name)
    .bind(digest(&secret))
    .bind(Stamp::now())
    .fetch_one(pool)
    .await?;
    Ok((token, secret))
}

pub async fn list_for_user(pool: &DbPool, user_id: i64) -> anyhow::Result<Vec<McpToken>> {
    Ok(sqlx::query_as(
        "SELECT id, user_id, name, created_at, last_used_at FROM mcp_tokens
         WHERE user_id = $1 ORDER BY created_at DESC, id DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?)
}

/// Delete `user_id`'s token `id`. Returns whether it existed.
pub async fn revoke(pool: &DbPool, user_id: i64, id: i64) -> anyhow::Result<bool> {
    let result = sqlx::query("DELETE FROM mcp_tokens WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() == 1)
}

/// The bearer of `secret`, or `None` for an unknown or revoked token. Records
/// use at most once per `TOUCH_INTERVAL` to keep writes off the request path.
pub async fn authenticate(pool: &DbPool, secret: &str) -> anyhow::Result<Option<Bearer>> {
    if !secret.starts_with(PREFIX) {
        return Ok(None);
    }
    let row: Option<(i64, Option<Stamp>, i64, String, bool)> = sqlx::query_as(
        "SELECT t.id, t.last_used_at, u.id, u.username, u.is_admin
         FROM mcp_tokens t JOIN users u ON u.id = t.user_id
         WHERE t.token_hash = $1",
    )
    .bind(digest(secret))
    .fetch_optional(pool)
    .await?;
    let Some((token_id, last_used_at, user_id, username, is_admin)) = row else {
        return Ok(None);
    };

    let now = Timestamp::now();
    if last_used_at.is_none_or(|used| used.0 < now - TOUCH_INTERVAL)
        && let Err(e) = sqlx::query("UPDATE mcp_tokens SET last_used_at = $1 WHERE id = $2")
            .bind(Stamp(now))
            .bind(token_id)
            .execute(pool)
            .await
    {
        tracing::warn!("Failed to record use of MCP token {token_id}: {e}");
    }

    Ok(Some(Bearer {
        token_id,
        user_id,
        username,
        is_admin,
    }))
}
