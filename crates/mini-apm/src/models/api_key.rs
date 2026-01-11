use crate::DbPool;
use chrono::Utc;
use rand::Rng;
use sha2::{Digest, Sha256};

const PREFIX: &str = "mini_apm_k_";

#[derive(Debug, Clone)]
pub struct ApiKey {
    pub id: i64,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

pub fn create(pool: &DbPool, name: &str) -> anyhow::Result<String> {
    let conn = pool.get()?;

    // Generate random key
    let random_bytes: [u8; 24] = rand::thread_rng().r#gen();
    let raw_key = format!("{}{}", PREFIX, hex::encode(random_bytes));
    let key_hash = hash_key(&raw_key);

    conn.execute(
        "INSERT INTO api_keys (name, key_hash, created_at) VALUES (?1, ?2, ?3)",
        (&name, &key_hash, Utc::now().to_rfc3339()),
    )?;

    Ok(raw_key)
}

pub fn verify(pool: &DbPool, raw_key: &str) -> anyhow::Result<bool> {
    if raw_key.is_empty() {
        return Ok(false);
    }

    let conn = pool.get()?;
    let key_hash = hash_key(raw_key);

    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM api_keys WHERE key_hash = ?1)",
            [&key_hash],
            |row| row.get(0),
        )
        .unwrap_or(false);

    if exists {
        // Update last_used_at
        let _ = conn.execute(
            "UPDATE api_keys SET last_used_at = ?1 WHERE key_hash = ?2",
            (Utc::now().to_rfc3339(), &key_hash),
        );
    }

    Ok(exists)
}

pub fn list(pool: &DbPool) -> anyhow::Result<Vec<ApiKey>> {
    let conn = pool.get()?;
    let mut stmt = conn
        .prepare("SELECT id, name, created_at, last_used_at FROM api_keys ORDER BY created_at")?;

    let keys = stmt
        .query_map([], |row| {
            Ok(ApiKey {
                id: row.get(0)?,
                name: row.get(1)?,
                created_at: row.get(2)?,
                last_used_at: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(keys)
}

fn hash_key(raw_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw_key.as_bytes());
    hex::encode(hasher.finalize())
}
