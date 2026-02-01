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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db;

    fn test_pool() -> DbPool {
        let config = Config::default();
        db::init(&config).expect("Failed to create test database")
    }

    #[test]
    fn test_create_api_key_format() {
        let pool = test_pool();

        let key = create(&pool, "test-key").unwrap();

        // Should start with prefix
        assert!(key.starts_with(PREFIX));
        // Should be prefix (11 chars) + 48 hex chars = 59 total
        assert_eq!(key.len(), 11 + 48);
    }

    #[test]
    fn test_create_api_key_unique() {
        let pool = test_pool();

        let key1 = create(&pool, "key1").unwrap();
        let key2 = create(&pool, "key2").unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_verify_valid_key() {
        let pool = test_pool();

        let key = create(&pool, "test-key").unwrap();
        let is_valid = verify(&pool, &key).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_verify_invalid_key() {
        let pool = test_pool();

        let is_valid = verify(&pool, "mini_apm_k_invalid_key_12345").unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_verify_empty_key() {
        let pool = test_pool();

        let is_valid = verify(&pool, "").unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_verify_updates_last_used_at() {
        let pool = test_pool();

        let key = create(&pool, "test-key").unwrap();

        // Initially last_used_at should be None
        let keys = list(&pool).unwrap();
        assert!(keys[0].last_used_at.is_none());

        // Verify the key (which updates last_used_at)
        verify(&pool, &key).unwrap();

        // Now last_used_at should be set
        let keys = list(&pool).unwrap();
        assert!(keys[0].last_used_at.is_some());
    }

    #[test]
    fn test_list_api_keys() {
        let pool = test_pool();

        create(&pool, "key-alpha").unwrap();
        create(&pool, "key-beta").unwrap();

        let keys = list(&pool).unwrap();

        assert_eq!(keys.len(), 2);
        // Should be ordered by created_at
        assert_eq!(keys[0].name, "key-alpha");
        assert_eq!(keys[1].name, "key-beta");
    }

    #[test]
    fn test_list_empty() {
        let pool = test_pool();

        let keys = list(&pool).unwrap();

        assert!(keys.is_empty());
    }

    #[test]
    fn test_hash_key_deterministic() {
        let key = "mini_apm_k_test123";

        let hash1 = hash_key(key);
        let hash2 = hash_key(key);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_key_different_inputs() {
        let hash1 = hash_key("key1");
        let hash2 = hash_key("key2");

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_key_length() {
        let hash = hash_key("test");

        // SHA256 produces 32 bytes = 64 hex chars
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_api_key_struct_fields() {
        let pool = test_pool();

        create(&pool, "my-api-key").unwrap();

        let keys = list(&pool).unwrap();
        let key = &keys[0];

        assert!(key.id > 0);
        assert_eq!(key.name, "my-api-key");
        assert!(!key.created_at.is_empty());
        assert!(key.last_used_at.is_none());
    }
}
