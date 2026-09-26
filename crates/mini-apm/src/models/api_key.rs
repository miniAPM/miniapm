use crate::DbPool;
use crate::time;
use rand::Rng;
use sha2::{Digest, Sha256};

const PREFIX: &str = "mini_apm_k_";

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ApiKey {
    pub id: i64,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

pub async fn create(pool: &DbPool, name: &str) -> anyhow::Result<String> {
    // Generate random key
    let random_bytes: [u8; 24] = rand::thread_rng().r#gen();
    let raw_key = format!("{}{}", PREFIX, hex::encode(random_bytes));
    let key_hash = hash_key(&raw_key);

    sqlx::query("INSERT INTO api_keys (name, key_hash, created_at) VALUES (?1, ?2, ?3)")
        .bind(name)
        .bind(&key_hash)
        .bind(time::now_rfc3339())
        .execute(pool)
        .await?;

    Ok(raw_key)
}

pub async fn verify(pool: &DbPool, raw_key: &str) -> anyhow::Result<bool> {
    if raw_key.is_empty() {
        return Ok(false);
    }

    let key_hash = hash_key(raw_key);

    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM api_keys WHERE key_hash = ?1)")
            .bind(&key_hash)
            .fetch_one(pool)
            .await
            .unwrap_or(false);

    if exists {
        // Update last_used_at
        let _ = sqlx::query("UPDATE api_keys SET last_used_at = ?1 WHERE key_hash = ?2")
            .bind(time::now_rfc3339())
            .bind(&key_hash)
            .execute(pool)
            .await;
    }

    Ok(exists)
}

pub async fn list(pool: &DbPool) -> anyhow::Result<Vec<ApiKey>> {
    let keys = sqlx::query_as::<_, ApiKey>(
        "SELECT id, name, created_at, last_used_at FROM api_keys ORDER BY created_at",
    )
    .fetch_all(pool)
    .await?;

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

    async fn test_pool() -> DbPool {
        let config = Config::default();
        db::init(&config)
            .await
            .expect("Failed to create test database")
    }

    #[tokio::test]
    async fn test_create_api_key_format() {
        let pool = test_pool().await;

        let key = create(&pool, "test-key").await.unwrap();

        // Should start with prefix
        assert!(key.starts_with(PREFIX));
        // Should be prefix (11 chars) + 48 hex chars = 59 total
        assert_eq!(key.len(), 11 + 48);
    }

    #[tokio::test]
    async fn test_create_api_key_unique() {
        let pool = test_pool().await;

        let key1 = create(&pool, "key1").await.unwrap();
        let key2 = create(&pool, "key2").await.unwrap();

        assert_ne!(key1, key2);
    }

    #[tokio::test]
    async fn test_verify_valid_key() {
        let pool = test_pool().await;

        let key = create(&pool, "test-key").await.unwrap();
        let is_valid = verify(&pool, &key).await.unwrap();

        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_verify_invalid_key() {
        let pool = test_pool().await;

        let is_valid = verify(&pool, "mini_apm_k_invalid_key_12345").await.unwrap();

        assert!(!is_valid);
    }

    #[tokio::test]
    async fn test_verify_empty_key() {
        let pool = test_pool().await;

        let is_valid = verify(&pool, "").await.unwrap();

        assert!(!is_valid);
    }

    #[tokio::test]
    async fn test_verify_updates_last_used_at() {
        let pool = test_pool().await;

        let key = create(&pool, "test-key").await.unwrap();

        // Initially last_used_at should be None
        let keys = list(&pool).await.unwrap();
        assert!(keys[0].last_used_at.is_none());

        // Verify the key (which updates last_used_at)
        verify(&pool, &key).await.unwrap();

        // Now last_used_at should be set
        let keys = list(&pool).await.unwrap();
        assert!(keys[0].last_used_at.is_some());
    }

    #[tokio::test]
    async fn test_list_api_keys() {
        let pool = test_pool().await;

        create(&pool, "key-alpha").await.unwrap();
        create(&pool, "key-beta").await.unwrap();

        let keys = list(&pool).await.unwrap();

        assert_eq!(keys.len(), 2);
        // Should be ordered by created_at
        assert_eq!(keys[0].name, "key-alpha");
        assert_eq!(keys[1].name, "key-beta");
    }

    #[tokio::test]
    async fn test_list_empty() {
        let pool = test_pool().await;

        let keys = list(&pool).await.unwrap();

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

    #[tokio::test]
    async fn test_api_key_struct_fields() {
        let pool = test_pool().await;

        create(&pool, "my-api-key").await.unwrap();

        let keys = list(&pool).await.unwrap();
        let key = &keys[0];

        assert!(key.id > 0);
        assert_eq!(key.name, "my-api-key");
        assert!(!key.created_at.is_empty());
        assert!(key.last_used_at.is_none());
    }
}
