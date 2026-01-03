use crate::DbPool;
use chrono::Utc;
use rand::Rng;

const API_KEY_SETTING: &str = "api_key";
const API_KEY_PREFIX: &str = "mapm_";

/// Get the current API key, creating one if it doesn't exist
pub fn get_or_create_api_key(pool: &DbPool) -> anyhow::Result<String> {
    let conn = pool.get()?;

    // Use INSERT OR IGNORE to handle race conditions atomically
    let new_key = generate_api_key();
    conn.execute(
        "INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)",
        (API_KEY_SETTING, &new_key, Utc::now().to_rfc3339()),
    )?;

    // Now fetch the actual key (either existing or the one we just inserted)
    let key: String = conn.query_row(
        "SELECT value FROM settings WHERE key = ?1",
        [API_KEY_SETTING],
        |row| row.get(0),
    )?;

    Ok(key)
}

/// Regenerate the API key
pub fn regenerate_api_key(pool: &DbPool) -> anyhow::Result<String> {
    let conn = pool.get()?;
    let new_key = generate_api_key();

    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)",
        (API_KEY_SETTING, &new_key, Utc::now().to_rfc3339()),
    )?;

    tracing::info!("Regenerated API key");
    Ok(new_key)
}

/// Verify an API key
pub fn verify_api_key(pool: &DbPool, key: &str) -> anyhow::Result<bool> {
    if key.is_empty() {
        return Ok(false);
    }

    let conn = pool.get()?;
    let stored: Option<String> = conn
        .query_row(
            "SELECT value FROM settings WHERE key = ?1",
            [API_KEY_SETTING],
            |row| row.get(0),
        )
        .ok();

    Ok(stored.as_deref() == Some(key))
}

/// Get the API key (for display)
pub fn get_api_key(pool: &DbPool) -> anyhow::Result<Option<String>> {
    let conn = pool.get()?;
    let key: Option<String> = conn
        .query_row(
            "SELECT value FROM settings WHERE key = ?1",
            [API_KEY_SETTING],
            |row| row.get(0),
        )
        .ok();
    Ok(key)
}

fn generate_api_key() -> String {
    let random_bytes: [u8; 24] = rand::thread_rng().gen();
    format!("{}{}", API_KEY_PREFIX, hex::encode(random_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;

    fn create_test_pool() -> DbPool {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder().max_size(1).build(manager).unwrap();

        // Create settings table
        let conn = pool.get().unwrap();
        conn.execute(
            "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)",
            [],
        )
        .unwrap();

        pool
    }

    #[test]
    fn test_get_or_create_api_key_creates_new() {
        let pool = create_test_pool();
        let key = get_or_create_api_key(&pool).unwrap();

        assert!(key.starts_with(API_KEY_PREFIX));
        assert_eq!(key.len(), API_KEY_PREFIX.len() + 48); // 24 bytes = 48 hex chars
    }

    #[test]
    fn test_get_or_create_api_key_returns_existing() {
        let pool = create_test_pool();
        let key1 = get_or_create_api_key(&pool).unwrap();
        let key2 = get_or_create_api_key(&pool).unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_regenerate_api_key() {
        let pool = create_test_pool();
        let key1 = get_or_create_api_key(&pool).unwrap();
        let key2 = regenerate_api_key(&pool).unwrap();

        assert_ne!(key1, key2);
        assert!(key2.starts_with(API_KEY_PREFIX));
    }

    #[test]
    fn test_verify_api_key_success() {
        let pool = create_test_pool();
        let key = get_or_create_api_key(&pool).unwrap();

        assert!(verify_api_key(&pool, &key).unwrap());
    }

    #[test]
    fn test_verify_api_key_failure() {
        let pool = create_test_pool();
        let _key = get_or_create_api_key(&pool).unwrap();

        assert!(!verify_api_key(&pool, "wrong_key").unwrap());
        assert!(!verify_api_key(&pool, "").unwrap());
    }

    #[test]
    fn test_get_api_key() {
        let pool = create_test_pool();

        // No key yet
        assert!(get_api_key(&pool).unwrap().is_none());

        // After creation
        let key = get_or_create_api_key(&pool).unwrap();
        assert_eq!(get_api_key(&pool).unwrap(), Some(key));
    }
}
