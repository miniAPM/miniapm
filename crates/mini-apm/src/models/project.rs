use crate::DbPool;
use crate::time;
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Project {
    pub id: i64,
    pub name: String,
    pub slug: String,
    pub api_key: String,
    pub created_at: String,
}

/// Generate a random API key for a project
fn generate_api_key() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 24] = rng.r#gen();
    format!("proj_{}", hex::encode(bytes))
}

/// Generate a slug from project name
fn slugify(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Ensure default project exists when projects are enabled
pub async fn ensure_default_project(pool: &DbPool) -> anyhow::Result<Project> {
    // Check if any project exists
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projects")
        .fetch_one(pool)
        .await?;

    if count == 0 {
        let now = time::now_rfc3339();
        let api_key = generate_api_key();

        let result = sqlx::query(
            "INSERT INTO projects (name, slug, api_key, created_at) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("Default")
        .bind("default")
        .bind(&api_key)
        .bind(&now)
        .execute(pool)
        .await?;

        tracing::info!("Created default project with API key: {}", api_key);

        return Ok(Project {
            id: result.last_insert_rowid(),
            name: "Default".to_string(),
            slug: "default".to_string(),
            api_key,
            created_at: now,
        });
    }

    // Return first project
    let project = sqlx::query_as::<_, Project>(
        "SELECT id, name, slug, api_key, created_at FROM projects ORDER BY id LIMIT 1",
    )
    .fetch_one(pool)
    .await?;

    Ok(project)
}

/// List all projects
pub async fn list_all(pool: &DbPool) -> anyhow::Result<Vec<Project>> {
    let projects = sqlx::query_as::<_, Project>(
        "SELECT id, name, slug, api_key, strftime('%Y-%m-%d %H:%M', created_at) AS created_at FROM projects ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    Ok(projects)
}

/// Find project by ID
pub async fn find(pool: &DbPool, id: i64) -> anyhow::Result<Option<Project>> {
    let project = sqlx::query_as::<_, Project>(
        "SELECT id, name, slug, api_key, created_at FROM projects WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(project)
}

/// Find project by slug
pub async fn find_by_slug(pool: &DbPool, slug: &str) -> anyhow::Result<Option<Project>> {
    let project = sqlx::query_as::<_, Project>(
        "SELECT id, name, slug, api_key, created_at FROM projects WHERE slug = ?1",
    )
    .bind(slug)
    .fetch_optional(pool)
    .await?;

    Ok(project)
}

/// Find project by API key
pub async fn find_by_api_key(pool: &DbPool, api_key: &str) -> anyhow::Result<Option<Project>> {
    let project = sqlx::query_as::<_, Project>(
        "SELECT id, name, slug, api_key, created_at FROM projects WHERE api_key = ?1",
    )
    .bind(api_key)
    .fetch_optional(pool)
    .await?;

    Ok(project)
}

/// Create a new project
pub async fn create(pool: &DbPool, name: &str) -> anyhow::Result<Project> {
    let now = time::now_rfc3339();
    let slug = slugify(name);
    let api_key = generate_api_key();

    let result = sqlx::query(
        "INSERT INTO projects (name, slug, api_key, created_at) VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(name)
    .bind(&slug)
    .bind(&api_key)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(Project {
        id: result.last_insert_rowid(),
        name: name.to_string(),
        slug,
        api_key,
        created_at: now,
    })
}

/// Delete a project
pub async fn delete(pool: &DbPool, id: i64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM projects WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Regenerate API key for a project
pub async fn regenerate_api_key(pool: &DbPool, id: i64) -> anyhow::Result<String> {
    let new_key = generate_api_key();

    sqlx::query("UPDATE projects SET api_key = ?1 WHERE id = ?2")
        .bind(&new_key)
        .bind(id)
        .execute(pool)
        .await?;

    Ok(new_key)
}

/// Get project count
pub async fn count(pool: &DbPool) -> anyhow::Result<i64> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projects")
        .fetch_one(pool)
        .await?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db;

    async fn test_pool() -> DbPool {
        let config = Config {
            sqlite_path: ":memory:".to_string(),
            ..Default::default()
        };
        db::init(&config)
            .await
            .expect("Failed to create test database")
    }

    #[test]
    fn test_generate_api_key_format() {
        let key = generate_api_key();
        assert!(key.starts_with("proj_"));
        assert_eq!(key.len(), 5 + 48); // "proj_" + 48 hex chars (24 bytes)
    }

    #[test]
    fn test_generate_api_key_unique() {
        let key1 = generate_api_key();
        let key2 = generate_api_key();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_slugify_simple() {
        assert_eq!(slugify("My Project"), "my-project");
    }

    #[test]
    fn test_slugify_special_chars() {
        assert_eq!(slugify("Test@Project#123"), "test-project-123");
    }

    #[test]
    fn test_slugify_multiple_spaces() {
        assert_eq!(slugify("My   Cool   Project"), "my-cool-project");
    }

    #[test]
    fn test_slugify_leading_trailing() {
        assert_eq!(slugify("  Project  "), "project");
    }

    #[tokio::test]
    async fn test_ensure_default_project_creates_one() {
        let pool = test_pool().await;

        let project = ensure_default_project(&pool).await.unwrap();

        assert_eq!(project.name, "Default");
        assert_eq!(project.slug, "default");
        assert!(project.api_key.starts_with("proj_"));
    }

    #[tokio::test]
    async fn test_ensure_default_project_returns_existing() {
        let pool = test_pool().await;

        let project1 = ensure_default_project(&pool).await.unwrap();
        let project2 = ensure_default_project(&pool).await.unwrap();

        assert_eq!(project1.id, project2.id);
        assert_eq!(project1.api_key, project2.api_key);
    }

    #[tokio::test]
    async fn test_create_project() {
        let pool = test_pool().await;

        let project = create(&pool, "Test Project").await.unwrap();

        assert_eq!(project.name, "Test Project");
        assert_eq!(project.slug, "test-project");
        assert!(project.api_key.starts_with("proj_"));
    }

    #[tokio::test]
    async fn test_find_project_by_id() {
        let pool = test_pool().await;
        let created = create(&pool, "Find Me").await.unwrap();

        let found = find(&pool, created.id).await.unwrap();

        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "Find Me");
    }

    #[tokio::test]
    async fn test_find_project_by_id_not_found() {
        let pool = test_pool().await;

        let found = find(&pool, 99999).await.unwrap();

        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_find_project_by_slug() {
        let pool = test_pool().await;
        create(&pool, "My App").await.unwrap();

        let found = find_by_slug(&pool, "my-app").await.unwrap();

        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "My App");
    }

    #[tokio::test]
    async fn test_find_project_by_api_key() {
        let pool = test_pool().await;
        let created = create(&pool, "API Test").await.unwrap();

        let found = find_by_api_key(&pool, &created.api_key).await.unwrap();

        assert!(found.is_some());
        assert_eq!(found.unwrap().id, created.id);
    }

    #[tokio::test]
    async fn test_list_all_projects() {
        let pool = test_pool().await;
        create(&pool, "Project A").await.unwrap();
        create(&pool, "Project B").await.unwrap();
        create(&pool, "Project C").await.unwrap();

        let projects = list_all(&pool).await.unwrap();

        assert_eq!(projects.len(), 3);
    }

    #[tokio::test]
    async fn test_delete_project() {
        let pool = test_pool().await;
        let created = create(&pool, "Delete Me").await.unwrap();

        delete(&pool, created.id).await.unwrap();

        let found = find(&pool, created.id).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_regenerate_api_key() {
        let pool = test_pool().await;
        let created = create(&pool, "Regen Test").await.unwrap();
        let old_key = created.api_key.clone();

        let new_key = regenerate_api_key(&pool, created.id).await.unwrap();

        assert_ne!(old_key, new_key);
        assert!(new_key.starts_with("proj_"));

        let found = find(&pool, created.id).await.unwrap().unwrap();
        assert_eq!(found.api_key, new_key);
    }

    #[tokio::test]
    async fn test_count_projects() {
        let pool = test_pool().await;

        assert_eq!(count(&pool).await.unwrap(), 0);

        create(&pool, "One").await.unwrap();
        assert_eq!(count(&pool).await.unwrap(), 1);

        create(&pool, "Two").await.unwrap();
        assert_eq!(count(&pool).await.unwrap(), 2);
    }
}
