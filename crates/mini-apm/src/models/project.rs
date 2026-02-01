use crate::DbPool;
use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Helper function to map a database row to a Project struct
fn map_row_to_project(row: &rusqlite::Row) -> rusqlite::Result<Project> {
    Ok(Project {
        id: row.get(0)?,
        name: row.get(1)?,
        slug: row.get(2)?,
        api_key: row.get(3)?,
        created_at: row.get(4)?,
    })
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
pub fn ensure_default_project(pool: &DbPool) -> anyhow::Result<Project> {
    let conn = pool.get()?;

    // Check if any project exists
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM projects", [], |row| row.get(0))?;

    if count == 0 {
        let now = Utc::now().to_rfc3339();
        let api_key = generate_api_key();

        conn.execute(
            "INSERT INTO projects (name, slug, api_key, created_at) VALUES (?1, ?2, ?3, ?4)",
            ("Default", "default", &api_key, &now),
        )?;

        tracing::info!("Created default project with API key: {}", api_key);

        return Ok(Project {
            id: conn.last_insert_rowid(),
            name: "Default".to_string(),
            slug: "default".to_string(),
            api_key,
            created_at: now,
        });
    }

    // Return first project
    let project = conn.query_row(
        "SELECT id, name, slug, api_key, created_at FROM projects ORDER BY id LIMIT 1",
        [],
        map_row_to_project,
    )?;

    Ok(project)
}

/// List all projects
pub fn list_all(pool: &DbPool) -> anyhow::Result<Vec<Project>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT id, name, slug, api_key, strftime('%Y-%m-%d %H:%M', created_at) FROM projects ORDER BY name",
    )?;

    let projects = stmt
        .query_map([], map_row_to_project)?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(projects)
}

/// Find project by ID
pub fn find(pool: &DbPool, id: i64) -> anyhow::Result<Option<Project>> {
    let conn = pool.get()?;

    let project = conn
        .query_row(
            "SELECT id, name, slug, api_key, created_at FROM projects WHERE id = ?1",
            [id],
            map_row_to_project,
        )
        .ok();

    Ok(project)
}

/// Find project by slug
pub fn find_by_slug(pool: &DbPool, slug: &str) -> anyhow::Result<Option<Project>> {
    let conn = pool.get()?;

    let project = conn
        .query_row(
            "SELECT id, name, slug, api_key, created_at FROM projects WHERE slug = ?1",
            [slug],
            map_row_to_project,
        )
        .ok();

    Ok(project)
}

/// Find project by API key
pub fn find_by_api_key(pool: &DbPool, api_key: &str) -> anyhow::Result<Option<Project>> {
    let conn = pool.get()?;

    let project = conn
        .query_row(
            "SELECT id, name, slug, api_key, created_at FROM projects WHERE api_key = ?1",
            [api_key],
            map_row_to_project,
        )
        .ok();

    Ok(project)
}

/// Create a new project
pub fn create(pool: &DbPool, name: &str) -> anyhow::Result<Project> {
    let conn = pool.get()?;

    let now = Utc::now().to_rfc3339();
    let slug = slugify(name);
    let api_key = generate_api_key();

    conn.execute(
        "INSERT INTO projects (name, slug, api_key, created_at) VALUES (?1, ?2, ?3, ?4)",
        (name, &slug, &api_key, &now),
    )?;

    let project_id = conn.last_insert_rowid();

    Ok(Project {
        id: project_id,
        name: name.to_string(),
        slug,
        api_key,
        created_at: now,
    })
}

/// Delete a project
pub fn delete(pool: &DbPool, id: i64) -> anyhow::Result<()> {
    let conn = pool.get()?;
    conn.execute("DELETE FROM projects WHERE id = ?1", [id])?;
    Ok(())
}

/// Regenerate API key for a project
pub fn regenerate_api_key(pool: &DbPool, id: i64) -> anyhow::Result<String> {
    let conn = pool.get()?;
    let new_key = generate_api_key();

    conn.execute(
        "UPDATE projects SET api_key = ?1 WHERE id = ?2",
        (&new_key, id),
    )?;

    Ok(new_key)
}

/// Get project count
pub fn count(pool: &DbPool) -> anyhow::Result<i64> {
    let conn = pool.get()?;
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM projects", [], |row| row.get(0))?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::config::Config;

    fn test_pool() -> DbPool {
        let config = Config {
            sqlite_path: ":memory:".to_string(),
            ..Default::default()
        };
        db::init(&config).expect("Failed to create test database")
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

    #[test]
    fn test_ensure_default_project_creates_one() {
        let pool = test_pool();

        let project = ensure_default_project(&pool).unwrap();

        assert_eq!(project.name, "Default");
        assert_eq!(project.slug, "default");
        assert!(project.api_key.starts_with("proj_"));
    }

    #[test]
    fn test_ensure_default_project_returns_existing() {
        let pool = test_pool();

        let project1 = ensure_default_project(&pool).unwrap();
        let project2 = ensure_default_project(&pool).unwrap();

        assert_eq!(project1.id, project2.id);
        assert_eq!(project1.api_key, project2.api_key);
    }

    #[test]
    fn test_create_project() {
        let pool = test_pool();

        let project = create(&pool, "Test Project").unwrap();

        assert_eq!(project.name, "Test Project");
        assert_eq!(project.slug, "test-project");
        assert!(project.api_key.starts_with("proj_"));
    }

    #[test]
    fn test_find_project_by_id() {
        let pool = test_pool();
        let created = create(&pool, "Find Me").unwrap();

        let found = find(&pool, created.id).unwrap();

        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "Find Me");
    }

    #[test]
    fn test_find_project_by_id_not_found() {
        let pool = test_pool();

        let found = find(&pool, 99999).unwrap();

        assert!(found.is_none());
    }

    #[test]
    fn test_find_project_by_slug() {
        let pool = test_pool();
        create(&pool, "My App").unwrap();

        let found = find_by_slug(&pool, "my-app").unwrap();

        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "My App");
    }

    #[test]
    fn test_find_project_by_api_key() {
        let pool = test_pool();
        let created = create(&pool, "API Test").unwrap();

        let found = find_by_api_key(&pool, &created.api_key).unwrap();

        assert!(found.is_some());
        assert_eq!(found.unwrap().id, created.id);
    }

    #[test]
    fn test_list_all_projects() {
        let pool = test_pool();
        create(&pool, "Project A").unwrap();
        create(&pool, "Project B").unwrap();
        create(&pool, "Project C").unwrap();

        let projects = list_all(&pool).unwrap();

        assert_eq!(projects.len(), 3);
    }

    #[test]
    fn test_delete_project() {
        let pool = test_pool();
        let created = create(&pool, "Delete Me").unwrap();

        delete(&pool, created.id).unwrap();

        let found = find(&pool, created.id).unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn test_regenerate_api_key() {
        let pool = test_pool();
        let created = create(&pool, "Regen Test").unwrap();
        let old_key = created.api_key.clone();

        let new_key = regenerate_api_key(&pool, created.id).unwrap();

        assert_ne!(old_key, new_key);
        assert!(new_key.starts_with("proj_"));

        let found = find(&pool, created.id).unwrap().unwrap();
        assert_eq!(found.api_key, new_key);
    }

    #[test]
    fn test_count_projects() {
        let pool = test_pool();

        assert_eq!(count(&pool).unwrap(), 0);

        create(&pool, "One").unwrap();
        assert_eq!(count(&pool).unwrap(), 1);

        create(&pool, "Two").unwrap();
        assert_eq!(count(&pool).unwrap(), 2);
    }
}
