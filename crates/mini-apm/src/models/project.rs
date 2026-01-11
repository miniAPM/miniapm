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
        |row| {
            Ok(Project {
                id: row.get(0)?,
                name: row.get(1)?,
                slug: row.get(2)?,
                api_key: row.get(3)?,
                created_at: row.get(4)?,
            })
        },
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
        .query_map([], |row| {
            Ok(Project {
                id: row.get(0)?,
                name: row.get(1)?,
                slug: row.get(2)?,
                api_key: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?
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
            |row| {
                Ok(Project {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    slug: row.get(2)?,
                    api_key: row.get(3)?,
                    created_at: row.get(4)?,
                })
            },
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
            |row| {
                Ok(Project {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    slug: row.get(2)?,
                    api_key: row.get(3)?,
                    created_at: row.get(4)?,
                })
            },
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
            |row| {
                Ok(Project {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    slug: row.get(2)?,
                    api_key: row.get(3)?,
                    created_at: row.get(4)?,
                })
            },
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
