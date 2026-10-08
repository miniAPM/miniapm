use crate::DbPool;
use crate::db::Db;
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
/// Slug of the project MiniAPM records its own requests and errors into
pub const SELF_SLUG: &str = "self";

pub async fn ensure_default_project(pool: &DbPool) -> anyhow::Result<Project> {
    // Check if any project other than `self` exists
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projects WHERE slug != $1")
        .bind(SELF_SLUG)
        .fetch_one(pool)
        .await?;

    if count == 0 {
        let now = time::now_rfc3339();
        let api_key = generate_api_key();

        let id = sqlx::query_scalar(
            "INSERT INTO projects (name, slug, api_key, created_at) VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind("Default")
        .bind("default")
        .bind(&api_key)
        .bind(&now)
        .fetch_one(pool)
        .await?;

        tracing::info!("Created default project with API key: {}", api_key);

        return Ok(Project {
            id,
            name: "Default".to_string(),
            slug: "default".to_string(),
            api_key,
            created_at: now,
        });
    }

    // Return first project
    let project = sqlx::query_as::<_, Project>(
        "SELECT id, name, slug, api_key, created_at FROM projects WHERE slug != $1 ORDER BY id LIMIT 1",
    )
    .bind(SELF_SLUG)
    .fetch_one(pool)
    .await?;

    Ok(project)
}

/// The project MiniAPM records itself into. It cannot be deleted and its
/// API key is refused by the collector: data only arrives in-process.
pub async fn ensure_self_project(pool: &DbPool) -> anyhow::Result<Project> {
    sqlx::query(
        "INSERT INTO projects (name, slug, api_key, created_at) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
    )
    .bind("MiniAPM")
    .bind(SELF_SLUG)
    .bind(generate_api_key())
    .bind(time::now_rfc3339())
    .execute(pool)
    .await?;

    find_by_slug(pool, SELF_SLUG)
        .await?
        .ok_or_else(|| anyhow::anyhow!("project name `MiniAPM` is taken, cannot create `self`"))
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

pub async fn find(pool: &DbPool, id: i64) -> anyhow::Result<Option<Project>> {
    find_by(pool, "id", id).await
}

pub async fn find_by_slug(pool: &DbPool, slug: &str) -> anyhow::Result<Option<Project>> {
    find_by(pool, "slug", slug).await
}

pub async fn find_by_api_key(pool: &DbPool, api_key: &str) -> anyhow::Result<Option<Project>> {
    find_by(pool, "api_key", api_key).await
}

async fn find_by<'q, T>(
    pool: &DbPool,
    column: &'static str,
    value: T,
) -> anyhow::Result<Option<Project>>
where
    T: 'q + Send + sqlx::Encode<'q, Db> + sqlx::Type<Db>,
{
    let sql =
        format!("SELECT id, name, slug, api_key, created_at FROM projects WHERE {column} = $1");
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(value)
        .fetch_optional(pool)
        .await?)
}

/// Create a new project
pub async fn create(pool: &DbPool, name: &str) -> anyhow::Result<Project> {
    let now = time::now_rfc3339();
    let slug = slugify(name);
    let api_key = generate_api_key();

    let id = sqlx::query_scalar(
        "INSERT INTO projects (name, slug, api_key, created_at) VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(name)
    .bind(&slug)
    .bind(&api_key)
    .bind(&now)
    .fetch_one(pool)
    .await?;

    Ok(Project {
        id,
        name: name.to_string(),
        slug,
        api_key,
        created_at: now,
    })
}

/// Delete a project
pub async fn delete(pool: &DbPool, id: i64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM projects WHERE id = $1 AND slug != $2")
        .bind(id)
        .bind(SELF_SLUG)
        .execute(pool)
        .await?;
    Ok(())
}

/// Regenerate API key for a project
pub async fn regenerate_api_key(pool: &DbPool, id: i64) -> anyhow::Result<String> {
    let new_key = generate_api_key();

    sqlx::query("UPDATE projects SET api_key = $1 WHERE id = $2")
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
mod tests;
