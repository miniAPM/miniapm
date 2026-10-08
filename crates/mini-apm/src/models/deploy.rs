use crate::DbPool;
use crate::time;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Deploy {
    pub id: i64,
    pub project_id: Option<i64>,
    pub git_sha: String,
    pub version: Option<String>,
    pub env: Option<String>,
    pub deployed_at: String,
    pub description: Option<String>,
    pub deployer: Option<String>,
}

impl Deploy {
    pub fn short_sha(&self) -> &str {
        if self.git_sha.len() >= 7 {
            &self.git_sha[..7]
        } else {
            &self.git_sha
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct IncomingDeploy {
    pub git_sha: String,
    pub version: Option<String>,
    pub env: Option<String>,
    pub description: Option<String>,
    pub deployer: Option<String>,
    pub timestamp: Option<Timestamp>,
}

pub async fn insert(
    pool: &DbPool,
    deploy: &IncomingDeploy,
    project_id: Option<i64>,
) -> anyhow::Result<i64> {
    let timestamp = time::rfc3339(deploy.timestamp.unwrap_or_else(Timestamp::now));

    let id = sqlx::query_scalar(
        r#"
        INSERT INTO deploys (project_id, git_sha, version, env, deployed_at, description, deployer)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id
        "#,
    )
    .bind(project_id)
    .bind(&deploy.git_sha)
    .bind(deploy.version.as_deref())
    .bind(deploy.env.as_deref())
    .bind(timestamp)
    .bind(deploy.description.as_deref())
    .bind(deploy.deployer.as_deref())
    .fetch_one(pool)
    .await?;

    Ok(id)
}

pub async fn list(
    pool: &DbPool,
    project_id: Option<i64>,
    limit: i64,
) -> anyhow::Result<Vec<Deploy>> {
    let deploys = sqlx::query_as::<_, Deploy>(
        r#"
        SELECT id, project_id, git_sha, version, env,
               strftime('%Y-%m-%d %H:%M', deployed_at) as deployed_at,
               description, deployer
        FROM deploys
        WHERE ($1 IS NULL OR project_id = $1)
        ORDER BY deployed_at DESC
        LIMIT $2
        "#,
    )
    .bind(project_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(deploys)
}

/// Get deploys within a time range for chart markers
pub async fn list_since(
    pool: &DbPool,
    project_id: Option<i64>,
    since: &str,
) -> anyhow::Result<Vec<Deploy>> {
    let deploys = sqlx::query_as::<_, Deploy>(
        r#"
        SELECT id, project_id, git_sha, version, env,
               deployed_at,
               description, deployer
        FROM deploys
        WHERE deployed_at >= $1 AND ($2 IS NULL OR project_id = $2)
        ORDER BY deployed_at ASC
        "#,
    )
    .bind(since)
    .bind(project_id)
    .fetch_all(pool)
    .await?;

    Ok(deploys)
}

/// Get the most recent deploy
pub async fn latest(pool: &DbPool, project_id: Option<i64>) -> anyhow::Result<Option<Deploy>> {
    let deploy = sqlx::query_as::<_, Deploy>(
        r#"
        SELECT id, project_id, git_sha, version, env,
               strftime('%Y-%m-%d %H:%M', deployed_at) as deployed_at,
               description, deployer
        FROM deploys
        WHERE ($1 IS NULL OR project_id = $1)
        ORDER BY deployed_at DESC
        LIMIT 1
        "#,
    )
    .bind(project_id)
    .fetch_optional(pool)
    .await?;

    Ok(deploy)
}

#[cfg(test)]
mod tests;
