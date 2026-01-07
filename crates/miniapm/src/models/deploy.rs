use crate::DbPool;
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub timestamp: Option<String>,
}

pub fn insert(
    pool: &DbPool,
    deploy: &IncomingDeploy,
    project_id: Option<i64>,
) -> anyhow::Result<i64> {
    let conn = pool.get()?;
    let now = Utc::now().to_rfc3339();
    let timestamp = deploy.timestamp.as_ref().unwrap_or(&now);

    conn.execute(
        r#"
        INSERT INTO deploys (project_id, git_sha, version, env, deployed_at, description, deployer)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
        (
            project_id,
            &deploy.git_sha,
            &deploy.version,
            &deploy.env,
            timestamp,
            &deploy.description,
            &deploy.deployer,
        ),
    )?;

    Ok(conn.last_insert_rowid())
}

pub fn list(pool: &DbPool, project_id: Option<i64>, limit: i64) -> anyhow::Result<Vec<Deploy>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        r#"
        SELECT id, project_id, git_sha, version, env,
               strftime('%Y-%m-%d %H:%M', deployed_at) as deployed_at,
               description, deployer
        FROM deploys
        WHERE (?1 IS NULL OR project_id = ?1)
        ORDER BY deployed_at DESC
        LIMIT ?2
        "#,
    )?;

    let deploys = stmt
        .query_map(rusqlite::params![project_id, limit], |row| {
            Ok(Deploy {
                id: row.get(0)?,
                project_id: row.get(1)?,
                git_sha: row.get(2)?,
                version: row.get(3)?,
                env: row.get(4)?,
                deployed_at: row.get(5)?,
                description: row.get(6)?,
                deployer: row.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(deploys)
}

/// Get deploys within a time range for chart markers
pub fn list_since(
    pool: &DbPool,
    project_id: Option<i64>,
    since: &str,
) -> anyhow::Result<Vec<Deploy>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        r#"
        SELECT id, project_id, git_sha, version, env,
               deployed_at,
               description, deployer
        FROM deploys
        WHERE deployed_at >= ?1 AND (?2 IS NULL OR project_id = ?2)
        ORDER BY deployed_at ASC
        "#,
    )?;

    let deploys = stmt
        .query_map(rusqlite::params![since, project_id], |row| {
            Ok(Deploy {
                id: row.get(0)?,
                project_id: row.get(1)?,
                git_sha: row.get(2)?,
                version: row.get(3)?,
                env: row.get(4)?,
                deployed_at: row.get(5)?,
                description: row.get(6)?,
                deployer: row.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(deploys)
}

/// Get the most recent deploy
pub fn latest(pool: &DbPool, project_id: Option<i64>) -> anyhow::Result<Option<Deploy>> {
    let conn = pool.get()?;
    let deploy = conn
        .query_row(
            r#"
            SELECT id, project_id, git_sha, version, env,
                   strftime('%Y-%m-%d %H:%M', deployed_at) as deployed_at,
                   description, deployer
            FROM deploys
            WHERE (?1 IS NULL OR project_id = ?1)
            ORDER BY deployed_at DESC
            LIMIT 1
            "#,
            rusqlite::params![project_id],
            |row| {
                Ok(Deploy {
                    id: row.get(0)?,
                    project_id: row.get(1)?,
                    git_sha: row.get(2)?,
                    version: row.get(3)?,
                    env: row.get(4)?,
                    deployed_at: row.get(5)?,
                    description: row.get(6)?,
                    deployer: row.get(7)?,
                })
            },
        )
        .ok();

    Ok(deploy)
}

pub fn delete_before(pool: &DbPool, before: &str) -> anyhow::Result<usize> {
    let conn = pool.get()?;
    let deleted = conn.execute("DELETE FROM deploys WHERE deployed_at < ?1", [before])?;
    Ok(deleted)
}
