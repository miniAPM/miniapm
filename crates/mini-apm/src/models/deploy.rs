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
    fn test_short_sha_full() {
        let deploy = Deploy {
            id: 1,
            project_id: None,
            git_sha: "abc123def456".to_string(),
            version: None,
            env: None,
            deployed_at: "2024-01-01".to_string(),
            description: None,
            deployer: None,
        };
        assert_eq!(deploy.short_sha(), "abc123d");
    }

    #[test]
    fn test_short_sha_short() {
        let deploy = Deploy {
            id: 1,
            project_id: None,
            git_sha: "abc".to_string(),
            version: None,
            env: None,
            deployed_at: "2024-01-01".to_string(),
            description: None,
            deployer: None,
        };
        assert_eq!(deploy.short_sha(), "abc");
    }

    #[test]
    fn test_insert_deploy() {
        let pool = test_pool();
        let incoming = IncomingDeploy {
            git_sha: "abc123".to_string(),
            version: Some("v1.0.0".to_string()),
            env: Some("production".to_string()),
            description: Some("Initial release".to_string()),
            deployer: Some("ci".to_string()),
            timestamp: None,
        };

        let id = insert(&pool, &incoming, None).unwrap();

        assert!(id > 0);
    }

    #[test]
    fn test_insert_deploy_with_project() {
        let pool = test_pool();
        let project = crate::models::project::create(&pool, "Test").unwrap();

        let incoming = IncomingDeploy {
            git_sha: "def456".to_string(),
            version: None,
            env: None,
            description: None,
            deployer: None,
            timestamp: None,
        };

        let id = insert(&pool, &incoming, Some(project.id)).unwrap();
        let deploys = list(&pool, Some(project.id), 10).unwrap();

        assert_eq!(deploys.len(), 1);
        assert_eq!(deploys[0].id, id);
        assert_eq!(deploys[0].project_id, Some(project.id));
    }

    #[test]
    fn test_list_deploys() {
        let pool = test_pool();

        for i in 0..5 {
            let incoming = IncomingDeploy {
                git_sha: format!("sha{}", i),
                version: None,
                env: None,
                description: None,
                deployer: None,
                timestamp: None,
            };
            insert(&pool, &incoming, None).unwrap();
        }

        let deploys = list(&pool, None, 10).unwrap();
        assert_eq!(deploys.len(), 5);
    }

    #[test]
    fn test_list_deploys_limit() {
        let pool = test_pool();

        for i in 0..5 {
            let incoming = IncomingDeploy {
                git_sha: format!("sha{}", i),
                version: None,
                env: None,
                description: None,
                deployer: None,
                timestamp: None,
            };
            insert(&pool, &incoming, None).unwrap();
        }

        let deploys = list(&pool, None, 3).unwrap();
        assert_eq!(deploys.len(), 3);
    }

    #[test]
    fn test_latest_deploy() {
        let pool = test_pool();

        let incoming1 = IncomingDeploy {
            git_sha: "first".to_string(),
            version: None,
            env: None,
            description: None,
            deployer: None,
            timestamp: Some("2024-01-01T00:00:00Z".to_string()),
        };
        insert(&pool, &incoming1, None).unwrap();

        let incoming2 = IncomingDeploy {
            git_sha: "second".to_string(),
            version: None,
            env: None,
            description: None,
            deployer: None,
            timestamp: Some("2024-01-02T00:00:00Z".to_string()),
        };
        insert(&pool, &incoming2, None).unwrap();

        let deploy = latest(&pool, None).unwrap().unwrap();
        assert_eq!(deploy.git_sha, "second");
    }

    #[test]
    fn test_latest_deploy_empty() {
        let pool = test_pool();
        let deploy = latest(&pool, None).unwrap();
        assert!(deploy.is_none());
    }

    #[test]
    fn test_delete_before() {
        let pool = test_pool();

        let old = IncomingDeploy {
            git_sha: "old".to_string(),
            version: None,
            env: None,
            description: None,
            deployer: None,
            timestamp: Some("2020-01-01T00:00:00Z".to_string()),
        };
        insert(&pool, &old, None).unwrap();

        let recent = IncomingDeploy {
            git_sha: "recent".to_string(),
            version: None,
            env: None,
            description: None,
            deployer: None,
            timestamp: Some("2024-01-01T00:00:00Z".to_string()),
        };
        insert(&pool, &recent, None).unwrap();

        let deleted = delete_before(&pool, "2023-01-01").unwrap();
        assert_eq!(deleted, 1);

        let remaining = list(&pool, None, 10).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].git_sha, "recent");
    }
}
