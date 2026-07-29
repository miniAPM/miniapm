use crate::DbPool;
use chrono::Utc;
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
    pub timestamp: Option<String>,
}

pub async fn insert(
    pool: &DbPool,
    deploy: &IncomingDeploy,
    project_id: Option<i64>,
) -> anyhow::Result<i64> {
    let now = Utc::now().to_rfc3339();
    let timestamp = deploy.timestamp.as_deref().unwrap_or(&now);

    let result = sqlx::query(
        r#"
        INSERT INTO deploys (project_id, git_sha, version, env, deployed_at, description, deployer)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
    )
    .bind(project_id)
    .bind(&deploy.git_sha)
    .bind(deploy.version.as_deref())
    .bind(deploy.env.as_deref())
    .bind(timestamp)
    .bind(deploy.description.as_deref())
    .bind(deploy.deployer.as_deref())
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
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
        WHERE (?1 IS NULL OR project_id = ?1)
        ORDER BY deployed_at DESC
        LIMIT ?2
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
        WHERE deployed_at >= ?1 AND (?2 IS NULL OR project_id = ?2)
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
        WHERE (?1 IS NULL OR project_id = ?1)
        ORDER BY deployed_at DESC
        LIMIT 1
        "#,
    )
    .bind(project_id)
    .fetch_optional(pool)
    .await?;

    Ok(deploy)
}

pub async fn delete_before(pool: &DbPool, before: &str) -> anyhow::Result<usize> {
    let result = sqlx::query("DELETE FROM deploys WHERE deployed_at < ?1")
        .bind(before)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db;

    async fn test_pool() -> DbPool {
        let config = Config::default();
        db::init(&config).await.expect("Failed to create test database")
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

    #[tokio::test]
    async fn test_insert_deploy() {
        let pool = test_pool().await;
        let incoming = IncomingDeploy {
            git_sha: "abc123".to_string(),
            version: Some("v1.0.0".to_string()),
            env: Some("production".to_string()),
            description: Some("Initial release".to_string()),
            deployer: Some("ci".to_string()),
            timestamp: None,
        };

        let id = insert(&pool, &incoming, None).await.unwrap();

        assert!(id > 0);
    }

    #[tokio::test]
    async fn test_insert_deploy_with_project() {
        let pool = test_pool().await;
        let project = crate::models::project::create(&pool, "Test").await.unwrap();

        let incoming = IncomingDeploy {
            git_sha: "def456".to_string(),
            version: None,
            env: None,
            description: None,
            deployer: None,
            timestamp: None,
        };

        let id = insert(&pool, &incoming, Some(project.id)).await.unwrap();
        let deploys = list(&pool, Some(project.id), 10).await.unwrap();

        assert_eq!(deploys.len(), 1);
        assert_eq!(deploys[0].id, id);
        assert_eq!(deploys[0].project_id, Some(project.id));
    }

    #[tokio::test]
    async fn test_list_deploys() {
        let pool = test_pool().await;

        for i in 0..5 {
            let incoming = IncomingDeploy {
                git_sha: format!("sha{}", i),
                version: None,
                env: None,
                description: None,
                deployer: None,
                timestamp: None,
            };
            insert(&pool, &incoming, None).await.unwrap();
        }

        let deploys = list(&pool, None, 10).await.unwrap();
        assert_eq!(deploys.len(), 5);
    }

    #[tokio::test]
    async fn test_list_deploys_limit() {
        let pool = test_pool().await;

        for i in 0..5 {
            let incoming = IncomingDeploy {
                git_sha: format!("sha{}", i),
                version: None,
                env: None,
                description: None,
                deployer: None,
                timestamp: None,
            };
            insert(&pool, &incoming, None).await.unwrap();
        }

        let deploys = list(&pool, None, 3).await.unwrap();
        assert_eq!(deploys.len(), 3);
    }

    #[tokio::test]
    async fn test_latest_deploy() {
        let pool = test_pool().await;

        let incoming1 = IncomingDeploy {
            git_sha: "first".to_string(),
            version: None,
            env: None,
            description: None,
            deployer: None,
            timestamp: Some("2024-01-01T00:00:00Z".to_string()),
        };
        insert(&pool, &incoming1, None).await.unwrap();

        let incoming2 = IncomingDeploy {
            git_sha: "second".to_string(),
            version: None,
            env: None,
            description: None,
            deployer: None,
            timestamp: Some("2024-01-02T00:00:00Z".to_string()),
        };
        insert(&pool, &incoming2, None).await.unwrap();

        let deploy = latest(&pool, None).await.unwrap().unwrap();
        assert_eq!(deploy.git_sha, "second");
    }

    #[tokio::test]
    async fn test_latest_deploy_empty() {
        let pool = test_pool().await;
        let deploy = latest(&pool, None).await.unwrap();
        assert!(deploy.is_none());
    }

    #[tokio::test]
    async fn test_delete_before() {
        let pool = test_pool().await;

        let old = IncomingDeploy {
            git_sha: "old".to_string(),
            version: None,
            env: None,
            description: None,
            deployer: None,
            timestamp: Some("2020-01-01T00:00:00Z".to_string()),
        };
        insert(&pool, &old, None).await.unwrap();

        let recent = IncomingDeploy {
            git_sha: "recent".to_string(),
            version: None,
            env: None,
            description: None,
            deployer: None,
            timestamp: Some("2024-01-01T00:00:00Z".to_string()),
        };
        insert(&pool, &recent, None).await.unwrap();

        let deleted = delete_before(&pool, "2023-01-01").await.unwrap();
        assert_eq!(deleted, 1);

        let remaining = list(&pool, None, 10).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].git_sha, "recent");
    }
}
