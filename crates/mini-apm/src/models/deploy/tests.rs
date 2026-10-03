use super::*;
use crate::{db::test_pool, models::project};

#[tokio::test]
async fn history_is_project_scoped_ordered_and_limited() -> anyhow::Result<()> {
    let pool = test_pool().await;
    let project = project::create(&pool, "App").await?;
    let other = project::create(&pool, "Other").await?;
    assert!(latest(&pool, Some(project.id)).await?.is_none());

    for (sha, day, project_id) in [
        ("second", 2, Some(project.id)),
        ("first", 1, Some(project.id)),
        ("other", 3, Some(other.id)),
        ("unscoped", 4, None),
    ] {
        insert(
            &pool,
            &IncomingDeploy {
                git_sha: sha.into(),
                version: Some("v1".into()),
                env: Some("production".into()),
                description: Some("release".into()),
                deployer: Some("ci".into()),
                timestamp: Some(format!("2024-01-0{day}T00:00:00Z").parse()?),
            },
            project_id,
        )
        .await?;
    }

    let history = list(&pool, Some(project.id), 10).await?;
    assert_eq!(
        history
            .iter()
            .map(|d| d.git_sha.as_str())
            .collect::<Vec<_>>(),
        ["second", "first"]
    );
    assert_eq!(list(&pool, Some(project.id), 1).await?[0].git_sha, "second");
    let latest = latest(&pool, Some(project.id))
        .await?
        .expect("latest deploy");
    assert_eq!(latest.git_sha, "second");
    assert_eq!(latest.project_id, Some(project.id));
    assert_eq!(latest.version.as_deref(), Some("v1"));
    assert_eq!(latest.env.as_deref(), Some("production"));
    assert_eq!(latest.description.as_deref(), Some("release"));
    assert_eq!(latest.deployer.as_deref(), Some("ci"));
    assert_eq!(list(&pool, None, 10).await?.len(), 4);

    let since = list_since(&pool, Some(project.id), "2024-01-02T00:00:00+00:00").await?;
    assert_eq!(
        since.iter().map(|d| d.git_sha.as_str()).collect::<Vec<_>>(),
        ["second"]
    );
    Ok(())
}
