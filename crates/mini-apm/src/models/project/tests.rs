use super::*;
use crate::db::test_pool;

#[tokio::test]
async fn default_project_is_stable_and_distinct_from_self_monitoring() -> anyhow::Result<()> {
    let pool = test_pool().await;
    let internal = ensure_self_project(&pool).await?;
    let default = ensure_default_project(&pool).await?;

    assert_ne!(default.id, internal.id);
    assert_eq!(
        (default.name.as_str(), default.slug.as_str()),
        ("Default", "default")
    );
    assert_eq!(
        ensure_default_project(&pool).await?.api_key,
        default.api_key
    );
    assert_eq!(ensure_self_project(&pool).await?.id, internal.id);
    delete(&pool, internal.id).await?;
    assert!(
        find(&pool, internal.id).await?.is_some(),
        "self project is protected"
    );
    assert_eq!(count(&pool).await?, 2);
    Ok(())
}

#[tokio::test]
async fn project_lifecycle_persists_names_and_revokes_rotated_keys() -> anyhow::Result<()> {
    let pool = test_pool().await;
    let mut created = Vec::new();
    for (name, slug) in [
        ("My   Cool   Project", "my-cool-project"),
        ("Test@Project#123", "test-project-123"),
        ("  Project  ", "project"),
    ] {
        let project = create(&pool, name).await?;
        assert_eq!(project.slug, slug);
        assert_eq!(find(&pool, project.id).await?.expect("by id").name, name);
        assert_eq!(
            find_by_slug(&pool, slug).await?.expect("by slug").id,
            project.id
        );
        assert_eq!(
            find_by_api_key(&pool, &project.api_key)
                .await?
                .expect("by key")
                .id,
            project.id
        );
        created.push(project);
    }
    assert_eq!(list_all(&pool).await?.len(), 3);
    assert_ne!(created[0].api_key, created[1].api_key);
    let project = &created[0];
    let rotated = regenerate_api_key(&pool, project.id).await?;
    assert_ne!(rotated, project.api_key);
    assert!(find_by_api_key(&pool, &project.api_key).await?.is_none());
    assert_eq!(
        find_by_api_key(&pool, &rotated)
            .await?
            .expect("rotated key")
            .id,
        project.id
    );

    delete(&pool, project.id).await?;
    assert!(find(&pool, project.id).await?.is_none());
    assert!(find_by_slug(&pool, &project.slug).await?.is_none());
    assert!(find_by_api_key(&pool, &rotated).await?.is_none());
    assert_eq!(count(&pool).await?, 2);
    Ok(())
}
