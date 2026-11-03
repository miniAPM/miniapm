use super::*;
use crate::db::test_pool;
use crate::models::user;

#[tokio::test]
async fn tokens_authenticate_their_owner_until_revoked() -> anyhow::Result<()> {
    let pool = test_pool().await;
    let alice = user::create(&pool, "alice", "alice-password", true).await?;
    let bob = user::create(&pool, "bob", "bob-password", false).await?;

    let (token, secret) = create(&pool, alice, "  laptop  ").await?;
    assert_eq!(token.name, "laptop");
    assert!(secret.starts_with(PREFIX));
    assert!(token.last_used_at.is_none());

    let bearer = authenticate(&pool, &secret).await?.expect("valid token");
    assert_eq!(
        bearer,
        Bearer {
            token_id: token.id,
            user_id: alice,
            username: "alice".into(),
            is_admin: true,
        }
    );
    let listed = list_for_user(&pool, alice).await?;
    assert_eq!(listed.len(), 1);
    assert!(listed[0].last_used_at.is_some());
    assert!(list_for_user(&pool, bob).await?.is_empty());

    for wrong in [
        "",
        "mcp_",
        "proj_abc",
        &secret[..secret.len() - 1],
        &secret.to_uppercase(),
    ] {
        assert_eq!(authenticate(&pool, wrong).await?, None, "{wrong:?}");
    }

    assert!(!revoke(&pool, bob, token.id).await?);
    assert!(revoke(&pool, alice, token.id).await?);
    assert!(!revoke(&pool, alice, token.id).await?);
    assert_eq!(authenticate(&pool, &secret).await?, None);
    Ok(())
}

#[tokio::test]
async fn names_are_validated_and_tokens_go_with_their_user() -> anyhow::Result<()> {
    let pool = test_pool().await;
    let carol = user::create(&pool, "carol", "carol-password", false).await?;

    for name in ["", "   ", &"x".repeat(MAX_NAME_CHARS + 1)] {
        assert!(create(&pool, carol, name).await.is_err(), "{name:?}");
    }
    let (_, secret) = create(&pool, carol, &"é".repeat(MAX_NAME_CHARS)).await?;

    user::delete(&pool, carol).await?;
    assert_eq!(authenticate(&pool, &secret).await?, None);
    assert!(list_for_user(&pool, carol).await?.is_empty());
    Ok(())
}
