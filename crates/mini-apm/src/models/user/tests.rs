use super::*;
use crate::db::test_pool;

#[test]
fn username_validation_handles_boundaries_and_character_rules() {
    use UsernameValidationError::*;
    for (username, expected) in [
        ("".to_string(), Err(Empty)),
        ("   ".to_string(), Err(Empty)),
        ("ab".to_string(), Err(TooShort)),
        ("abc".to_string(), Ok(())),
        ("a".repeat(32), Ok(())),
        ("a".repeat(33), Err(TooLong)),
        ("  alice  ".to_string(), Ok(())),
        ("User_Name-123".to_string(), Ok(())),
        ("user@name".to_string(), Err(InvalidCharacters)),
        ("user name".to_string(), Err(InvalidCharacters)),
        ("user.name".to_string(), Err(InvalidCharacters)),
        ("user!name".to_string(), Err(InvalidCharacters)),
    ] {
        assert_eq!(validate_username(&username), expected, "{username:?}");
    }
}

#[tokio::test]
async fn admin_bootstrap_is_idempotent_and_requires_password_change() -> anyhow::Result<()> {
    let pool = test_pool().await;
    ensure_default_admin(&pool).await?;
    ensure_default_admin(&pool).await?;
    let users = list_all(&pool).await?;
    assert_eq!(users.len(), 1);
    let admin = &users[0];
    assert_eq!(admin.username, "admin");
    assert!(admin.is_admin);
    assert!(admin.must_change_password);

    change_password(&pool, admin.id, "chosen-password").await?;
    let authenticated = authenticate(&pool, "admin", "chosen-password")
        .await?
        .expect("admin login");
    assert!(!authenticated.must_change_password);
    Ok(())
}

#[tokio::test]
async fn authentication_password_changes_and_deletion_follow_account_lifecycle()
-> anyhow::Result<()> {
    let pool = test_pool().await;
    let id = create(&pool, "alice", "old", false).await?;
    let other_id = create(&pool, "other", "old", true).await?;
    let stored = find(&pool, id).await?.expect("created user");
    assert!(!stored.is_admin);
    assert!(!stored.must_change_password);
    assert!(find(&pool, other_id).await?.expect("admin user").is_admin);
    assert_ne!(
        stored.password_hash,
        find(&pool, other_id).await?.expect("other").password_hash
    );
    assert_eq!(list_all(&pool).await?.len(), 2);

    for (username, password, accepted) in [
        ("alice", "old", true),
        ("alice", "wrong", false),
        ("missing", "old", false),
    ] {
        assert_eq!(
            authenticate(&pool, username, password).await?.is_some(),
            accepted,
            "{username}"
        );
    }
    assert!(
        find(&pool, id)
            .await?
            .expect("user")
            .last_login_at
            .is_some()
    );
    assert!(verify_password_for_user(&pool, id, "old").await?);
    assert!(!verify_password_for_user(&pool, id, "wrong").await?);
    assert!(!verify_password_for_user(&pool, i64::MAX, "old").await?);

    change_password(&pool, id, "new").await?;
    assert!(authenticate(&pool, "alice", "old").await?.is_none());
    assert_eq!(
        authenticate(&pool, "alice", "new")
            .await?
            .expect("new password")
            .id,
        id
    );

    // Corrupted credentials must fail closed, not panic or authenticate.
    sqlx::query("UPDATE users SET password_hash = 'not-a-valid-hash' WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await?;
    assert!(authenticate(&pool, "alice", "new").await?.is_none());

    delete(&pool, id).await?;
    assert!(find(&pool, id).await?.is_none());
    assert!(authenticate(&pool, "alice", "new").await?.is_none());
    assert_eq!(list_all(&pool).await?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn sessions_expire_and_logout_revokes_only_the_selected_token() -> anyhow::Result<()> {
    let pool = test_pool().await;
    let id = create(&pool, "alice", "secret", false).await?;
    let active = create_session(&pool, id).await?;
    let expired = create_session(&pool, id).await?;
    assert_ne!(active, expired);
    sqlx::query("UPDATE sessions SET expires_at = $1 WHERE token = $2")
        .bind(crate::time::days_ago(1))
        .bind(&expired)
        .execute(&pool)
        .await?;

    assert!(get_user_from_session(&pool, &expired).await?.is_none());
    assert!(get_user_from_session(&pool, "unknown").await?.is_none());
    assert_eq!(delete_expired_sessions(&pool).await?, 1);
    assert_eq!(
        get_user_from_session(&pool, &active)
            .await?
            .expect("active session")
            .id,
        id
    );
    delete_session(&pool, &active).await?;
    assert!(get_user_from_session(&pool, &active).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn invites_activate_once_and_cleanup_preserves_active_accounts() -> anyhow::Result<()> {
    let pool = test_pool().await;
    let token = create_with_invite(&pool, "invited", false).await?;
    let invited = find_by_invite_token(&pool, &token)
        .await?
        .expect("valid invite");
    assert!(invited.password_hash.is_none());
    assert!(authenticate(&pool, "invited", "new").await?.is_none());
    accept_invite(&pool, invited.id, "new").await?;
    let activated = authenticate(&pool, "invited", "new")
        .await?
        .expect("activated account");
    assert_eq!(activated.id, invited.id);
    assert!(activated.invite_token.is_none());
    assert!(activated.invite_expires_at.is_none());
    assert!(find_by_invite_token(&pool, &token).await?.is_none());

    let expired = create_with_invite(&pool, "expired", false).await?;
    let valid = create_with_invite(&pool, "valid", false).await?;
    sqlx::query("UPDATE users SET invite_expires_at = $1 WHERE invite_token = $2")
        .bind(crate::time::days_ago(1))
        .bind(&expired)
        .execute(&pool)
        .await?;
    assert!(find_by_invite_token(&pool, &expired).await?.is_none());
    assert_eq!(delete_expired_invites(&pool).await?, 1);
    assert_eq!(
        find_by_invite_token(&pool, &valid)
            .await?
            .expect("valid invite survives")
            .username,
        "valid"
    );
    assert!(authenticate(&pool, "invited", "new").await?.is_some());
    assert_eq!(list_all(&pool).await?.len(), 2);
    Ok(())
}
