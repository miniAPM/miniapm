use super::*;

fn header<'r>(res: &'r Response, name: &str) -> Option<&'r str> {
    res.headers().get(name).and_then(|v| v.to_str().ok())
}

#[tokio::test]
async fn sign_in_sets_a_session_cookie_and_redirects() -> anyhow::Result<()> {
    let pool = mini_apm::db::test_pool().await;
    models::user::create(&pool, "alice", "correct-horse", false).await?;
    let bob = models::user::create(&pool, "bob", "correct-horse", false).await?;
    sqlx::query("UPDATE users SET must_change_password = TRUE WHERE id = $1")
        .bind(bob)
        .execute(&pool)
        .await?;

    for (username, password, location) in [
        ("alice", "correct-horse", Some("/")),
        ("bob", "correct-horse", Some("/auth/change-password")),
        ("alice", "wrong", None),
    ] {
        let form = LoginForm {
            username: username.into(),
            password: password.into(),
        };
        let res = login_submit(State(pool.clone()), Form(form)).await;
        let expected = if location.is_some() {
            StatusCode::SEE_OTHER
        } else {
            StatusCode::OK
        };
        assert_eq!(res.status(), expected, "{username}/{password}");
        assert_eq!(header(&res, "location"), location, "{username}/{password}");
        assert_eq!(
            header(&res, "set-cookie").is_some_and(|c| c.starts_with("miniapm_session=")),
            location.is_some(),
            "{username}/{password}"
        );
    }

    let token = models::user::create_with_invite(&pool, "carol", false).await?;
    let form = InviteForm {
        password: "correct-horse".into(),
        confirm_password: "correct-horse".into(),
    };
    let res = invite_submit(State(pool.clone()), Path(token), Form(form)).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(header(&res, "location"), Some("/"));
    assert!(header(&res, "set-cookie").is_some_and(|c| c.starts_with("miniapm_session=")));
    Ok(())
}
