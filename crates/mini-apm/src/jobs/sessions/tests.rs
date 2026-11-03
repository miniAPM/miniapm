use super::*;

#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "sqlite")]
mod sqlite;

#[test]
fn only_confirmed_statement_failures_are_retryable() {
    for error in [
        sqlx::Error::PoolTimedOut,
        sqlx::Error::PoolClosed,
        sqlx::Error::RowNotFound,
        sqlx::Error::Io(std::io::Error::other("connection lost")),
        sqlx::Error::Protocol("unknown result".into()),
    ] {
        assert!(!retryable(&error), "{error}");
    }
    #[cfg(feature = "postgres")]
    let cases = [
        ("40001", true),
        ("40P01", true),
        ("55P03", true),
        ("23505", false),
        ("42501", false),
        ("57014", false),
        ("08006", false),
        ("57P01", false),
        ("", false),
    ];
    #[cfg(feature = "sqlite")]
    let cases = [
        ("5", true),
        ("261", true),
        ("517", true),
        ("773", true),
        ("6", false),
        ("19", false),
        ("1811", false),
        ("1", false),
        ("garbage", false),
        ("", false),
    ];
    for (code, expected) in cases {
        assert_eq!(retryable_code(code), expected, "{code}");
    }
}

async fn seed(pool: &DbPool) -> anyhow::Result<Stamp> {
    let cutoff = Stamp::now();
    let user = models::user::create(pool, "cleanup", "secret", false).await?;
    for (token, seconds) in [("expired", -1), ("boundary", 0), ("active", 86_400)] {
        sqlx::query(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(token)
        .bind(user)
        .bind(cutoff)
        .bind(Stamp(cutoff.0 + jiff::SignedDuration::from_secs(seconds)))
        .execute(pool)
        .await?;
    }
    Ok(cutoff)
}

async fn tokens(pool: &DbPool) -> sqlx::Result<Vec<String>> {
    sqlx::query_scalar("SELECT token FROM sessions ORDER BY token")
        .fetch_all(pool)
        .await
}
