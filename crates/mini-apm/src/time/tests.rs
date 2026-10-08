use super::*;

#[tokio::test]
async fn stamps_write_the_stored_layout_and_read_both_offset_suffixes() -> anyhow::Result<()> {
    let pool = crate::db::test_pool().await;
    for (nanos, stored) in [
        (0, "2026-09-26T11:13:48+00:00"),
        (500_000_000, "2026-09-26T11:13:48.500+00:00"),
        (123_456_000, "2026-09-26T11:13:48.123456+00:00"),
        (123_456_789, "2026-09-26T11:13:48.123456789+00:00"),
    ] {
        let stamp = Stamp(Timestamp::new(1_790_421_228, nanos)?);
        let written: String = sqlx::query_scalar("SELECT $1")
            .bind(stamp)
            .fetch_one(&pool)
            .await?;
        assert_eq!(written, stored);
        for text in [stored, &stamp.0.to_string()] {
            let read: Stamp = sqlx::query_scalar("SELECT $1")
                .bind(text)
                .fetch_one(&pool)
                .await?;
            assert_eq!(read, stamp, "{text}");
        }
        assert_eq!(stamp.to_string(), "2026-09-26 11:13");
    }
    Ok(())
}
