use super::*;

#[test]
fn test_rfc3339_matches_stored_layout() {
    for (nanos, expected) in [
        (0, "2026-09-26T11:13:48+00:00"),
        (500_000_000, "2026-09-26T11:13:48.500+00:00"),
        (123_456_000, "2026-09-26T11:13:48.123456+00:00"),
        (123_456_789, "2026-09-26T11:13:48.123456789+00:00"),
    ] {
        let ts = Timestamp::new(1_790_421_228, nanos).unwrap();
        assert_eq!(rfc3339(ts), expected);
    }
}
