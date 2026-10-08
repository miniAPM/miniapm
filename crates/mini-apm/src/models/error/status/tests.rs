use super::*;
use ErrorStatusEvent::*;

#[test]
fn test_transitions() {
    for (status, event, expected) in [
        ("open", Resolve, Some("resolved")),
        ("open", Ignore, Some("ignored")),
        ("open", Reopen, None),
        ("open", Recur, None),
        ("resolved", Reopen, Some("open")),
        ("resolved", Ignore, Some("ignored")),
        ("resolved", Resolve, None),
        ("resolved", Recur, Some("open")),
        ("ignored", Resolve, Some("resolved")),
        ("ignored", Reopen, Some("open")),
        ("ignored", Recur, None),
        ("bogus", Resolve, None),
    ] {
        let label = format!("{status} {event:?}");
        assert_eq!(transition(status, event), expected, "{label}");
    }
    assert_eq!(
        recur_transitions().collect::<Vec<_>>(),
        [("resolved", "open")]
    );
}
