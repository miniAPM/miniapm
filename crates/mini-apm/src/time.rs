//! UTC timestamps as stored in SQLite TEXT columns

use jiff::fmt::temporal::DateTimePrinter;
use jiff::tz::Offset;
use jiff::{SignedDuration, Timestamp};

#[cfg(test)]
mod tests;

/// RFC 3339 with a `+00:00` offset and 0, 3, 6 or 9 fraction digits. This is
/// the layout of existing rows, so SQL string comparisons against them stay
/// chronological.
pub fn rfc3339(ts: Timestamp) -> String {
    let precision = match ts.subsec_nanosecond() {
        0 => 0,
        n if n % 1_000_000 == 0 => 3,
        n if n % 1_000 == 0 => 6,
        _ => 9,
    };
    DateTimePrinter::new()
        .precision(Some(precision))
        .timestamp_with_offset_to_string(&ts, Offset::UTC)
}

/// The current time, formatted by [`rfc3339`]
pub fn now_rfc3339() -> String {
    rfc3339(Timestamp::now())
}

/// The instant `hours` hours ago
pub fn hours_ago(hours: i64) -> Timestamp {
    Timestamp::now() - SignedDuration::from_hours(hours)
}

/// The instant `days` 24-hour days ago
pub fn days_ago(days: i64) -> Timestamp {
    hours_ago(days * 24)
}
