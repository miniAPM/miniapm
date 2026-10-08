//! UTC timestamps as stored in the database

use jiff::fmt::temporal::DateTimePrinter;
use jiff::tz::Offset;
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};
use std::fmt;

#[cfg(feature = "sqlite")]
mod sqlite;
#[cfg(test)]
mod tests;

/// An instant read from or bound to a timestamp column, displayed as
/// `YYYY-MM-DD HH:MM` UTC
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Stamp(pub Timestamp);

impl Stamp {
    pub fn now() -> Self {
        Self(Timestamp::now())
    }
}

impl From<Timestamp> for Stamp {
    fn from(ts: Timestamp) -> Self {
        Self(ts)
    }
}

impl fmt::Display for Stamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.strftime("%Y-%m-%d %H:%M"))
    }
}

/// RFC 3339 with a `+00:00` offset and 0, 3, 6 or 9 fraction digits. This is
/// the layout of existing rows, so SQL string comparisons against them stay
/// chronological.
fn rfc3339(ts: Timestamp) -> String {
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

/// The instant `hours` hours ago
pub fn hours_ago(hours: i64) -> Stamp {
    Stamp(Timestamp::now() - SignedDuration::from_hours(hours))
}

/// The instant `days` 24-hour days ago
pub fn days_ago(days: i64) -> Stamp {
    hours_ago(days * 24)
}
