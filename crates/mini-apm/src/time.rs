//! UTC timestamps as stored in the database

use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};
use std::fmt;

#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "sqlite")]
mod sqlite;

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

/// The instant `hours` hours ago
pub fn hours_ago(hours: i64) -> Stamp {
    Stamp(Timestamp::now() - SignedDuration::from_hours(hours))
}

/// The instant `days` 24-hour days ago
pub fn days_ago(days: i64) -> Stamp {
    hours_ago(days * 24)
}
