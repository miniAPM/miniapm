use super::Stamp;
use jiff::Timestamp;
use jiff::fmt::temporal::DateTimePrinter;
use jiff::tz::Offset;
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use sqlx::sqlite::{SqliteTypeInfo, SqliteValueRef};
use sqlx::{Database, Decode, Encode, Sqlite, Type};

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

impl Type<Sqlite> for Stamp {
    fn type_info() -> SqliteTypeInfo {
        <str as Type<Sqlite>>::type_info()
    }

    fn compatible(ty: &SqliteTypeInfo) -> bool {
        <str as Type<Sqlite>>::compatible(ty)
    }
}

impl Encode<'_, Sqlite> for Stamp {
    fn encode_by_ref(
        &self,
        buf: &mut <Sqlite as Database>::ArgumentBuffer,
    ) -> Result<IsNull, BoxDynError> {
        Encode::<Sqlite>::encode(rfc3339(self.0), buf)
    }
}

impl<'r> Decode<'r, Sqlite> for Stamp {
    fn decode(value: SqliteValueRef<'r>) -> Result<Self, BoxDynError> {
        Ok(Self(<&str as Decode<Sqlite>>::decode(value)?.parse()?))
    }
}

#[cfg(all(test, not(feature = "postgres")))]
mod tests;
