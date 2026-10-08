use super::{Stamp, rfc3339};
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use sqlx::sqlite::{SqliteTypeInfo, SqliteValueRef};
use sqlx::{Database, Decode, Encode, Sqlite, Type};

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
