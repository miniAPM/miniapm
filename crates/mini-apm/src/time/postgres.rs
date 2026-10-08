use super::Stamp;
use jiff_sqlx::ToSqlx;
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use sqlx::postgres::{PgTypeInfo, PgValueRef};
use sqlx::{Database, Decode, Encode, Postgres, Type};

impl Type<Postgres> for Stamp {
    fn type_info() -> PgTypeInfo {
        <jiff_sqlx::Timestamp as Type<Postgres>>::type_info()
    }
}

impl Encode<'_, Postgres> for Stamp {
    fn encode_by_ref(
        &self,
        buf: &mut <Postgres as Database>::ArgumentBuffer,
    ) -> Result<IsNull, BoxDynError> {
        Encode::<Postgres>::encode(self.0.to_sqlx(), buf)
    }
}

impl<'r> Decode<'r, Postgres> for Stamp {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        Ok(Self(
            <jiff_sqlx::Timestamp as Decode<Postgres>>::decode(value)?.to_jiff(),
        ))
    }
}
