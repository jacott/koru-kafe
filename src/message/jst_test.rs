use std::time::SystemTime;

use bytes::BytesMut;
use pretty_assertions::assert_matches;
use serde_json::json;
use tokio_postgres::types::ToSql;

use super::*;

#[test]
fn from_sql() {
    fn int_check<T: ToSql>(n: T, t: &PgType) {
        let mut buf = BytesMut::new();
        let _ = n.to_sql(t, &mut buf);
        assert_matches!(FromSql::from_sql(t, &buf), Ok(Jst::Int(123)));
    }

    int_check(123i16, &PgType::INT2);
    int_check(123i32, &PgType::INT4);
    int_check(123i64, &PgType::INT8);

    let mut buf = BytesMut::new();
    let t = SystemTime::now();
    let _ = t.to_sql(&PgType::TIMESTAMP, &mut buf);
    assert_matches!(
        FromSql::from_sql(&PgType::TIMESTAMP, &buf),
        Ok(Jst::Date(v)) if v.as_millis() == t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis()
    );

    assert_matches!(FromSql::from_sql(&PgType::TEXT, b"abc123"),
                     Ok(Jst::String(v)) if v.as_ref() == b"abc123");

    let j = json!({"abc": 123});
    let mut buf = BytesMut::new();
    let _ = j.to_sql(&PgType::JSONB, &mut buf);
    assert_eq!(JsonValue::from_sql(&PgType::JSONB, &buf).unwrap(), j);

    assert_matches!(FromSql::from_sql(&PgType::BYTEA, b"abc123"),
                     Ok(Jst::Uint8Array(v)) if v.as_ref() == b"abc123");
}
