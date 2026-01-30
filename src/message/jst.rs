use std::time::{Duration, SystemTime};

use bytes::Bytes;
use tokio_postgres::types::{to_sql_checked, FromSql, ToSql, Type as PgType};

pub type JsonValue = serde_json::Value;

#[derive(Default, Clone, PartialEq, Debug)]
pub struct Array(Vec<Jst>);
impl Array {
    pub fn push(&mut self, value: Jst) {
        self.0.push(value);
    }
    pub fn get<T: TryFrom<Jst>>(&self, i: usize) -> Option<T> {
        self.0.get(i)?.clone().try_into().ok()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Jst> {
        self.0.iter()
    }
}
impl TryFrom<Jst> for Array {
    type Error = Error;

    fn try_from(value: Jst) -> Result<Self, Self::Error> {
        match value {
            Jst::NestedArray(v) => Ok(v),
            _ => Err(Error::UnexpectedMessageType),
        }
    }
}

#[derive(Default, Clone, PartialEq, Debug)]
pub struct Object(linked_hash_map::LinkedHashMap<Bytes, Jst>);
impl Object {
    pub fn get<T: TryFrom<Jst>>(&self, key: impl Into<Bytes>) -> Option<T> {
        let key = key.into();
        self.0.get(&key)?.clone().try_into().ok()
    }

    pub fn get_jst(&self, key: impl Into<Bytes>) -> Option<&Jst> {
        let key = key.into();
        self.0.get(&key)
    }

    pub fn insert(&mut self, key: Bytes, value: Jst) {
        self.0.insert(key, value);
    }

    pub fn iter(&self) -> linked_hash_map::Iter<'_, Bytes, Jst> {
        self.0.iter()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Error {
    MissingDictionaryString,
    MessageTooSmall,
    InvalidUtf8String,
    CorruptMessage,
    MessageStringTerminator,
    UnexpectedMessageType,
    ExpectedObject,
    UnexpectedValue,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Clone, PartialEq, Debug)]
pub enum Jst {
    Undefined,
    Null,
    True,
    False,
    String(Bytes),
    Array,
    Object,
    NullObject,
    Key(Bytes),
    Int(i64),
    Float(f64),
    Date(Duration),
    Uint8Array(Bytes),
    SparseIndex(usize),
    Error(Error),
    Json(JsonValue),
    EndObject,
    NestedObject(Object),
    NestedArray(Array),
}
impl Jst {
    pub fn key<V: Into<Bytes>>(arg: V) -> Jst {
        Jst::Key(arg.into())
    }

    pub fn string<V: Into<Bytes>>(arg: V) -> Jst {
        Jst::String(arg.into())
    }

    pub fn bin<V: Into<Bytes>>(arg: V) -> Jst {
        Jst::Uint8Array(arg.into())
    }

    pub fn is_err(&self) -> bool {
        matches!(self, Jst::Error(_))
    }
}
impl ToSql for Jst {
    fn to_sql(
        &self,
        ty: &PgType,
        out: &mut bytes::BytesMut,
    ) -> Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + Sync + Send>>
    where
        Self: Sized,
    {
        let v = JsonValue::try_from(self.to_owned());
        v.unwrap().to_sql(ty, out)
    }

    fn accepts(_ty: &PgType) -> bool
    where
        Self: Sized,
    {
        true
    }

    to_sql_checked!();
}
impl<'a> FromSql<'a> for Jst {
    fn from_sql(
        ty: &PgType,
        raw: &'a [u8],
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        match *ty {
            PgType::INT2 => Ok(Jst::Int(<i16 as FromSql>::from_sql(ty, raw)? as i64)),
            PgType::INT4 => Ok(Jst::Int(<i32 as FromSql>::from_sql(ty, raw)? as i64)),
            PgType::INT8 => Ok(Jst::Int(FromSql::from_sql(ty, raw)?)),
            PgType::OID => Ok(Jst::Int(<u32 as FromSql>::from_sql(ty, raw)? as i64)),
            PgType::BOOL => Ok(if FromSql::from_sql(ty, raw)? {
                Jst::True
            } else {
                Jst::False
            }),
            PgType::TEXT => Ok(Jst::String(Bytes::from_owner(raw.to_owned()))),
            PgType::JSON | PgType::JSONB => Ok(Jst::Json(serde_json::Value::from_sql(ty, raw)?)),
            PgType::CHAR | PgType::VARCHAR | PgType::TIMESTAMP => Ok(Jst::Date(
                <SystemTime as FromSql>::from_sql(ty, raw)?
                    .duration_since(SystemTime::UNIX_EPOCH)?,
            )),

            _ => Ok(Jst::Uint8Array(Bytes::copy_from_slice(raw))),
        }
    }

    fn accepts(_ty: &tokio_postgres::types::Type) -> bool {
        true
    }
}
impl From<i64> for Jst {
    fn from(value: i64) -> Self {
        Jst::Int(value)
    }
}
impl TryFrom<Jst> for i64 {
    type Error = Error;

    fn try_from(value: Jst) -> Result<Self, Self::Error> {
        if let Jst::Int(value) = value {
            Ok(value)
        } else {
            Err(Error::UnexpectedMessageType)
        }
    }
}
impl From<&str> for Jst {
    fn from(value: &str) -> Self {
        Jst::String(value.to_owned().into())
    }
}
impl TryFrom<Jst> for Bytes {
    type Error = Error;

    fn try_from(value: Jst) -> Result<Self, Self::Error> {
        match value {
            Jst::String(bytes) | Jst::Uint8Array(bytes) => Ok(bytes),
            _ => Err(Error::UnexpectedMessageType),
        }
    }
}
impl From<JsonValue> for Jst {
    fn from(value: JsonValue) -> Self {
        Self::from(&value)
    }
}
impl From<&JsonValue> for Jst {
    fn from(value: &JsonValue) -> Self {
        match value {
            JsonValue::Null => Jst::Null,
            JsonValue::Bool(v) => {
                if *v {
                    Jst::True
                } else {
                    Jst::False
                }
            }
            JsonValue::Number(number) => {
                if number.is_i64() {
                    Jst::Int(number.as_i64().unwrap())
                } else if number.is_u64() {
                    let x = number.as_u64().unwrap();
                    let n32 = x as u32;
                    if n32 as u64 == x {
                        Jst::Int(n32 as i64)
                    } else {
                        Jst::Float(x as f64)
                    }
                } else {
                    Jst::Float(number.as_f64().unwrap_or(0.0))
                }
            }
            JsonValue::String(s) => Jst::String(Bytes::copy_from_slice(s.as_bytes())),
            JsonValue::Array(a) => json_array_to_nested_jst(a),
            JsonValue::Object(o) => json_object_to_nested_jst(o),
        }
    }
}

impl TryFrom<Jst> for JsonValue {
    type Error = Error;

    fn try_from(value: Jst) -> Result<Self, Self::Error> {
        Ok(match value {
            Jst::Null | Jst::Undefined => JsonValue::Null,
            Jst::True => JsonValue::Bool(true),
            Jst::False => JsonValue::Bool(false),
            Jst::String(bytes) => JsonValue::String(
                str::from_utf8(bytes.as_ref())
                    .map_err(|_| Error::InvalidUtf8String)?
                    .to_owned(),
            ),
            Jst::Int(v) => JsonValue::Number(serde_json::Number::from(v)),
            Jst::Float(v) => {
                JsonValue::Number(serde_json::Number::from_f64(v).ok_or(Error::CorruptMessage)?)
            }
            Jst::Date(duration) => JsonValue::String(format!("{}ms", duration.as_millis())),
            Jst::Json(value) => value,
            Jst::NestedObject(v) => JsonValue::try_from(v)?,
            Jst::NestedArray(v) => JsonValue::try_from(v)?,
            _ => return Err(Error::UnexpectedMessageType),
        })
    }
}
impl TryFrom<Jst> for String {
    type Error = Error;

    fn try_from(value: Jst) -> Result<Self, Self::Error> {
        match value {
            Jst::String(bytes) => Ok(String::from_utf8_lossy(bytes.as_ref()).to_string()),
            _ => Err(Error::UnexpectedMessageType),
        }
    }
}
impl TryFrom<Jst> for Duration {
    type Error = Error;

    fn try_from(value: Jst) -> Result<Self, Self::Error> {
        match value {
            Jst::Date(duration) => Ok(duration),
            _ => Err(Error::UnexpectedMessageType),
        }
    }
}
impl TryFrom<Jst> for Object {
    type Error = Error;

    fn try_from(value: Jst) -> Result<Self, Self::Error> {
        match value {
            Jst::NestedObject(v) => Ok(v),
            _ => Err(Error::UnexpectedMessageType),
        }
    }
}
impl TryFrom<JsonValue> for Object {
    type Error = Error;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}
impl TryFrom<&JsonValue> for Object {
    type Error = Error;

    fn try_from(value: &JsonValue) -> Result<Self, Self::Error> {
        match value {
            JsonValue::Object(m) => {
                let mut o = Self::default();
                for (k, v) in m {
                    let k = Bytes::copy_from_slice(k.as_bytes());
                    o.insert(k, v.into());
                }
                Ok(o)
            }
            _ => Err(Error::UnexpectedMessageType),
        }
    }
}
impl TryFrom<Object> for JsonValue {
    type Error = Error;

    fn try_from(value: Object) -> Result<Self, Self::Error> {
        let mut o: serde_json::Map<String, JsonValue> = Default::default();
        for (k, v) in value.iter() {
            let k = str::from_utf8(k.as_ref())
                .map_err(|_| Error::InvalidUtf8String)?
                .to_owned();
            o.insert(k, v.clone().try_into()?);
        }
        Ok(JsonValue::Object(o))
    }
}
impl TryFrom<Array> for JsonValue {
    type Error = Error;

    fn try_from(value: Array) -> Result<Self, Self::Error> {
        let mut o: Vec<JsonValue> = Default::default();
        for v in value.iter() {
            o.push(v.clone().try_into()?);
        }
        Ok(JsonValue::Array(o))
    }
}

fn json_array_to_nested_jst(array: &[JsonValue]) -> Jst {
    Jst::NestedArray(Array(array.iter().map(|v| v.into()).collect()))
}

fn json_object_to_nested_jst(map: &serde_json::Map<String, JsonValue>) -> Jst {
    let mut o = Object::default();
    for (k, v) in map.iter() {
        let k = Bytes::copy_from_slice(k.as_bytes());
        o.insert(k, v.into());
    }
    Jst::NestedObject(o)
}

#[cfg(test)]
#[path = "jst_test.rs"]
mod test;
