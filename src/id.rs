use std::{
    fmt::{Debug, Display},
    hash::Hash,
};

use tokio_postgres::types::{FromSql, Type as PgType};

use crate::uuidv7::{CHARS, Uuidv7, char_to_u6};

pub fn pack_v1id(bytes: &[u8]) -> u128 {
    let mut res = 63u128;
    for b in bytes {
        res = (res << 6) | char_to_u6(*b) as u128;
    }
    res
}

pub fn unpack_v1id(val: u128) -> String {
    const TERM: usize = 63;
    let mut id = String::new();

    let mut shift = 16 * 6;
    let mut code = 0;

    while shift != 0 && code == 0 {
        code = (val >> shift) as usize & TERM;

        if code != 0 {
            if code != TERM {
                id.push(CHARS[code] as char);
            }
            break;
        }
        shift -= 6;
    }

    while shift != 0 {
        shift -= 6;
        code = (val >> shift) as usize & 63;
        if code == TERM {
            return id;
        }
        id.push(CHARS[code] as char);
    }

    id
}

const OLD_MAX_TIME: u128 = 324438067906031283646553055293375;

#[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id(Uuidv7);
impl Id {
    pub fn as_u128(&self) -> u128 {
        self.0.as_u128()
    }

    pub fn is_empty(&self) -> bool {
        self.0.as_u128() == 0
    }
}
impl<'a> FromSql<'a> for Id {
    fn from_sql(
        ty: &PgType,
        raw: &'a [u8],
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        match ty {
            &PgType::TEXT => Ok(String::from_sql(ty, raw)?.as_str().into()),
            // &PgType::UUID => {
            //     let bytes = types::uuid_from_sql(raw)?;
            //     Ok((<u128 as FromSql>::from_sql(ty, raw)? as u128).into())
            // }
            _ => panic!("Called with incorrect pg type"),
        }
    }

    fn accepts(ty: &PgType) -> bool {
        matches!(
            ty,
            &PgType::TEXT // | &PgType::UUID
        )
    }
}
impl Debug for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Id").field(&self.to_string()).finish()
    }
}
impl Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n: u128 = self.0.into();
        let s = if n < OLD_MAX_TIME { unpack_v1id(n) } else { self.0.to_string() };
        f.write_str(&s)
    }
}
impl From<&str> for Id {
    fn from(value: &str) -> Self {
        Self(if value.len() <= 17 {
            pack_v1id(value.as_bytes()).into()
        } else {
            Uuidv7::from(value)
        })
    }
}
impl From<&[u8]> for Id {
    fn from(value: &[u8]) -> Self {
        Self(if value.len() <= 17 { pack_v1id(value).into() } else { Uuidv7::from(value) })
    }
}
impl<'a> From<&'a Id> for String {
    fn from(value: &'a Id) -> Self {
        value.to_string()
    }
}
impl From<Id> for u128 {
    fn from(value: Id) -> Self {
        value.0.into()
    }
}
impl From<u128> for Id {
    fn from(value: u128) -> Self {
        Self(value.into())
    }
}

#[cfg(test)]
#[path = "id_test.rs"]
mod test;
