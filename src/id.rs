use std::{
    fmt::{Debug, Display, Write},
    hash::Hash,
};

use tokio_postgres::types::{FromSql, Type as PgType};

use crate::uuidv7::{CHARS, Uuidv7, char_to_u6};

fn pack_v1id(bytes: &[u8]) -> u128 {
    let mut res = 63u128;
    for b in bytes {
        res = (res << 6) | char_to_u6(*b) as u128;
    }
    res
}

const OLD_MAX_TIME: u128 = 0x4000000000000 << 64;
const FULL_ID: u128 = 319447951257513809177169207754752;
const EXTENDED_ID: u128 = 324518553658426726783156020576256;

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

        if n < OLD_MAX_TIME {
            if n < FULL_ID {
                return v1_decode(f, n);
            } else {
                return base64_decode(f, n, if n >= EXTENDED_ID { 18 } else { 17 });
            }
        } else {
            return Uuidv7::write_str(f, n);
        }
    }
}

fn v1_decode(f: &mut std::fmt::Formatter<'_>, val: u128) -> Result<(), std::fmt::Error> {
    const TERM: usize = 63;

    let mut shift = 17 * 6;

    while shift != 0 {
        shift -= 6;
        let code = (val >> shift) as usize & TERM;

        if code != 0 {
            if code != TERM {
                f.write_char(CHARS[code] as char)?;
            }
            break;
        }
    }

    while shift != 0 {
        shift -= 6;
        f.write_char(CHARS[(val >> shift) as usize & TERM] as char)?;
    }

    Ok(())
}

fn base64_decode(
    f: &mut std::fmt::Formatter<'_>,
    val: u128,
    len: usize,
) -> Result<(), std::fmt::Error> {
    const TERM: usize = 63;

    let mut shift = (len) * 6;

    while shift != 0 {
        shift -= 6;
        f.write_char(CHARS[(val >> shift) as usize & TERM] as char)?;
    }

    Ok(())
}

impl From<&str> for Id {
    fn from(value: &str) -> Self {
        Self(if value.len() <= 18 {
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
