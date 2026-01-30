use chrono::{TimeZone, Utc};
use std::time::{Duration, UNIX_EPOCH};

use super::*;

#[test]
fn to_from() {
    let id = Uuidv7::time_and_rand(UNIX_EPOCH + Duration::from_nanos(300), 0u128);
    assert_eq!(id.to_string(), "--------R-5-----------");

    let dt = Utc.with_ymd_and_hms(2025, 6, 3, 1, 2, 3).unwrap();
    let nanos = (0.1234567 * 1_000_000.0) as u32;
    let st: SystemTime = (dt + chrono::Duration::nanoseconds(nanos as i64)).into();
    let id = Uuidv7::time_and_rand(st, 1234567890u128);
    let s = "-ORoIpQtRUf-----HON1pV";
    assert_eq!(id.to_string(), s);

    let id = Uuidv7::from(5 + (6 << 64));
    let s = "----------N---------0F";
    assert_eq!(id.to_string(), s);

    let id2 = Uuidv7::from(s);
    assert_eq!(id, id2);

    let id = Uuidv7::from(12345679012345678901234567890123456789);
    let s = "1Jblz4R69-ZA-ERwAYb04F";
    assert_eq!(id.to_string(), s);

    let id2 = Uuidv7::from(s);
    assert_eq!(id, id2);
}

#[test]
fn random() {
    let id1 = Uuidv7::random();
    let id2 = Uuidv7::random();
    assert!(id1 <= id2);
    assert!(id1 <= id2);
    let s = id1.to_string();
    assert_eq!(id1, Uuidv7::from(s.as_str()));
}
