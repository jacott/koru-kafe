use super::*;

#[test]
fn from_v1() {
    let id = Id::from("v1id");
    let n = 1072180072u128;
    assert_eq!(id.to_string().as_str(), "v1id");
    assert_eq!(format!("{id:?}").as_str(), r#"Id("v1id")"#);
    assert_eq!(id, n.into());
    let uuid: Uuidv7 = n.into();
    assert_eq!(uuid.to_string().as_str(), "----------------EzVgP-");

    let id1 = Id::from("zzz12345671234561");
    let id2 = Id::from("zzz12345671234568");
    assert!(id1 < id2);
    assert!(id < id1);
    assert_eq!(id1, 324438049489177981257820891537858u128.into());
    assert_eq!(id2, 324438049489177981257820891537865u128.into());
    assert_eq!(id2.to_string().as_str(), "zzz12345671234568");
    assert_eq!(id1.to_string().as_str(), "zzz12345671234561");
}

#[test]
fn to_string() {
    let z18 = "zzzzzzzzzzzzzzzzzz";
    let id = Id::from(z18);
    assert_eq!(id.to_string().as_str(), z18);

    let id2: Id = (id.as_u128() + 1).into();

    assert_eq!(id2.to_string().as_str(), "zzzzzzzzzzzzzzzzz~");
}

#[test]
fn shortid() {
    let assert_to_string = |s: &str| assert_eq!(Id::from(s).to_string().as_str(), s);

    assert_to_string("~~~~~~~~~~~~~~~~~~");
    assert_to_string("~~~~~~~~~~~~~~~~~");
    assert_to_string("-----------------");
    assert_to_string("admingj");
    assert_to_string("----------admingj");
    assert_to_string("-----------admingj");
    assert_to_string("~~~~~~~~~~~~~~~~");
}
