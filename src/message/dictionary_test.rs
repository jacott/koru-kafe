#[cfg(test)]
use super::*;

#[test]
fn dict_add() {
    let gde = GlobalDictEncoder::default();
    let mut dict = LocalDictEncoder::new(&gde);
    assert_eq!(dict.add("foo".into()), Ok(0x100));
    assert_eq!(dict.add("foo".into()), Ok(0x100));

    assert_eq!(dict.add("bar".into()), Ok(0x101));

    dict.upper_limit = 3;

    assert_eq!(dict.add("zar".into()), Ok(0x102));
    assert_eq!(
        dict.add("car".into()),
        Err("Too many entries in LocalDictionary")
    );
}

#[test]
fn encode_global_dict() {
    let mut dict = GlobalDictEncoder::default();

    dict.add("foo").unwrap();
    dict.add("bár\0").unwrap();

    let gd = dict.encode();
    let mut enc = BytesMut::new();
    enc.put_u8(8);
    gd.global_as_bytes(&mut enc);

    assert_eq!(dict.get_id("foo".as_bytes()), Some(0xfffd));
    assert_eq!(dict.get_id("bár\0".as_bytes()), Some(0xfffe));

    let exp = Bytes::from_static(&[8, 102, 111, 111, 0xff, 98, 195, 161, 114, 0, 0xff, 0]);
    assert_eq!(&enc, &exp);

    assert_eq!(gd.get_word(0xfffe).unwrap(), "bár\0".as_bytes());

    let mut dict = GlobalDictDecoder::default();

    {
        let mut rem = dict.decode(exp.clone().slice(1..)).unwrap();

        let rem = rem.copy_to_bytes(rem.remaining());
        assert_eq!(rem, exp.slice(12..));
    }
    assert_eq!(dict.get_word(0xfffe).unwrap(), "bár\0".as_bytes());

    let ld = LocalDictDecoder::new(&dict);

    assert_eq!(ld.get_word(0xfffe).unwrap(), "bár\0".as_bytes());
    assert_eq!(ld.get_word(0xfffd).unwrap(), "foo".as_bytes());
}

#[test]
fn global_dict_from_data() {
    let data = &[
        0x24, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0xff, 0x24, 0x6d, 0x61, 0x74, 0x63, 0x68, 0xff,
        0x47, 0x61, 0x6d, 0x65, 0xff, 0x50, 0x6c, 0x61, 0x79, 0xff, 0x00,
    ];
    let dict = GlobalDictDecoder::new(data);
    assert_eq!(
        dict.get_word(0xfffd),
        Some(Bytes::from_static(b"Game")).as_ref()
    );
}

#[test]
fn encode_local_dict() {
    let mut ge = GlobalDictEncoder::default();
    let gd = ge.encode();
    let mut le = LocalDictEncoder::new(&ge);
    le.add("foo".into()).unwrap();
    le.add("bár\0".into()).unwrap();

    let exp = vec![102, 111, 111, 0xff, 98, 195, 161, 114, 0, 0xff, 0];

    let mut buffer = BytesMut::new();
    le.encode(&mut buffer);
    assert_eq!(&buffer, &exp);
    let mut ld = LocalDictDecoder::new(&gd);
    let buffer: Bytes = buffer.into();
    {
        let rest = ld.decode(buffer.clone()).unwrap();
        assert!(!rest.has_remaining());
    }
    assert_eq!(ld.c2k[0], "foo".as_bytes());

    {
        let exp: Bytes = exp.into();
        let mut rem = ld.decode(exp.slice(1..)).unwrap();
        let rem = rem.copy_to_bytes(rem.remaining());
        assert_eq!(rem, exp.slice(11..));
    }

    assert_eq!(le.get_id("foo".as_bytes()), Some(256));

    assert_eq!(le.get_id("bár\0".as_bytes()), Some(257));

    assert_eq!(ld.get_word(256).unwrap(), "foo".as_bytes());
    assert_eq!(ld.get_word(257).unwrap(), "bár\0".as_bytes());
}
