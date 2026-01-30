use std::time::{Duration, SystemTime};

use crate::to_hex_string;

use super::*;

fn empty_global() -> (GlobalDictEncoder, GlobalDictDecoder) {
    (GlobalDictEncoder::default(), GlobalDictDecoder::default())
}

fn t_encode(msg: &[Jst], ge: &GlobalDictEncoder) -> Bytes {
    let dict = LocalDictEncoder::new(ge);
    t_encode_local(msg, dict)
}

fn t_encode_local(msg: &[Jst], le: LocalDictEncoder) -> Bytes {
    let mut encoder = super::Encoder::new(8, le);
    for o in msg {
        encoder.add(o);
    }
    encoder.encode()
}

fn t_decode<'a>(array: impl Buf, global_dict: &'a GlobalDictDecoder) -> Decoder<'a> {
    super::Decoder::new(array, global_dict)
}

macro_rules! assert_enc {
    ($msg:expr, $exp:expr) => {
        let (ge, gd) = empty_global();
        assert_enc!(ge => gd, $msg, $exp)
    };
    ($gle:expr => $gld:expr, $msg:expr, $exp:expr) => {
        let msg: &[Jst] = &$msg;
        let exp: &[u8] = &$exp;
        let mut act = t_encode(msg, &$gle);
        let mut act = act.copy_to_bytes(act.remaining());
        if exp.len() != 1 || exp[0] != 0 {
            if exp[0] == 8 {
                assert_eq!(&act.as_ref(), &exp);
            } else {
                assert_eq!(&act.slice(2..).as_ref(), &exp);
            }
        }
        act.get_u8();
        let ans: Vec<Jst> = t_decode(act, &$gld).collect();
        assert_eq!(&ans, msg);
    };
    ($msg:expr) => {
        assert_enc!($msg, [0])
    };
}

fn jstr(i: &str) -> Jst {
    Jst::String(Bytes::copy_from_slice(i.as_bytes()))
}

#[test]
fn encode_undefined() {
    assert_enc!([Jst::Undefined], [1]);
}

#[test]
fn encode_null() {
    assert_enc!([Jst::Null], [2]);
}

#[test]
fn encode_true() {
    assert_enc!([Jst::True], [3]);
}

#[test]
fn encode_false() {
    assert_enc!([Jst::False], [4]);
}

#[test]
fn encode_empty_string() {
    assert_enc!([jstr("")], [5]);
}

#[test]
fn encode_empty_array() {
    assert_enc!([Jst::Array, Jst::EndObject], [20]);
}

#[test]
fn encode_empty_object() {
    assert_enc!([Jst::Object, Jst::EndObject], [21]);
}

#[test]
fn encode_empty_null_object() {
    assert_enc!([Jst::NullObject, Jst::EndObject], [23]);
}

#[test]
fn encode_null_object() {
    assert_enc!(
        [
            Jst::NullObject,
            Jst::Key(Bytes::copy_from_slice(b"x")),
            Jst::Int(1),
            Jst::EndObject
        ],
        [8, 120, 255, 0, 22, 1, 0, 65, 0]
    );
}

#[test]
fn single_small_int() {
    assert_enc!([Jst::Int(1)], [65]);
}

#[test]
fn small_string() {
    assert_enc!([jstr("12")], [8, 49, 50, 255, 0, 17, 1, 0]);
    assert_enc!([jstr("\na bit more Ჾ蠇 text\n\x01\x7f\x00\n\n\n")]);
}

#[test]
fn preserves_byte_order_mark() {
    assert_enc!(
        [jstr("\u{feff}x")],
        [8, 239, 187, 191, 120, 255, 0, 17, 1, 0]
    );
}

#[test]
fn surrogate_characters() {
    let text = "h💣éÿ€";
    let exp = vec![
        8, 0, 140, 104, 240, 159, 146, 163, 195, 169, 195, 191, 226, 130, 172,
    ];

    let text = jstr(text);

    let (ge, gd) = empty_global();
    let mut dict = LocalDictEncoder::new(&ge);
    dict.upper_limit = 0;

    let msg = [text];

    let mut enc = t_encode_local(&msg, dict);
    let mut enc = enc.copy_to_bytes(enc.remaining());
    assert_eq!(&enc.as_ref(), &exp);

    enc.get_u8();
    let ans: Vec<Jst> = t_decode(enc, &gd).collect();
    assert_eq!(ans, &msg);
}

#[test]
fn big_string() {
    let s = [b'x'; 140];
    let s = String::from_utf8_lossy(&s);
    assert_enc!([jstr(&s), jstr(&s[..100])]);
}

#[test]
fn string_in_global_dict() {
    let mut ge = GlobalDictEncoder::default();
    ge.add("Friday").unwrap();
    ge.add("x").unwrap();
    let gd = ge.encode();

    assert_enc!(ge => gd, [jstr("x")], [129, 120]);
    assert_eq!(ge.get_id(b"x"), Some(65534));

    assert_enc!(ge => gd, [jstr("Friday")], [17, 255, 253]);

    assert_enc!(ge => gd, [jstr("new")], [8, 110, 101, 119, 255, 0, 17, 1, 0]);
}

#[test]
fn encode_small_integer() {
    assert_enc!([Jst::Int(1)], [0x41]);
}

#[test]
fn encode_int() {
    let (ge, gd) = empty_global();

    let testi = |n, exp: &[u8]| {
        let v = [Jst::Int(n)];
        assert_enc!(v, exp);
    };

    let testif = |n, exp: &[u8]| {
        let v = [Jst::Int(n)];
        let mut enc = t_encode(&v, &ge);
        let enc = enc.copy_to_bytes(enc.remaining());
        assert_eq!(&enc.slice(2..), &exp);
        let msg = t_decode(enc.slice(1..), &gd).next().unwrap();
        assert_eq!(msg, Jst::Float(n as f64));
    };

    testi(1, &[0x41]);
    testi(0x3f, &[0x7f]);
    testi(64, &[10, 64]);
    testi(-1, &[10, 255]);

    testi(-1.324e8 as i64, &[12, 248, 27, 188, 128]);
    testi(-4561, &[11, 238, 47]);
    testi(256, &[11, 1, 0]);

    testif(2147483648, &[13, 65, 224, 0, 0, 0, 0, 0, 0]);
    testif(-2147483649, &[13, 193, 224, 0, 0, 0, 32, 0, 0]);
}

#[test]
fn encode_float() {
    let (ge, gd) = empty_global();
    let testf = |n, exp: &[u8]| {
        let v = [Jst::Float(n)];
        assert_enc!(v, exp);
    };
    let testfi = |n, exp: &[u8]| {
        let v = [Jst::Float(n)];
        let mut enc = t_encode(&v, &ge);
        let enc = enc.copy_to_bytes(enc.remaining());
        assert_eq!(&enc.slice(2..), &exp);
        let msg = t_decode(enc.slice(1..), &gd).next().unwrap();
        assert_eq!(msg, Jst::Int(n as i64));
    };

    testf(45123.4567, &[14, 26, 229, 75, 7]);
    testf(-1.345e200, &[13, 233, 124, 29, 57, 187, 232, 23, 124]);

    testfi(-1.324e8, &[12, 248, 27, 188, 128]);

    let f = Jst::Float(f64::NAN);
    let mut enc = t_encode(&[f], &ge);
    let enc = enc.copy_to_bytes(enc.remaining());

    assert_eq!(&enc.as_ref(), &[8, 0, 13, 127, 248, 0, 0, 0, 0, 0, 0]);
    let msg = t_decode(enc.slice(1..), &gd).next().unwrap();
    match msg {
        Jst::Float(v) => {
            assert!(v.is_nan());
        }
        _ => unreachable!("Not a float"),
    }
}

#[test]
fn encode_date() {
    assert_enc!(
        [Jst::Date(Duration::from_millis(1402293586434))],
        [8, 0, 15, 66, 116, 103, 243, 96, 160, 32, 0]
    );
}

#[test]
fn encode_binary() {
    let mut v = Vec::<u8>::new();
    for i in 0..20 {
        v.push(i);
    }
    let v = Jst::Uint8Array(v.into());

    assert_enc!(
        [v],
        [
            8, 0, 16, 0, 0, 0, 20, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
            18, 19,
        ]
    );
}

#[test]
fn encode_array() {
    assert_enc!(
        [
            Jst::Array,
            Jst::Int(1),
            Jst::Int(2),
            jstr("hello"),
            Jst::EndObject
        ],
        [8, 104, 101, 108, 108, 111, 255, 0, 6, 65, 66, 17, 1, 0, 0]
    );

    // nested
    assert_enc!(
        [
            Jst::Array,
            Jst::Int(1),
            Jst::Int(2),
            Jst::Array,
            Jst::True,
            Jst::Null,
            Jst::Array,
            Jst::Undefined,
            jstr("hello"),
            Jst::EndObject,
            Jst::Int(0),
            Jst::EndObject,
            Jst::Int(5),
            Jst::EndObject
        ],
        [
            8, 104, 101, 108, 108, 111, 255, 0, 6, 65, 66, 6, 3, 2, 6, 1, 17, 1, 0, 0, 64, 0, 69,
            0,
        ]
    );
}

#[test]
fn sparse_arrays() {
    let mut v = vec![
        Jst::Array,
        Jst::SparseIndex(130),
        jstr("x"),
        Jst::Int(1),
        Jst::SparseIndex(5432 - 132),
        Jst::Null,
        Jst::EndObject,
    ];
    assert_enc!(
        v.as_ref(),
        [6, 18, 130, 129, 120, 65, 19, 0, 0, 20, 180, 2, 0]
    );

    v[1] = Jst::SparseIndex(127);
    v.insert(1, Jst::Int(0));
    v.insert(2, Jst::Int(-1));
    v.insert(3, Jst::Int(-2));

    assert_enc!(
        v.as_ref(),
        [6, 64, 10, 255, 10, 254, 18, 127, 129, 120, 65, 19, 0, 0, 20, 180, 2, 0,]
    );
}

#[test]
fn populated_object() {
    let mut ge = GlobalDictEncoder::default();
    ge.add("foo").unwrap();
    let gd = ge.encode();

    let v = [
        Jst::Object,
        Jst::key("foo"),
        Jst::string("bar"),
        Jst::key("baz"),
        Jst::string("foo"),
        Jst::EndObject,
    ];

    #[rustfmt::skip]
    assert_enc!(ge => gd, v, [
        8,                             // Dictionary
        98, 97, 114, 0xff,             // local entry: bar
        98, 97, 122, 0xff,             // local entry: baz
        0,                             // end-of-dict
        7,                             // object
        0xff, 0xfe, 17, 1, 0,          // foo: bar
        1, 1, 17, 0xff, 0xfe,          // baz: foo
        0                              // eom
    ]);
}

#[test]
fn bad_message() {
    #[rustfmt::skip]
    let msg = Bytes::from_owner([
        8,                             // Dictionary
        98, 97, 114, 0xff,             // local entry: bar
        98, 97, 122, 0xff,             // local entry: baz
        0,                             // end-of-dict
        61, 2, 3, 4,                   // junk
        7,                             // object
        0xff, 0xfe, 17, 1, 0,          // foo: bar
        1, 1, 17, 0xff, 0xfe,          // baz: foo
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2,
    ]);

    let gd = GlobalDictDecoder::default();

    let mut dec = Decoder::new(msg, &gd);
    assert!(dec.any(|v| matches!(v, Jst::Error(Error::UnexpectedMessageType))));

    let missing_dict = Bytes::from_owner([10, 2, 4, 5]);
    let mut dec = Decoder::new(missing_dict, &gd);
    assert!(dec.all(|v| v.is_err()));

    let mut dec = Decoder::new(Bytes::from_static(&[0, 11]), &gd);
    assert!(dec.any(|v| matches!(v, Jst::Error(Error::CorruptMessage))));
}

#[test]
fn large_object() {
    let mut o = vec![Jst::Object];
    for i in 0..129 {
        o.push(Jst::key(format!("{}", i)));
        o.push(Jst::Int(i));
    }
    o.push(Jst::EndObject);
    assert_enc!(o);
}

#[test]
fn mixed() {
    let mut ge = GlobalDictEncoder::default();
    ge.add("baz").unwrap();
    ge.add("bif").unwrap();
    let gd = ge.encode();

    #[rustfmt::skip]
    let msg = [
        Jst::Int(1),
        Jst::Uint8Array(Bytes::from_static(&[4, 7, 6, 4])),

        Jst::Object,

        Jst::key("foo"), Jst::Object,
          Jst::key("bar"), jstr("abc"),
          Jst::key("baz"), Jst::Array, Jst::Float(-3.234e30), Jst::Int(63), Jst::Float(3e200), Jst::EndObject,
          Jst::EndObject,

        Jst::key("longStr"), Jst::string(vec![b'{', 10]),
        Jst::key("baz"), Jst::True,
        Jst::key("a12"), Jst::Float(1.23),
        Jst::EndObject,

        jstr(""),
        Jst::False,
        Jst::Date(Duration::from_millis(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        )),
        Jst::Null,
        Jst::Float(f64::INFINITY),
        Jst::Undefined,
    ];

    assert_enc!(ge => gd, msg, [0]);
}

#[test]
fn unchanged_encoding_system() {
    let mut ge = GlobalDictEncoder::default();
    ge.add("order").unwrap();
    let gd = ge.encode();

    #[rustfmt::skip]
    let data = [
        jstr("6"),
        jstr("save"),
        jstr("Ticket"),
        jstr("jJ9MiaHtcdgJzbFvn"),
        Jst::Object,
        Jst::key("bin_id"), jstr("GStTJFXHDZmSkXM4z"),
        Jst::key("order"), Jst::Int(256),
        Jst::EndObject,
    ];

    let enc = t_encode(&data, &ge);
    assert_eq!(
        to_hex_string(enc),
        "08 73 61 76 65 ff 54 69 63 6b 65 74 ff 6a 4a 39 4d 69 61 48 74 63 64 67 4a 7a 62 \
         46 76 6e ff 62 69 6e 5f 69 64 ff 47 53 74 54 4a 46 58 48 44 5a 6d 53 6b 58 4d 34 \
         7a ff 00 81 36 11 01 00 11 01 01 11 01 02 07 01 03 11 01 04 ff fe 0b 01 00 00"
    );

    let mut enc = t_encode(&data, &ge);
    enc.get_u8();
    let dec = Decoder::new(enc, &gd);
    let dec: Vec<Jst> = dec.collect();
    assert_eq!(&dec[..], &data);
}

#[test]
fn transportation() {
    let encodemsg = |ge| {
        let mut enc = Encoder::message(b'Q', ge);
        enc.add_into("1");
        enc.add_into(1);
        enc.add_into("Game");
        enc.add_into("GStTJFXHDZmSkXM4z");
        enc.encode()
    };

    let mut ge = GlobalDictEncoder::default();
    ge.add("$remove").unwrap();
    ge.add("$match").unwrap();
    ge.add("Game").unwrap();
    ge.add("Play").unwrap();

    let gd = ge.encode();

    let mut data1 = encodemsg(&ge);

    let mut data = BytesMut::new();
    gd.global_as_bytes(&mut data);
    let data = data.freeze();

    let gd = GlobalDictDecoder::new(data.as_ref());
    let ge2 = GlobalDictEncoder::from_decoder(&gd).unwrap();
    let mut data2 = encodemsg(&ge2);

    assert_eq!(
        to_hex_string(data.clone()).as_str(),
        "24 72 65 6d 6f 76 65 ff 24 6d 61 74 63 68 ff 47 61 6d 65 ff 50 6c 61 79 ff 00"
    );

    assert_eq!(
        data1.copy_to_bytes(data1.remaining()),
        data2.copy_to_bytes(data2.remaining())
    );
}

#[test]
fn encode_empty_message() {
    let (ge, _gd) = empty_global();

    let enc = Encoder::message(b'P', &ge);
    let mut enc = enc.encode();
    let enc = enc.copy_to_bytes(enc.remaining());
    assert_eq!(enc, vec![80, 0]);
}
