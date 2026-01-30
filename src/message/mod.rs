use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use dictionary::*;
pub use dictionary::{DictDecoder, DictEncoder, GlobalDictDecoder, GlobalDictEncoder, LocalDictEncoder};
pub use jst::Jst;
use jst::{Error, JsonValue};

use crate::websockets;

mod dictionary;
pub mod jst;

const T_TERM: u8 = dictionary::T_TERM;
const T_UNDEF: u8 = 1;
const T_NULL: u8 = 2;
const T_TRUE: u8 = 3;
const T_FALSE: u8 = 4;
const T_EMPTY_STRING: u8 = 5;
const T_ARRAY: u8 = 6;
const T_OBJECT: u8 = 7;
const T_DICT: u8 = 8;
const T_STRING: u8 = 9;
const T_INT8: u8 = 10;
const T_INT16: u8 = 11;
const T_INT32: u8 = 12;
const T_FLOAT64: u8 = 13;
const T_DEC4: u8 = 14;
const T_DATE: u8 = 15;
const T_BINARY: u8 = 16;
const T_DICT_STRING: u8 = 17;
const T_SPARSE_SMALL: u8 = 18;
const T_SPARSE_LARGE: u8 = 19;
const T_EMPTY_ARRAY: u8 = 20;
const T_EMPTY_OBJECT: u8 = 21;
const T_NULL_OBJECT: u8 = 22;
const T_EMPTY_NULL_OBJECT: u8 = 23;

const T_SM_NUMBER: u8 = 0x40;
const T_SM_STRING: u8 = 0x80;

const MESSAGE_TOO_SMALL: Jst = Jst::Error(Error::MessageTooSmall);
const CORRUPT_MESSAGE: Jst = Jst::Error(Error::CorruptMessage);

enum EncoderState {
    Object,
    NullObject,
    Array,
    Keys,
    Entries,
}

pub struct Encoder<'a> {
    msg: BytesMut,
    dict: LocalDictEncoder<'a>,
    state: Vec<EncoderState>,
    msg_type: u8,
}
impl<'a> Encoder<'a> {
    pub fn new(msg_type: u8, dict: LocalDictEncoder<'a>) -> Self {
        Self {
            msg: BytesMut::new(),
            dict,
            state: vec![EncoderState::Entries],
            msg_type,
        }
    }

    pub fn message(msg_type: u8, global_dict: &'a GlobalDictEncoder) -> Self {
        let local_dict = LocalDictEncoder::new(global_dict);
        Self::new(msg_type, local_dict)
    }

    fn start_object(&mut self, object: &Jst) {
        let last = self.state.pop().expect("Missing state");
        match object {
            Jst::EndObject => {
                let s = match last {
                    EncoderState::Object => T_EMPTY_OBJECT,
                    _ => T_EMPTY_NULL_OBJECT,
                };
                self.msg.put_u8(s);
            }
            _ => {
                let s = match last {
                    EncoderState::Object => T_OBJECT,
                    _ => T_NULL_OBJECT,
                };
                self.msg.put_u8(s);
                self.state.push(EncoderState::Keys);
                self.add_to_object(object);
            }
        }
    }

    fn add_to_object(&mut self, object: &Jst) {
        match object {
            Jst::Key(k) => {
                let i = self.dict.add(k.clone()).unwrap_or_else(|e| panic!("{e}"));
                self.msg.put_u16(i);
            }
            Jst::EndObject => {
                self.msg.put_u8(T_TERM);
                self.state.pop();
            }
            _ => self.add_value(object),
        }
    }

    fn encode_int(&mut self, v: i64) {
        if v >= 0 && v < (T_SM_NUMBER as i64) {
            self.msg.put_u8(T_SM_NUMBER | (v as u8));
        } else if v > -129 && v < 128 {
            self.msg.put_u8(T_INT8);
            self.msg.extend_from_slice(&(v as i8).to_be_bytes());
        } else if v > -32769 && v < 32768 {
            self.msg.put_u8(T_INT16);
            self.msg.extend_from_slice(&(v as i16).to_be_bytes());
        } else if v > -2147483649 && v < 2147483648 {
            self.msg.put_u8(T_INT32);
            self.msg.extend_from_slice(&(v as i32).to_be_bytes());
        } else {
            self.msg.put_u8(T_FLOAT64);
            self.msg.extend_from_slice(&(v as f64).to_be_bytes());
        }
    }

    fn encode_float(&mut self, v: f64) {
        {
            let iv = v as i32;
            if iv as f64 == v {
                self.encode_int(iv as i64);
            } else {
                let m4 = v * 10000.0;
                let dec4 = m4 as i32;
                if dec4 as f64 == m4 {
                    self.msg.put_u8(T_DEC4);
                    self.msg.put_i32(dec4);
                } else {
                    self.msg.put_u8(T_FLOAT64);
                    self.msg.put_f64(v);
                }
            }
        }
    }

    fn encode_string(&mut self, v: &Bytes) {
        {
            if v.is_empty() {
                self.msg.put_u8(T_EMPTY_STRING);
            } else {
                let len = v.len();
                if len != 1 {
                    let dkey = if !self.dict.is_full() && len < 100 && v[0] != b'{' {
                        let id = self.dict.get_id(v);
                        if id.is_some() { id } else { Some(self.dict.add(v.clone()).expect("Can't add to dict")) }
                    } else {
                        self.dict.get_id(v)
                    };
                    if let Some(i) = dkey {
                        self.msg.put_u8(T_DICT_STRING);
                        self.msg.put_u16(i);
                        return;
                    }
                }
                if len < 128 {
                    self.msg.put_u8(T_SM_STRING | len as u8);
                    self.msg.extend_from_slice(v);
                } else {
                    self.msg.put_u8(T_STRING);
                    self.msg.extend_from_slice(v);
                    self.msg.put_u8(0xff);
                }
            }
        }
    }

    fn add_value(&mut self, object: &Jst) {
        match object {
            Jst::Undefined => self.msg.put_u8(T_UNDEF),
            Jst::Null => self.msg.put_u8(T_NULL),
            Jst::True => self.msg.put_u8(T_TRUE),
            Jst::False => self.msg.put_u8(T_FALSE),

            Jst::String(v) => self.encode_string(v),
            Jst::Array => self.state.push(EncoderState::Array),
            Jst::Object => self.state.push(EncoderState::Object),
            Jst::NullObject => self.state.push(EncoderState::NullObject),
            Jst::Int(v) => self.encode_int(*v),
            Jst::Float(v) => self.encode_float(*v),
            Jst::Date(duration) => {
                self.msg.put_u8(T_DATE);
                self.msg.put_f64(duration.as_millis() as f64);
            }
            Jst::Uint8Array(v) => {
                if v.len() > 100_000_000 {
                    panic!("Value too large {}", v.len());
                }
                self.msg.put_u8(T_BINARY);
                self.msg.put_u32(v.len() as u32);
                self.msg.extend_from_slice(v);
            }
            Jst::SparseIndex(v) => {
                let v = *v;
                if v < 0x100 {
                    self.msg.put_u8(T_SPARSE_SMALL);
                    self.msg.put_u8(v as u8);
                } else if v < 0x100000000 {
                    self.msg.put_u8(T_SPARSE_LARGE);
                    self.msg.put_u32(v as u32);
                }
            }
            Jst::EndObject => {
                if self.state.len() < 2 {
                    panic!("Unexpected EndObject");
                }
                self.state.pop();
                self.msg.put_u8(T_TERM);
            }
            Jst::Json(json) => {
                self.encode_json(json);
            }

            v => panic!("Unexpected token {v:?}"),
        };
    }

    pub fn add_into(&mut self, object: impl Into<Jst>) {
        let object = object.into();
        self.add(&object);
    }

    pub fn add(&mut self, object: &Jst) {
        match self.state.last().expect("Missing state") {
            EncoderState::Array => match object {
                Jst::EndObject => self.msg.put_u8(T_EMPTY_ARRAY),
                _ => {
                    self.state.pop().expect("Missing state");
                    self.state.push(EncoderState::Entries);
                    self.msg.put_u8(T_ARRAY);
                    self.add_value(object);
                }
            },
            EncoderState::Object | EncoderState::NullObject => self.start_object(object),
            EncoderState::Keys => {
                self.add_to_object(object);
            }
            EncoderState::Entries => {
                self.add_value(object);
            }
        }
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity((self.dict.len() as usize) * 4);
        buf.put_u8(self.msg_type);
        self.dict.encode(&mut buf);
        buf.extend_from_slice(self.msg.chunk());
        buf.freeze()
    }

    fn encode_json(&mut self, json: &JsonValue) {
        match json {
            JsonValue::Null => self.msg.put_u8(T_NULL),
            JsonValue::Bool(v) => {
                if *v {
                    self.msg.put_u8(T_TRUE)
                } else {
                    self.msg.put_u8(T_FALSE)
                }
            }
            JsonValue::Number(number) => {
                if number.is_i64() {
                    self.encode_int(number.as_i64().unwrap());
                } else if number.is_u64() {
                    let x = number.as_u64().unwrap();
                    let n32 = x as u32;
                    if n32 as u64 == x {
                        self.encode_int(n32 as i64);
                    } else {
                        self.encode_float(x as f64);
                    }
                } else {
                    self.encode_float(number.as_f64().unwrap_or(0.0));
                }
            }
            JsonValue::String(s) => {
                let b = Bytes::copy_from_slice(s.as_bytes());
                self.encode_string(&b);
            }
            JsonValue::Array(values) => {
                self.msg.put_u8(T_ARRAY);
                for n in values {
                    self.encode_json(n);
                }
                self.msg.put_u8(T_TERM);
            }
            JsonValue::Object(map) => {
                self.msg.put_u8(T_OBJECT);
                for (k, v) in map {
                    let k = Bytes::copy_from_slice(k.as_bytes());
                    let i = self.dict.add(k).unwrap_or_else(|e| panic!("{e}"));
                    self.msg.put_u16(i);
                    self.encode_json(v);
                }
                self.msg.put_u8(T_TERM);
            }
        }
    }
}
impl<'a> From<Encoder<'a>> for websockets::Message {
    fn from(value: Encoder<'a>) -> Self {
        let mut bytes = value.encode();
        let bytes = bytes.copy_to_bytes(bytes.remaining());
        websockets::Message::binary(bytes)
    }
}

#[derive(Debug, Clone)]
enum DecoderState {
    Next,
    EndObject,
    NextKey,
    NextKeyObject,
    Error(Error),
}

pub struct Decoder<'a> {
    msg: Bytes,
    dict: LocalDictDecoder<'a>,
    state: Vec<DecoderState>,
}
impl<'a> Decoder<'a> {
    pub fn new(msg: impl Buf, global_dict: &'a GlobalDictDecoder) -> Self {
        let mut dict = LocalDictDecoder::new(global_dict);

        let (msg, state) = match dict.decode(msg) {
            Ok(mut m2) => (m2.copy_to_bytes(m2.remaining()), DecoderState::Next),
            Err(_) => (Bytes::new(), DecoderState::Error(Error::CorruptMessage)),
        };
        Self {
            msg,
            dict,
            state: vec![state],
        }
    }

    fn next_item(&mut self) -> Option<Jst> {
        if self.msg.is_empty() {
            return None;
        }
        let c = self.msg.get_u8();

        match c {
            T_UNDEF => Some(Jst::Undefined),
            T_NULL => Some(Jst::Null),
            T_TRUE => Some(Jst::True),
            T_FALSE => Some(Jst::False),
            T_INT8 => Some(
                self.msg
                    .try_get_i8()
                    .map(|v| Jst::Int(v as i64))
                    .unwrap_or(CORRUPT_MESSAGE),
            ),
            T_INT16 => Some(
                self.msg
                    .try_get_i16()
                    .map(|v| Jst::Int(v as i64))
                    .unwrap_or(CORRUPT_MESSAGE),
            ),
            T_INT32 => Some(
                self.msg
                    .try_get_i32()
                    .map(|v| Jst::Int(v as i64))
                    .unwrap_or(CORRUPT_MESSAGE),
            ),
            T_EMPTY_STRING => Some(Jst::String(Bytes::new())),
            T_DICT_STRING => Some(if self.msg.remaining() < 2 {
                MESSAGE_TOO_SMALL
            } else {
                let id = self.msg.get_u16();
                if let Some(s) = self.dict.get_word(id) {
                    Jst::String(s.clone())
                } else {
                    Jst::Error(Error::MissingDictionaryString)
                }
            }),
            T_STRING => Some(
                if let Some(i) = self
                    .msg
                    .iter()
                    .enumerate()
                    .find_map(|(i, &v)| if v == 0xff { Some(i) } else { None })
                {
                    let s = self.msg.split_to(i);
                    self.msg.advance(1);
                    Jst::String(s)
                } else {
                    Jst::Error(Error::MessageStringTerminator)
                },
            ),
            T_DEC4 => Some(
                self.msg
                    .try_get_i32()
                    .map(|v| Jst::Float(v as f64 / 10000.0))
                    .unwrap_or(CORRUPT_MESSAGE),
            ),
            T_FLOAT64 => Some(self.msg.try_get_f64().map(Jst::Float).unwrap_or(CORRUPT_MESSAGE)),
            T_DATE => Some(
                self.msg
                    .try_get_f64()
                    .map(|v| Jst::Date(Duration::from_millis(v as u64)))
                    .unwrap_or(CORRUPT_MESSAGE),
            ),
            T_BINARY => Some(
                if let Ok(len) = self.msg.try_get_u32()
                    && self.msg.remaining() >= len as usize
                {
                    let bytes = self.msg.copy_to_bytes(len as usize);
                    Jst::Uint8Array(bytes)
                } else {
                    Jst::Error(Error::MessageTooSmall)
                },
            ),

            T_EMPTY_ARRAY => {
                self.state.push(DecoderState::EndObject);
                Some(Jst::Array)
            }
            T_EMPTY_OBJECT => {
                self.state.push(DecoderState::EndObject);
                Some(Jst::Object)
            }
            T_EMPTY_NULL_OBJECT => {
                self.state.push(DecoderState::EndObject);
                Some(Jst::NullObject)
            }
            T_ARRAY => {
                self.state.push(DecoderState::Next);
                Some(Jst::Array)
            }
            T_OBJECT => {
                self.state.push(DecoderState::NextKey);
                Some(Jst::Object)
            }
            T_NULL_OBJECT => {
                self.state.push(DecoderState::NextKey);
                Some(Jst::NullObject)
            }
            T_TERM => {
                if self.state.is_empty() {
                    None
                } else {
                    self.state.pop();
                    Some(Jst::EndObject)
                }
            }
            T_SPARSE_SMALL => Some(
                self.msg
                    .try_get_u8()
                    .map(|v| Jst::SparseIndex(v as usize))
                    .unwrap_or(CORRUPT_MESSAGE),
            ),
            T_SPARSE_LARGE => Some(
                self.msg
                    .try_get_u32()
                    .map(|v| Jst::SparseIndex(v as usize))
                    .unwrap_or(CORRUPT_MESSAGE),
            ),
            v if v & T_SM_STRING != 0 => Some({
                let len = v as usize - T_SM_STRING as usize;
                if self.msg.remaining() < len {
                    MESSAGE_TOO_SMALL
                } else {
                    let bytes = self.msg.copy_to_bytes(len);

                    Jst::String(bytes)
                }
            }),
            v if v & T_SM_NUMBER != 0 => Some(Jst::Int((v - T_SM_NUMBER) as i64)),

            T_DICT | 24u8..=u8::MAX => Some(Jst::Error(Error::UnexpectedMessageType)),
        }
    }

    pub fn get_string_as_bytes(&mut self) -> Option<Bytes> {
        if let Some(Jst::String(bytes)) = self.next() { Some(bytes) } else { None }
    }

    pub fn next_into<T: TryFrom<Jst>>(&mut self) -> Result<T, Error> {
        match self.next() {
            Some(Jst::Error(e)) => Err(e),
            Some(v) => v.try_into().map_err(|_| Error::UnexpectedMessageType),
            None => Err(Error::MessageTooSmall),
        }
    }

    pub fn read_array(&mut self) -> Result<jst::Array, Error> {
        let mut object = jst::Array::default();
        while let Some(o) = self.next() {
            match o {
                Jst::Array => object.push(Jst::NestedArray(self.read_array()?)),
                Jst::NullObject | Jst::Object => object.push(Jst::NestedObject(self.read_object()?)),
                Jst::EndObject => return Ok(object),
                _ => {
                    object.push(o);
                }
            }
        }
        Ok(object)
    }

    pub fn read_object(&mut self) -> Result<jst::Object, Error> {
        let mut object = jst::Object::default();
        while let Some(o) = self.next() {
            match o {
                Jst::Key(key) => {
                    let Some(o) = self.next() else {
                        break;
                    };
                    match o {
                        Jst::Array => object.insert(key, Jst::NestedArray(self.read_array()?)),
                        Jst::NullObject | Jst::Object => object.insert(key, Jst::NestedObject(self.read_object()?)),
                        _ => {
                            object.insert(key, o);
                        }
                    }
                }
                Jst::EndObject => return Ok(object),
                _ => break,
            }
        }
        Err(Error::CorruptMessage)
    }
}
impl<'a> Iterator for Decoder<'a> {
    type Item = Jst;

    fn next(&mut self) -> Option<Self::Item> {
        let state = match self.state.last().cloned() {
            Some(state) => state,
            None => return Some(CORRUPT_MESSAGE),
        };
        match state {
            DecoderState::Next => self.next_item(),
            DecoderState::NextKey => {
                self.state.pop();
                if self.msg.remaining() < 2 || matches!(self.msg.first(), Some(&T_TERM)) {
                    self.msg.advance(1);
                    Some(Jst::EndObject)
                } else {
                    let id = self.msg.get_u16();
                    self.state.push(DecoderState::NextKeyObject);
                    self.dict.get_word(id).map(|v| Jst::Key(v.clone()))
                }
            }
            DecoderState::NextKeyObject => {
                self.state.pop();
                self.state.push(DecoderState::NextKey);
                self.next_item()
            }
            DecoderState::EndObject => {
                self.state.pop();
                Some(Jst::EndObject)
            }
            DecoderState::Error(msg) => {
                self.state.pop();
                self.state.push(DecoderState::Next);
                Some(Jst::Error(msg))
            }
        }
    }
}

#[cfg(test)]
#[path = "mod_test.rs"]
mod test;
