use std::cmp::{self, min};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use radixdb::RadixTree;

use crate::ts_net;

pub(crate) const T_TERM: u8 = 0;

const LOCAL_OFFSET: u16 = 0x100;
const MAX_CAPICITY: u16 = 0xfff0;
const GLOBAL_OFFSET: i32 = 0xffff;

pub trait DictEncoder {
    fn get_id(&self, key: &[u8]) -> Option<u16>;

    fn len(&self) -> u16;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub trait DictDecoder {
    fn get_word(&self, id: u16) -> Option<&Bytes>;
    fn len(&self) -> u16;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn decode(&mut self, mut msg: impl Buf) -> Result<impl Buf, ts_net::Error> {
        const SEP: u8 = 0xff;
        let mut word = BytesMut::new();
        let mut term = false;
        while msg.has_remaining() {
            let mut spos = 0;
            {
                let chunk = msg.chunk();
                for &v in chunk.iter() {
                    match v {
                        SEP => break,
                        T_TERM if spos == 0 => {
                            term = true;
                            break;
                        }
                        _ => spos += 1,
                    }
                }
            }

            if spos > 0 {
                word.extend_from_slice(&msg.chunk()[..spos]);
                let w = word.freeze();
                word = BytesMut::new();

                self.push(w)?;
                msg.advance(min(spos + 1, msg.remaining()));
            } else if term {
                msg.advance(spos + 1);
                self.finalize();
                return Ok(msg);
            } else {
                word.extend_from_slice(msg.chunk());
                msg.advance(msg.chunk().len());
            }
        }
        Err("Missing dictionary string".into())
    }

    fn finalize(&mut self);
    fn push(&mut self, key: Bytes) -> Result<(), ts_net::Error>;
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GlobalDictEncoder {
    k2c: RadixTree,
    length: u16,
    size: usize,
}
impl GlobalDictEncoder {
    pub fn from_decoder(gdd: &GlobalDictDecoder) -> Result<Self, ts_net::Error> {
        let mut gde = Self::default();
        for v in gdd.c2k.iter() {
            gde.insert(v.clone())?;
        }
        Ok(gde)
    }

    pub fn encode(&mut self) -> GlobalDictDecoder {
        assert!(
            self.size >= self.length as usize,
            "Can't reencode a dictionary"
        );

        let mut c2k = vec![Bytes::new(); self.len() as usize];
        for (k, v) in self.k2c.iter() {
            c2k[radixdb_to_u16(v) as usize] = Bytes::copy_from_slice(k.as_ref());
        }

        self.size = 0;
        GlobalDictDecoder { c2k }
    }

    fn insert(&mut self, key: Bytes) -> Result<(), ts_net::Error> {
        let len = self.len();
        if len < MAX_CAPICITY {
            self.size += key.len() + 4;
            self.k2c.insert(key, self.length.to_be_bytes());
            self.length += 1;
            Ok(())
        } else {
            Err("Too many entries in GlobalDictionary".into())
        }
    }

    pub fn add<P: Into<Bytes>>(&mut self, key: P) -> Result<(), ts_net::Error> {
        assert!(
            self.size >= self.length as usize,
            "Global dictionary is already finalized"
        );
        let key = key.into();
        if !self.k2c.contains_key(&key) {
            self.insert(key)
        } else {
            Ok(())
        }
    }
}
impl DictEncoder for GlobalDictEncoder {
    fn get_id(&self, key: &[u8]) -> Option<u16> {
        let i = self.k2c.get(key).map(radixdb_to_u16)? as i32;
        u16::try_from(i + GLOBAL_OFFSET - (self.len() as i32)).ok()
    }

    fn len(&self) -> u16 {
        self.length
    }
}

#[derive(Debug, Default)]
pub struct GlobalDictDecoder {
    c2k: Vec<Bytes>,
}
impl GlobalDictDecoder {
    pub fn new(data: &[u8]) -> Self {
        let data = if data.ends_with(&[0xff, 0]) {
            &data[..data.len() - 2]
        } else {
            data
        };
        let c2k = data
            .split(|b| b == &0xff)
            .map(|slice| Bytes::from(slice.to_vec()))
            .collect();
        Self { c2k }
    }
    pub fn global_as_bytes(&self, buffer: &mut impl BufMut) {
        for k in &self.c2k[..] {
            buffer.put(k.clone());
            buffer.put_u8(255);
        }

        buffer.put_u8(0);
    }
}
impl DictDecoder for GlobalDictDecoder {
    fn get_word(&self, id: u16) -> Option<&Bytes> {
        let id = (id as i32 + self.len() as i32) - GLOBAL_OFFSET;
        if id >= 0 && id < self.c2k.len() as i32 {
            self.c2k.get(id as usize)
        } else {
            None
        }
    }

    fn len(&self) -> u16 {
        self.c2k.len() as u16
    }

    fn finalize(&mut self) {}

    fn push(&mut self, key: Bytes) -> Result<(), ts_net::Error> {
        if self.len() >= MAX_CAPICITY {
            Err("Too many entries in GlobalDictionary".into())
        } else {
            self.c2k.push(key);
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDictEncoder<'a> {
    k2c: RadixTree,
    length: u16,
    size: usize,
    global_dict: &'a GlobalDictEncoder,
    pub(super) upper_limit: u16,
}

impl<'a> LocalDictEncoder<'a> {
    pub fn new(global_dict: &'a GlobalDictEncoder) -> LocalDictEncoder<'a> {
        LocalDictEncoder {
            k2c: Default::default(),
            length: 0,
            size: 0,
            global_dict,
            upper_limit: cmp::min(MAX_CAPICITY, GLOBAL_OFFSET as u16 - global_dict.len()),
        }
    }

    pub fn encode(&self, buffer: &mut BytesMut) {
        let mut c2k = vec![String::new(); self.len() as usize];
        for (k, v) in self.k2c.iter() {
            let k = String::from_utf8_lossy(k.as_ref());
            c2k[radixdb_to_u16(v) as usize] = k.to_string();
        }

        for k in &c2k[..] {
            buffer.extend_from_slice(k.as_bytes());
            buffer.put_u8(255);
        }

        buffer.put_u8(0);
    }

    pub fn add(&mut self, key: Bytes) -> Result<u16, &'static str> {
        if let Some(id) = self.get_id(&key) {
            Ok(id)
        } else {
            self.insert(key)
        }
    }

    pub fn is_full(&self) -> bool {
        let len = self.len();
        len >= self.upper_limit || len >= 0xa000
    }

    fn insert(&mut self, key: Bytes) -> Result<u16, &'static str> {
        if self.is_full() {
            Err("Too many entries in LocalDictionary")
        } else {
            self.size += key.len() + 4;
            let i = self.length;
            self.k2c.insert(key, i.to_be_bytes());
            self.length += 1;
            Ok(i + LOCAL_OFFSET)
        }
    }
}

impl<'a> DictEncoder for LocalDictEncoder<'a> {
    fn get_id(&self, key: &[u8]) -> Option<u16> {
        let id = self.global_dict.get_id(key);
        if id.is_some() {
            id
        } else {
            let i = self.k2c.get(key).map(radixdb_to_u16)?;
            Some(i + LOCAL_OFFSET)
        }
    }

    fn len(&self) -> u16 {
        self.length
    }
}

#[derive(Debug)]
pub(crate) struct LocalDictDecoder<'a> {
    c2k: Vec<Bytes>,
    global_dict: &'a GlobalDictDecoder,
    pub(super) upper_limit: u16,
}

impl<'a> LocalDictDecoder<'a> {
    pub(crate) fn new(global_dict: &'a GlobalDictDecoder) -> LocalDictDecoder<'a> {
        LocalDictDecoder {
            c2k: Default::default(),
            global_dict,
            upper_limit: cmp::min(MAX_CAPICITY, GLOBAL_OFFSET as u16 - global_dict.len()),
        }
    }
}

impl<'a> DictDecoder for LocalDictDecoder<'a> {
    fn get_word(&self, id: u16) -> Option<&Bytes> {
        if id >= self.upper_limit {
            return self.global_dict.get_word(id);
        }
        let id = id as i32 - LOCAL_OFFSET as i32;

        if id >= 0 && id < self.c2k.len() as i32 {
            self.c2k.get(id as usize)
        } else {
            None
        }
    }

    fn len(&self) -> u16 {
        self.c2k.len() as u16
    }

    fn finalize(&mut self) {}

    fn push(&mut self, key: Bytes) -> Result<(), ts_net::Error> {
        if self.len() >= MAX_CAPICITY {
            Err("Too many entries in LocalDictionary".into())
        } else {
            self.c2k.push(key);
            Ok(())
        }
    }
}

fn radixdb_to_u16(value: radixdb::node::Value) -> u16 {
    u16::from_be_bytes(
        value
            .as_ref()
            .try_into()
            .expect("should have a two byte value"),
    )
}

#[cfg(test)]
#[path = "dictionary_test.rs"]
mod test;
