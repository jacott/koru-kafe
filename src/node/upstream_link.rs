use std::io::Cursor;
use std::num::TryFromIntError;
use std::string::FromUtf8Error;
use std::{fmt, io};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::{io::AsyncReadExt, sync::mpsc};
use tokio::{io::AsyncWriteExt, sync::broadcast};

use crate::ts_net::unix;
use crate::websockets::Message;

use super::session_manager::Slot;

pub type MpscSender = mpsc::Sender<Msg>;
pub type MpscReceiver = mpsc::Receiver<Msg>;
pub type BroadcastSender = broadcast::Sender<Msg>;
pub type BroadcastReceiver = broadcast::Receiver<Msg>;

#[derive(Debug, Clone)]
pub struct Frame {
    pub msg: Msg,
    pub slot: Slot,
}
impl Frame {
    pub fn connect<P: Into<Bytes>>(slot: Slot, remaining: P) -> Self {
        Self {
            msg: Msg::Connect(remaining.into()),
            slot,
        }
    }

    pub fn new<P: Into<Bytes>>(frame_type: u8, slot: Slot, remaining: P) -> crate::Result<Self> {
        let msg = match frame_type {
            T_CONNECT => Msg::Connect(remaining.into()),
            T_CLOSE => Msg::Close,
            T_BINARY => Msg::bin(remaining),
            T_TEXT => Msg::text(remaining),
            _ => return Err("Invalid type".into()),
        };

        Ok(Self { msg, slot })
    }

    pub fn from_msg(msg: Msg, slot: Slot) -> Self {
        Self { msg, slot }
    }

    pub fn request_dictionary() -> Self {
        Self {
            slot: Slot::control(),
            msg: Msg::Connect(Bytes::new()),
        }
    }

    fn msg_header(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(7);
        buf.put_u32_le(self.msg.as_bytes().len() as u32 + 7);
        buf.put_u16_le(self.slot.as_u16());
        buf.put_u8(self.msg.type_code());
        buf.freeze()
    }
}

const T_CONNECT: u8 = 0;
const T_CLOSE: u8 = 1;
const T_BINARY: u8 = 3;
const T_TEXT: u8 = 4;

const EMPTY: &[u8; 0] = &[];

#[derive(Debug, Clone)]
pub enum Msg {
    Connect(Bytes),
    Close,
    Binary(Bytes),
    Text(Bytes),
}
impl Msg {
    pub fn bin<P: Into<Bytes>>(msg: P) -> Self {
        Self::Binary(msg.into())
    }

    pub fn text<P: Into<Bytes>>(msg: P) -> Self {
        Self::Text(msg.into())
    }

    pub fn type_code(&self) -> u8 {
        match self {
            Msg::Connect(_) => T_CONNECT,
            Msg::Close => T_CLOSE,
            Msg::Binary(_) => T_BINARY,
            Msg::Text(_) => T_TEXT,
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Msg::Close => true,
            Msg::Connect(v) | Msg::Binary(v) | Msg::Text(v) => v.is_empty(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Msg::Close => EMPTY,
            Msg::Connect(v) | Msg::Binary(v) | Msg::Text(v) => v,
        }
    }
}
impl From<Message> for Msg {
    fn from(value: Message) -> Self {
        if let Some(v) = value.as_text() {
            Self::text(v.to_string())
        } else if value.is_close() {
            Self::Close
        } else {
            Self::Binary(value.into_payload().into())
        }
    }
}
impl From<Msg> for Message {
    fn from(value: Msg) -> Self {
        match value {
            Msg::Connect(_) => panic!("Tried to convert connect to websocket message"),
            Msg::Close => Message::close(None, ""),
            Msg::Binary(v) => Message::binary(v),
            Msg::Text(v) => Message::text(v),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Incomplete,
    Other(crate::Error),
}
impl From<String> for Error {
    fn from(src: String) -> Error {
        Error::Other(src.into())
    }
}
impl From<&str> for Error {
    fn from(src: &str) -> Error {
        src.to_string().into()
    }
}
impl From<FromUtf8Error> for Error {
    fn from(_src: FromUtf8Error) -> Error {
        "protocol error; invalid frame format".into()
    }
}
impl From<TryFromIntError> for Error {
    fn from(_src: TryFromIntError) -> Error {
        "protocol error; invalid frame format".into()
    }
}
impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Incomplete => "stream ended early".fmt(fmt),
            Error::Other(err) => err.fmt(fmt),
        }
    }
}

pub struct KoruSocketReader {
    stream: unix::OwnedReadHalf,
    buffer: BytesMut,
    exp_msg_len: usize,
}
impl KoruSocketReader {
    pub fn new(stream: unix::OwnedReadHalf) -> KoruSocketReader {
        KoruSocketReader {
            stream,
            buffer: BytesMut::with_capacity(4096),
            exp_msg_len: 0,
        }
    }

    pub async fn read_msg(&mut self) -> crate::Result<Option<Frame>> {
        loop {
            if let Some(frame) = self.parse_msg()? {
                return Ok(Some(frame));
            }
            // There is not enough buffered data to read a frame. Attempt to
            // read more data from the socket.
            //
            // On success, the number of bytes is returned. `0` indicates "end
            // of stream".
            if 0 == self.stream.read_buf(&mut self.buffer).await? {
                // The remote closed the connection. For this to be a clean
                // shutdown, there should be no data in the read buffer. If
                // there is, this means that the peer closed the socket while
                // sending a frame.
                if self.buffer.is_empty() {
                    return Ok(None);
                } else {
                    return Err("connection reset by peer".into());
                }
            }
        }
    }

    fn check(&mut self) -> Result<usize, Error> {
        let len = if self.exp_msg_len != 0 {
            self.exp_msg_len
        } else {
            if self.buffer.len() < 4 {
                return Err(Error::Incomplete);
            }
            let mut peek = Cursor::new(&self.buffer);
            peek.get_u32_le() as usize
        };
        if len > 20_000_000 {
            return Err(Error::from("message too big!"));
        }

        if self.buffer.len() >= len {
            self.exp_msg_len = len;
            Ok(len)
        } else {
            self.buffer.reserve(len - self.buffer.len());
            Err(Error::Incomplete)
        }
    }

    fn parse_msg(&mut self) -> crate::Result<Option<Frame>> {
        match self.check() {
            Ok(rem) => {
                let mut frame_data = self.buffer.split_to(rem);
                frame_data.advance(4);
                let slot = frame_data.get_u16_le().into();
                let frame_type = frame_data.get_u8();
                self.exp_msg_len = 0;
                let frame = Frame::new(
                    frame_type,
                    slot,
                    frame_data.copy_to_bytes(frame_data.remaining()),
                )?;
                Ok(Some(frame))
            }

            Err(Error::Incomplete) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

pub struct KoruSocketWriter {
    stream: unix::OwnedWriteHalf,
}
impl KoruSocketWriter {
    pub fn new(stream: unix::OwnedWriteHalf) -> KoruSocketWriter {
        KoruSocketWriter { stream }
    }
    pub async fn write_msg(&mut self, frame: &Frame) -> io::Result<u16> {
        let buf = frame.msg_header();
        self.stream.write_all(buf.as_ref()).await?;
        self.stream.write_all(frame.msg.as_bytes()).await?;
        self.stream.flush().await?;
        Ok(0)
    }
}

#[cfg(test)]
#[path = "upstream_link_test.rs"]
mod test;
