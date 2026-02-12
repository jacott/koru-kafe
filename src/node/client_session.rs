use std::{
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::{id::Id, websockets::Message};

use super::{
    Slot,
    remote_cursors::{
        self,
        canvas::{CanvasDb, CanvasInfo},
        message::CURSOR_CMD,
    },
    upstream_link::{self, Frame},
};

pub const SESSION_TIMEOUT: Duration = Duration::from_secs(30);
pub const SEND_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Default)]
struct Info {
    user_id: Id,
    db_id: u64,
    canvas_info: CanvasInfo,
}
impl Info {
    fn set_db_id<I: Into<Id>>(&mut self, db_id: I) {
        let db_id: Id = db_id.into();
        let db_id: u128 = db_id.into();

        self.db_id = db_id as u64;
    }
}

struct ConnInner {
    ids: RwLock<Info>,
    client_sink: mpsc::Sender<Message>,
    upstream_tx: mpsc::Sender<Frame>,
    slot: Slot,
}
impl ConnInner {
    fn new(
        slot: Slot,
        client_sink: mpsc::Sender<Message>,
        upstream_tx: mpsc::Sender<Frame>,
    ) -> Self {
        Self {
            client_sink,
            upstream_tx,
            slot,
            ids: RwLock::new(Info::default()),
        }
    }
}

#[derive(Clone)]
pub struct ClientSession {
    inner: Arc<ConnInner>,
}
impl std::fmt::Debug for ClientSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "ClientSession({:?})",
            &self.get_slot().as_u16()
        ))
    }
}
impl ClientSession {
    pub fn new(
        slot: Slot,
        client_sink: mpsc::Sender<Message>,
        upstream_tx: mpsc::Sender<Frame>,
    ) -> Self {
        Self {
            inner: Arc::new(ConnInner::new(slot, client_sink, upstream_tx)),
        }
    }
    fn read(&'_ self) -> RwLockReadGuard<'_, Info> {
        self.inner.ids.read().expect("poisoned")
    }
    fn write(&'_ self) -> RwLockWriteGuard<'_, Info> {
        self.inner.ids.write().expect("poisoned")
    }
    pub fn set_user_and_db_id(&self, user_id: Id, db_id: Id) {
        let mut guard = self.write();
        guard.user_id = user_id;
        guard.set_db_id(db_id);
    }
    pub fn get_user_id(&self) -> Id {
        self.read().user_id
    }
    pub fn get_db_id(&self) -> u64 {
        self.read().db_id
    }
    pub fn get_db_id_text(&self) -> String {
        let db_id: Id = (self.read().db_id as u128).into();
        db_id.to_string()
    }
    pub fn set_db_id<I: Into<Id>>(&self, db_id: I) {
        self.write().set_db_id(db_id);
    }
    pub fn get_canvas_info(&self) -> CanvasInfo {
        self.read().canvas_info.clone()
    }

    pub fn set_canvas_info(&self, value: CanvasInfo) -> CanvasInfo {
        std::mem::replace(&mut self.write().canvas_info, value)
    }

    pub fn set_canvas_slot(&self, value: u8) {
        self.write().canvas_info.slot = value;
    }

    // Define S as the generic stream, and E as a generic error
    pub async fn route_client_message(&self, msg: Message) -> crate::Result<()> {
        if msg.is_text() && msg.as_payload().len() == 1 && msg.as_payload()[0] == b'H' {
            let now = SystemTime::now();
            let msg = Message::text(format!(
                "K{}",
                now.duration_since(UNIX_EPOCH)
                    .expect("UNIX_EPOCH")
                    .as_millis()
            ));
            self.inner.client_sink.send(msg).await?;
        } else {
            let payload = msg.as_payload();
            if !payload.is_empty() {
                if payload[0] == remote_cursors::message::CURSOR_CMD {
                    CanvasDb::client_message(self, payload);
                } else {
                    self.inner
                        .upstream_tx
                        .send(Frame::from_msg(msg.into(), self.inner.slot))
                        .await?;
                }
            }
        }
        Ok(())
    }

    pub async fn route_upstream_text_message(&self, data: Bytes) -> crate::Result<()> {
        if data.starts_with(b"VS") {
            let data = &data[2..];
            let mut iter = data.splitn(3, |&b| b == b':');
            if let Some(user_id) = iter.next() {
                let mut guard = self.write();
                guard.user_id = user_id.into();
                if iter.next().is_some()
                    && let Some(db_id) = iter.next()
                {
                    guard.set_db_id(db_id);
                }
            }
        }
        self.inner
            .client_sink
            .send_timeout(Message::text(data), SEND_TIMEOUT)
            .await?;

        Ok(())
    }

    pub async fn route_upstream_binary_message(&self, data: Bytes) -> crate::Result<()> {
        if !data.is_empty() && data[0] == CURSOR_CMD {
            CanvasDb::upstream_message(self, &data);
        } else {
            self.inner
                .client_sink
                .send_timeout(Message::binary(data), SEND_TIMEOUT)
                .await?;
        }

        Ok(())
    }

    pub fn try_send_binary(&self, data: Bytes) {
        let _ = self.inner.client_sink.try_send(Message::binary(data));
    }

    pub(crate) fn send_binary_unless_half_full(&self, data: &Bytes) {
        let maxcap = self.inner.client_sink.max_capacity();
        if (maxcap - self.inner.client_sink.capacity()) << 1 < maxcap {
            self.try_send_binary(data.clone());
        }
    }

    pub async fn send_binary(&self, data: Bytes) -> Option<()> {
        if self
            .inner
            .client_sink
            .send_timeout(Message::binary(data), SEND_TIMEOUT)
            .await
            .is_err()
        {
            self.inner
                .upstream_tx
                .send(Frame::from_msg(upstream_link::Msg::Close, self.inner.slot))
                .await
                .ok()?;
        }

        Some(())
    }

    pub fn get_slot(&self) -> Slot {
        self.inner.slot
    }
}

#[cfg(test)]
#[path = "client_session_test.rs"]
mod test;
