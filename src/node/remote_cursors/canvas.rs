use std::{
    collections::HashMap,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::Duration,
};

use bytes::Bytes;
use log::info;
use tokio::time::Instant;

use crate::{
    id::Id,
    node::{Task, client_session::ClientSession, remote_cursors::message, session_manager::Slot},
    util::partition_list,
};

const UNASSIGNED_SLOT: u8 = 255;

#[derive(Clone)]
pub struct CanvasInfo {
    pub canvas: Option<Canvas>,
    pub slot: u8,
}
impl Default for CanvasInfo {
    fn default() -> Self {
        Self {
            canvas: Default::default(),
            slot: UNASSIGNED_SLOT,
        }
    }
}

#[derive(Default, Clone)]
pub struct CanvasDb(Arc<RwLock<HashMap<Id, Canvas>>>);
impl CanvasDb {
    pub fn add_client(&self, canvas_id: Id, client: &ClientSession) {
        let canvas = self.get_create(canvas_id);
        canvas.add_client(client);
    }

    pub fn get_create(&self, canvas_id: Id) -> Canvas {
        if let Some(db) = self.0.read().expect("poisoned").get(&canvas_id) {
            db.clone()
        } else {
            self.0
                .write()
                .expect("poisoned")
                .entry(canvas_id)
                .or_insert_with(|| Canvas::new(canvas_id))
                .clone()
        }
    }

    pub fn get(&self, canvas_id: Id) -> Option<Canvas> {
        self.0.read().expect("poisoned").get(&canvas_id).cloned()
    }

    pub fn upstream_message(client: &ClientSession, data: &[u8]) {
        if data.len() > 2 {
            match data[1] {
                message::NEW_CLIENTS => {
                    Canvas::remove_client(client);
                    let canvas_id = message::decode_canvas(data);
                    if !canvas_id.is_empty() {
                        let db = Task::cursor_db().get_canvas_db(client.get_db_id());
                        db.add_client(canvas_id, client);
                    }
                }
                _ => {
                    crate::info!(
                        "Unexpected Canvas command {:?}, {:?} - {:?}",
                        data[1],
                        client.get_slot(),
                        client.get_user_id(),
                    );
                }
            }
        }
    }

    pub fn client_message(client: &ClientSession, data: &[u8]) {
        if data.len() > 2 {
            match data[1] {
                message::MOVE => {
                    let info = client.get_canvas_info();
                    if let Some(canvas) = info.canvas {
                        canvas.cursor_move(info.slot, data);
                    }
                }
                _ => {
                    crate::info!(
                        "Unexpected Canvas command {:?}, {:?} - {:?}",
                        data[1],
                        client.get_slot(),
                        client.get_user_id(),
                    );
                }
            }
        }
    }
}

pub(crate) const ADD_DELAY: Duration = Duration::from_millis(100);
pub(crate) const MOVE_DELAY: Duration = Duration::from_millis(30);

struct ReportTimer {
    when: Instant,
    task: tokio::task::JoinHandle<()>,
}

type AssignmentMessages = (
    Vec<ClientSession>,
    Vec<Bytes>,
    Vec<(ClientSession, u8)>,
    Bytes,
);

#[derive(Default)]
struct CanvasInner {
    clients: Vec<ClientSession>,
    add_clients: HashMap<Slot, ClientSession>,
    remove_clients: HashMap<Slot, ClientSession>,
    timer: Option<ReportTimer>,
    canvas_id: Id,
    moves: Vec<u8>,
}
impl CanvasInner {
    fn cursor_move(&mut self, canvas: &Canvas, slot: u8, data: &[u8]) {
        if self.moves.is_empty() {
            self.moves.push(message::CURSOR_CMD);
            self.moves.push(message::MOVE);
        }
        let data = &data[2..];
        if data.len() == message::COORD_SIZE {
            message::add_move(&mut self.moves, slot, data);
            self.schedule_send(canvas, MOVE_DELAY);
        }
    }

    fn add(&mut self, canvas: &Canvas, client: &ClientSession) {
        let slot = client.get_slot();
        if self.remove_clients.remove(&slot).is_some() {
            return;
        }
        client.set_canvas_info(CanvasInfo {
            canvas: Some(canvas.clone()),
            slot: UNASSIGNED_SLOT,
        });
        self.add_clients.insert(slot, client.clone());
        self.schedule_send(canvas, ADD_DELAY);
    }

    fn remove(&mut self, canvas: &Canvas, client: &ClientSession) {
        let slot = client.get_slot();
        if self.add_clients.remove(&slot).is_some() {
            return;
        }
        self.remove_clients.insert(slot, client.clone());
        self.schedule_send(canvas, ADD_DELAY);
    }

    fn schedule_send(&mut self, canvas: &Canvas, delay: Duration) {
        let when = Instant::now() + delay;
        if let Some(timer) = &mut self.timer {
            if timer.when > when {
                // fixme! nees to test this
                timer.when = when;
                timer.task = canvas.clone().wake_after(when);
            }
        } else {
            self.timer = Some(ReportTimer {
                when,
                task: canvas.clone().wake_after(when),
            })
        }
    }

    fn extract_assignment_messages(&mut self) -> Option<AssignmentMessages> {
        if self.remove_clients.is_empty() && self.add_clients.is_empty() {
            return None;
        }
        let mut msgs = vec![];
        let mut assignments = vec![];

        info!(
            "\n{:?}:send ({}) \n add {}, remove {}, ",
            self.canvas_id,
            self.clients.iter().fold(String::new(), |a, c| format!(
                "{a} {:?}-{:?}",
                c.get_slot(),
                c.get_user_id()
            )),
            self.add_clients.iter().fold(String::new(), |a, c| format!(
                "{a} {:?}-{:?}",
                c.0,
                c.1.get_user_id()
            )),
            self.remove_clients
                .keys()
                .fold(String::new(), |a, c| format!("{a} {c:?}")),
        );

        let clients = &mut self.clients;

        if !self.remove_clients.is_empty() {
            let mut removed_canvas_slots = vec![];
            let idx = partition_list(clients, |s, pos, other| {
                if self.remove_clients.contains_key(&s.get_slot()) {
                    let pos = pos as u8;
                    removed_canvas_slots.push(pos);
                    if let Some(other) = other {
                        other.set_canvas_slot(pos);
                    }
                    true
                } else {
                    false
                }
            });

            if idx < clients.len() {
                msgs.push(message::encode_removed_clients(
                    self.canvas_id,
                    removed_canvas_slots.len(),
                    removed_canvas_slots.into_iter(),
                ));
            }
            clients.truncate(idx); // fixme! test this
            self.remove_clients.clear(); // fixme! test this
        }
        let old_clients = clients.clone();

        if !self.add_clients.is_empty() {
            msgs.push(message::encode_new_clients(
                self.canvas_id,
                self.add_clients.len(),
                self.add_clients.values().map(|c| {
                    assignments.push((c.clone(), clients.len() as u8));
                    clients.push(c.clone());
                    c.get_user_id()
                }),
            ));

            self.add_clients.clear();
        }

        info!(
            "\nnow ({}) \n msgs {}, assignments {}, ",
            clients.iter().fold(String::new(), |a, c| format!(
                "{a} {:?}-{:?}",
                c.get_slot(),
                c.get_user_id()
            )),
            msgs.len(),
            assignments.len(),
        );

        let all_clients = if assignments.is_empty() {
            Bytes::new()
        } else {
            message::encode_new_clients(
                self.canvas_id,
                self.add_clients.len(),
                clients.iter().map(|c| c.get_user_id()),
            )
        };

        Some((old_clients, msgs, assignments, all_clients))
    }
    fn try_send_moves(&mut self) {
        if self.moves.is_empty() {
            return;
        }
        let moves = std::mem::take(&mut self.moves);
        let moves = Bytes::from(moves);
        for client in &self.clients {
            client.send_binary_unless_half_full(&moves);
        }
    }

    fn fulfill_flush(&mut self, when: Instant) -> bool {
        if let Some(ref timer) = self.timer
            && timer.when == when
        {
            self.timer.take();
            return true;
        }
        false
    }
}

#[derive(Clone)]
pub struct Canvas {
    inner: Arc<RwLock<CanvasInner>>,
}
impl Canvas {
    pub fn new(canvas_id: Id) -> Self {
        Self {
            inner: Arc::new(RwLock::new(CanvasInner {
                canvas_id,
                ..Default::default()
            })),
        }
    }

    pub fn cursor_move(&self, slot: u8, data: &[u8]) {
        self.write().cursor_move(self, slot, data);
    }

    pub fn add_client(&self, client: &ClientSession) {
        self.write().add(self, client);
    }

    pub fn remove_client(client: &ClientSession) {
        let info = client.get_canvas_info();
        if let Some(canvas) = &info.canvas {
            canvas.write().remove(canvas, client);
            client.set_canvas_info(Default::default());
        }
    }

    fn write(&'_ self) -> RwLockWriteGuard<'_, CanvasInner> {
        self.inner.write().expect("poisoned")
    }

    fn read(&'_ self) -> RwLockReadGuard<'_, CanvasInner> {
        self.inner.read().expect("poisoned")
    }

    fn wake_after(self, when: Instant) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let now = Instant::now();
            if when > now {
                tokio::time::sleep(when - now).await;
            }
            self.flush(when).await;
        })
    }

    async fn flush(&self, when: Instant) {
        let (canvas_id, assignments) = {
            let mut guard = self.write();
            if !guard.fulfill_flush(when) {
                return;
            }
            guard.try_send_moves();
            (guard.canvas_id, guard.extract_assignment_messages())
        };
        if let Some((clients, messages, per_client, all_clients)) = assignments {
            if !all_clients.is_empty() {
                for (client, canvas_slot) in per_client {
                    client.set_canvas_slot(canvas_slot);
                    client
                        .send_binary(message::encode_assign_slot(canvas_id, canvas_slot))
                        .await;
                    client.send_binary(all_clients.clone()).await;
                }
            }
            for data in messages {
                for client in &clients {
                    client.send_binary(data.clone()).await;
                }
            }
        }
    }

    pub fn get_canvas_id(&self) -> Id {
        self.read().canvas_id
    }
}

#[cfg(test)]
#[path = "canvas_test.rs"]
mod test;
