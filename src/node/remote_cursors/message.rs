use std::cmp::min;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::id::Id;

pub const CURSOR_CMD: u8 = b'>';

pub const MOVE: u8 = 0;
//   const AttachShape = 1;
pub const NEW_CLIENTS: u8 = 2;
pub const REMOVED_CLIENTS: u8 = 3;
pub const ASSIGN_SLOT: u8 = 4;

pub const ID_LEN: usize = std::mem::size_of::<u128>();
pub const COORD_SIZE: usize = 4;
pub const MOVE_SIZE: usize = COORD_SIZE + 1;

pub fn add_move(moves: &mut Vec<u8>, slot: u8, data: &[u8]) {
    let moves2 = moves.get_mut(2..).expect("should have header");
    if let Some(chunk) = moves2.chunks_exact_mut(MOVE_SIZE).find(|c| c[0] == slot) {
        chunk[1..].copy_from_slice(data);
    } else {
        moves.push(slot);
        moves.extend_from_slice(data);
    }
}

pub fn encode_new_client(client_id: Id, canvas_id: Id) -> Bytes {
    encode_new_clients(canvas_id, 1, std::iter::once(client_id))
}

pub fn encode_new_clients(
    canvas_id: Id,
    len: usize,
    client_ids: impl Iterator<Item = Id>,
) -> Bytes {
    let mut msg = BytesMut::with_capacity((1 + len) * ID_LEN + 2);
    msg.put_u8(CURSOR_CMD);
    msg.put_u8(NEW_CLIENTS);
    msg.put_u128_le(canvas_id.as_u128());
    for id in client_ids {
        msg.put_u128_le(id.as_u128())
    }
    msg.freeze()
}

pub fn encode_assign_slot(canvas_id: Id, canvas_slot: u8) -> Bytes {
    let mut msg = BytesMut::with_capacity(2 + ID_LEN + 1);
    msg.put_u8(CURSOR_CMD);
    msg.put_u8(ASSIGN_SLOT);
    msg.put_u128_le(canvas_id.as_u128());
    msg.put_u8(canvas_slot);
    msg.freeze()
}

pub fn encode_removed_clients(
    canvas_id: Id,
    len: usize,
    client_slots: impl Iterator<Item = u8>,
) -> Bytes {
    let mut msg = BytesMut::with_capacity(len + 2 + ID_LEN);
    msg.put_u8(CURSOR_CMD);
    msg.put_u8(REMOVED_CLIENTS);
    msg.put_u128_le(canvas_id.as_u128());
    for canvas_slot in client_slots {
        msg.put_u8(canvas_slot)
    }
    msg.freeze()
}

pub fn decode_canvas(mut msg: Bytes) -> Id {
    if msg.len() < ID_LEN + 2 {
        Id::default()
    } else {
        msg.advance(2);
        msg.get_u128_le().into()
    }
}

pub fn decode_clients(mut msg: Bytes) -> impl Iterator<Item = Id> {
    msg.advance(min(msg.remaining(), 2 + ID_LEN));

    let count = msg.remaining() / ID_LEN;
    std::iter::repeat_with(move || msg.get_u128_le().into()).take(count)
}

pub fn decode_removes(mut msg: Bytes) -> impl Iterator<Item = u8> {
    msg.advance(min(msg.remaining(), 2 + ID_LEN));

    let count = msg.remaining();
    std::iter::repeat_with(move || msg.get_u8()).take(count)
}

pub fn decode_assigned_slot(mut msg: Bytes) -> u8 {
    msg.advance(min(msg.remaining(), 2 + ID_LEN));
    msg.get_u8()
}

#[cfg(test)]
#[path = "message_test.rs"]
mod test;
