use super::*;

#[test]
fn encode_new_client() {
    let client_id = "client".into();
    let canvas_id = "canvas1".into();
    let msg = super::encode_new_client(client_id, canvas_id);
    assert_eq!(
        &msg[..],
        b">\x02\xc2]\xeary\xfe\0\0\0\0\0\0\0\0\0\0\xb8\x9c\xb6\xf0\xf9\x03\0\0\0\0\0\0\0\0\0\0",
    );
}

#[test]
fn encode_new_clients() {
    let canvas_id = "canvas1".into();
    let client1 = "xuS2FaH1T3I6KSZv9".into();
    let client2 = "jtHixB53oqvBzNnNb".into();
    let msg = super::encode_new_clients(canvas_id, 1, [client1, client2].into_iter());

    assert_eq!(decode_canvas(&msg), canvas_id);

    assert_eq!(
        decode_clients(&msg).collect::<Vec<Id>>(),
        vec![client1, client2]
    );
}

#[test]
fn encode_removed_clients() {
    let canvas_id = "canvas1".into();
    let msg = super::encode_removed_clients(canvas_id, 2, [5, 9].into_iter());

    assert_eq!(decode_canvas(&msg), canvas_id);

    assert_eq!(decode_removes(&msg).collect::<Vec<u8>>(), vec![5, 9]);
}

#[test]
fn encode_assign_slot() {
    let canvas_id = "canvas1".into();
    let msg = super::encode_assign_slot(canvas_id, 6);

    assert_eq!(decode_canvas(&msg), canvas_id);

    assert_eq!(decode_assigned_slot(&msg), 6);
}

// fixme! limit max clients
