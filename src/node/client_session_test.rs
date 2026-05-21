use tokio::task::JoinSet;

use crate::{
    node::{
        self, Task,
        remote_cursors::{self, canvas},
    },
    test_helper,
};

use super::*;

#[tokio::test(start_paused = true)]
async fn remote_cursors_new_client() {
    test_helper::async_test(async {
        let mut jset = JoinSet::new();

        jset.spawn(Task::scope(async move {
            let client_id = "client123".into();
            let canvas_id: Id = "canvas12".into();

            let (client_sess, mut client_rx) = node::test_helper::client_session(2, "user1", "db1");
            let (client2_sess, _client2_rx) = node::test_helper::client_session(3, "user2", "db1");
            client_sess
                .route_upstream_binary_message(remote_cursors::message::encode_new_client(
                    client_id, canvas_id,
                ))
                .await
                .unwrap();

            tokio::time::advance(Duration::from_millis(2)).await;
            assert!(client_rx.try_recv().is_err());

            let cdb = Task::cursor_db().get_canvas_db(client_sess.get_db_id());
            let canvas = cdb.get(canvas_id).unwrap();

            assert_eq!(canvas.get_canvas_id(), canvas_id);

            tokio::time::advance(canvas::ADD_DELAY).await;

            assert!(client_rx.recv().await.is_some());
            assert!(client_rx.try_recv().is_ok());
            assert!(client_rx.try_recv().is_err());

            client2_sess
                .route_upstream_binary_message(remote_cursors::message::encode_new_client(
                    "user2".into(),
                    canvas_id,
                ))
                .await
                .unwrap();

            tokio::time::advance(canvas::ADD_DELAY).await;

            let msg = client_rx.recv().await.unwrap();
            let msg = msg.as_payload();
            let clients: Vec<_> = remote_cursors::message::decode_clients(&msg)
                .map(|i| i.to_string())
                .collect();

            assert_eq!(clients, &["user2"]);
        }));

        test_helper::assert_join_set(jset, 500).await;
        Ok(())
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn remote_cursors_broadcast() {
    test_helper::async_test(async {
        let mut jset = JoinSet::new();

        jset.spawn(Task::scope(async move {
            let client_id = "client123".into();
            let client2_id = "client456".into();
            let canvas_id: Id = "canvas12".into();

            let (client_sess, mut client_rx) = node::test_helper::client_session(2, "user1", "db1");
            let (client2_sess, mut client2_rx) =
                node::test_helper::client_session(3, "user2", "db1");

            client_sess
                .route_upstream_binary_message(remote_cursors::message::encode_new_client(
                    client_id, canvas_id,
                ))
                .await
                .unwrap();

            client2_sess
                .route_upstream_binary_message(remote_cursors::message::encode_new_client(
                    client2_id, canvas_id,
                ))
                .await
                .unwrap();

            assert!(client_rx.recv().await.is_some());
            assert!(client2_rx.recv().await.is_some());
            while client_rx.try_recv().is_ok() {}
            while client2_rx.try_recv().is_ok() {}

            let emesg = remote_cursors::message::encode_broadcast(5, &[1, 2, 3]);

            let cmsg = Message::binary(emesg);

            client_sess.route_client_message(cmsg).await.unwrap();

            let msg = client2_rx.recv().await.unwrap();
            let msg = msg.as_payload();
            let (slot, data) = remote_cursors::message::decode_broadcast(&msg);

            assert_eq!(slot, client_sess.get_canvas_info().slot);
            assert_eq!(data, &[1, 2, 3]);

            assert!(client_rx.try_recv().is_err());
        }));

        test_helper::assert_join_set(jset, 500).await;
        Ok(())
    })
    .await;
}

#[test]
fn send_binary_unless_half_full() {
    let (client_sess, mut client_rx) = node::test_helper::client_session(2, "user1", "db1");
    static MSG: &[u8] = &[1, 2, 3];
    let data = Bytes::from_static(MSG);
    for _ in 0..18 {
        client_sess.send_binary_unless_half_full(&data);
    }
    assert_eq!(client_sess.inner.client_sink.capacity(), 16);
    while let Ok(ans) = client_rx.try_recv() {
        assert_eq!(&ans.as_payload()[..], MSG);
    }
    assert_eq!(client_sess.inner.client_sink.capacity(), 32);
}
