use pretty_assertions::assert_matches;
use tokio::{
    sync::mpsc::error::TryRecvError,
    task::{JoinSet, yield_now},
};

use crate::{
    node::{self, Task},
    test_helper,
};

use super::*;

async fn flush_timer(canvas: &Canvas) {
    tokio::time::advance(ADD_DELAY + Duration::from_millis(2)).await;
    while canvas.read().timer.is_some() {
        yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn double_add_client_same() {
    test_helper::async_test(async {
        let mut jset = JoinSet::new();

        jset.spawn(Task::scope(async move {
            let no_id = 0.into();
            let db_id = Id::from("db1").as_u128() as u64;
            let db = Task::cursor_db().get_canvas_db(db_id);
            let canvas_id = "canvas1".into();
            let (user1, _user1_client_rx) = node::test_helper::client_session(1, "user1", "db1");

            // add_remove client
            db.add_client(canvas_id, &user1);
            db.add_client(no_id, &user1);
            assert!(user1.get_canvas_info().canvas.is_none());
            assert_eq!(user1.get_canvas_info().slot, 255);

            let canvas = db.get_create(canvas_id);
            assert_eq!(canvas.read().clients.len(), 0);
            assert_eq!(canvas.read().remove_clients.len(), 0);
            assert_eq!(canvas.read().add_clients.len(), 0);

            // add_client
            db.add_client(canvas_id, &user1);
            db.add_client(canvas_id, &user1);
            db.add_client(canvas_id, &user1);
            assert_eq!(
                user1.get_canvas_info().canvas.unwrap().get_canvas_id(),
                canvas_id
            );
            assert_eq!(user1.get_canvas_info().slot, 255);
            assert_eq!(canvas.read().clients.len(), 0);
            assert_eq!(canvas.read().add_clients.len(), 1);

            let when = canvas.read().timer.as_ref().unwrap().when;
            canvas.flush(when).await;

            assert_eq!(canvas.read().clients.len(), 1);
            assert_eq!(canvas.read().add_clients.len(), 0);
            assert_eq!(canvas.read().remove_clients.len(), 0);
            assert_eq!(
                user1.get_canvas_info().canvas.unwrap().get_canvas_id(),
                canvas_id
            );
            assert_eq!(user1.get_canvas_info().slot, 0);

            // remove client
            db.add_client(no_id, &user1);
            db.add_client(no_id, &user1);
            db.add_client(no_id, &user1);
            assert!(user1.get_canvas_info().canvas.is_none());
            assert_eq!(user1.get_canvas_info().slot, 255);
            assert_eq!(canvas.read().clients.len(), 1);
            assert_eq!(canvas.read().remove_clients.len(), 1);
            assert_eq!(canvas.read().add_clients.len(), 0);

            let when = canvas.read().timer.as_ref().unwrap().when;
            canvas.flush(when).await;

            assert_eq!(canvas.read().remove_clients.len(), 0);
            assert_eq!(canvas.read().add_clients.len(), 0);
            assert_eq!(canvas.read().clients.len(), 0);
        }));

        test_helper::assert_join_set(jset, 500).await;
        Ok(())
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn double_add_client_different() {
    test_helper::async_test(async {
        let mut jset = JoinSet::new();

        jset.spawn(Task::scope(async move {
            let db_id = Id::from("db1").as_u128() as u64;
            let db = Task::cursor_db().get_canvas_db(db_id);
            let canvas_id1 = "canvas1".into();
            let canvas_id2 = "canvas2".into();
            let (user1, _user1_client_rx) = node::test_helper::client_session(1, "user1", "db1");

            // add_client
            db.add_client(canvas_id1, &user1);
            let canvas1 = db.get_create(canvas_id1);
            let when = canvas1.read().timer.as_ref().unwrap().when;
            canvas1.flush(when).await;

            // move client
            db.add_client(canvas_id2, &user1);
            let canvas2 = db.get_create(canvas_id2);
            assert_eq!(
                user1.get_canvas_info().canvas.unwrap().get_canvas_id(),
                canvas_id2
            );
            assert_eq!(user1.get_canvas_info().slot, 255);
            assert_eq!(canvas1.read().clients.len(), 1);
            assert_eq!(canvas1.read().remove_clients.len(), 1);
            assert_eq!(canvas1.read().add_clients.len(), 0);

            assert_eq!(canvas2.read().clients.len(), 0);
            assert_eq!(canvas2.read().remove_clients.len(), 0);
            assert_eq!(canvas2.read().add_clients.len(), 1);

            let when = canvas1.read().timer.as_ref().unwrap().when;
            canvas1.flush(when).await;
            let when = canvas2.read().timer.as_ref().unwrap().when;
            canvas2.flush(when).await;

            assert_eq!(canvas1.read().clients.len(), 0);
            assert_eq!(canvas1.read().remove_clients.len(), 0);
            assert_eq!(canvas1.read().add_clients.len(), 0);

            assert_eq!(canvas2.read().clients.len(), 1);
            assert_eq!(canvas2.read().remove_clients.len(), 0);
            assert_eq!(canvas2.read().add_clients.len(), 0);

            // move back, nah
            db.add_client(canvas_id1, &user1);
            assert_eq!(
                user1.get_canvas_info().canvas.unwrap().get_canvas_id(),
                canvas_id1
            );
            assert_eq!(user1.get_canvas_info().slot, 255);
            assert_eq!(canvas2.read().remove_clients.len(), 1);
            assert_eq!(canvas1.read().add_clients.len(), 1);

            db.add_client(canvas_id2, &user1);
            assert_eq!(
                user1.get_canvas_info().canvas.unwrap().get_canvas_id(),
                canvas_id2
            );
            assert_eq!(user1.get_canvas_info().slot, 255);
            assert_eq!(canvas2.read().remove_clients.len(), 0);
            assert_eq!(canvas1.read().add_clients.len(), 0);
        }));

        test_helper::assert_join_set(jset, 500).await;
        Ok(())
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn extract_assignment_messages_add() {
    test_helper::async_test(async {
        let mut jset = JoinSet::new();

        jset.spawn(Task::scope(async move {
            let db_id = Id::from("db1").as_u128() as u64;
            let db = Task::cursor_db().get_canvas_db(db_id);
            let canvas_id1 = "canvas1".into();

            let (user1, _user1_client_rx) = node::test_helper::client_session(1, "user1", "db1");
            let (user2, _user2_client_rx) = node::test_helper::client_session(2, "user2", "db1");
            let (user3, _user3_client_rx) = node::test_helper::client_session(3, "user3", "db1");

            // add_clients
            db.add_client(canvas_id1, &user1);
            db.add_client(canvas_id1, &user2);
            db.add_client(canvas_id1, &user3);

            let canvas = user1.get_canvas_info().canvas.unwrap();
            assert_eq!(canvas.read().remove_clients.len(), 0);
            assert_eq!(canvas.read().add_clients.len(), 3);
            assert_eq!(canvas.read().clients.len(), 0);

            let (old_clients, messages, per_client, all_clients) =
                canvas.write().extract_assignment_messages(&canvas).unwrap();

            assert_eq!(old_clients.len(), 0);
            assert_eq!(all_clients.len(), 66);
            assert_eq!(per_client.len(), 3);
            assert_eq!(messages.len(), 1);

            assert_eq!(canvas.read().remove_clients.len(), 0);
            assert_eq!(canvas.read().add_clients.len(), 0);
            assert_eq!(canvas.read().clients.len(), 3);
        }));

        test_helper::assert_join_set(jset, 500).await;
        Ok(())
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn extract_assignment_messages_remove() {
    test_helper::async_test(async {
        let mut jset = JoinSet::new();

        jset.spawn(Task::scope(async move {
            let db_id = Id::from("db1").as_u128() as u64;
            let db = Task::cursor_db().get_canvas_db(db_id);
            let canvas_id1 = "canvas1".into();

            let (user1, _user1_client_rx) = node::test_helper::client_session(1, "user1", "db1");
            let (user2, _user2_client_rx) = node::test_helper::client_session(2, "user2", "db1");
            let (user3, _user3_client_rx) = node::test_helper::client_session(3, "user3", "db1");

            // add_clients
            db.add_client(canvas_id1, &user1);
            let canvas = user1.get_canvas_info().canvas.unwrap();
            canvas.write().extract_assignment_messages(&canvas).unwrap();
            db.add_client(canvas_id1, &user2);
            canvas.write().extract_assignment_messages(&canvas).unwrap();
            db.add_client(canvas_id1, &user3);
            canvas.write().extract_assignment_messages(&canvas).unwrap();

            assert_eq!(user1.get_canvas_info().slot, 0);
            assert_eq!(user2.get_canvas_info().slot, 1);
            assert_eq!(user3.get_canvas_info().slot, 2);

            db.add_client(0.into(), &user2);

            let (old_clients, messages, per_client, all_clients) =
                canvas.write().extract_assignment_messages(&canvas).unwrap();

            assert_eq!(old_clients.len(), 2);
            assert_eq!(all_clients.len(), 0);
            assert_eq!(per_client.len(), 0);
            assert_eq!(messages.len(), 1);

            assert_eq!(canvas.read().remove_clients.len(), 0);
            assert_eq!(canvas.read().add_clients.len(), 0);
            assert_eq!(canvas.read().clients.len(), 2);

            assert_eq!(user1.get_canvas_info().slot, 0);
            assert_eq!(user2.get_canvas_info().slot, 255);
            assert_eq!(user3.get_canvas_info().slot, 1);
        }));

        test_helper::assert_join_set(jset, 500).await;
        Ok(())
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn add_remove_client() {
    test_helper::async_test(async {
        let mut jset = JoinSet::new();

        jset.spawn(Task::scope(async move {
            let db_id = Id::from("db1").as_u128() as u64;
            let db = Task::cursor_db().get_canvas_db(db_id);
            let canvas_id = "canvas1".into();
            let (user1, _user1_client_rx) = node::test_helper::client_session(1, "user1", "db1");
            let (user2, _user2_client_rx) = node::test_helper::client_session(2, "user2", "db1");

            db.add_client(canvas_id, &user1);
            db.add_client(canvas_id, &user2);
            let canvas = user1.get_canvas_info().canvas.unwrap();
            Canvas::drop_client(&user1);
            assert_eq!(canvas.read().add_clients.len(), 1);

            tokio::time::advance(Duration::from_millis(1)).await;
            let when = canvas.read().timer.as_ref().unwrap().when;

            // time needs to match
            canvas.flush(when - Duration::from_millis(1)).await;
            assert_eq!(canvas.read().add_clients.len(), 1);

            canvas.flush(when).await;

            assert_eq!(canvas.read().add_clients.len(), 0);

            assert_eq!(user1.get_canvas_info().slot, 255);
            assert_eq!(user2.get_canvas_info().slot, 0);

            db.add_client(canvas_id, &user1);

            let when = canvas.read().timer.as_ref().unwrap().when;
            canvas.flush(when).await;

            assert_eq!(canvas.read().add_clients.len(), 0);
            assert_eq!(user1.get_canvas_info().slot, 1);

            Canvas::drop_client(&user2);
            canvas.flush(when).await;

            assert_eq!(user1.get_canvas_info().slot, 0);
            assert_eq!(user2.get_canvas_info().slot, 255);
        }));

        test_helper::assert_join_set(jset, 500).await;
        Ok(())
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn sending_slot_assignments() {
    test_helper::async_test(async {
        let mut jset = JoinSet::new();

        jset.spawn(Task::scope(async move {
            let db_id: Id = "db1".into();
            let db_id: u128 = db_id.into();
            let db_id = db_id as u64;
            let db = Task::cursor_db().get_canvas_db(db_id);
            let canvas_id = "canvas1".into();
            let (user1, mut user1_client_rx) = node::test_helper::client_session(1, "user1", "db1");
            let (user2, mut user2_client_rx) = node::test_helper::client_session(2, "user2", "db1");

            db.add_client(canvas_id, &user1);
            let canvas = user1.get_canvas_info().canvas.unwrap();
            assert_eq!(canvas.get_canvas_id(), canvas_id);
            let when = canvas.inner.read().unwrap().timer.as_ref().unwrap().when;

            db.add_client(canvas_id, &user2);
            let canvas_copy = db.get(canvas_id).unwrap();
            tokio::time::advance(Duration::from_millis(1)).await;

            // don't change timer
            assert_eq!(canvas.read().timer.as_ref().unwrap().when, when);

            assert_matches!(user1_client_rx.try_recv(), Err(TryRecvError::Empty));

            assert!(canvas.inner.read().unwrap().timer.is_some());
            tokio::time::advance(ADD_DELAY).await;

            while canvas.read().timer.is_some() {
                yield_now().await;
            }

            // my slot
            let msg = user1_client_rx.try_recv().unwrap();
            assert!(msg.is_binary());
            let msg = msg.as_payload();
            assert_eq!(msg[0], message::CURSOR_CMD);
            assert_eq!(msg[1], message::ASSIGN_SLOT);
            assert_eq!(message::decode_canvas(msg), canvas_id);
            let u1_slot = message::decode_assigned_slot(msg);

            let msg = user2_client_rx.try_recv().unwrap();
            let msg = msg.as_payload();
            let u2_slot = message::decode_assigned_slot(msg);

            assert_eq!(u2_slot + u1_slot, 1);

            // new clients
            let msg = user1_client_rx.try_recv().unwrap();
            assert!(msg.is_binary());
            let msg = msg.as_payload();
            assert_eq!(msg[0], message::CURSOR_CMD);
            assert_eq!(msg[1], message::NEW_CLIENTS);
            assert_eq!(message::decode_canvas(msg), canvas_id);

            let mut cids = message::decode_clients(msg).collect::<Vec<Id>>();
            cids.sort();
            let expids = [user1.clone(), user2.clone()].map(|c| c.get_user_id());
            assert_eq!(cids, expids);

            let canvas2_id = "canvas2".into();
            db.add_client(canvas2_id, &user1);
            let canvas2 = db.get(canvas2_id).unwrap();
            assert!(!Arc::ptr_eq(&canvas2.inner, &canvas.inner));
            assert!(Arc::ptr_eq(&canvas.inner, &canvas_copy.inner));

            flush_timer(&canvas2).await;

            let msg = user1_client_rx.try_recv().unwrap();
            assert!(msg.is_binary());
            let msg = msg.as_payload();
            assert_eq!(msg[0], message::CURSOR_CMD);
            assert_eq!(msg[1], message::ASSIGN_SLOT);
            assert_eq!(message::decode_canvas(msg), canvas2_id);
            let u1_slot = message::decode_assigned_slot(msg);
            assert_eq!(u1_slot, 0);

            let msg = user1_client_rx.try_recv().unwrap();
            assert!(msg.is_binary());
            user2_client_rx.try_recv().unwrap();

            db.add_client(canvas2_id, &user2);
            flush_timer(&canvas2).await;
            user2_client_rx.try_recv().unwrap();
            user2_client_rx.try_recv().unwrap();
            user2_client_rx.try_recv().unwrap();

            Canvas::drop_client(&user1);

            assert_eq!(canvas2.read().clients.len(), 2);
            assert_eq!(canvas2.read().remove_clients.len(), 1);
            assert_eq!(canvas2.read().add_clients.len(), 0);

            flush_timer(&canvas2).await;

            assert_eq!(canvas2.read().clients.len(), 1);
            assert_eq!(canvas2.read().remove_clients.len(), 0);
            assert_eq!(canvas2.read().add_clients.len(), 0);

            let msg = user2_client_rx.try_recv().unwrap();
            assert!(msg.is_binary());
            let msg = msg.as_payload();
            assert_eq!(msg[0], message::CURSOR_CMD);
            assert_eq!(msg[1], message::REMOVED_CLIENTS);
            assert_eq!(message::decode_canvas(msg), canvas2_id);
            assert_eq!(message::decode_removes(msg).collect::<Vec<u8>>(), vec![0],);

            assert_eq!(user2.get_canvas_info().slot, 0);
        }));

        test_helper::assert_join_set(jset, 500).await;
        Ok(())
    })
    .await;
}
