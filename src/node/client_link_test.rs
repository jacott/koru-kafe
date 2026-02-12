use std::sync::atomic::AtomicBool;

use futures_util::stream;
use pretty_assertions::assert_matches;
use tokio::task::JoinSet;

use crate::{
    node::{Task, session_manager::Slot},
    test_helper,
};

use super::*;

// fixme! do I still need this?
// use std::task::{Context, Poll};

// struct MockSink {
//     messages: mpsc::Sender<Message>,
// }
// impl Sink<Message> for MockSink {
//     type Error = mpsc::error::TrySendError<Message>;

//     fn poll_ready(
//         self: Pin<&mut Self>,
//         _cx: &mut Context<'_>,
//     ) -> std::task::Poll<Result<(), Self::Error>> {
//         Poll::Ready(Ok(()))
//     }

//     fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
//         self.messages.try_send(item)?;
//         Ok(())
//     }

//     fn poll_flush(
//         self: Pin<&mut Self>,
//         _cx: &mut Context<'_>,
//     ) -> std::task::Poll<Result<(), Self::Error>> {
//         Poll::Ready(Ok(()))
//     }

//     fn poll_close(
//         self: Pin<&mut Self>,
//         _cx: &mut Context<'_>,
//     ) -> std::task::Poll<Result<(), Self::Error>> {
//         Poll::Ready(Ok(()))
//     }
// }

#[tokio::test]
async fn test_heartbeat() {
    test_helper::async_test(async {
        let mut jset = JoinSet::new();

        jset.spawn(Task::scope(async move {
            let alive = Arc::new(AtomicBool::new(false));
            let (ws_tx, mut ws_rx) = mpsc::channel(10);
            let (upstream_tx, mut upstream_rx) = mpsc::channel(10);
            let slot: Slot = 1.into();
            let client_sess = ClientSession::new(slot, ws_tx.clone(), upstream_tx);

            // 2. Create a sequence of mock messages (Heartbeat followed by a Data message)
            let messages: Vec<Result<Message, std::io::Error>> =
                vec![Ok(Message::text("H")), Ok(Message::text("Hello World"))];
            let mock_stream = stream::iter(messages);

            // 3. Run the handler
            // Note: This finishes because mock_stream eventually returns None
            receive_from_client(&client_sess, mock_stream, alive.clone()).await;

            // 4. Assertions for Heartbeat ('H' -> 'K')
            assert!(
                alive.load(Ordering::Relaxed),
                "Heartbeat should set alive to true"
            );

            let response = ws_rx
                .recv()
                .await
                .expect("Should have received a response to H");
            assert!(
                response.as_payload().starts_with(b"K"),
                "Response should be a 'K' message"
            );

            // 5. Assertions for Forwarding
            let forwarded = upstream_rx
                .recv()
                .await
                .expect("Should have forwarded the second message");

            assert_matches!(forwarded.slot.into(), 1);
            assert_matches!(forwarded.msg, Msg::Text(_));
            assert_eq!(&forwarded.msg.as_bytes(), b"Hello World");
        }));

        test_helper::assert_join_set(jset, 500).await;
        Ok(())
    })
    .await;
}

#[tokio::test]
async fn vs_to_client() {
    test_helper::async_test(async {
        let mut jset = JoinSet::new();

        jset.spawn(Task::scope(async move {
            let (tx_in, rx_in) = mpsc::channel(32);
            // Use a futures mpsc channel as the Sink
            let (sink_tx, mut sink_rx) = mpsc::channel::<Message>(32);
            let slot: Slot = 1.into();
            let (upstream_tx, _upstream_rx) = mpsc::channel(10);

            let client_sess = ClientSession::new(slot, sink_tx, upstream_tx);

            // Run the handler
            tokio::spawn(receive_from_upstream(client_sess.clone(), rx_in));

            // Send messages
            tx_in
                .try_send(ClientMessage::Msg(Msg::text(
                    "VSmyuserid:authsesskey:org123",
                )))
                .unwrap();

            // Assert the sink received them
            assert_eq!(
                &sink_rx.recv().await.unwrap().as_text().unwrap(),
                &"VSmyuserid:authsesskey:org123"
            );

            assert_eq!(client_sess.get_user_id().to_string().as_str(), "myuserid");
            assert_eq!(client_sess.get_db_id_text().as_str(), "org123");
        }));

        test_helper::assert_join_set(jset, 500).await;
        Ok(())
    })
    .await;
}

// fixme! test closing client detaches from cursor canvas
