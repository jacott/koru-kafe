use http::{Uri, header};
use pretty_assertions::assert_matches;

use crate::{
    test_helper,
    test_util::{self, init_node},
};

use super::*;

#[test]
fn init_message() {
    let comms = NodeJsConn {
        version: Bytes::from_static(b"v1.7.0-64-sdfdfsd"),
        version_hash: Bytes::from_static(b"123456"),
        full_msg: Bytes::from_static(b"full_msg"),
        dict_msg: Bytes::from_static(b"dict_msg"),
        short_msg: Bytes::from_static(b"short_msg"),
        ..Default::default()
    };
    assert_eq!(&comms.init_message(1), &Bytes::new());
    assert_eq!(&comms.init_message(2), &Bytes::new());
    assert_eq!(&comms.init_message(VERSION_CLIENT_BEHIND), &comms.full_msg);
    assert_eq!(
        &comms.init_message(VERSION_GOOD_DICTIONARY),
        &comms.short_msg
    );
    assert_eq!(&comms.init_message(VERSION_BAD_DICTIONARY), &comms.dict_msg);
}

#[test]
fn is_reload() {
    let mut authc = ClientConnect {
        task: Default::default(),
        version_match: VERSION_GOOD_DICTIONARY,
        init_message: Bytes::from_static(b"short_msg"),
        slot: 2.into(),
        upstream_tx: mpsc::channel(1).0,
    };
    assert!(!authc.is_reload());
    authc.version_match = 2;
    assert!(authc.is_reload());
}

#[tokio::test]
async fn connect_client() {
    test_helper::async_test(async {
        let (koru_node, mut njs_rx) = init_node();
        let mut req =
            crate::Request::new(test_util::build_incoming_body(Bytes::new()).await.unwrap());
        *req.uri_mut() = Uri::from_static("/abc/def?hello=word");
        req.headers_mut()
            .append(header::HOST, "foo.com".parse().unwrap());

        let ip_addr = IpAddr::from([127, 0, 0, 1]);
        let (msg, mut rx) = ClientConnectMessage::new(&req, &ip_addr);
        let outbytes = msg.bytes();
        assert_eq!(
            &outbytes[..],
            b"/abc/def?hello=word\x00127.0.0.1\0host\xfffoo.com\0"
        );

        let mut jset = JoinSet::new();

        jset.spawn(Task::scope(async move {
            let slot = koru_node.connect_client(msg).await.unwrap();

            let creq = njs_rx.recv().await.unwrap();
            assert_matches!(creq.msg, Msg::Connect(_));
            assert_eq!(outbytes, creq.msg.as_bytes());

            koru_node
                .get_client(slot)
                .unwrap()
                .send(ClientMessage::Msg(Msg::Text("hello".into())))
                .await
                .unwrap();

            let resp = rx.recv().await.unwrap();
            if let ClientMessage::Msg(msg) = resp {
                assert_eq!(msg.as_bytes(), b"hello");
            } else {
                panic!("Expected AuthClient message");
            }
        }));

        test_helper::assert_join_set(jset, 500).await;
        Ok(())
    })
    .await;
}

#[tokio::test]
async fn connect_client_no_nodejs() {
    test_helper::async_test(async {
        let mut jset = JoinSet::new();

        jset.spawn(Task::scope(async move {
            let (koru_node, _) = init_node();
            let req =
                crate::Request::new(test_util::build_incoming_body(Bytes::new()).await.unwrap());

            let ip_addr = IpAddr::from([127, 0, 0, 1]);
            let (msg, mut rx) = ClientConnectMessage::new(&req, &ip_addr);

            koru_node.connect_client(msg).await;

            let resp = rx.recv().await.unwrap();
            assert_matches!(resp, ClientMessage::Err(StatusCode::SERVICE_UNAVAILABLE));
        }));

        test_helper::assert_join_set(jset, 500).await;
        Ok(())
    })
    .await;
}
