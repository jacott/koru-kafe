use pretty_assertions::assert_matches;
use tempfile::tempdir;
use tokio::{
    net::{UnixListener, UnixStream},
    task::JoinSet,
};

use crate::test_helper;

use super::*;

#[test]
fn frame_new() {
    let frame = Frame::new(0, 123.into(), Bytes::new()).unwrap();
    assert_eq!(frame.slot, 123.into());
    assert_eq!(frame.msg.type_code(), T_CONNECT);

    let frame = Frame::new(1, 123.into(), Bytes::from_static(b"123")).unwrap();
    assert_eq!(frame.msg.type_code(), T_CLOSE);

    let frame = Frame::new(2, 123.into(), Bytes::from_static(b"123"))
        .err()
        .unwrap();
    assert_eq!(frame.to_string().as_str(), "Invalid type");

    let frame = Frame::new(3, 132.into(), Bytes::from_static(b"123")).unwrap();
    assert_eq!(frame.msg.type_code(), T_BINARY);
    assert_eq!(frame.slot, 132.into());
    assert_eq!(frame.msg.as_bytes(), b"123");

    let frame = Frame::new(4, 123.into(), Bytes::from_static(b"123")).unwrap();
    assert_eq!(frame.msg.type_code(), T_TEXT);
}

#[tokio::test]
async fn connect() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("test_socket");

    let listener = UnixListener::bind(&socket_path).unwrap();

    let mut js = JoinSet::new();

    js.spawn(async move {
        // Accept the first incoming connection.
        if let Ok((mut stream, _addr)) = listener.accept().await {
            let mut buf = [0; 3]; // small buf to ensure segmentation is handled correctly
            loop {
                match stream.read(&mut buf).await {
                    Ok(n) => {
                        if n == 0 {
                            return;
                        }

                        tokio::time::sleep(std::time::Duration::from_millis(2)).await;

                        if stream.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        }
    });

    js.spawn(async move {
        let stream = UnixStream::connect(&socket_path).await.unwrap();

        let (rx, tx) = stream.into_split();

        let mut conn_writer = KoruSocketWriter::new(tx);
        let mut conn_reader = KoruSocketReader::new(rx);

        let msg = Frame::new(T_CONNECT, 123.into(), Bytes::new()).unwrap();
        conn_writer.write_msg(&msg).await.unwrap();

        let msg = conn_reader.read_msg().await.unwrap().unwrap();

        assert_eq!(msg.slot, 123.into());
    });

    test_helper::assert_join_set(js, 0).await;
}

#[tokio::test]
async fn test_check() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("test_socket");

    let _listener = UnixListener::bind(&socket_path).unwrap();

    let mut js = JoinSet::new();

    js.spawn(async move {
        let stream = UnixStream::connect(&socket_path).await.unwrap();

        let (rx, _tx) = stream.into_split();

        let mut conn_reader = KoruSocketReader::new(rx);

        let err = conn_reader.check().err().unwrap();
        assert_matches!(err, Error::Incomplete);

        conn_reader.buffer.put_u32_le(456);

        let err = conn_reader.check().err().unwrap();

        assert_matches!(err, Error::Incomplete);

        assert_eq!(conn_reader.exp_msg_len, 0);

        conn_reader.buffer = BytesMut::new();

        conn_reader.buffer.put_u32_le(7);
        conn_reader.buffer.put_u8(b'a');

        let err = conn_reader.check().err().unwrap();

        assert_matches!(err, Error::Incomplete);

        conn_reader.buffer.put_bytes(b'b', 5);

        assert_eq!(conn_reader.check().unwrap(), 7);

        assert_eq!(&conn_reader.buffer.chunk()[4..7], b"abb");
    });

    test_helper::assert_join_set(js, 0).await;
}
