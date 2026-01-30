use bytes::Buf;
use http_body_util::Empty;
use hyper::server::conn::http1;
use hyper::{Request, Result};
use hyper::{
    body::{Bytes, Incoming},
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::DuplexStream;
use tokio::sync::mpsc;

use crate::{
    Jst,
    message::{Encoder, GlobalDictEncoder},
    node::{KoruNode, upstream_link::Frame},
};
use crate::{ResultResp, node, resp};

// An async function that consumes a request, does nothing with it and returns a
// response.
async fn make_response(_req: Request<Incoming>, msg: Bytes) -> ResultResp {
    Ok(resp(200, msg))
}

async fn fetch_incoming(stream: DuplexStream) -> Result<Incoming> {
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::task::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::get("http://x")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let res = sender.send_request(req).await?;

    Ok(res.into_body())
}

pub async fn build_incoming_body(msg: Bytes) -> Result<Incoming> {
    let (client, server) = tokio::io::duplex(5);

    let io = TokioIo::new(server);
    // Spin up a new task in Tokio so we can continue to listen for new TCP connection on the
    // current task without waiting for the processing of the HTTP1 connection we just received
    // to finish
    tokio::task::spawn(async move {
        // Handle the connection from the client using HTTP1 and pass any
        // HTTP requests received on that connection to the `hello` function
        let _ = http1::Builder::new()
            .timer(TokioTimer::new())
            .serve_connection(io, service_fn(|r| make_response(r, msg.clone())))
            .await;
    });

    fetch_incoming(client).await
}

pub(crate) fn set_init_msg(koru_node: &KoruNode) -> mpsc::Receiver<Frame> {
    let (upstream_tx, upstream_rx) = mpsc::channel(1);
    let gde = GlobalDictEncoder::default();

    let mut enc = Encoder::message(b'X', &gde);
    enc.add(&Jst::string("dev"));
    enc.add(&Jst::string("hash"));
    enc.add(&Jst::bin(&b"hello\xff\0"[..]));
    enc.add(&Jst::string("dicthash"));
    let mut msg = enc.encode();
    let msg = msg.copy_to_bytes(msg.remaining());

    koru_node.set_init_msg(msg, upstream_tx);

    upstream_rx
}

pub(crate) fn init_node() -> (KoruNode, mpsc::Receiver<Frame>) {
    let koru_node = node::KoruNode::new("test/uds".to_owned());
    let njs_rx = crate::test_util::set_init_msg(&koru_node);
    node::Task::global().add_ts_node(koru_node.clone());
    (koru_node, njs_rx)
}
