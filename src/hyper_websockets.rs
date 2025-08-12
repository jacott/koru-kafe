use digest::Digest;
use http::Response;
use http_body_util::Empty;
use hyper::{body::Bytes, upgrade::Upgraded};
use hyper_util::rt::TokioIo;
use sha1::Sha1;
use tokio_websockets::{server, upgrade};

pub type UpgradedWebsocket = tokio_websockets::WebSocketStream<TokioIo<Upgraded>>;

pub fn upgrade_response(request: &mut crate::Req) -> crate::Result<Response<Empty<Bytes>>> {
    let key = request
        .headers()
        .get("Sec-WebSocket-Key")
        .ok_or("MissingSecWebSocketKey")?;

    if request.headers().get("Sec-WebSocket-Version").map(|v| v.as_bytes()) != Some(b"13") {
        return Err("MissingSecWebSocketVersionHeader".into());
    }

    let response = upgrade::Response::builder()
        .status(hyper::StatusCode::SWITCHING_PROTOCOLS)
        .header(hyper::header::CONNECTION, "upgrade")
        .header(hyper::header::UPGRADE, "websocket")
        .header("Sec-WebSocket-Accept", &derive_accept_key(key.as_bytes()))
        .body(Empty::new())
        .expect("bug: failed to build response");

    Ok(response)
}

fn derive_accept_key(request_key: &[u8]) -> String {
    // ... field is constructed by concatenating /key/ ...
    // ... with the string "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" (RFC 6455)
    const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut sha1 = Sha1::default();
    sha1.update(request_key);
    sha1.update(WS_GUID);
    data_encoding::BASE64.encode(&sha1.finalize())
}

pub async fn upgrade(request: &mut crate::Req) -> crate::Result<UpgradedWebsocket> {
    let upgraded = hyper::upgrade::on(request).await?;
    let stream = TokioIo::new(upgraded);
    let ws = server::Builder::new().serve(stream);

    Ok(ws)
}
