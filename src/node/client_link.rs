use std::{
    any::Any,
    net::IpAddr,
    pin::pin,
    sync::{
        Arc,
        atomic::{self, Ordering},
    },
};

use async_trait::async_trait;
use futures_util::{Sink, SinkExt, Stream, StreamExt, future::select};
use http::StatusCode;
use http_body_util::BodyExt;
use hyper::Response;
use tokio::sync::mpsc::{self, error::TryRecvError};

use crate::{
    Req, ResultResp,
    domain::{Domain, Location},
    info,
    node::{
        ClientConnectMessage,
        client_session::{ClientSession, SESSION_TIMEOUT},
        remote_cursors::canvas::Canvas,
        upstream_link::{Frame, Msg},
    },
    static_resp,
    websockets::{self, Message},
};

use super::{ClientConnect, ClientMessage, KoruNode};

async fn handle_client(
    mut req: Req,
    upstream_rx: mpsc::Receiver<ClientMessage>,
    authc: ClientConnect,
) -> crate::Result<()> {
    let ws = websockets::upgrade(&mut req).await?;
    let (mut ws_s, ws_r) = ws.split();

    let (ws_tx, ws_rx) = mpsc::channel(32);

    let alive = Arc::new(atomic::AtomicBool::new(true));

    if authc.is_reload() {
        Err("reload client")?;
    }

    let ClientConnect {
        init_message,
        slot,
        upstream_tx,
        task,
        ..
    } = authc;

    ws_s.send(Message::binary(init_message)).await?;

    task.with(async move {
        let sess = ClientSession::new(slot, ws_tx.clone(), upstream_tx);

        let to_client = send_to_client(ws_s, ws_rx);
        let from_client = receive_from_client(&sess, ws_r, alive.clone());

        let from_upstream = receive_from_upstream(sess.clone(), upstream_rx);

        let timeout = async move {
            loop {
                tokio::time::sleep(SESSION_TIMEOUT).await;
                if !alive.load(Ordering::Relaxed) {
                    break;
                }

                alive.store(false, Ordering::Relaxed);
            }
        };

        let _ = select(
            select(pin!(to_client), pin!(from_upstream)),
            select(pin!(from_client), pin!(timeout)),
        )
        .await;

        Canvas::remove_client(&sess);
    })
    .await;

    Ok(())
}

async fn receive_from_upstream(
    sess: ClientSession,
    mut upstream_rx: mpsc::Receiver<ClientMessage>,
) {
    while let Some(ClientMessage::Msg(msg)) = upstream_rx.recv().await {
        let is_done = match msg {
            Msg::Binary(bytes) => sess.route_upstream_binary_message(bytes).await.is_err(),
            Msg::Text(bytes) => sess.route_upstream_text_message(bytes).await.is_err(),
            Msg::Close => true,
            Msg::Connect(_) => panic!("Received connect msg"),
        };
        if is_done {
            break;
        }
    }
}

// Define S as the generic stream, and E as a generic error
async fn receive_from_client<S, E>(
    client_sess: &ClientSession,
    mut ws_r: S,
    alive: Arc<atomic::AtomicBool>,
) -> crate::Result<()>
where
    // S must be a Stream that yields a Result containing a WebSocket Message
    S: Stream<Item = Result<Message, E>> + Unpin,
    // E can be any type, as your code simply discards errors with Err(_) => break
{
    while let Some(msg) = ws_r.next().await {
        match msg {
            Ok(msg) => {
                alive.store(true, Ordering::Relaxed);
                client_sess.route_client_message(msg).await?;
            }
            Err(_) => {
                break;
            }
        }
    }
    Ok(())
}

async fn send_to_client<S>(mut ws_s: S, mut ws_rx: mpsc::Receiver<Message>)
where
    // S must accept Messages, and must be Unpin to use SinkExt methods safely
    S: Sink<Message> + Unpin,
{
    'outer: while let Some(msg) = ws_rx.recv().await {
        if ws_s.feed(msg).await.is_err() {
            break;
        }
        loop {
            match ws_rx.try_recv() {
                Ok(msg) => {
                    if ws_s.feed(msg).await.is_err() {
                        break 'outer;
                    }
                }
                Err(TryRecvError::Empty) => {
                    if ws_s.flush().await.is_err() {
                        break 'outer;
                    }
                    break;
                }
                Err(TryRecvError::Disconnected) => break 'outer,
            }
        }
    }
}

#[derive(Debug)]
pub struct Connection {
    kn_auth_tx: mpsc::Sender<ClientConnectMessage>,
}
impl Connection {
    pub(crate) fn new() -> Self {
        let kn_auth_tx = KoruNode::start_client_connect();
        Self { kn_auth_tx }
    }

    fn upgrade_response(
        &self,
        req: Req,
        from_addr: IpAddr,
        from_js: mpsc::Receiver<ClientMessage>,
        authc: ClientConnect,
    ) -> ResultResp {
        let response = websockets::upgrade_response(&req)?;

        tokio::task::spawn(async move {
            let slot = authc.slot;
            let upstream_tx = authc.upstream_tx.clone();
            if let Err(err) = handle_client(req, from_js, authc).await {
                info!("Unexpect close -  {slot:?} {err:?}");
            } else {
                info!("close socket - {slot:?} {from_addr:?}");
            }
            let _ = upstream_tx.send(Frame::from_msg(Msg::Close, slot)).await;
        });

        let (parts, body) = response.into_parts();

        Ok(Response::from_parts(
            parts,
            body.map_err(|err| crate::Error::from(err.to_string()))
                .boxed(),
        ))
    }
}
#[async_trait]
impl Location for Connection {
    async fn connect(&self, _domain: Domain, req: Req, ip_addr: IpAddr, _count: u16) -> ResultResp {
        let (cr, mut rx) = ClientConnectMessage::new(&req, &ip_addr);
        if self.kn_auth_tx.send(cr).await.is_err() {
            return Ok(static_resp(StatusCode::SERVICE_UNAVAILABLE));
        }
        match rx.recv().await {
            Some(ClientMessage::AuthResponse(authc)) => {
                self.upgrade_response(req, ip_addr, rx, *authc)
            }
            Some(ClientMessage::Err(sc)) => Ok(static_resp(sc)),
            Some(_) => panic!("Unexpected client message"),
            None => Ok(static_resp(StatusCode::SERVICE_UNAVAILABLE)),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
#[path = "client_link_test.rs"]
mod test;
