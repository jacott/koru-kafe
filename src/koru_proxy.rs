use fastwebsockets::{handshake, upgrade, Frame, OpCode};
use hyper::{http::HeaderValue, Body, Client, Request, Response, Version};
use std::{future::Future, net::IpAddr};
use tokio::net::TcpStream;

use crate::Result;

fn convert_req(req: &mut Request<Body>, ip_addr: &IpAddr) {
    *req.version_mut() = Version::HTTP_11;

    let headers = req.headers_mut();

    headers.insert(
        "X-Real-IP",
        HeaderValue::from_str(ip_addr.to_string().as_str()).unwrap(),
    );
}

// Tie hyper's executor to tokio runtime
struct SpawnExecutor;

impl<Fut> hyper::rt::Executor<Fut> for SpawnExecutor
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    fn execute(&self, fut: Fut) {
        tokio::task::spawn(fut);
    }
}

pub async fn websocket(fut: upgrade::UpgradeFut, mut req: Request<Body>, ip_addr: IpAddr) -> Result<()> {
    convert_req(&mut req, &ip_addr);

    let mut ws_r = fut.await?;
    ws_r.set_writev(true);
    ws_r.set_auto_close(true);
    ws_r.set_auto_pong(true);

    let stream = TcpStream::connect("127.0.0.1:3000").await?;
    let (mut ws_w, _) = handshake::client(&SpawnExecutor, req, stream).await?;

    loop {
        tokio::select! {
            frame = ws_r.read_frame() => {
                let frame = frame?;
                match frame.opcode {
                    OpCode::Close => break,
                    OpCode::Text | OpCode::Binary => {
                        let frame = Frame::new(true, frame.opcode, None, frame.payload);
                        ws_w.write_frame(frame).await?;
                    }
                    _ => {}
                }
            }
            frame = ws_w.read_frame() => {
                let frame = frame?;
                match frame.opcode {
                    OpCode::Close => break,
                    OpCode::Text | OpCode::Binary => {
                        let frame = Frame::new(true, frame.opcode, None, frame.payload);
                        ws_r.write_frame(frame).await?;
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

pub async fn pass(mut req: Request<Body>, ip_addr: IpAddr, server_socket: &str) -> crate::Result<Response<Body>> {
    convert_req(&mut req, &ip_addr);

    *req.uri_mut() = format!(
        "http://{}{}",
        server_socket,
        req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/")
    )
    .parse()
    .unwrap();

    let client = Client::new();

    Ok(client.request(req).await?)
}
