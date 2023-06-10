use fastwebsockets::{handshake, upgrade, Frame, OpCode};
use hyper::{http::HeaderValue, Body, Client, Request, Response, Version};
use std::{
    future::Future,
    io,
    net::IpAddr,
    time::{Duration, SystemTime},
};
use tokio::{net::TcpStream, process::Command, sync::Mutex};

use crate::Result;

#[derive(Default)]
pub struct Service {
    pub server_socket: String,
    pub cmd: Option<(String, String, Vec<String>)>,
    run_lock: Mutex<()>,
}

impl Service {
    pub fn cmd_name(&self) -> Option<String> {
        self.cmd.as_ref().map(|cmd| cmd.0.to_string())
    }

    pub async fn start(&self) -> io::Result<()> {
        const ZERO_DUR: Duration = Duration::new(0, 0);
        if let Some((arg0, cmd, args)) = &self.cmd {
            let _ = self.run_lock.lock().await;
            let mut wait_time = 0;
            loop {
                let now = SystemTime::now();
                let mut child = Command::new(cmd).arg0(arg0).args(args).spawn()?;
                eprintln!("Running ({}) {}: {} {:?}", child.id().unwrap_or(0), arg0, cmd, args);
                child.wait().await?;
                if now.elapsed().unwrap_or(ZERO_DUR).as_secs() > 300 {
                    wait_time = 0;
                } else if wait_time == 0 {
                    wait_time = 1;
                } else {
                    tokio::time::sleep(Duration::new(1 << (wait_time - 1), 0)).await;
                    wait_time += 1;
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "No command for this service",
        ))
    }
}

fn convert_req(req: &mut Request<Body>, ip_addr: &IpAddr) {
    *req.version_mut() = Version::HTTP_11;

    let headers = req.headers_mut();

    if let Ok(v) = HeaderValue::from_str(ip_addr.to_string().as_str()) {
        headers.insert("X-Real-IP", v);
    }
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

pub async fn websocket(
    fut: upgrade::UpgradeFut,
    mut req: Request<Body>,
    from_addr: &IpAddr,
    to_addr: &str,
) -> Result<()> {
    convert_req(&mut req, from_addr);

    let mut ws_r = fut.await?;
    ws_r.set_writev(true);
    ws_r.set_auto_close(true);
    ws_r.set_auto_pong(true);

    let stream = TcpStream::connect(to_addr).await?;
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
    .parse()?;

    let client = Client::new();

    Ok(client.request(req).await?)
}
