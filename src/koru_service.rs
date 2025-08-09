use futures_util::{
    sink::SinkExt,
    stream::{SplitSink, SplitStream, StreamExt},
};
use http_body_util::BodyExt;
use hyper::{body::Body, header::HOST, http::HeaderValue, Request, Response, Version};
use hyper_tungstenite::{tungstenite::Message, HyperWebsocket, WebSocketStream};
use hyper_util::rt::TokioIo;
use std::{
    io,
    net::IpAddr,
    time::{Duration, SystemTime},
};
use tokio::{net::TcpStream, process::Command, sync::Mutex};

use crate::{info, Result};

#[derive(Default, Debug)]
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
                let mut child = Command::new(cmd).arg0(arg0).args(args).kill_on_drop(true).spawn()?;
                info!("Running ({}) {}: {} {:?}", child.id().unwrap_or(0), arg0, cmd, args);
                child.wait().await?;
                info!("Finished running {arg0} ({})", child.id().unwrap_or(0));
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

fn convert_req(req: &mut Request<impl Body>, ip_addr: &IpAddr, prefix: Option<&str>) -> Result<()> {
    *req.version_mut() = Version::HTTP_11;

    let headers = req.headers_mut();

    headers.insert(HOST, HeaderValue::from_str("localhost").unwrap());
    if let Ok(v) = HeaderValue::from_str(ip_addr.to_string().as_str()) {
        headers.insert("X-Real-IP", v);
    }

    let uri_str = req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/");

    match prefix {
        Some(v) => *req.uri_mut() = format!("{v}{uri_str}").parse()?,
        None => *req.uri_mut() = uri_str.parse()?,
    };

    Ok(())
}

pub async fn websocket(
    fut: HyperWebsocket,
    req: Request<impl Body>,
    from_addr: &IpAddr,
    to_authority: &str,
) -> Result<()> {
    let (mut wss_s, mut wss_r) = ws_connect_server(req, from_addr, to_authority).await?;

    let ws_r = fut.await?;
    let (mut wsc_s, mut wsc_r) = ws_r.split();

    tokio::spawn(async move {
        while let Some(msg) = wsc_r.next().await {
            match msg {
                Ok(msg) => {
                    if let Err(err) = wss_s.send(msg).await {
                        info!("close socket - {:?}", err);
                        break;
                    }
                }
                Err(err) => {
                    info!("close socket - {:?}", err);
                    break;
                }
            }
        }
    });

    tokio::spawn(async move {
        while let Some(msg) = wss_r.next().await {
            match msg {
                Ok(msg) => {
                    if let Err(err) = wsc_s.send(msg).await {
                        info!("close socket - {:?}", err);
                        break;
                    }
                }
                Err(err) => {
                    info!("close socket - {:?}", err);
                    break;
                }
            }
        }
    });

    Ok(())
}

pub async fn ws_connect_server(
    mut req: Request<impl Body>,
    from_addr: &IpAddr,
    to_authority: &str,
) -> Result<(
    SplitSink<WebSocketStream<TcpStream>, Message>,
    SplitStream<WebSocketStream<TcpStream>>,
)> {
    let prefix = format!("ws://{to_authority}");
    convert_req(&mut req, from_addr, Some(&prefix))?;
    let stream = TcpStream::connect(to_authority).await?;

    let req = req.map(|_| ());

    let ws_w = tokio_tungstenite::client_async(req, stream).await?.0;

    Ok(ws_w.split())
}

pub async fn pass(mut req: crate::Req, ip_addr: IpAddr, to_authority: &str) -> crate::ResultResp {
    convert_req(&mut req, &ip_addr, None)?;
    let client_stream = TcpStream::connect(to_authority).await?;
    let io = TokioIo::new(client_stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {err:?}");
        }
    });

    let web_res = sender.send_request(req).await?;

    let (parts, body) = web_res.into_parts();
    Ok(Response::from_parts(parts, body.map_err(|err| err.into()).boxed()))
}
