use futures_util::{sink::SinkExt, stream::StreamExt};
use hyper::{client::HttpConnector, http::HeaderValue, Body, Client, Request, Response, Version};
use hyper_tungstenite::HyperWebsocket;
use std::{
    io,
    net::IpAddr,
    time::{Duration, SystemTime},
};
use tokio::{net::TcpStream, process::Command, sync::Mutex};

use crate::Result;

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

fn convert_req(req: &mut Request<Body>, ip_addr: &IpAddr, scheme: &str, auth: &str) -> Result<()> {
    *req.version_mut() = Version::HTTP_11;

    let headers = req.headers_mut();

    if let Ok(v) = HeaderValue::from_str(ip_addr.to_string().as_str()) {
        headers.insert("X-Real-IP", v);
    }

    let uri_str = format!(
        "{}://{}{}",
        scheme,
        auth,
        req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/")
    );
    *req.uri_mut() = uri_str.parse()?;

    Ok(())
}

pub async fn websocket(
    fut: HyperWebsocket,
    mut req: Request<Body>,
    from_addr: &IpAddr,
    to_authority: &str,
) -> Result<()> {
    convert_req(&mut req, from_addr, "ws", to_authority)?;
    let stream = TcpStream::connect(to_authority).await?;

    let req = req.map(|_| ());

    let (ws_w, _) = tokio_tungstenite::client_async(req, stream).await?;

    let ws_r = fut.await?;
    let (mut wsc_s, mut wsc_r) = StreamExt::split(ws_r);

    let (mut wss_s, mut wss_r) = StreamExt::split(ws_w);

    tokio::spawn(async move {
        while let Some(msg) = wsc_r.next().await {
            match msg {
                Ok(msg) => {
                    if let Err(err) = wss_s.send(msg).await {
                        eprintln!("close socket - {:?}", err);
                        break;
                    }
                }
                Err(err) => {
                    eprintln!("close socket - {:?}", err);
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
                        eprintln!("close socket - {:?}", err);
                        break;
                    }
                }
                Err(err) => {
                    eprintln!("close socket - {:?}", err);
                    break;
                }
            }
        }
    });

    Ok(())
}

pub async fn pass(
    mut req: Request<Body>,
    ip_addr: IpAddr,
    client: Client<HttpConnector>,
    to_authority: &str,
) -> crate::Result<Response<Body>> {
    convert_req(&mut req, &ip_addr, "http", to_authority)?;

    Ok(client.request(req).await?)
}
