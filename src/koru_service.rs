use futures_util::{future::select, SinkExt, StreamExt};
use http::{
    header::{ACCEPT_ENCODING, ACCEPT_LANGUAGE, USER_AGENT},
    HeaderName, Uri,
};
use http_body_util::{BodyExt, Empty};
use hyper::{
    body::{Body, Bytes},
    header::HOST,
    http::HeaderValue,
    Request, Response, Version,
};
use hyper_util::rt::TokioIo;
use std::{
    io,
    net::IpAddr,
    pin::pin,
    sync::{
        atomic::{self, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::TcpStream,
    process::Command,
    sync::{
        mpsc::{self, error::TryRecvError},
        Mutex,
    },
};
use tokio_websockets::{ClientBuilder, Message};

use crate::{
    hyper_websockets::{self},
    info, Result,
};

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

fn convert_uri(uri: &Uri, prefix: &str) -> String {
    let uri_str = uri.path_and_query().map(|x| x.as_str()).unwrap_or("/");
    format!("{prefix}{uri_str}")
}

fn convert_req(req: &mut Request<impl Body>, ip_addr: &IpAddr, prefix: Option<&str>) -> Result<()> {
    *req.version_mut() = Version::HTTP_11;

    let headers = req.headers_mut();

    headers.insert(HOST, HeaderValue::from_str("localhost").unwrap());
    if let Ok(v) = HeaderValue::from_str(ip_addr.to_string().as_str()) {
        headers.insert("X-Real-IP", v);
    }

    *req.uri_mut() = convert_uri(req.uri(), prefix.unwrap_or("")).parse()?;

    Ok(())
}

pub fn websocket(mut req: crate::Req, from_addr: &IpAddr, to_authority: &str) -> Result<Response<Empty<Bytes>>> {
    const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");
    let to_authority = format!("ws://{to_authority}");

    let mut wss = ClientBuilder::from_uri(convert_uri(req.uri(), &to_authority).parse()?)
        .add_header(X_REAL_IP, HeaderValue::from_str(from_addr.to_string().as_str())?)?;

    for header in [ACCEPT_ENCODING, ACCEPT_LANGUAGE, USER_AGENT] {
        if let Some(value) = req.headers_mut().get(&header) {
            wss = wss.add_header(header, value.clone())?;
        }
    }

    let from_addr = from_addr.to_string();
    let response = hyper_websockets::upgrade_response(&mut req)?;

    tokio::task::spawn(async move {
        let wsc = match hyper_websockets::upgrade(&mut req).await {
            Ok(v) => v,
            Err(err) => {
                info!("Upgrade failed {err:?}");
                return;
            }
        };
        let (mut wsc_s, mut wsc_r) = wsc.split();

        let (wss, _) = match wss.connect().await {
            Ok(v) => v,
            Err(err) => {
                info!("Server app connect failed {err:?}");
                return;
            }
        };
        let (mut wss_s, mut wss_r) = wss.split();

        let (wsc_tx, mut wsc_rx) = mpsc::channel(2);
        let wsc_tx2 = wsc_tx.clone();

        let alive1 = Arc::new(atomic::AtomicBool::new(true));
        let alive2 = alive1.clone();

        let to_client = pin!(async move {
            'outer: while let Some(msg) = wsc_rx.recv().await {
                if wsc_s.feed(msg).await.is_err() {
                    break;
                }
                loop {
                    match wsc_rx.try_recv() {
                        Ok(msg) => {
                            if wsc_s.feed(msg).await.is_err() {
                                break 'outer;
                            }
                        }
                        Err(TryRecvError::Empty) => {
                            if wsc_s.flush().await.is_err() {
                                break 'outer;
                            }
                            break;
                        }
                        Err(TryRecvError::Disconnected) => break 'outer,
                    }
                }
            }
        });

        let from_client = pin!(async move {
            while let Some(msg) = wsc_r.next().await {
                match msg {
                    Ok(msg) if msg.is_text() && msg.as_payload().len() == 1 && msg.as_payload()[0] == b'H' => {
                        alive2.store(true, Ordering::Relaxed);
                        let now = SystemTime::now();
                        let msg = Message::text(format!(
                            "K{}",
                            now.duration_since(UNIX_EPOCH).expect("UNIX_EPOCH").as_millis()
                        ));
                        if wsc_tx2.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Ok(msg) => {
                        alive2.store(true, Ordering::Relaxed);
                        if wss_s.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        });

        const TIMEOUT: Duration = Duration::from_secs(30);

        let from_app = pin!(async move {
            while let Some(msg) = wss_r.next().await {
                match msg {
                    Ok(msg) => {
                        if wsc_tx.send_timeout(msg, TIMEOUT).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        });

        let timeout = pin!(async move {
            loop {
                tokio::time::sleep(TIMEOUT).await;
                if !alive1.load(Ordering::Relaxed) {
                    break;
                }

                alive1.store(false, Ordering::Relaxed);
            }
        });

        let _ = select(select(to_client, from_app), select(from_client, timeout)).await;
        info!("close socket - {:?}", from_addr);
    });

    Ok(response)
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
