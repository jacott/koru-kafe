use crate::{
    domain::{Domain, DomainMap},
    info,
};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use socket2::{Socket, TcpKeepalive};
use std::ops::DerefMut;
use std::sync::Arc;
use std::{io, sync::Mutex};
use std::{net::IpAddr, time::Duration};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::{LazyConfigAcceptor, rustls};

async fn handler(
    req: crate::Req,
    ip_addr: IpAddr,
    domains: Arc<Mutex<DomainMap>>,
) -> crate::ResultResp {
    let host = req.uri().host().or_else(|| crate::host_from_req(&req));
    if let Some(domain) = with_domain(host, &domains) {
        match domain.find_location(req.uri().path()) {
            None => domain.handle_error(
                Box::new(io::Error::new(io::ErrorKind::NotFound, "Not Found")),
                req.uri().path(),
            ),
            Some(loc) => match loc.connect(domain.clone(), req, ip_addr, 0).await {
                Ok(resp) => Ok(resp),
                Err(err) => domain.handle_error(err, ""),
            },
        }
    } else {
        info!("{} 404 - no domain handler", req.uri().path());
        Ok(crate::resp_404())
    }
}

fn with_domain(host: Option<&str>, domains: &Arc<Mutex<DomainMap>>) -> Option<Domain> {
    let guard = domains.lock().expect("Should unlock");
    if let Some(host) = host {
        Some(guard.get(host).or_else(|| guard.get("*"))?.clone())
    } else {
        Some(guard.get("*")?.clone())
    }
}

const SHOULD_LOCK: &str = "should lock";

pub async fn listen(
    addr: String,
    domains: DomainMap,
    mut reload: mpsc::Receiver<DomainMap>,
    is_tls: bool,
) -> crate::Result<()> {
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("listen on {addr} failed - {e}")))?;

    let domains = Arc::new(Mutex::new(domains));
    let d2 = domains.clone();

    tokio::spawn(async move {
        while let Some(new_domains) = reload.recv().await {
            *d2.lock().expect(SHOULD_LOCK) = new_domains;
        }
    });

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let std_stream = stream.into_std()?; // Convert to std to use socket2
        std_stream.set_nodelay(true)?;
        let socket = Socket::from(std_stream);

        let keepalive = TcpKeepalive::new()
            .with_time(Duration::from_secs(60)) // Start probing after 60s idle
            .with_interval(Duration::from_secs(10)); // Probe every 10s after that

        socket.set_tcp_keepalive(&keepalive)?;

        // Convert back to Tokio
        let stream = tokio::net::TcpStream::from_std(socket.into())?;
        let ip_addr = peer_addr.ip();
        if is_tls {
            let domains = domains.clone();
            tokio::spawn(async move {
                let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
                futures_util::pin_mut!(acceptor);

                match acceptor.as_mut().await {
                    Ok(start) => {
                        let client_hello = start.client_hello();
                        let host = client_hello.server_name();
                        if let Some(host) = &host {
                            println!("{host}: hello {ip_addr}");
                        }
                        if let Some(domain) = with_domain(host, &domains) {
                            match start
                                .into_stream(domain.tls_config().clone().expect("TLS config"))
                                .await
                            {
                                Ok(stream) => {
                                    handle_hyper_result(
                                        ip_addr,
                                        hyper_util::server::conn::auto::Builder::new(
                                            TokioExecutor::new(),
                                        )
                                        .serve_connection_with_upgrades(
                                            TokioIo::new(stream),
                                            service_fn(move |req| {
                                                handler(req, ip_addr, domains.clone())
                                            }),
                                        )
                                        .await,
                                    );
                                }
                                Err(err) => {
                                    handle_error(err, ip_addr, acceptor.deref_mut()).await;
                                }
                            }
                        }
                    }
                    Err(err) => {
                        handle_error(err, ip_addr, acceptor.deref_mut()).await;
                    }
                }
            });
        } else {
            let domains = domains.clone();
            tokio::spawn(async move {
                handle_hyper_result(
                    ip_addr,
                    hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(
                            TokioIo::new(stream),
                            service_fn(move |req| handler(req, ip_addr, domains.clone())),
                        )
                        .await,
                );
            });
        }
    }
}

fn handle_hyper_result(peer_addr: IpAddr, res: crate::Result<()>) {
    if let Err(e) = res {
        info!("{peer_addr:?} - {e}");
    }
}

async fn handle_error(
    err: io::Error,
    peer_addr: IpAddr,
    acceptor: &mut LazyConfigAcceptor<TcpStream>,
) {
    info!("{peer_addr:?} - 400 Bad Request: {}", &err);
    if let Some(mut stream) = acceptor.take_io() {
        let _ = stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n\r\nBad Request\n")
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn with_domain() {
        let dm = Arc::new(Mutex::new(HashMap::new()));
        assert!(super::with_domain(Some("foo"), &dm).is_none());
        assert!(super::with_domain(None, &dm).is_none());

        let any = Domain::builder().name("*".to_string()).build();

        {
            let mut guard = dm.lock().unwrap();
            guard.insert("*".to_string(), any.clone());
        }
        let ans = super::with_domain(Some("foo"), &dm);
        assert!(ans.is_some());
        assert_eq!(ans.unwrap().name(), "*");

        {
            let mut guard = dm.lock().unwrap();
            guard.insert(
                "foo".to_string(),
                Domain::builder().name("foo".to_string()).build(),
            );
        }
        let ans = super::with_domain(Some("foo"), &dm);
        assert!(ans.is_some());
        assert_eq!(ans.unwrap().name(), "foo");

        assert_eq!(&super::with_domain(None, &dm).unwrap().name(), &any.name());
    }
}
