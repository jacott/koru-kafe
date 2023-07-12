use crate::domain::{Domain, DomainMap};
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use std::net::IpAddr;
use std::ops::DerefMut;
use std::sync::Arc;
use std::{io, sync::Mutex};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::{rustls, LazyConfigAcceptor};

async fn handler(req: Request<Body>, ip_addr: IpAddr, domain: Option<Domain>) -> crate::Result<Response<Body>> {
    if let Some(domain) = domain {
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
        eprintln!("{} 404 - no domain handler", req.uri().path());
        Ok(Response::builder().status(404).body(Body::from("Not found\n"))?)
    }
}

fn with_domain(host: Option<&str>, domains: &DomainMap) -> Option<Domain> {
    if let Some(host) = host {
        Some(domains.get(host).or_else(|| domains.get("*"))?.clone())
    } else {
        Some(domains.get("*")?.clone())
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
        .map_err(|e| io::Error::new(e.kind(), format!("listen on {} failed - {}", addr, e)))?;

    let domains = Arc::new(Mutex::new(domains));
    let d2 = domains.clone();

    tokio::spawn(async move {
        while let Some(new_domains) = reload.recv().await {
            *d2.lock().expect(SHOULD_LOCK) = new_domains;
        }
    });

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let domains = domains.lock().expect(SHOULD_LOCK).clone();
        let ip_addr = peer_addr.ip();
        if is_tls {
            tokio::spawn(async move {
                let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
                futures_util::pin_mut!(acceptor);

                match acceptor.as_mut().await {
                    Ok(start) => {
                        let client_hello = start.client_hello();
                        let host = client_hello.server_name();

                        if let Some(domain) = with_domain(host, &domains) {
                            match start
                                .into_stream(domain.tls_config().clone().expect("TLS config"))
                                .await
                            {
                                Ok(stream) => {
                                    handle_hyper_result(
                                        Http::new()
                                            .serve_connection(
                                                stream,
                                                service_fn(move |req| handler(req, ip_addr, Some(domain.clone()))),
                                            )
                                            .with_upgrades()
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
            tokio::spawn(async move {
                handle_hyper_result(
                    Http::new()
                        .serve_connection(
                            stream,
                            service_fn(move |req| {
                                let host = crate::host_from_req(&req);
                                let domain = with_domain(host, &domains);
                                handler(req, ip_addr, domain)
                            }),
                        )
                        .with_upgrades()
                        .await,
                );
            });
        }
    }
}

fn handle_hyper_result(res: Result<(), hyper::Error>) {
    if let Err(e) = res {
        if let Some(e) = e.into_cause() {
            if let Ok(e) = e.downcast::<io::Error>() {
                match e.kind() {
                    io::ErrorKind::UnexpectedEof => {}
                    _ => {
                        eprintln!("An error occurred: {:?}", e);
                    }
                }
            }
        }
    }
}

async fn handle_error(err: io::Error, ip_addr: IpAddr, acceptor: &mut LazyConfigAcceptor<TcpStream>) {
    let msg = match err.kind() {
        io::ErrorKind::InvalidInput => {
            eprintln!("{:?} - 400 Not a TLS handshake", ip_addr);
            "HTTP/1.1 400 Expected an HTTPS request\r\n\r\n\r\nExpected an HTTPS request\n".to_string()
        }
        _ => {
            eprintln!("{:?} - 500 Server Error:\n{:?}\n", ip_addr, err);
            format!("HTTP/1.1 500 Server Error\r\n\r\n\r\n{:?}\n", err)
        }
    };
    if let Some(mut stream) = acceptor.take_io() {
        stream.write_all(msg.as_bytes()).await.unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn with_domain() {
        let mut dm: DomainMap = HashMap::new();
        assert!(super::with_domain(Some("foo"), &dm).is_none());
        assert!(super::with_domain(None, &dm).is_none());

        let any = Domain::builder().name("*".to_string()).build();
        dm.insert("*".to_string(), any.clone());
        let ans = super::with_domain(Some("foo"), &dm);
        assert!(ans.is_some());
        assert_eq!(ans.unwrap().name(), "*");

        dm.insert("foo".to_string(), Domain::builder().name("foo".to_string()).build());
        let ans = super::with_domain(Some("foo"), &dm);
        assert!(ans.is_some());
        assert_eq!(ans.unwrap().name(), "foo");

        assert_eq!(&super::with_domain(None, &dm).unwrap().name(), &any.name());
    }
}
