use crate::domain::{Domain, DomainMap};
use hyper::header::HOST;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
// use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::{rustls, LazyConfigAcceptor};

async fn handler(
    mut req: Request<Body>,
    ip_addr: IpAddr,
    domain: Option<Arc<Domain>>,
) -> crate::Result<Response<Body>> {
    let path = req.uri().path();

    if let Some(domain) = domain {
        match domain.find_location(path) {
            None => domain.handle_error(Box::new(io::Error::new(io::ErrorKind::NotFound, "Not Found"))),
            Some(loc) => match loc.convert(&domain, &mut req, &ip_addr) {
                Ok(nl) => {
                    let loc = match nl {
                        None => loc,
                        Some(loc) => loc,
                    };

                    match loc.connect(req, ip_addr).await {
                        Ok(resp) => Ok(resp),
                        Err(err) => domain.handle_error(err),
                    }
                }
                Err(err) => domain.handle_error(err),
            },
        }
    } else {
        eprintln!("{} 404", &path);
        Ok(Response::builder().status(404).body(Body::from("Not found\n"))?)
    }
}

fn host_from_req<T>(req: &Request<T>) -> Option<&str> {
    if let Some(host_raw) = req.headers().get(HOST) {
        if let Ok(host_raw) = host_raw.to_str() {
            return Some(match host_raw.rfind(':') {
                Some(idx) => &host_raw[..idx],
                None => host_raw,
            });
        }
    }
    None
}

fn with_domain(host: Option<&str>, domains: &DomainMap) -> Option<Arc<Domain>> {
    if let Some(host) = host {
        Some(domains.get(host)?.clone())
    } else {
        None
    }
}

pub async fn listen(addr: String, domains: DomainMap, mut reload: mpsc::Receiver<DomainMap>) -> crate::Result<()> {
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("listen on {} failed - {}", addr, e)))
        .unwrap();

    let mut domains = Arc::new(domains);
    loop {
        tokio::select! {
            new_domains = reload.recv() => {
                match new_domains {
                    Some(mut new_domains) => {
                        for (k, v) in domains.iter() {
                            if !new_domains.contains_key(k) {
                                new_domains.insert(k.to_string(), v.clone());
                            }
                        }
                        domains = Arc::new(new_domains)
                    },
                    None => return Ok(())
                }
            }
            conn = listener.accept() => {
                let (stream, peer_addr) = conn?;
                let domains = domains.clone();
                let ip_addr = peer_addr.ip();
                tokio::spawn(async move {
                    let res = Http::new()
                        .serve_connection(
                            stream,
                            service_fn(move |req| {
                                let host = host_from_req(&req);
                                let domain = with_domain(host, &domains);
                                handler(req, ip_addr, domain)
                            }),
                        )
                        .with_upgrades().await;
                    print_hyper_error(res);
                });
            }
        }
    }
}

fn print_hyper_error(res: Result<(), hyper::Error>) {
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

pub async fn tls_listen(addr: String, domains: DomainMap, mut reload: mpsc::Receiver<DomainMap>) -> crate::Result<()> {
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("listen on {} failed - {}", addr, e)))
        .unwrap();
    let mut domains = Arc::new(domains);

    loop {
        tokio::select! {
            new_domains = reload.recv() => {
                match new_domains {
                    Some(new_domains) => domains = Arc::new(new_domains),
                    None => return Ok(())
                }

                eprintln!("DEBUG new_domains {}", domains.len());
            }
            conn = listener.accept() => {
                let (stream, peer_addr) = conn?;
                let domains = domains.clone();
                let ip_addr = peer_addr.ip();
                tokio::spawn(async move {
                    let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
                    // futures_util::pin_mut!(acceptor);

                    match acceptor // .as_mut()
                        .await
                    {
                        Ok(start) => {
                            let client_hello = start.client_hello();
                            let host = client_hello.server_name();

                            if let Some(domain) = with_domain(host, &domains) {
                                let stream = start.into_stream(domain.tls_config.clone().unwrap()).await.unwrap();

                                let res = Http::new()
                                    .serve_connection(
                                        stream,
                                        service_fn(move |req| handler(req, ip_addr, Some(domain.clone()))),
                                    )
                                    .with_upgrades().await;
                                print_hyper_error(res);
                            }
                        }
                        Err(err) => {
                            let _msg = match err.kind() {
                                io::ErrorKind::InvalidInput => {
                                    eprintln!("{:?} - 400 Not a TLS handshake", ip_addr);
                                    "HTTP/1.1 400 Expected an HTTPS request\r\n\r\n\r\nExpected an HTTPS request\n".to_string()
                                }
                                _ => {
                                    eprintln!("{:?} - 500 Server Error:\n{:?}\n", ip_addr, err);
                                    format!("HTTP/1.1 500 Server Error\r\n\r\n\r\n{:?}\n", err)
                                }
                            };
                            // if let Some(mut stream) = acceptor.take_io() {
                            //     stream.write_all(msg.as_bytes()).await.unwrap();
                            // }
                        }
                    }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // use super::*;
    // use hyper::HeaderMap;

    // #[tokio::test]
    // async fn example_acceptor() {
    //     use tokio::io::AsyncWriteExt;
    //     let listener = tokio::net::TcpListener::bind("127.0.0.1:4443").await.unwrap();
    //     let (stream, _) = listener.accept().await.unwrap();
    //     let mut acceptor = tokio_rustls::AsyncAcceptor::new(stream);
    //     match acceptor.accept().await {
    //         Ok(start) => {
    //             let config = choose_server_config(start.client_hello()).await.unwrap();
    //             let stream = start.into_stream(config).await.unwrap();
    //             // Proceed with handling the ServerConnection.
    //         }
    //         Err(err) => {
    //             if let Some(mut stream) = acceptor.take_io() {
    //                 stream
    //                     .write_all(format!("HTTP/1.1 400 Invalid Input\r\n\r\n\r\n{:?}\n", err).as_bytes())
    //                     .await
    //                     .unwrap();
    //             }
    //         }
    //     }
    // }

    // #[test]
    // fn header_map() {
    //     let mut map = HeaderMap::new();
    //     //        map.insert(HOST, "hello".parse().unwrap());

    //     assert_eq!(map.get(HOST).unwrap_or(""), "");
    // }
}
