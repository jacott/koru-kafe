use crate::domain::{Domain, DomainMap};
use hyper::header::HOST;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::rustls;
use tokio_rustls::LazyConfigAcceptor;

async fn handler(req: Request<Body>, ip_addr: IpAddr, domain: Option<Arc<Domain>>) -> crate::Result<Response<Body>> {
    if let Some(domain) = domain {
        let path = req.uri().path();
        match domain.find_location(path) {
            None => Err(format!("Unhandled path: {}", path).into()),
            Some(loc) => {
                let loc = match loc.convert(&domain, &req, &ip_addr)? {
                    None => loc,
                    Some(loc) => loc,
                };
                loc.connect(req, ip_addr).await
            }
        }
    } else {
        Err(Box::new(io::Error::new(io::ErrorKind::NotFound, "Not found")))
    }
}

fn host_from_req<T>(req: &Request<T>) -> Option<&str> {
    if let Some(host_raw) = req.headers().get(HOST) {
        if let Ok(host_raw) = host_raw.to_str() {
            match host_raw.rfind(':') {
                Some(idx) => &host_raw[..idx],
                None => host_raw,
            };
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

pub async fn listen(addr: String, domains: DomainMap) -> crate::Result<()> {
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("listen on {} failed - {}", addr, e)))
        .unwrap();

    let domains = Arc::new(domains);
    loop {
        let (stream, _) = listener.accept().await?;
        let domains = domains.clone();
        let ip_addr = stream.peer_addr().unwrap().ip();
        tokio::spawn(async move {
            let conn_fut = Http::new()
                .serve_connection(
                    stream,
                    service_fn(move |req| {
                        let host = host_from_req(&req);
                        let domain = with_domain(host, &domains);
                        handler(req, ip_addr, domain)
                    }),
                )
                .with_upgrades();
            if let Err(e) = conn_fut.await {
                println!("An error occurred: {:?}", e);
            }
        });
    }
}

pub async fn tls_listen(addr: String, domains: DomainMap) -> crate::Result<()> {
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("listen on {} failed - {}", addr, e)))
        .unwrap();
    let domains = Arc::new(domains);
    loop {
        let (stream, _) = listener.accept().await?;
        let ip_addr = stream.peer_addr().unwrap().ip();
        let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
        let domains = domains.clone();
        tokio::spawn(async move {
            let start = acceptor.await.unwrap();

            let client_hello = start.client_hello();
            let host = client_hello.server_name();

            if let Some(domain) = with_domain(host, &domains) {
                let stream = start.into_stream(domain.tls_config.clone().unwrap()).await.unwrap();

                let conn_fut = Http::new()
                    .serve_connection(
                        stream,
                        service_fn(move |req| handler(req, ip_addr, Some(domain.clone()))),
                    )
                    .with_upgrades();
                if let Err(e) = conn_fut.await {
                    println!("An error occurred: {:?}", e);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    // use super::*;
    // use hyper::HeaderMap;

    // #[test]
    // fn header_map() {
    //     let mut map = HeaderMap::new();
    //     //        map.insert(HOST, "hello".parse().unwrap());

    //     assert_eq!(map.get(HOST).unwrap_or(""), "");
    // }
}
