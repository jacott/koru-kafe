use crate::domain::{Domain, DomainMap};
use hyper::header::HOST;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

async fn handler(
    req: Request<Body>,
    ip_addr: IpAddr,
    domain: crate::Result<Arc<Domain>>,
) -> crate::Result<Response<Body>> {
    let domain = domain?;
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
}

fn with_domain<T>(req: &Request<T>, domains: &DomainMap) -> crate::Result<Arc<Domain>> {
    if let Some(host_raw) = req.headers().get(HOST) {
        if let Ok(host_raw) = host_raw.to_str() {
            let host = match host_raw.rfind(':') {
                Some(idx) => &host_raw[..idx],
                None => host_raw,
            };
            match domains.get(host) {
                Some(domain) => return Ok(domain.clone()),
                None => return Err(format!("Unhandled Host: {}", host).into()),
            }
        }
    }
    Ok(domains.iter().next().expect("No domains!").1.clone())
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
                        let domain = with_domain(&req, &domains);
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
        let domains = domains.clone();
        let ip_addr = stream.peer_addr().unwrap().ip();
        tokio::spawn(async move {
            let conn_fut = Http::new()
                .serve_connection(
                    stream,
                    service_fn(move |req| {
                        let domain = with_domain(&req, &domains);
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
