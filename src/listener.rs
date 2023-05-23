use crate::domain::DomainMap;
use crate::Result;
use hyper::header::HOST;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

async fn handler(
    req: Request<Body>,
    ip_addr: IpAddr,
    domains: Arc<DomainMap>,
) -> Result<Response<Body>> {
    let path = req.uri().path();
    let host_raw = req.headers()[HOST].to_str()?;
    let host = match host_raw.rfind(':') {
        Some(idx) => &host_raw[..idx],
        None => host_raw,
    };
    let dom = match domains.get(host) {
        None => return Err(format!("Unhandled Host: {}", host).into()),
        Some(dom) => dom,
    };
    match dom.find_location(path) {
        None => Err(format!("Unhandled path: {}", path).into()),
        Some(loc) => {
            let loc = match loc.convert(dom, &req, &ip_addr)? {
                None => loc,
                Some(loc) => loc,
            };
            loc.connect(req, ip_addr).await
        }
    }
}

pub async fn listen(addr: String, domains: DomainMap) -> Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    println!("Server started, listening on {}", addr);
    let domains = Arc::new(domains);
    loop {
        let domains = domains.clone();
        let (stream, _) = listener.accept().await?;
        let ip_addr = stream.peer_addr().unwrap().ip();
        tokio::spawn(async move {
            let conn_fut = Http::new()
                .serve_connection(
                    stream,
                    service_fn(move |req| handler(req, ip_addr, domains.clone())),
                )
                .with_upgrades();
            if let Err(e) = conn_fut.await {
                println!("An error occurred: {:?}", e);
            }
        });
    }
}
