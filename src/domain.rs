use async_trait::async_trait;
use hyper::{Body, Request, Response};
use radix_trie::Trie;
use std::{collections::HashMap, error::Error, fmt::Display, net::IpAddr, sync::Arc};
use tokio_rustls::rustls;

use crate::{koru_proxy, static_files};

pub type DynLocation = dyn Location + Send + Sync;
pub type RcDynLocation = Arc<DynLocation>;
pub type DomainMap = HashMap<String, Arc<Domain>>;

#[derive(Default)]
pub struct Domain {
    pub root: String,
    pub cert_path: String,
    pub tls_config: Option<Arc<rustls::ServerConfig>>,
    pub proxies: HashMap<String, ProxyConf>,
    pub locations: HashMap<String, RcDynLocation>,
    pub location_prefixes: Trie<String, RcDynLocation>,
}

impl Domain {
    pub fn find_location(&self, path: &str) -> Option<RcDynLocation> {
        self.locations
            .get(path)
            .or_else(|| self.location_prefixes.get_ancestor_value(path))
            .cloned()
    }
}

pub struct ProxyConf {
    pub server_socket: String,
}

#[derive(Debug)]
pub struct NoConnect;

impl Error for NoConnect {}

impl Display for NoConnect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NoConnect")
    }
}

#[async_trait]
pub trait Location {
    fn convert(
        &self,
        _domain: &Domain,
        _req: &Request<Body>,
        _ip_addr: &IpAddr,
    ) -> crate::Result<Option<RcDynLocation>> {
        Ok(None)
    }

    async fn connect(&self, _req: Request<Body>, _ip_addr: IpAddr) -> crate::Result<Response<Body>> {
        Err(Box::new(NoConnect))
    }
}

pub struct Rewrite {
    pub path: String,
}

#[async_trait]
impl Location for Rewrite {
    fn convert(
        &self,
        domain: &Domain,
        _req: &Request<Body>,
        _ip_addr: &IpAddr,
    ) -> crate::Result<Option<RcDynLocation>> {
        match domain.find_location(&self.path) {
            None => Err(format!("Can't find {}", self.path).into()),
            Some(l) => Ok(Some(l.clone())),
        }
    }
}

pub struct File {
    pub root: String,
}

#[async_trait]
impl Location for File {
    async fn connect(&self, req: Request<Body>, _ip_addr: IpAddr) -> crate::Result<Response<Body>> {
        eprintln!("DEBUG self.root {:?}", self.root);

        static_files::send_file(req, &self.root).await
    }
}

pub struct HttpProxy {
    pub server_socket: String,
}

#[async_trait]
impl Location for HttpProxy {
    async fn connect(&self, req: Request<Body>, ip_addr: IpAddr) -> crate::Result<Response<Body>> {
        koru_proxy::pass(req, ip_addr, &self.server_socket).await
    }
}

pub struct WebsocketProxy {
    pub server_socket: String,
}

#[async_trait]
impl Location for WebsocketProxy {
    async fn connect(&self, mut req: Request<Body>, ip_addr: IpAddr) -> crate::Result<Response<Body>> {
        let (response, fut) = fastwebsockets::upgrade::upgrade(&mut req)?;

        tokio::task::spawn(async move {
            if let Err(e) = tokio::task::unconstrained(koru_proxy::websocket(fut, req, ip_addr)).await {
                eprintln!("Error in websocket connection: {}", e);
            }
        });

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use hyper::body::to_bytes;

    use super::*;

    struct Foo;

    #[async_trait]
    impl Location for Foo {
        async fn connect(&self, _req: Request<Body>, _ip_addr: IpAddr) -> crate::Result<Response<Body>> {
            let ans = tokio::join!(tokio::task::spawn(async move {
                println!("{:?}", _req);
                _req
            }));
            Ok(Response::builder()
                .body((format!("hello {:?}", ans.0.unwrap().method())).into())
                .unwrap())
        }
    }
    #[tokio::test]
    async fn connect() {
        let mut d: Domain = Default::default();
        d.location_prefixes.insert("/".to_string(), Arc::new(Foo {}));

        let req = Default::default();
        let ip_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        let resp = d
            .location_prefixes
            .get("/")
            .unwrap()
            .connect(req, ip_addr)
            .await
            .unwrap();

        assert_eq!(to_bytes(resp.into_body()).await.unwrap(), "hello GET");
    }

    #[tokio::test]
    async fn rewrite() {
        let mut d: Domain = Default::default();
        d.location_prefixes.insert("/".to_string(), Arc::new(Foo {}));

        let req = Default::default();
        let ip_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        let resp = d
            .location_prefixes
            .get("/")
            .unwrap()
            .connect(req, ip_addr)
            .await
            .unwrap();

        assert_eq!(to_bytes(resp.into_body()).await.unwrap(), "hello GET");
    }
}
