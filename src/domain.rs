use async_trait::async_trait;
use http_body_util::BodyExt;
use hyper::{
    body::Bytes,
    header,
    http::uri::{self, PathAndQuery},
    Response, StatusCode, Uri,
};
use radix_trie::Trie;
use std::{
    any::Any,
    collections::HashMap,
    error::Error,
    fmt::{Debug, Display},
    io,
    net::IpAddr,
    str::FromStr,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
};
use tokio_rustls::rustls;

use crate::{error, koru_service, static_files};

pub type DynLocation = dyn Location + Send + Sync;
pub type RcDynLocation = Arc<DynLocation>;
pub type DynConf = dyn Conf + Send + Sync;
pub type RcDynConf = Arc<DynConf>;
pub type DomainMap = HashMap<String, Domain>;
pub type ServiceMap = HashMap<String, Arc<koru_service::Service>>;

#[derive(Default, Debug, Clone)]
pub struct Domain {
    shared: Arc<Shared>,
}

#[derive(Default)]
struct Shared {
    root: String,
    name: String,
    aliases: Vec<String>,
    cert_path: String,
    state: RwLock<State>,
}

#[derive(Debug, Default)]
struct State {
    tls_config: Option<Arc<rustls::ServerConfig>>,
    services: ServiceMap,
    locations: HashMap<String, RcDynLocation>,
    location_prefixes: Trie<String, RcDynLocation>,
    confs: HashMap<&'static str, RcDynConf>,
}

#[derive(Debug, Default)]
pub struct DomainBuilder {
    shared: Shared,
}

impl Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared").field("name", &self.name).finish()
    }
}

impl DomainBuilder {
    pub fn root(&mut self, value: String) -> &mut DomainBuilder {
        self.shared.root = value;
        self
    }

    pub fn name(&mut self, value: String) -> &mut DomainBuilder {
        self.shared.name = value;
        self
    }

    pub fn cert_path(&mut self, value: String) -> &mut DomainBuilder {
        self.shared.cert_path = value;
        self
    }

    pub fn aliases(&mut self, value: Vec<String>) -> &mut DomainBuilder {
        self.shared.aliases = value;
        self
    }

    pub fn build(&mut self) -> Domain {
        let mut shared = Default::default();
        std::mem::swap(&mut self.shared, &mut shared);
        Domain {
            shared: Arc::new(shared),
        }
    }
}

impl Domain {
    pub fn builder() -> DomainBuilder {
        DomainBuilder::default()
    }

    pub fn root(&self) -> &str {
        &self.shared.root
    }

    pub fn name(&self) -> &str {
        &self.shared.name
    }

    pub fn cert_path(&self) -> &str {
        &self.shared.cert_path
    }

    pub fn aliases(&self) -> &Vec<String> {
        &self.shared.aliases
    }

    pub fn set_tls_config(&self, value: Option<Arc<rustls::ServerConfig>>) {
        self.write_state().tls_config = value;
    }

    pub fn tls_config(&self) -> Option<Arc<rustls::ServerConfig>> {
        self.read_state().tls_config.clone()
    }

    pub fn add_location(&self, key: String, value: RcDynLocation) -> Option<RcDynLocation> {
        let locations = &mut self.write_state().locations;
        locations.insert(key, value)
    }

    pub fn add_prefix_location(&self, key: String, value: RcDynLocation) -> Option<RcDynLocation> {
        let locations = &mut self.write_state().location_prefixes;
        locations.insert(key, value)
    }

    pub fn find_location(&self, path: &str) -> Option<RcDynLocation> {
        if let Some(v) = self.read_state().locations.get(path) {
            Some(v.clone())
        } else {
            self.read_state().location_prefixes.get_ancestor_value(path).cloned()
        }
    }

    pub fn add_service(&self, key: String, value: Arc<koru_service::Service>) -> Option<Arc<koru_service::Service>> {
        let services = &mut self.write_state().services;
        services.insert(key, value)
    }

    pub fn get_service(&self, name: &str) -> Option<Arc<koru_service::Service>> {
        self.read_state().services.get(name).cloned()
    }

    pub fn add_conf(&self, key: &'static str, value: RcDynConf) -> Option<RcDynConf> {
        let confs = &mut self.write_state().confs;
        confs.insert(key, value)
    }

    pub fn get_conf(&self, path: &str) -> Option<RcDynConf> {
        self.read_state().confs.get(path).cloned()
    }

    pub fn handle_error(&self, err: crate::Error, path: &str) -> crate::ResultResp {
        if let Some(e) = err.downcast_ref::<io::Error>() {
            return match e.kind() {
                io::ErrorKind::PermissionDenied => self.client_error(400, e.to_string(), path),
                io::ErrorKind::NotFound => self.client_error(404, e.to_string(), path),
                io::ErrorKind::ConnectionRefused => self.server_error(502, e.to_string(), path),
                _ => self.server_error(500, e.to_string(), path),
            };
        }

        if let Some(e) = err.downcast_ref::<hyper::Error>() {
            if e.is_user() {
                return self.client_error(400, e.to_string(), path);
            }
            if e.is_closed() {
                return self.server_error(502, e.to_string(), path);
            }
            return self.server_error(500, e.to_string(), path);
        }

        self.server_error(500, err.to_string(), path)
    }

    pub fn client_error(&self, code: u16, message: String, path: &str) -> crate::ResultResp {
        let msg = format!("{} {}{} Client error {}\n", code, self.shared.name, path, message);
        Ok(crate::resp(code, Bytes::from(msg)))
    }

    pub fn server_error(&self, code: u16, message: String, path: &str) -> crate::ResultResp {
        let msg = format!("{} {}{} Server error\n{}\n", code, self.shared.name, path, message);
        error!("{}", msg);

        Ok(crate::resp(code, Bytes::from(msg)))
    }

    fn write_state(&self) -> RwLockWriteGuard<'_, State> {
        self.shared.state.write().expect("should lock state")
    }

    fn read_state(&self) -> RwLockReadGuard<'_, State> {
        self.shared.state.read().expect("should lock state")
    }

    pub(crate) fn fill_service_map(
        &self,
        service_map: &mut HashMap<String, Arc<koru_service::Service>>,
    ) -> Result<(), (String, String)> {
        for (name, service) in self.read_state().services.iter() {
            if let Some(cmd) = service.cmd_name()
                && service_map.insert(cmd.to_string(), service.clone()).is_some()
            {
                return Err((name.to_string(), format!("Duplicate service app {cmd}")));
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct NoConnect;

impl Error for NoConnect {}

impl Display for NoConnect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NoConnect")
    }
}

pub trait Conf {
    fn as_any(&self) -> &dyn Any;

    fn name(&self) -> &str;
}

#[async_trait]
pub trait Location {
    async fn connect(&self, _domain: Domain, _req: crate::Req, _ip_addr: IpAddr, count: u16) -> crate::ResultResp;

    fn info(&self) -> String {
        "Location".to_string()
    }

    fn as_any(&self) -> &dyn Any;
}

impl core::fmt::Debug for dyn Location + Send + Sync {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.info())
    }
}

impl core::fmt::Debug for dyn Conf + Send + Sync {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug)]
pub struct Rewrite {
    pub path: String,
}

#[async_trait]
impl Location for Rewrite {
    async fn connect(&self, domain: Domain, mut req: crate::Req, ip_addr: IpAddr, count: u16) -> crate::ResultResp {
        if count > 2 {
            return Err("nested connect count exceeded for Rewrite".into());
        }
        let mut parts = req.uri().clone().into_parts();

        if let Some(query) = req.uri().query() {
            parts.path_and_query = Some(PathAndQuery::from_str(&format!("{}?{}", &self.path, query))?);
        } else {
            parts.path_and_query = Some(PathAndQuery::from_str(self.path.as_str())?);
        }
        *req.uri_mut() = Uri::from_parts(parts)?;

        match domain.find_location(&self.path) {
            None => Err(format!("Can't find {}", self.path).into()),
            Some(l) => l.connect(domain, req, ip_addr, count + 1).await,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Debug, Default)]
pub struct Redirect {
    pub code: StatusCode,
    pub scheme: Option<String>,
    pub authority: Option<String>,
    pub path: Option<String>,
    pub query: Option<String>,
}

#[async_trait]
impl Location for Redirect {
    async fn connect(&self, _domain: Domain, req: crate::Req, _ip_addr: IpAddr, _count: u16) -> crate::ResultResp {
        let mut parts = req.uri().clone().into_parts();

        if let Some(scheme) = &self.scheme {
            parts.scheme = Some(uri::Scheme::from_str(scheme)?);
        } else if parts.scheme.is_none() {
            parts.scheme = Some(uri::Scheme::from_str("https")?);
        }

        if let Some(v) = &self.authority {
            parts.authority = Some(uri::Authority::from_str(v)?);
        } else if parts.authority.is_none()
            && let Some(host) = req.uri().host().or_else(|| crate::host_from_req(&req))
        {
            parts.authority = Some(uri::Authority::from_str(host)?);
        }

        let curr_pq = || {
            parts
                .path_and_query
                .unwrap_or_else(|| PathAndQuery::from_str("/").expect("/ to be valid"))
        };

        parts.path_and_query = Some(if let Some(p) = &self.path {
            if let Some(q) = &self.query {
                PathAndQuery::from_str(&format!("{p}?{q}"))?
            } else {
                PathAndQuery::from_str(p)?
            }
        } else if let Some(q) = &self.query {
            PathAndQuery::from_str(&format!("{}?{q}", curr_pq().path()))?
        } else {
            curr_pq()
        });

        Ok(Response::builder()
            .status(self.code)
            .header(header::LOCATION, Uri::from_parts(parts)?.to_string())
            .body(crate::empty_body())?)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Debug)]
pub struct File {
    pub opts: static_files::Opts,
}

#[async_trait]
impl Location for File {
    async fn connect(&self, _domain: Domain, req: crate::Req, _ip_addr: IpAddr, _count: u16) -> crate::ResultResp {
        static_files::send_file(req.into_parts().0, &self.opts).await
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Debug)]
pub struct HttpProxy {
    pub server_socket: String,
}

#[async_trait]
impl Location for HttpProxy {
    async fn connect(&self, _domain: Domain, req: crate::Req, ip_addr: IpAddr, _count: u16) -> crate::ResultResp {
        koru_service::pass(req, ip_addr, &self.server_socket).await
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Debug)]
pub struct WebsocketProxy {
    pub server_socket: String,
}

#[async_trait]
impl Location for WebsocketProxy {
    async fn connect(&self, _domain: Domain, req: crate::Req, ip_addr: IpAddr, _count: u16) -> crate::ResultResp {
        let response = koru_service::websocket(req, &ip_addr, &self.server_socket)?;
        let (parts, body) = response.into_parts();

        Ok(Response::from_parts(
            parts,
            body.map_err(|err| crate::Error::from(err.to_string())).boxed(),
        ))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
#[path = "domain_test.rs"]
mod test;
