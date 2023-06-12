use crate::{
    domain::{self, Domain, DomainMap, DynLocation, Redirect},
    koru_service, listener,
    location_path::expand_path,
    static_files,
};
use directories::ProjectDirs;
use hyper::StatusCode;
use lazy_static::lazy_static;
use mime_guess::Mime;
use serde_derive::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env, fs, io,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};
use std::{error::Error, fmt};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};
use tokio_rustls::rustls;
use yaml_rust::{yaml, Yaml, YamlLoader};

pub type ListernerMap = HashMap<String, domain::DomainMap>;

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Conf;

#[derive(Clone, PartialEq, Debug, Eq)]
pub struct ConfError {
    pub file: String,
    pub field: String,
    pub info: String,
}

impl ConfError {
    pub fn new(file: &Path, field: &str, info: &str) -> ConfError {
        ConfError {
            file: if let Some(fname) = file.file_name() {
                String::from(fname.to_str().unwrap_or("???"))
            } else {
                "???".to_string()
            },
            field: field.to_owned(),
            info: info.to_owned(),
        }
    }
}

impl Error for ConfError {}

impl fmt::Display for ConfError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{} at filed {} file {}", self.info, self.field, self.file)
    }
}

fn convert_err<T, E: Error>(pbuf: &Path, r: Result<T, E>) -> Result<T, ConfError> {
    match r {
        Ok(r) => Ok(r),
        Err(err) => Err(ConfError::new(pbuf, "", &err.to_string())),
    }
}

pub trait LocationBuilder {
    fn yaml_to_location(&self, domain: &Domain, yaml: &Yaml) -> Result<Arc<DynLocation>, String>;
}

type DynLocationBuilder = dyn LocationBuilder + Sync + Send;

struct RewriteBuilder;
impl LocationBuilder for RewriteBuilder {
    fn yaml_to_location(&self, _domain: &Domain, yaml: &Yaml) -> Result<Arc<DynLocation>, String> {
        match yaml.as_str() {
            Some(s) => Ok(Arc::new(domain::Rewrite { path: s.to_string() })),
            None => Err("Invalid rewrite rule; expected string".to_string()),
        }
    }
}

struct RedirectBuilder;
impl LocationBuilder for RedirectBuilder {
    fn yaml_to_location(&self, _domain: &Domain, yaml: &Yaml) -> Result<Arc<DynLocation>, String> {
        match yaml.as_hash() {
            Some(h) => {
                let mut rw: Redirect = Default::default();

                for (k, v) in h {
                    match k.as_str() {
                        None => return Err(format!("Unexpected error at {:?}", k)),
                        Some(k) => {
                            if k == "code" {
                                if let Some(i) = v.as_i64() {
                                    match StatusCode::from_u16(i as u16) {
                                        Ok(v) => rw.code = v,
                                        Err(err) => return Err(err.to_string()),
                                    }
                                }
                            } else {
                                if let Some(v) = v.as_str() {
                                    match k {
                                        "scheme" => rw.scheme = Some(v.to_string()),
                                        "authority" => rw.authority = Some(v.to_string()),
                                        "path" => rw.path = Some(v.to_string()),
                                        "query" => rw.query = Some(v.to_string()),
                                        _ => return Err(format!("Unexpected field: {}", k)),
                                    }
                                    continue;
                                }

                                return Err(format!("Invalid field value: {:?}", k));
                            }
                        }
                    }
                }

                Ok(Arc::new(rw))
            }
            None => Err("Invalid redirect rule; expected opts".to_string()),
        }
    }
}

struct FileBuilder;
impl LocationBuilder for FileBuilder {
    fn yaml_to_location(&self, domain: &Domain, yaml: &Yaml) -> Result<Arc<DynLocation>, String> {
        match yaml.as_hash() {
            Some(h) => {
                let default_mime = yaml_get_opt_string(h, "default_mime")?;
                let default_mime = match default_mime {
                    Some(v) => Mime::from_str(v.as_str()).map_err(|v| v.to_string())?,
                    None => mime::TEXT_PLAIN,
                };
                let opts = static_files::Opts {
                    root: yaml_get_opt_string(h, "root")?.unwrap_or_else(|| domain.root.clone()),
                    default_mime,
                    cache_control: yaml_get_opt_string(h, "cache_control")?.unwrap_or_else(|| "no-cache".to_string()),
                };
                Ok(Arc::new(domain::File { opts }))
            }
            None => Err("Invalid file rule; expected string".to_string()),
        }
    }
}

struct HttpProxyBuilder;
impl LocationBuilder for HttpProxyBuilder {
    fn yaml_to_location(&self, domain: &Domain, yaml: &Yaml) -> Result<Arc<DynLocation>, String> {
        match yaml.as_str() {
            Some(s) => match domain.services.get(&s.to_string()) {
                Some(proxy) => Ok(Arc::new(domain::HttpProxy {
                    server_socket: proxy.server_socket.clone(),
                })),
                None => Err(format!("Proxy not found! {}", s)),
            },
            None => Err("Invalid http_proxy rule; expected string".to_string()),
        }
    }
}

struct WebsocketProxyBuilder;
impl LocationBuilder for WebsocketProxyBuilder {
    fn yaml_to_location(&self, domain: &Domain, yaml: &Yaml) -> Result<Arc<DynLocation>, String> {
        match yaml.as_str() {
            Some(s) => match domain.services.get(&s.to_string()) {
                Some(proxy) => Ok(Arc::new(domain::WebsocketProxy {
                    server_socket: proxy.server_socket.clone(),
                })),
                None => Err(format!("Proxy not found! {}", s)),
            },
            None => Err("Invalid websocket_proxy rule; expected string".to_string()),
        }
    }
}

pub struct LocationBuilders {
    map: RwLock<HashMap<String, Arc<DynLocationBuilder>>>,
}
impl LocationBuilders {
    pub fn add(name: &str, builder: Arc<DynLocationBuilder>) {
        LOCATION_BUILDERS
            .map
            .write()
            .expect("lock write to work")
            .insert(name.to_string(), builder);
    }

    pub fn get(name: &str) -> Option<Arc<DynLocationBuilder>> {
        LOCATION_BUILDERS
            .map
            .read()
            .expect("lock read to work")
            .get(name)
            .cloned()
    }
}

lazy_static! {
    static ref LOCATION_BUILDERS: LocationBuilders = {
        let mut m: HashMap<String, Arc<DynLocationBuilder>> = HashMap::new();
        m.insert("rewrite".to_string(), Arc::new(RewriteBuilder));
        m.insert("redirect".to_string(), Arc::new(RedirectBuilder));
        m.insert("file".to_string(), Arc::new(FileBuilder));
        m.insert("http_proxy".to_string(), Arc::new(HttpProxyBuilder));
        m.insert("websocket_proxy".to_string(), Arc::new(WebsocketProxyBuilder));
        LocationBuilders { map: RwLock::new(m) }
    };
}

fn load_domain(path: &Path) -> Result<(Vec<String>, Domain), ConfError> {
    let cfg = convert_err(path, fs::read_to_string(path))?;
    let docs = convert_err(path, YamlLoader::load_from_str(&cfg))?;
    let cerr = |field, i| ConfError::new(path, field, i);
    if docs.len() != 1 {
        return Err(ConfError::new(path, "first line", "expected Hash"));
    }
    if let Some(Yaml::Hash(map)) = docs.get(0) {
        let get_opt_field = |f: &str| map.get(&Yaml::String(f.to_string()));
        let get_field = |f: &str| match get_opt_field(f) {
            None => Err(ConfError::new(path, f, "Missing field")),
            Some(v) => Ok(v),
        };
        let opt_field = |field: &str| {
            let field = field.to_string();
            match map.get(&Yaml::String(field.clone())) {
                None => Ok(String::new()),
                Some(v) => {
                    if let Some(v) = v.as_str() {
                        Ok(v.to_string())
                    } else {
                        Err(ConfError::new(path, &field, "Invalid value"))
                    }
                }
            }
        };

        let field = &"listeners";
        let listeners = match get_field(field)?.as_vec() {
            None => Err(cerr(field, "Expected String Vector")),
            Some(v) => to_env_string_list(v).ok_or(cerr(field, "Expected String Vector")),
        }?;

        let mut domain = Domain {
            root: opt_field("root")?,
            cert_path: opt_field("cert_path")?,
            ..Default::default()
        };

        let field = &"services";
        if let Some(paths) = get_opt_field(field).and_then(|v| v.as_hash()) {
            for (k, v) in paths {
                let k = k.as_str().unwrap_or("");
                if v.as_hash().is_none() {
                    return Err(cerr(field, &format!("Invalid services value {:?}", v)));
                }
                domain
                    .services
                    .insert(k.to_string(), Arc::new(load_services(path, k, v)?));
            }
        }

        let field = &"locations";
        if let Some(paths) = get_field(field)?.as_hash() {
            for (k, v) in paths {
                let k = k.as_str().unwrap_or("");
                if k.is_empty() || !k.starts_with('/') {
                    return Err(cerr(field, "Invalid path"));
                }
                if v.as_hash().is_none() {
                    return Err(cerr(field, &format!("Invalid value {:?}", v)));
                }
                let loc = load_location(&domain, path, k, v)?;
                for k in expand_path(k) {
                    if let Some(ks) = k.strip_suffix('*') {
                        domain.location_prefixes.insert(ks.to_string(), loc.clone());
                    } else {
                        domain.locations.insert(k.to_string(), loc.clone());
                    }
                }
            }
        }
        let field = &"name";
        if let Some(name) = map.get(&Yaml::String(field.to_string())).and_then(|v| v.as_str()) {
            domain.name = name.to_string();
        } else {
            let mut name = path
                .file_name()
                .expect("conf to be a filename")
                .to_string_lossy()
                .to_string();
            name.truncate(name.len() - 4);
            domain.name = name;
        }

        let field = &"aliases";
        if let Some(aliases) = map
            .get(&Yaml::String(field.to_string()))
            .and_then(|v| v.as_vec().and_then(|v| to_env_string_list(v)))
        {
            domain.aliases = aliases;
        }

        Ok((listeners, domain))
    } else {
        Err(cerr("", "Expected hash"))
    }
}

fn load_services(path: &Path, k: &str, v: &Yaml) -> Result<koru_service::Service, ConfError> {
    let mut service: koru_service::Service = Default::default();
    if let Some(v) = v.as_hash() {
        for (sk, sv) in v {
            let sk = sk.as_str().unwrap_or("");
            match sk {
                "server_socket" => {
                    if let Some(v) = sv.as_str() {
                        service.server_socket = to_env_string(v);
                        continue;
                    }
                }
                "cmd" => {
                    if let Some(mut v) = sv.as_vec().and_then(|v| to_env_string_list(v)) {
                        if v.len() > 1 {
                            let mut iter = v.drain(..);
                            service.cmd = Some((iter.next().unwrap(), iter.next().unwrap(), iter.collect()));
                            continue;
                        }
                    }
                }
                _ => (),
            }
            return Err(ConfError::new(
                path,
                k,
                &format!("Invalid service field {:?}!\n{:?}", sk, v),
            ));
        }
    }

    Ok(service)
}

fn to_env_string_list(v: &[Yaml]) -> Option<Vec<String>> {
    let ans: Result<Vec<String>, ()> = v
        .iter()
        .map(|v| match v {
            Yaml::String(v) => Ok(to_env_string(v)),
            Yaml::Integer(v) => Ok(v.to_string()),
            _ => Err(()),
        })
        .collect();
    ans.ok()
}

fn to_env_string(v: &str) -> String {
    let v = v.to_string();
    let mut prev = 0;
    let mut result = String::new();
    for (i, matched) in v.match_indices(|c| matches!(c, '$' | '}')) {
        match matched {
            "$" => {
                result += &v[prev..i];
                prev = i;
            }
            _ => {
                let var = &v[prev..i + 1];
                if prev + 1 < i && &var[0..2] == "${" {
                    let name = &var[2..var.len() - 1];
                    match env::var(name) {
                        Ok(v) => {
                            result += v.as_str();
                        }
                        Err(_) => {
                            result += var;
                        }
                    }
                } else {
                    result += var;
                }
                prev = i + 1;
            }
        }
    }
    result += &v[prev..];
    result
}

fn load_location(domain: &Domain, path: &Path, k: &str, v: &Yaml) -> Result<Arc<DynLocation>, ConfError> {
    if let Some(v) = v.as_hash() {
        let mut iter = v.iter();
        if let Some(t) = iter.next() {
            if iter.next().is_none() {
                if let Some(name) = t.0.as_str() {
                    if let Some(lb) = LocationBuilders::get(name) {
                        return lb
                            .yaml_to_location(domain, t.1)
                            .map_err(|e| ConfError::new(path, name, &e));
                    }
                }
            }
        }
    }

    Err(ConfError::new(path, k, &format!("Invalid value {:?}", v)))
}

pub fn default_cfg() -> Result<PathBuf, ConfError> {
    match ProjectDirs::from("", "", "koru-kafe") {
        None => Err(ConfError::new(&PathBuf::new(), "???", "Can't find config dir")),
        Some(pdir) => Ok(pdir.config_dir().to_owned()),
    }
}

pub async fn load_and_monitor(cdir: &Path, mut reload: mpsc::Receiver<()>) -> Result<oneshot::Receiver<()>, ConfError> {
    let cdir = PathBuf::from(cdir);
    let last_scanned = crate::round_time_secs(SystemTime::now());
    let mut set = JoinSet::new();

    let mut reload_map = HashMap::new();
    load_and_start(&mut set, &mut reload_map, &cdir, UNIX_EPOCH).await?;

    let (finished_tx, finished_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut last_scanned = last_scanned;
        loop {
            tokio::select! {
                _ = set.join_next() => {
                    set.shutdown().await;
                    break;
                }
                r = reload.recv() => {
                    match r {
                        Some(_) => {
                            let prev_mod_time = last_scanned;
                            last_scanned = crate::round_time_secs(SystemTime::now());
                            if let Err(err) = load_and_start(&mut set, &mut reload_map, &cdir, prev_mod_time).await {
                                eprintln!("Error reloading config:\n{:?}::\n", err);
                                set.shutdown().await;
                                break;
                            }
                        },
                        None => {
                            set.shutdown().await;
                            break;
                        }
                    }
                }
            }
        }

        eprintln!("Shutdown");

        let _ = finished_tx.send(());
    });

    Ok(finished_rx)
}

pub fn load_from(cdir: &Path, _modified_since: SystemTime) -> Result<(ListernerMap, domain::ServiceMap), ConfError> {
    let mut listener_map: HashMap<String, DomainMap> = HashMap::new();
    let mut service_map = HashMap::new();
    let mut tls_config_map: HashMap<String, Arc<rustls::ServerConfig>> = HashMap::new();

    for entry in convert_err(cdir, fs::read_dir(cdir))?.filter_map(|entry| {
        entry.ok().and_then(|e| {
            e.path().file_name()?.to_str().and_then(|n| {
                if n.ends_with(".yml") && n != "default-config.yml" {
                    Some(e)
                } else {
                    None
                }
            })
        })
    }) {
        let (listeners, mut domain) = load_domain(&entry.path())?;

        for (name, service) in domain.services.iter() {
            if let Some(cmd) = service.cmd_name() {
                if service_map.insert(cmd.to_string(), service.clone()).is_some() {
                    return Err(ConfError::new(
                        &entry.path(),
                        name,
                        &format!("Duplicate service app {}", cmd),
                    ));
                }
            }
        }

        if !domain.cert_path.is_empty() {
            if let Some(config) = tls_config_map.get(&domain.cert_path) {
                domain.tls_config = Some(config.clone());
            } else {
                tls_config_map.insert(
                    domain.cert_path.clone(),
                    set_cert(&mut domain).map_err(|msg| ConfError::new(&entry.path(), "cert_path", &msg))?,
                );
            }
        }
        let domain = Arc::new(domain);
        for l in listeners {
            if let Some(dm) = listener_map.get(&l) {
                if let Some(v) = dm.values().next() {
                    if v.cert_path.is_empty() != domain.cert_path.is_empty() {
                        return Err(ConfError::new(
                            cdir,
                            "cert_path",
                            &format!(
                                "Mixed TLS and Plain domains on listener: {} and {}\n",
                                v.name, domain.name
                            ),
                        ));
                    }
                }
            }
            let entry = listener_map.entry(l).or_insert(HashMap::new());
            entry.insert(domain.name.to_string(), domain.clone());
            for name in &domain.aliases {
                entry.insert(name.to_string(), domain.clone());
            }
        }
    }
    Ok((listener_map, service_map))
}

fn set_cert(domain: &mut Domain) -> Result<Arc<rustls::ServerConfig>, String> {
    let mut cert = PathBuf::from(&domain.cert_path);
    let mut priv_key = cert.clone();
    cert.push("fullchain.pem");
    priv_key.push("privkey.pem");
    let cert = load_certs(&cert).map_err(|e| format!("bad cert {:?}: {}", cert, e))?;
    let priv_key = load_key(&priv_key).map_err(|e| format!("bad privkey {:?}: {}", priv_key, e))?;

    match rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert, priv_key)
    {
        Err(err) => Err(err.to_string()),
        Ok(mut config) => {
            config.alpn_protocols.push(b"h2".to_vec());
            config.alpn_protocols.push(b"http/1.1".to_vec());

            let config = Arc::new(config);
            domain.tls_config = Some(config.clone());

            Ok(config)
        }
    }
}

fn load_certs(path: &Path) -> io::Result<Vec<rustls::Certificate>> {
    rustls_pemfile::certs(&mut io::BufReader::new(fs::File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(rustls::Certificate).collect())
}

fn load_key(path: &Path) -> io::Result<rustls::PrivateKey> {
    let keyfile = fs::File::open(path)?;
    let mut reader = io::BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::RSAKey(key)) => return Ok(rustls::PrivateKey(key)),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return Ok(rustls::PrivateKey(key)),
            Some(rustls_pemfile::Item::ECKey(key)) => return Ok(rustls::PrivateKey(key)),
            None => break,
            _ => {}
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("no keys found in {:?} (encrypted keys not supported)", path),
    ))
}

fn yaml_get_opt_string(h: &yaml::Hash, field: &str) -> Result<Option<String>, String> {
    if let Some(v) = h.get(&Yaml::String(field.to_string())) {
        if let Some(v) = v.as_str() {
            Ok(Some(v.to_string()))
        } else {
            Err(format!("field {} not a string", field))
        }
    } else {
        Ok(None)
    }
}

type ReloadMap = HashMap<String, mpsc::Sender<HashMap<String, Arc<Domain>>>>;

async fn load_and_start(
    set: &mut JoinSet<()>,
    reload_map: &mut ReloadMap,
    cdir: &Path,
    last_scanned: SystemTime,
) -> Result<(), ConfError> {
    let (domain_map, mut services_map) = load_from(cdir, last_scanned)?;

    if !services_map.is_empty() {
        if last_scanned != UNIX_EPOCH {
            eprintln!(
                "Managed services is not currently supported for reload!\n{:?}\n",
                services_map.keys().collect::<Vec<&String>>()
            );
        } else {
            for (_, service) in services_map.drain() {
                set.spawn(async move {
                    if let Err(err) = service.start().await {
                        eprintln!(
                            "Failed to start {}:\n{:?}\n",
                            service.cmd_name().unwrap_or_default(),
                            err
                        );
                    }
                });
            }
        }
    }

    for (addr, domains) in domain_map {
        if let Some(tx) = reload_map.get_mut(&addr) {
            println!("Reloading Server listening on {}", addr);

            if let Err(err) = tx.send(domains).await {
                return Err(ConfError::new(cdir, &addr, err.to_string().as_str()));
            }
        } else {
            println!("Listening on {}", addr);

            let (tx, rx) = mpsc::channel(1);

            reload_map.insert(addr.clone(), tx);

            set.spawn(async move {
                if let Some(d) = domains.values().next() {
                    let res = if d.cert_path.is_empty() {
                        listener::listen(addr, domains, rx).await
                    } else {
                        listener::tls_listen(addr, domains, rx).await
                    };
                    if let Err(err) = res {
                        eprintln!("Listen err {:?}", err);
                    }
                }
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    // use super::*;

    use std::{path::Path, time::UNIX_EPOCH};

    use crate::domain::Redirect;

    fn s(v: &str) -> String {
        v.to_string()
    }

    #[test]
    fn load_from() -> crate::Result<()> {
        let (cb, _) = super::load_from(Path::new("tests/config"), UNIX_EPOCH)?;
        assert_eq!(cb.len(), 2);

        let ds = cb.get("[::]:8088").unwrap();
        let (n, d) = ds.iter().next().unwrap();
        assert_eq!(n, "*");

        let rw = d
            .location_prefixes
            .get_ancestor_value("/abc/123")
            .unwrap()
            .as_any()
            .downcast_ref::<Redirect>()
            .unwrap();

        assert_eq!(rw.code, 301);
        assert_eq!(rw.scheme, Some("https".to_string()));
        assert_eq!(rw.path, None);

        let ds = cb.get("localhost:8080").unwrap();

        let (n, d) = ds.iter().next().unwrap();
        assert_eq!(n, "localhost");
        let (n, service) = d.services.iter().next().unwrap();
        assert_eq!(n, "app");
        assert_eq!(
            service.cmd,
            Some((s("my-test-cmd"), s("../cmd-name"), vec![s("arg1"), s("arg2")]))
        );
        assert_eq!(service.server_socket, "localhost:3000");

        let v1 = d.location_prefixes.get_ancestor_value("/ws/123").unwrap();
        let v2 = d.locations.get("/rc").unwrap();

        assert_eq!(format!("{v1:?}"), format!("{v2:?}"));

        Ok(())
    }

    #[test]
    fn to_arg_list() -> crate::Result<()> {
        let yaml =
            yaml_rust::YamlLoader::load_from_str(r##"[1, 2, "th$r}ee", "f{ou}r${PWD}f$ve${HOME}", "${HOME}"] "##)?;
        let yaml = yaml[0].as_vec().unwrap();

        let exp = vec![
            "1".to_string(),
            "2".to_string(),
            "th$r}ee".to_string(),
            format!("f{2}r{0}f$ve{1}", std::env::var("PWD")?, std::env::var("HOME")?, "{ou}"),
            std::env::var("HOME")?,
        ];

        let ans = super::to_env_string_list(yaml).unwrap();

        assert_eq!(ans, exp);
        Ok(())
    }
}
