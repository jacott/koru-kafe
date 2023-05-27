use crate::domain::{self, Domain, DynLocation};
use directories::ProjectDirs;
use serde_derive::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
};
use std::{error::Error, fmt};
use tokio_rustls::rustls;
use yaml_rust::{Yaml, YamlLoader};

pub mod domain_conf;

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Conf {}

#[derive(Debug, Deserialize, Serialize)]
pub struct Listener {
    pub host: String,
    pub port: String,
    pub domains: Vec<domain_conf::DomainConf>,
}

impl Listener {
    pub fn key(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl Default for Listener {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: "8080".to_string(),
            domains: vec![Default::default()],
        }
    }
}

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

impl Error for ConfError {
    fn description(&self) -> &str {
        self.info.as_ref()
    }

    fn cause(&self) -> Option<&dyn Error> {
        None
    }
}

impl fmt::Display for ConfError {
    // col starts from 0
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "{} at filed {} file {}",
            self.info, self.field, self.file
        )
    }
}

fn convert_err<T, E: Error>(pbuf: &Path, r: Result<T, E>) -> Result<T, ConfError> {
    match r {
        Ok(r) => Ok(r),
        Err(err) => Err(ConfError::new(pbuf, "", &err.to_string())),
    }
}

fn load_domain(path: &Path) -> Result<(Vec<String>, Domain, String), ConfError> {
    eprintln!("entry {:?}", path);
    let cfg = convert_err(path, fs::read_to_string(path))?;
    let docs = convert_err(path, YamlLoader::load_from_str(&cfg))?;
    let cerr = |field, i| ConfError::new(path, field, i);
    if docs.len() != 1 {
        return Err(ConfError::new(path, "first line", "expected Hash"));
    }
    if let Some(Yaml::Hash(map)) = docs.get(0) {
        let get_field = |f: &str| match map.get(&Yaml::String(f.to_string())) {
            None => Err(ConfError::new(path, f, "Missing field")),
            Some(v) => Ok(v),
        };
        let field = &"listeners";
        let listeners = match get_field(field)?.as_vec() {
            None => Err(cerr(field, "Expected String Vector")),
            Some(v) => {
                let vs: Vec<String> = v
                    .iter()
                    .filter_map(|v| v.as_str().map(|v| v.to_string()))
                    .collect();
                if v.len() == vs.len() {
                    Ok(vs)
                } else {
                    Err(cerr(field, "Expected String Vector"))
                }
            }
        }?;

        let mut domain: Domain = Default::default();

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

        domain.root = opt_field("root")?;
        domain.cert_path = opt_field("cert_path")?;

        let field = &"proxies";
        if let Some(paths) = get_field(field)?.as_hash() {
            for (k, v) in paths {
                let k = k.as_str().unwrap_or("");
                if v.as_hash().is_none() {
                    return Err(cerr(field, &format!("Invalid value {:?}", v)));
                }
                domain
                    .proxies
                    .insert(k.to_string(), load_proxy(path, k, v)?);
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
                if k.ends_with('*') {
                    let ks = k.strip_suffix('*').unwrap();
                    domain
                        .location_prefixes
                        .insert(ks.to_string(), load_location(&domain, path, k, v)?);
                } else {
                    domain
                        .locations
                        .insert(k.to_string(), load_location(&domain, path, k, v)?);
                }
            }
        }
        let mut name = path.file_name().unwrap().to_string_lossy().to_string();
        name.truncate(name.len() - 4);
        Ok((listeners, domain, name))
    } else {
        Err(cerr("", "Expected hash"))
    }
}

fn load_proxy(path: &Path, k: &str, v: &Yaml) -> Result<domain::ProxyConf, ConfError> {
    if let Some(v) = v.as_hash() {
        let mut iter = v.iter();
        if let Some(t) = iter.next() {
            if iter.next().is_none() && t.0.as_str().unwrap_or("") == "server_socket" {
                if let Some(t) = t.1.as_str() {
                    return Ok(domain::ProxyConf {
                        server_socket: t.to_string(),
                    });
                }
            }
        }
    }

    Err(ConfError::new(path, k, &format!("Invalid value {:?}", v)))
}

fn load_location(
    domain: &Domain,
    path: &Path,
    k: &str,
    v: &Yaml,
) -> Result<Arc<DynLocation>, ConfError> {
    if let Some(v) = v.as_hash() {
        let mut iter = v.iter();
        if let Some(t) = iter.next() {
            if iter.next().is_none() {
                let loc = match t.0.as_str().unwrap_or("") {
                    "rewrite" => rewrite_from_yaml(t.1),
                    "http_proxy" => http_proxy_from_yaml(domain, t.1),
                    "websocket_proxy" => websocket_proxy_from_yaml(domain, t.1),
                    _ => None,
                };
                if let Some(loc) = loc {
                    return Ok(loc);
                }
            }
        }
    }

    Err(ConfError::new(path, k, &format!("Invalid value {:?}", v)))
}

fn rewrite_from_yaml(t: &Yaml) -> Option<Arc<DynLocation>> {
    Some(Arc::new(domain::Rewrite {
        path: t.as_str()?.to_string(),
    }))
}

fn http_proxy_from_yaml(domain: &Domain, t: &Yaml) -> Option<Arc<DynLocation>> {
    Some(Arc::new(domain::HttpProxy {
        server_socket: domain
            .proxies
            .get(&t.as_str()?.to_string())?
            .server_socket
            .clone(),
    }))
}

fn websocket_proxy_from_yaml(domain: &Domain, t: &Yaml) -> Option<Arc<DynLocation>> {
    Some(Arc::new(domain::WebsocketProxy {
        server_socket: domain
            .proxies
            .get(&t.as_str()?.to_string())?
            .server_socket
            .clone(),
    }))
}

pub type ListernerMap = HashMap<String, domain::DomainMap>;

pub fn load() -> Result<(ListernerMap, ListernerMap), ConfError> {
    let pdir = ProjectDirs::from("", "", "koru-kafe");
    if pdir.is_none() {
        return Err(ConfError::new(
            &PathBuf::new(),
            "???",
            "Can't find config dir",
        ));
    }
    let pdir = pdir.unwrap();
    let cdir = pdir.config_dir();
    let mut tls_map = HashMap::new(); // TLS encrypted socket listener
    let mut psl_map = HashMap::new(); // unencrypted socket listener
    let mut tls_config_map: HashMap<String, Arc<rustls::ServerConfig>> = HashMap::new();

    for entry in convert_err(cdir, fs::read_dir(cdir))?.filter_map(|entry| {
        entry.ok().and_then(|e| {
            e.path().file_name()?.to_str().and_then(|n| {
                if n.ends_with(".yml") && n != "default-config.yml" {
                    Some(e)
                } else {
                    eprintln!("n {:?}", n);
                    None
                }
            })
        })
    }) {
        let (listeners, mut domain, domain_name) = load_domain(&entry.path())?;

        if let Some(config) = tls_config_map.get(&domain.cert_path) {
            domain.tls_config = Some(config.clone());
        } else {
            match set_cert(&mut domain) {
                Ok(config) => tls_config_map.insert(domain.cert_path.clone(), config),
                Err(err) => return Err(ConfError::new(&entry.path(), "cert_path", &err.to_string())),
            };
        }
        let domain = Arc::new(domain);
        for l in listeners {
            let entry = if domain.cert_path.is_empty() {
                psl_map.entry(l).or_insert(HashMap::new())
            } else {
                tls_map.entry(l).or_insert(HashMap::new())
            };
            entry.insert(domain_name.to_string(), domain.clone());
        }
    }
    Ok((tls_map, psl_map))
}

fn set_cert(domain: &mut Domain) -> Result<Arc<rustls::ServerConfig>, io::Error> {
    let mut cert = PathBuf::from(&domain.cert_path);
    let mut priv_key = cert.clone();
    cert.push("fullchain.pem");
    priv_key.push("privKey.pem");
    let cert = load_certs(&cert)?;
    let priv_key = load_key(&priv_key)?;

    let mut config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert, priv_key)
        .unwrap();

    config.alpn_protocols.push(b"h2".to_vec());
    config.alpn_protocols.push(b"http/1.1".to_vec());

    let config = Arc::new(config);
    domain.tls_config = Some(config.clone());

    Ok(config)
}

fn load_certs(path: &Path) -> io::Result<Vec<rustls::Certificate>> {
    rustls_pemfile::certs(&mut io::BufReader::new(fs::File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(rustls::Certificate).collect())
}

fn load_key(path: &Path) -> io::Result<rustls::PrivateKey> {
    eprintln!("DEBUG path {:?}", path);

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

#[cfg(test)]
mod tests {
    // use super::*;

    #[test]
    fn expr() {
        let s = "1234*";
        assert_eq!(format!("slice {:?}", s.strip_suffix('*')), "FIXME");
    }
}
//     #[tokio::test]
//     async fn yaml() -> crate::Result<()> {
//         spawn_listeners().await?;
//         Ok(())
//     }
//     //     #[test]
//     //     fn default() -> crate::Result<()> {
//     //         let cfg: Conf = Default::default();

//     //         let out = toml::to_string_pretty(&cfg)?;
//     //         eprintln!("{}", out);
//     //         assert_eq!(
//     //             out,
//     //             r###"[[listeners]]
//     // host = "127.0.0.1"
//     // port = "8080"

//     // [[listeners.domains]]
//     // name = "localhost"
//     // root = "app/localhost"

//     // [listeners.domains.proxies.proxy]
//     // host_addr = "localhost:3000"

//     // [listeners.domains.locations]

//     // [listeners.domains.location_prefixes."/"]
//     // Proxy = "proxy"
//     // "###
//     //             .to_string()
//     //         );
//     //         Ok(())
//     //     }
// }
