use std::collections::HashMap;

use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct DomainConf {
    pub listeners: Vec<String>,
    pub root: String,
    pub proxies: Vec<Proxy>,
    pub locations: HashMap<String, Location>,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Location {
    Proxy { path: String, name: String },
    Rewrite(String),
    // Root(String),
    // WebsocketProxy(String),
    // Return(u16, String),
}

impl Default for Location {
    fn default() -> Self {
        Location::Proxy {
            path: "/".to_string(),
            name: "app".to_string(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Proxy {
    name: String,
    host_addr: String,
}

impl Default for Proxy {
    fn default() -> Self {
        Self {
            name: "app".to_string(),
            host_addr: "localhost:3000".to_string(),
        }
    }
}

impl Default for DomainConf {
    fn default() -> Self {
        let name = "localhost".to_string();
        let root = format!("app/{}", &name);
        let mut locations = HashMap::new();
        locations.insert("localhost:8080".to_string(), Default::default());
        Self {
            root,
            listeners: vec!["127.0.0.1:8080".to_string()],
            proxies: vec![Default::default()],
            locations,
        }
    }
}

impl DomainConf {
    pub fn load(_path: &str) -> crate::Result<DomainConf> {
        let cfg = Default::default();
        Ok(cfg)
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn default() -> crate::Result<()> {
//         let cfg: DomainConf = Default::default();
//         eprintln!("h1 {:?}", cfg);
//         let out = toml::to_string_pretty(&cfg);
//         eprintln!("h2 {:?}", out);

//         assert_eq!(
//             out?,
//             r###"name = "localhost"
// root = "app/localhost"

// [proxies.proxy]
// host_addr = "localhost:3000"

// [locations]

// [location_prefixes."/"]
// Proxy = "proxy"
// "###
//             .to_string()
//         );
//         Ok(())
//     }
// }
