use std::{
    fmt,
    time::{Duration, SystemTime},
};

use http::StatusCode;
use http_body_util::{combinators, BodyExt, Empty, Full};
pub use hyper::body::Bytes;
use hyper::{
    body::{Body, Incoming},
    header, Request, Response,
};
pub use tracing::{error, info};

pub mod conf;
pub mod domain;
pub mod koru_service;
pub mod listener;
pub mod location_path;
pub mod static_files;
pub mod websockets;

#[cfg(test)]
pub mod test_util;

pub const SRC_PATH: &str = env!("CARGO_MANIFEST_DIR");

#[macro_export]
macro_rules! fixme {
    ($a:expr) => {{
        extern crate std;
        std::eprintln!(
            // split so that not found when looking for the word in an editor
            "FIXME\
             ! at ./{}:{}:{}\n{:?}",
            file!(),
            line!(),
            column!(),
            $a,
        )
    }};
}

#[derive(Debug)]
pub struct BadRequestError(String);

impl fmt::Display for BadRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bad Request: {}\r\n", self.0)
    }
}

impl std::error::Error for BadRequestError {}

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

pub type BoxBody = combinators::BoxBody<Bytes, crate::Error>;
pub type Req = Request<Incoming>;
pub type Resp = Response<BoxBody>;
pub type ResultResp = Result<Resp>;

pub fn full_body<T: Into<Bytes>>(chunk: T) -> BoxBody {
    Full::new(chunk.into()).map_err(|never| match never {}).boxed()
}
pub fn resp<T: Into<Bytes>>(code: u16, chunk: T) -> Resp {
    Response::builder().status(code).body(full_body(chunk)).unwrap()
}

pub fn static_resp<C: Into<StatusCode>>(code: C) -> Resp {
    let code = code.into();
    Response::builder()
        .status(code)
        .body(full_body(Bytes::from(code.to_string())))
        .unwrap()
}

pub fn resp_404() -> Resp {
    static_resp(StatusCode::NOT_FOUND)
}

fn empty_body() -> BoxBody {
    Empty::new().map_err(|never| match never {}).boxed()
}

pub fn round_time_secs(time: SystemTime) -> SystemTime {
    SystemTime::UNIX_EPOCH
        + Duration::new(
            time.duration_since(SystemTime::UNIX_EPOCH)
                .expect("EPOCH to work")
                .as_secs(),
            0,
        )
}

pub fn host_from_req(req: &Request<impl Body>) -> Option<&str> {
    if let Some(host_raw) = req.headers().get(header::HOST)
        && let Ok(host_raw) = host_raw.to_str()
    {
        return Some(match host_raw.rfind(':') {
            Some(idx) => {
                if host_raw[idx + 1..].parse::<u16>().is_ok() {
                    &host_raw[..idx]
                } else {
                    host_raw
                }
            }
            None => host_raw,
        });
    }
    None
}
