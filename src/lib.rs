use std::time::{Duration, SystemTime};

use http_body_util::{combinators, BodyExt, Empty, Full};
use hyper::{
    body::{Body, Bytes, Incoming},
    header, Request, Response,
};

pub mod conf;
pub mod domain;
pub mod hyper_websockets;
pub mod koru_service;
pub mod listener;
pub mod location_path;
pub mod static_files;

#[cfg(test)]
pub mod test_util;

pub const SRC_PATH: &str = env!("CARGO_MANIFEST_DIR");

#[macro_export]
macro_rules! fixme {
    ($a:expr) => {
        eprintln!(
            // split so that not found when looking for the word in an editor
            "fixme\
             !{:?}\n    at {}:{}:{}",
            $a,
            file!(),
            line!(),
            column!()
        )
    };
}

#[macro_export]
macro_rules! info {
    ($($arg:expr),*) => {
        eprintln!("kafe info: {}",  format!($($arg,)*))
        // eprintln!(
        //     // split so that not found when looking for the word in an editor
        //     "info: {}\n    at {}/{}:{}:{}",
        //     format!($($arg,)*),
        //     $crate::SRC_PATH,
        //     file!(),
        //     line!(),
        //     column!()
        // )
    };
}

#[macro_export]
macro_rules! error {
    ($($arg:expr),*) => {
        eprintln!(
            // split so that not found when looking for the word in an editor
            "error: {}\n    at {}:{}:{}",
            format!($($arg,)*),
            file!(),
            line!(),
            column!()
        )
    };
}

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

pub fn static_resp(code: u16, chunk: &'static str) -> Resp {
    Response::builder()
        .status(code)
        .body(full_body(Bytes::from(chunk)))
        .unwrap()
}

pub fn resp_404() -> Resp {
    static_resp(404, "Not found\n")
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
