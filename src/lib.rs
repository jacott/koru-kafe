use std::time::{Duration, SystemTime};

use hyper::{header, Request};

pub mod conf;
pub mod domain;
pub mod koru_service;
pub mod listener;
pub mod location_path;
pub mod static_files;

pub const SRC_PATH: &str = env!("CARGO_MANIFEST_DIR");

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
        let f = file!();
        eprintln!(
            // split so that not found when looking for the word in an editor
            "error: {}\n    at {}/{}:{}:{}",
            format!($($arg,)*),
            if f.starts_with('/') { &"" } else { $crate::SRC_PATH },
            f,
            line!(),
            column!()
        )
    };
}

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

pub fn round_time_secs(time: SystemTime) -> SystemTime {
    SystemTime::UNIX_EPOCH
        + Duration::new(
            time.duration_since(SystemTime::UNIX_EPOCH)
                .expect("EPOCH to work")
                .as_secs(),
            0,
        )
}

pub fn host_from_req<T>(req: &Request<T>) -> Option<&str> {
    if let Some(host_raw) = req.headers().get(header::HOST) {
        if let Ok(host_raw) = host_raw.to_str() {
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
    }
    None
}
