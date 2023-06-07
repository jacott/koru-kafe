use std::time::{Duration, SystemTime};

pub mod conf;
pub mod domain;
pub mod koru_service;
pub mod listener;
pub mod location_path;
pub mod static_files;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

pub fn round_time_secs(time: SystemTime) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::new(time.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(), 0)
}
