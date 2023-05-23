pub mod conf;
pub mod domain;
pub mod koru_proxy;
pub mod listener;
pub mod static_files;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;
