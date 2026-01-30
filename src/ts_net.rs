use std::{error, fmt::Display, io};

use http::StatusCode;
pub use tokio::net::*;

#[derive(Debug, PartialEq)]
pub struct Error {
    pub code: StatusCode,
    pub reason: String,
}
impl Error {
    pub fn new(code: StatusCode, reason: String) -> Self {
        Self { code, reason }
    }

    pub fn bad_gateway<E: Display>(value: E) -> Self {
        Self {
            code: StatusCode::BAD_GATEWAY,
            reason: value.to_string(),
        }
    }

    pub fn unauthorized<E: Display>(value: E) -> Self {
        Self {
            code: StatusCode::UNAUTHORIZED,
            reason: value.to_string(),
        }
    }

    pub fn internal_error<E: Display>(value: E) -> Self {
        Self {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            reason: value.to_string(),
        }
    }

    pub fn access_denied() -> Error {
        "access_denied".into()
    }

    pub fn closed() -> Error {
        "closed".into()
    }
}
impl error::Error for Error {}
impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code.as_u16(), self.reason)
    }
}
impl From<&str> for Error {
    fn from(value: &str) -> Self {
        Self::internal_error(value)
    }
}
impl From<String> for Error {
    fn from(value: String) -> Self {
        Self::internal_error(value)
    }
}
impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::internal_error(value.to_string())
    }
}
