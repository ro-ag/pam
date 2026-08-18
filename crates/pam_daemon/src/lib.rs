#![forbid(unsafe_code)]

mod error;
mod lifecycle;
mod status;

#[cfg(test)]
mod lifecycle_test;

pub use error::{DaemonError, StatusError};
pub use lifecycle::{DaemonConfig, run, serve_until};
pub use status::{StatusExchange, request_status};
