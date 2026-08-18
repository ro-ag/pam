#![forbid(unsafe_code)]

mod error;
mod lifecycle;
mod ptrack;
mod status;

#[cfg(test)]
mod lifecycle_test;
#[cfg(test)]
mod ptrack_test;

pub use error::{DaemonError, ExchangeError, StatusError};
pub use lifecycle::{BriefProvider, DaemonConfig, run, serve_until};
pub use status::{ClientExchange, StatusExchange, request_exchange, request_status};
