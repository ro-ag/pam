#![forbid(unsafe_code)]

mod error;
mod flow;
mod lifecycle;
#[cfg(target_os = "macos")]
mod macos_admission;
mod model_service;
mod ptrack;
mod status;
#[cfg(test)]
mod status_test;

#[cfg(test)]
mod flow_test;
#[cfg(test)]
mod lifecycle_test;
#[cfg(all(test, target_os = "macos"))]
mod macos_admission_test;
#[cfg(test)]
mod model_service_test;
#[cfg(test)]
mod ptrack_test;

pub use error::{DaemonError, ExchangeError, StatusError};
pub use lifecycle::{BriefProvider, DaemonConfig, run, serve_until};
pub use status::{
    ClientExchange, StatusExchange, StreamingExchange, StreamingExchangeError, request_exchange,
    request_exchange_streaming, request_status,
};
