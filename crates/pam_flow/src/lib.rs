//! Flow definitions.
#![forbid(unsafe_code)]
pub mod duration;
pub use duration::{DurationError, format_duration, parse_duration};
#[cfg(test)]
mod duration_test;
pub mod schema;
pub use schema::{Action, Approval, ArgValue, ConnectorId, Effect, Flow, Input, OutputPolicy, Retry, Role, SCHEMA_VERSION, Step, When};
#[cfg(test)]
mod schema_test;
