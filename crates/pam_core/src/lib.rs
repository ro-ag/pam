#![forbid(unsafe_code)]

mod identity;
mod queue;

#[cfg(test)]
mod identity_test;
#[cfg(test)]
mod queue_test;

pub use identity::{CallerId, IdempotencyKey, ProjectId, RequestId};
pub use queue::{ProjectPermit, ProjectQueue};

pub const APPLICATION_VERSION: &str = env!("CARGO_PKG_VERSION");
