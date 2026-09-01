//! Daemon services. Each domain (transport, policy gate, queue manager,
//! executor, approvals, audit) runs as a long-lived task owning its state
//! and communicating over typed channels.

pub mod policy;
pub mod runtime_dir;
pub mod transport;

#[cfg(test)]
mod policy_test;
#[cfg(test)]
mod runtime_dir_test;
