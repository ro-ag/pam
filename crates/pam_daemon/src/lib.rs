//! Daemon services. Each domain (transport, policy gate, queue manager,
//! executor, approvals, audit) runs as a long-lived task owning its state
//! and communicating over typed channels.

pub mod approval;
pub mod daemon;
pub mod executor;
pub mod policy;
pub mod queue;
pub mod runtime_dir;
pub mod transport;

#[cfg(test)]
mod approval_test;
#[cfg(test)]
mod daemon_test;
#[cfg(test)]
mod executor_test;
#[cfg(test)]
mod policy_test;
#[cfg(test)]
mod queue_test;
#[cfg(test)]
mod runtime_dir_test;
