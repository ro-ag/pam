//! Daemon services. Each domain (transport, policy gate, queue manager,
//! executor, approvals, audit) runs as a long-lived task owning its state
//! and communicating over typed channels.

pub mod admin;
pub mod admin_logs;
pub mod admin_models;
pub mod approval;
pub mod daemon;
pub mod executor;
pub mod lifecycle;
pub mod log_service;
pub mod model_service;
pub mod policy;
pub mod queue;
pub mod runtime_dir;
pub mod secrets;
pub mod transport;

#[cfg(test)]
mod admin_logs_test;
#[cfg(test)]
mod admin_models_test;
#[cfg(test)]
mod admin_test;
#[cfg(test)]
mod approval_test;
#[cfg(test)]
mod daemon_test;
#[cfg(test)]
mod executor_test;
#[cfg(test)]
mod lifecycle_test;
#[cfg(test)]
mod log_service_test;
#[cfg(test)]
mod model_service_test;
#[cfg(test)]
mod policy_test;
#[cfg(test)]
mod queue_test;
#[cfg(test)]
mod runtime_dir_test;
#[cfg(test)]
mod secrets_test;
