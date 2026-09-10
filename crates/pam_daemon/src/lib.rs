//! Daemon services. Each domain (transport, policy gate, queue manager,
//! executor, approvals, audit) runs as a long-lived task owning its state
//! and communicating over typed channels.

pub mod admin;
pub mod admin_compressor;
pub mod admin_connectors;
pub mod admin_flows;
pub mod admin_logs;
pub mod admin_models;
pub mod admin_retention;
pub mod admin_transport;
pub mod approval;
pub mod command_containment;
#[cfg(test)]
mod command_containment_test;
pub mod connector_service;
mod correlation;
mod correlation_eval;
#[cfg(test)]
mod correlation_eval_test;
pub mod daemon;
mod evidence_service;
mod evidence_view;
#[cfg(test)]
mod evidence_view_test;
pub mod executor;
mod flow_contract;
#[cfg(test)]
mod flow_contract_test;
pub mod flow_exec;
mod flow_result_service;
#[cfg(test)]
mod flow_result_service_test;
pub mod flow_service;
pub mod lifecycle;
mod log_semantic;
pub mod log_service;
pub mod model_service;
pub mod policy;
pub mod queue;
pub mod retention;
pub mod runtime_dir;
pub mod secrets;
pub mod transport;

#[cfg(test)]
mod admin_connectors_test;
#[cfg(test)]
mod admin_flows_test;
#[cfg(test)]
mod admin_logs_test;
#[cfg(test)]
mod admin_models_test;
#[cfg(test)]
mod admin_retention_test;
#[cfg(test)]
mod admin_test;
#[cfg(test)]
mod approval_test;
#[cfg(test)]
mod connector_service_test;
#[cfg(test)]
mod daemon_repository_test;
#[cfg(test)]
mod daemon_test;
#[cfg(test)]
mod executor_test;
#[cfg(test)]
mod flow_exec_test;
#[cfg(test)]
mod flow_service_test;
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
mod retention_test;
#[cfg(test)]
mod runtime_dir_test;
#[cfg(test)]
mod secrets_test;

#[cfg(test)]
mod transport_test;

mod blocking_jobs;
#[cfg(test)]
mod blocking_jobs_test;
pub mod request_budget;
#[cfg(test)]
mod request_budget_test;

pub mod scope_policy;
#[cfg(test)]
mod scope_policy_test;

mod admission_rate;
#[cfg(test)]
mod admission_rate_test;
