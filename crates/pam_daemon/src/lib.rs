//! Daemon services. Each domain (transport, policy gate, queue manager,
//! executor, approvals, audit) runs as a long-lived task owning its state
//! and communicating over typed channels.

pub mod admin;
pub mod admin_connectors;
pub mod admin_engine;
#[cfg(test)]
mod admin_engine_test;
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
mod context_summary;
#[cfg(test)]
mod context_summary_test;
mod correlation;
mod correlation_eval;
#[cfg(test)]
mod correlation_eval_test;
pub mod daemon;
pub mod diagnosis_service;
#[cfg(test)]
mod diagnosis_service_test;
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
pub mod log_service;
pub mod model_readiness;
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
mod lifecycle_recovery_test;
#[cfg(test)]
mod lifecycle_test;
#[cfg(test)]
mod log_service_test;
#[cfg(test)]
mod model_readiness_test;
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

pub(crate) mod sonar_mapping;
#[cfg(test)]
mod sonar_mapping_test;

mod flow_recovery;
#[cfg(test)]
mod flow_recovery_test;

#[cfg(test)]
mod flow_resume_integration_test;

#[cfg(test)]
mod queue_watch_test;

mod flow_watch;
#[cfg(test)]
mod flow_watch_test;

#[cfg(test)]
mod correlation_test;

#[cfg(test)]
mod watch_integration_test;

mod landing_checkout;
mod landing_git;
mod landing_pack;
mod landing_policy;
#[cfg(test)]
mod landing_policy_test;
