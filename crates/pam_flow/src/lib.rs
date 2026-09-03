//! Flow definitions: the YAML schema, validation, normalized rendering,
//! digest, the embedded starter flows, and the global library directory.
//!
//! Pure library — no daemon knowledge. See
//! `docs/specs/2026-09-02-flows-connectors-design.md`.
//!
//! A flow is one YAML file: an id, a name, a description, optional inputs,
//! and an ordered list of steps. A step either runs an allowlisted local
//! program (`run: [git, status, --short]`) or calls one read-only connector
//! operation (`connector: github`, `call: runs`). [`parse`] turns the text
//! into a [`Flow`] or into a [`FlowError::Invalid`] naming the offending
//! YAML path; [`to_normalized_yaml`] renders a `Flow` back in canonical key
//! order with defaults omitted, and [`digest`] fingerprints that rendering.
//!
//! ```
//! let flow = pam_flow::parse(
//!     "schema: 1\nid: demo\nname: Demo\nsteps:\n  - id: status\n    run: [git, status]\n",
//! )?;
//! assert_eq!(flow.steps.len(), 1);
//! assert!(pam_flow::to_normalized_yaml(&flow).starts_with("schema: 1\n"));
//! # Ok::<(), pam_flow::FlowError>(())
//! ```

#![forbid(unsafe_code)]

pub mod builtin;
pub mod duration;
pub mod library;
pub mod normalize;
pub mod schema;
pub mod validate;
pub mod vars;

pub use builtin::{BuiltinFlow, builtin, builtin_yaml};
pub use duration::{DurationError, format_duration, parse_duration};
pub use library::{Entry, Library, Source};
pub use normalize::{digest, to_normalized_yaml};
pub use schema::{
    Action, Approval, ArgValue, ConnectorId, Effect, Flow, Input, OutputPolicy, Retry, Role,
    SCHEMA_VERSION, Step, When,
};
pub use validate::{
    CallSpec, DEFAULT_TIMEOUT, FlowError, MAX_ARG_BYTES, MAX_ARGS, MAX_ARGV_BYTES,
    MAX_DESCRIPTION_BYTES, MAX_FILE_BYTES, MAX_ID_BYTES, MAX_INPUTS, MAX_LIBRARY_ENTRIES,
    MAX_NAME_BYTES, MAX_RETRY_ATTEMPTS, MAX_RETRY_BACKOFF, MAX_STEPS, MAX_TIMEOUT, SHELLS,
    connector_calls, is_sensitive_arg, is_shell, looks_secret_like, parse, parse_value,
};
pub use vars::{VarError, Vars, references, substitute};

#[cfg(test)]
mod builtin_test;
#[cfg(test)]
mod duration_test;
#[cfg(test)]
mod library_test;
#[cfg(test)]
mod normalize_test;
#[cfg(test)]
mod schema_test;
#[cfg(test)]
mod validate_test;
#[cfg(test)]
mod vars_test;
