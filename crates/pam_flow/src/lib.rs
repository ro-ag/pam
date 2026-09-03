//! Flow definitions.
#![forbid(unsafe_code)]
pub mod duration;
pub use duration::{DurationError, format_duration, parse_duration};
#[cfg(test)]
mod duration_test;
pub mod schema;
pub use schema::{
    Action, Approval, ArgValue, ConnectorId, Effect, Flow, Input, OutputPolicy, Retry, Role,
    SCHEMA_VERSION, Step, When,
};
#[cfg(test)]
mod schema_test;
pub mod vars;
pub use vars::{VarError, Vars, references, substitute};
pub mod validate;
#[cfg(test)]
mod vars_test;
pub use validate::{
    CallSpec, DEFAULT_TIMEOUT, FlowError, MAX_ARG_BYTES, MAX_ARGS, MAX_ARGV_BYTES,
    MAX_DESCRIPTION_BYTES, MAX_FILE_BYTES, MAX_ID_BYTES, MAX_INPUTS, MAX_LIBRARY_ENTRIES,
    MAX_NAME_BYTES, MAX_RETRY_ATTEMPTS, MAX_RETRY_BACKOFF, MAX_STEPS, MAX_TIMEOUT, SHELLS,
    connector_calls, is_sensitive_arg, is_shell, looks_secret_like, parse,
};
pub mod normalize;
#[cfg(test)]
mod validate_test;
pub use normalize::{digest, to_normalized_yaml};
pub mod builtin;
#[cfg(test)]
mod normalize_test;
pub use builtin::{BuiltinFlow, builtin, builtin_yaml};
#[cfg(test)]
mod builtin_test;
