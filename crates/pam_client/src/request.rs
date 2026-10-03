//! Building the request [`Envelope`] a `pam` subcommand sends.
//!
//! Every subcommand funnels through [`build_envelope`]: a fresh
//! `req_<ulid>` id, the advisory caller identity from
//! [`crate::caller::cached_caller`], and this binary's build version (kept
//! on the envelope for the stored row; the daemon's version rule reads the
//! connection's hello). Capability arguments arrive as JSON
//! text on the command line and are validated by [`parse_args_object`] —
//! the wire `args` field is always a JSON object.

use pam_proto::{Envelope, PROTOCOL_VERSION};
use thiserror::Error;

use crate::caller::cached_caller;

/// Default `deadline_ms` when a subcommand does not override it.
pub const DEFAULT_DEADLINE_MS: u64 = 60_000;

/// Why command-line capability arguments were rejected.
#[derive(Debug, Error)]
pub enum ArgsError {
    /// The text is not valid JSON.
    #[error("capability args are not valid JSON: {source}")]
    Invalid {
        /// The underlying parse error.
        #[from]
        source: serde_json::Error,
    },
    /// The text is valid JSON but not an object.
    #[error("capability args must be a JSON object, got {found}")]
    NotAnObject {
        /// What the JSON turned out to be (`array`, `string`, ...).
        found: &'static str,
    },
}

/// Parses command-line capability arguments: valid JSON **object** text,
/// or `None` for the empty object `{}`.
pub fn parse_args_object(text: Option<&str>) -> Result<serde_json::Value, ArgsError> {
    let Some(text) = text else {
        return Ok(serde_json::json!({}));
    };
    let value: serde_json::Value = serde_json::from_str(text)?;
    if value.is_object() {
        Ok(value)
    } else {
        Err(ArgsError::NotAnObject {
            found: json_type_name(&value),
        })
    }
}

/// The JSON type name of `value`, for error messages.
fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

/// A fresh request id: `req_` plus a ULID.
#[must_use]
pub fn new_request_id() -> String {
    format!("req_{}", ulid::Ulid::new())
}

/// Builds the envelope for one request: fresh id, detected caller, this
/// binary's build version, and the given capability parameters.
#[must_use]
pub fn build_envelope(
    capability: &str,
    args: serde_json::Value,
    wait: bool,
    deadline_ms: u64,
    idempotency_key: Option<String>,
) -> Envelope {
    build_envelope_with_id(
        new_request_id(),
        capability,
        args,
        wait,
        deadline_ms,
        idempotency_key,
    )
}

/// [`build_envelope`] with the request id chosen by the caller, so the id
/// is known **before** anything is sent: a CLI can print it when the reply
/// never arrives (the daemon uses it as the ticket), and the GUI can mark
/// its own control requests so their lifecycle events are not fed back
/// into its refresh loop.
#[must_use]
pub fn build_envelope_with_id(
    id: String,
    capability: &str,
    args: serde_json::Value,
    wait: bool,
    deadline_ms: u64,
    idempotency_key: Option<String>,
) -> Envelope {
    Envelope {
        v: PROTOCOL_VERSION,
        id,
        capability: capability.to_owned(),
        client_version: env!("CARGO_PKG_VERSION").to_owned(),
        caller: cached_caller(),
        args,
        idempotency_key,
        deadline_ms,
        wait,
    }
}
