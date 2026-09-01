//! Request envelope sent by the client over the `pam.sock` `ROUTER` socket.

use serde::{Deserialize, Serialize};

/// Identity of the process issuing a request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Caller {
    /// Agent name, e.g. `claude`.
    pub agent: String,
    /// Absolute path of the repository the caller is working in.
    pub repo: String,
    /// Process id of the calling client.
    pub pid: u32,
}

/// Versioned request envelope.
///
/// Unknown fields are ignored on deserialize so an older daemon can read
/// envelopes from a newer client without failing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    /// Protocol version, currently [`crate::PROTOCOL_VERSION`].
    pub v: u32,
    /// Request id, `req_<ulid>`; also the `PUB` topic for its events.
    pub id: String,
    /// Capability being invoked, e.g. `log.summarize`.
    pub capability: String,
    /// Build version of the client binary, for the version handshake.
    pub client_version: String,
    /// Who is calling.
    pub caller: Caller,
    /// Capability-specific arguments, opaque to the envelope.
    pub args: serde_json::Value,
    /// Caller-chosen key for deduplicating retries; omitted when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// Deadline for the request, in milliseconds.
    pub deadline_ms: u64,
    /// When `false`, the daemon answers immediately with a ticket.
    pub wait: bool,
}
