//! Responses returned by the daemon over the `pam.sock` `ROUTER` socket.

use serde::{Deserialize, Serialize};

/// How a completed request turned out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The request was answered in full.
    Solved,
    /// The daemon changed something on the caller's behalf.
    Changed,
    /// The daemon verified a claim without changing anything.
    Verified,
    /// The daemon ran to completion but could not resolve the request.
    Unresolved,
    /// The request cannot proceed without outside intervention.
    Blocked,
}

/// Exactly one of these answers every request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    /// The request completed; `outcome` says how it went.
    Result {
        /// Request id this response answers.
        id: String,
        /// How the request turned out.
        outcome: Outcome,
        /// Capability-specific result body.
        body: serde_json::Value,
        /// Evidence ids (`ev_<ulid>`) backing the result.
        evidence: Vec<String>,
    },
    /// The daemon declined the request.
    Refusal {
        /// Request id this response answers.
        id: String,
        /// Machine-readable cause of the refusal.
        cause: String,
        /// Human-readable explanation.
        detail: String,
        /// Sentence pointing the human at the GUI to recover.
        recovery: String,
    },
    /// The request was queued; sent when the envelope had `wait: false`.
    Ticket {
        /// Request id this response answers.
        id: String,
        /// Ticket id to poll or subscribe with.
        ticket: String,
        /// Position in the queue at enqueue time.
        position: u64,
    },
}
