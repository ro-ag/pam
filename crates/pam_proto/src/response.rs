//! Responses the daemon returns, inside a `reply` or `end` frame
//! ([`crate::wire`]).

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
        /// True when the cause is transient: the same request, sent again
        /// later, may be admitted (capacity, rate, drain, restart, an
        /// elapsed deadline, a daemon-side bookkeeping failure). False —
        /// and absent on the wire — for every refusal that would only
        /// repeat. Set by the daemon where it raises the refusal; a client
        /// prefers it over any list of causes it keeps for older daemons.
        #[serde(default, skip_serializing_if = "is_false")]
        retryable: bool,
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

/// `skip_serializing_if` predicate: a non-retryable refusal keeps the wire
/// shape it always had.
#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if hands the field by reference"
)]
fn is_false(flag: &bool) -> bool {
    !*flag
}

impl Response {
    /// The id of the request this response answers.
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Result { id, .. } | Self::Refusal { id, .. } | Self::Ticket { id, .. } => id,
        }
    }

    /// A refusal that would only repeat if the request were sent again.
    #[must_use]
    pub fn refusal(
        id: impl Into<String>,
        cause: impl Into<String>,
        detail: impl Into<String>,
        recovery: impl Into<String>,
    ) -> Self {
        Self::Refusal {
            id: id.into(),
            cause: cause.into(),
            detail: detail.into(),
            recovery: recovery.into(),
            retryable: false,
        }
    }

    /// A refusal for a transient cause: `retryable` is set, so a client
    /// may send the same request again after backing off.
    #[must_use]
    pub fn transient_refusal(
        id: impl Into<String>,
        cause: impl Into<String>,
        detail: impl Into<String>,
        recovery: impl Into<String>,
    ) -> Self {
        Self::Refusal {
            id: id.into(),
            cause: cause.into(),
            detail: detail.into(),
            recovery: recovery.into(),
            retryable: true,
        }
    }
}
