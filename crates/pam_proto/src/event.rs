//! Lifecycle events published on the `events.sock` `PUB` socket.
//!
//! The `PUB` topic is the request id, so a client subscribes to exactly the
//! requests it cares about.

use serde::{Deserialize, Serialize};

/// One step in a request's lifecycle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// The request was accepted and is waiting its turn.
    Queued,
    /// A worker picked the request up.
    Started,
    /// The worker reported progress.
    Progress {
        /// Percent complete, when the worker can estimate it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pct: Option<u8>,
        /// Human-readable progress note.
        note: String,
    },
    /// The request is paused waiting for a human approval in the GUI.
    ApprovalPending,
    /// The request finished; the response carries the result.
    Done,
    /// The request was refused; the response carries the refusal.
    Refused,
}
