//! Approval service: pauses approval-gated requests until a human
//! resolves them in the GUI, or the approval times out.
//!
//! # Design
//!
//! The policy gate signals [`GateDecision::RequireApproval`]; the
//! pipeline then calls [`ApprovalService::request_approval`], which
//! inserts the unresolved `approval` row, parks the request in the
//! `waiting_approval` state, publishes [`Event::ApprovalPending`], and
//! waits for exactly one of: a resolution
//! ([`ApprovalService::resolve`]), the approval timeout (default
//! [`DEFAULT_APPROVAL_TIMEOUT`]), or the caller-side cancel signal.
//!
//! # Security surface: GUI-only, never agent-callable
//!
//! [`ApprovalService::resolve`] is a **daemon-internal** API. It is
//! deliberately *not* a capability an envelope can name, and the CLI has
//! no security subcommand that reaches it: v1's self-grant hole was an
//! agent approving its own operations, and the fix is structural — the
//! only path to a resolution is the GUI process calling into the daemon
//! as the human's surface. Until the GUI lands, integration tests reach
//! the service through [`DaemonHandle::approvals`]. The GUI's pending
//! list is [`ApprovalService::pending`], backed by the store, so it
//! survives a daemon restart.
//!
//! # Remember semantics (ask-once)
//!
//! An approval resolved with [`Resolution::Approve`] `remember: true`
//! inserts a `grant` row (audited as [`ACTION_GRANT_FROM_APPROVAL`]),
//! regardless of profile or class. The policy matrix decides what that
//! grant *means*: under relaxed it turns the next gate evaluation into
//! an outright allow (ask-once); under standard/strict a granted
//! destructive/external capability still requires per-operation approval
//! — the grant is harmless there and consistent everywhere, so the
//! service always inserts it and lets the matrix rule.
//!
//! # State and audit split
//!
//! The service owns the `approval` row and the resolution audit rows;
//! the **pipeline** owns every `request` state transition around the
//! wait, keeping a single request-state writer per path: the service
//! moves the row *into* `waiting_approval` when the wait begins (that
//! transition is part of the wait itself), and the pipeline moves it out
//! on the outcome — back to `queued` before lane placement on approval,
//! or to terminal `refused` (with its own refusal audit row) on denial,
//! timeout, or cancellation.
//!
//! Every resolution writes an [`ACTION_APPROVAL`] audit row:
//! approve → decision `approve`, actor `human`; deny → decision `deny`,
//! actor `human`; timeout → decision `timeout`, actor `system`;
//! cancelled-while-waiting → decision `deny`, actor `system`, with the
//! approval row resolved `denied` and note `cancelled`.
//!
//! [`GateDecision::RequireApproval`]: crate::policy::GateDecision::RequireApproval
//! [`DaemonHandle::approvals`]: crate::daemon::DaemonHandle::approvals

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use pam_proto::Event;
use pam_store::{Actor, ApprovalResolution, Decision, PendingApproval, Store, StoreError};
use thiserror::Error;
use tokio::sync::{Mutex, oneshot, watch};

use crate::transport::EventPublisher;

/// How long a pending approval waits before it times out, unless the
/// daemon was configured otherwise.
pub const DEFAULT_APPROVAL_TIMEOUT: Duration = Duration::from_mins(15);

/// `audit.action` for an approval resolution (approve, deny, timeout,
/// or cancellation while waiting).
pub const ACTION_APPROVAL: &str = "approval";

/// `audit.action` for the grant a remembered approval inserts.
pub const ACTION_GRANT_FROM_APPROVAL: &str = "grant_from_approval";

/// Note recorded on an approval row resolved by cancellation.
pub const NOTE_CANCELLED: &str = "cancelled";

/// How the human (via the GUI) resolved a pending approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// Let the operation run.
    Approve {
        /// When true, also insert a grant so the capability is
        /// remembered (see the module docs for what that means per
        /// profile).
        remember: bool,
    },
    /// Refuse the operation.
    Deny,
}

/// How one [`ApprovalService::request_approval`] wait ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalOutcome {
    /// A human approved; the pipeline continues into execution.
    Approved {
        /// True when the approval also inserted a grant.
        remember: bool,
    },
    /// A human denied; the pipeline refuses the request.
    Denied,
    /// Nobody answered within the timeout; the pipeline refuses.
    TimedOut,
    /// The caller-side cancel signal fired while waiting; the pipeline
    /// refuses.
    Cancelled,
}

/// Why a resolution could not be delivered.
#[derive(Debug, Error)]
pub enum ApprovalError {
    /// No request with this id is currently waiting for approval.
    #[error("no pending approval for request {request_id}")]
    NotFound {
        /// The id that had no pending approval.
        request_id: String,
    },
}

/// The approval service. One per daemon; see the module docs.
#[derive(Debug)]
pub struct ApprovalService {
    store: Arc<Store>,
    events: EventPublisher,
    timeout: Duration,
    /// request id → the waiting `request_approval` call's resolution
    /// channel. Entries live exactly as long as the wait.
    pending: Mutex<HashMap<String, oneshot::Sender<Resolution>>>,
}

impl ApprovalService {
    /// Builds the service over `store`, publishing on `events`, with
    /// `timeout` as the unanswered-approval bound (tests inject a short
    /// one; the daemon default is [`DEFAULT_APPROVAL_TIMEOUT`]).
    #[must_use]
    pub fn new(store: Arc<Store>, events: EventPublisher, timeout: Duration) -> Self {
        Self {
            store,
            events,
            timeout,
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Parks `request_id` until its approval is resolved.
    ///
    /// Inserts the unresolved `approval` row, moves the request to
    /// `waiting_approval`, publishes [`Event::ApprovalPending`], and
    /// waits for a resolution, the timeout, or `cancel` flipping to
    /// `true` (a closed `cancel` channel counts as cancellation — the
    /// caller lost its right to wait). Whatever ends the wait is
    /// recorded on the approval row and audited before this returns; the
    /// caller owns the request-state transition that follows (see the
    /// module docs for the split).
    ///
    /// # Errors
    ///
    /// Returns the underlying [`StoreError`] when the bookkeeping writes
    /// fail; the caller answers with an internal refusal.
    pub async fn request_approval(
        &self,
        request_id: &str,
        capability: &str,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<ApprovalOutcome, StoreError> {
        self.store.insert_approval(request_id, capability).await?;
        self.store
            .update_request_state(request_id, pam_store::RequestState::WaitingApproval, None)
            .await?;

        // Register the resolution channel before the event goes out, so
        // a GUI reacting to the event can always deliver its resolution.
        let rx = {
            let (tx, rx) = oneshot::channel();
            self.pending.lock().await.insert(request_id.to_owned(), tx);
            rx
        };
        let _ = self
            .events
            .publish(request_id, Event::ApprovalPending)
            .await;

        let outcome = tokio::select! {
            // Biased: a resolution that raced the timeout wins.
            biased;
            resolution = rx => match resolution {
                Ok(Resolution::Approve { remember }) => ApprovalOutcome::Approved { remember },
                Ok(Resolution::Deny) => ApprovalOutcome::Denied,
                // The sender vanished without resolving (service torn
                // down); treat it as a cancellation.
                Err(_) => ApprovalOutcome::Cancelled,
            },
            () = tokio::time::sleep(self.timeout) => ApprovalOutcome::TimedOut,
            _ = cancel.wait_for(|cancelled| *cancelled) => ApprovalOutcome::Cancelled,
        };
        // Timeout/cancel paths still hold a map entry; a late resolve
        // must get NotFound instead of a dead channel.
        self.pending.lock().await.remove(request_id);

        self.record_resolution(request_id, capability, outcome)
            .await?;
        Ok(outcome)
    }

    /// Delivers a human resolution to the waiting request — the
    /// daemon-internal path the GUI plumbing calls (see the module docs
    /// for why nothing agent-facing reaches this).
    ///
    /// The waiting [`Self::request_approval`] call performs the store
    /// writes and audit on receipt; this only hands the decision over.
    ///
    /// # Errors
    ///
    /// [`ApprovalError::NotFound`] when no wait is pending for
    /// `request_id` — unknown id, already resolved, timed out, or
    /// cancelled.
    pub async fn resolve(
        &self,
        request_id: &str,
        resolution: Resolution,
    ) -> Result<(), ApprovalError> {
        let sender = self
            .pending
            .lock()
            .await
            .remove(request_id)
            .ok_or_else(|| ApprovalError::NotFound {
                request_id: request_id.to_owned(),
            })?;
        sender
            .send(resolution)
            .map_err(|_| ApprovalError::NotFound {
                request_id: request_id.to_owned(),
            })
    }

    /// The GUI's pending list: every unresolved approval, joined with
    /// its request, oldest first.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`StoreError`] when the query fails.
    pub async fn pending(&self) -> Result<Vec<PendingApproval>, StoreError> {
        self.store.list_pending_approvals().await
    }

    /// Writes the approval row's resolution and the audit rows for one
    /// outcome (see the module docs for the exact decision/actor per
    /// outcome).
    async fn record_resolution(
        &self,
        request_id: &str,
        capability: &str,
        outcome: ApprovalOutcome,
    ) -> Result<(), StoreError> {
        let (resolution, note, decision, actor) = match outcome {
            ApprovalOutcome::Approved { .. } => (
                ApprovalResolution::Approved,
                None,
                Decision::Approve,
                Actor::Human,
            ),
            ApprovalOutcome::Denied => (
                ApprovalResolution::Denied,
                None,
                Decision::Deny,
                Actor::Human,
            ),
            ApprovalOutcome::TimedOut => (
                ApprovalResolution::Timeout,
                None,
                Decision::Timeout,
                Actor::System,
            ),
            ApprovalOutcome::Cancelled => (
                ApprovalResolution::Denied,
                Some(NOTE_CANCELLED),
                Decision::Deny,
                Actor::System,
            ),
        };
        self.store
            .resolve_approval(request_id, resolution, note)
            .await?;

        let remember = matches!(outcome, ApprovalOutcome::Approved { remember: true });
        let mut detail = serde_json::json!({
            "capability": capability,
            "resolution": resolution.as_str(),
        });
        if let ApprovalOutcome::Approved { .. } = outcome {
            detail["remember"] = serde_json::Value::Bool(remember);
        }
        if let Some(note) = note {
            detail["note"] = serde_json::Value::String(note.to_owned());
        }
        self.store
            .append_audit(
                request_id,
                ACTION_APPROVAL,
                decision,
                actor,
                Some(&detail.to_string()),
            )
            .await?;

        if remember {
            self.store.insert_grant(capability).await?;
            let grant_detail = serde_json::json!({ "capability": capability }).to_string();
            self.store
                .append_audit(
                    request_id,
                    ACTION_GRANT_FROM_APPROVAL,
                    Decision::Allow,
                    Actor::Human,
                    Some(&grant_detail),
                )
                .await?;
        }
        Ok(())
    }
}
