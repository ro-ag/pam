//! Approval service: pauses approval-gated requests until a human
//! resolves them in the GUI, or the approval times out.
//!
//! [`GateDecision::RequireApproval`] triggers [`ApprovalService::request_approval`]: inserts the
//! unresolved `approval` row, parks the request `waiting_approval`, publishes
//! [`Event::ApprovalPending`], and waits for exactly one of a resolution
//! ([`ApprovalService::resolve`]), the timeout ([`DEFAULT_APPROVAL_TIMEOUT`] default), or the
//! caller-side cancel signal.
//! - **Security surface (GUI-only)**: [`ApprovalService::resolve`] is daemon-internal — not a
//!   capability an envelope can name, and the CLI has no subcommand reaching it (the fix for the
//!   self-grant hole of an agent approving its own ops is structural: only the GUI process, as the
//!   human's surface, can resolve). Until the GUI lands, tests reach it via
//!   [`DaemonHandle::approvals`]. [`ApprovalService::pending`] is store-backed, so it survives a
//!   daemon restart.
//! - **Remember (ask-once)**: `remember: true` on [`Resolution::Approve`] inserts a `grant` row
//!   ([`ACTION_GRANT_FROM_APPROVAL`]), regardless of profile/class; the policy matrix decides its
//!   meaning — under relaxed it makes the next gate evaluation an outright allow, under
//!   standard/strict a granted destructive/external capability still needs per-operation approval,
//!   so the grant is harmless there. A flow step's wait carries the [`GrantBinding`] of what it
//!   is about to run ([`ApprovalService::request_step_approval`]), and remembering it records
//!   exactly that: this step as defined now, in this repository — a grant for that repository
//!   re-pointed at it, or a new one ([`GrantChange::Bind`]). An edited step, or another
//!   repository, asks again.
//! - **Managed policy over remember**: a remembered approval adds a grant, so it is refused
//!   wherever the managed policy refuses one ([`remember_refusal`]): `security.grants.remember:
//!   deny`, `security.grants.manual: deny`, a never-grant rule matching the capability, or either
//!   grants key held. `admin.approvals.resolve` refuses `remember: true` up front; this service
//!   enforces it again when it records the resolution, against the policy in force at that moment,
//!   by downgrading the approval to a one-time one (no grant row; the audit detail says
//!   `remember_refused`). A plain approval always works.
//! - **State/audit split**: the service owns the `approval` row and resolution audit rows; the
//!   pipeline owns every `request` state transition around the wait (single writer per path) — the
//!   service moves the row into `waiting_approval` when the wait begins, the pipeline moves it out
//!   on outcome (back to `queued` before lane placement on approval, or terminal `refused` with its
//!   own refusal audit row on denial/timeout/cancellation).
//! - Every resolution writes an [`ACTION_APPROVAL`] row: approve → `approve`/`human`; deny →
//!   `deny`/`human`; timeout → `timeout`/`system`; cancelled-while-waiting → `deny`/`system`
//!   (approval row resolved `denied`, note `cancelled`).
//! - **Atomic bookkeeping**: the approval row and the request's move to `waiting_approval` are one
//!   transaction ([`Store::insert_approval_waiting`]); the resolution, its audit row and — for a
//!   remembered approval — the grant and its audit row are another
//!   ([`Store::resolve_approval_audited`]). A crash cannot leave a resolved approval without its
//!   audit row, or a remembered grant nobody audited.
//! - **One decider**: the waiting [`ApprovalService::request_approval`] call decides how the wait
//!   ended and records it; [`ApprovalService::resolve`] hands a decision over and then waits for
//!   the waiter's acknowledgement. A resolution that loses the race to the timeout or to a
//!   cancellation is reported as not pending — the human is never told "approved" for a request
//!   the daemon recorded as timed out.
//! - **What is being approved**: a flow step's approval carries a [`StepSnapshot`] taken when the
//!   wait began — the resolved program, arguments, working directory and environment names of the
//!   run that is actually waiting, not a re-reading of the flow file at display time — plus a
//!   digest binding all of it to the flow's own digest and the step's capability name. The GUI
//!   shows the snapshot and returns the digest ([`ApprovalService::resolve_pinned`]); a digest that
//!   is not the pending wait's refuses with [`ApprovalError::Changed`], so an answer given to a
//!   stale card (an edited flow, or an earlier step of the same request) authorizes nothing.
//!
//! [`GateDecision::RequireApproval`]: crate::policy::GateDecision::RequireApproval
//! [`DaemonHandle::approvals`]: crate::daemon::DaemonHandle::approvals

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use pam_proto::Event;
use pam_store::{
    Actor, ApprovalResolution, AuditEntry, Decision, GrantBinding, GrantChange, PendingApproval,
    Store, StoreError,
};
use serde::Serialize;
use thiserror::Error;
use tokio::sync::{Mutex, oneshot, watch};

use crate::managed_policy::{
    CAUSE_POLICY_NOT_ALLOWED, CAUSE_SETTING_LOCKED, Key, PolicyView, WriteRefusal,
};
use crate::managed_policy_service::PolicyHandle;
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
    /// The resolution was pinned to a snapshot digest that is not the
    /// pending wait's: what the human was shown is not what is waiting.
    #[error("the pending approval for request {request_id} is not the one that was shown")]
    Changed {
        /// The id whose pending approval differs from the pinned digest.
        request_id: String,
    },
}

/// What a gated flow step will run, captured when its approval wait began
/// (see the module docs). Serialized as the `resolved` object of an
/// `admin.approvals.pending` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StepSnapshot {
    /// The program as resolved on this machine (an absolute path when it
    /// was found), or `connector:<id>` / `landing:<operation>` for a step
    /// that runs no local program.
    pub program: String,
    /// The arguments after the program, one element each, every `${…}`
    /// filled in. For a connector step: the call name, then `name=value`
    /// per argument.
    pub argv: Vec<String>,
    /// The directory the step runs in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// The environment variable names the step sets — names only, never
    /// values.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env_keys: Vec<String>,
    /// SHA-256 over the flow's digest, the step's capability name and
    /// every field above: what an approval of this card authorizes.
    pub digest: String,
}

impl StepSnapshot {
    /// Builds the snapshot and its digest. `flow_digest` is
    /// [`pam_flow::digest`] of the flow the request is running;
    /// `capability` is the step's `flow.step:<flow>/<step>` name.
    #[must_use]
    pub fn new(
        flow_digest: &str,
        capability: &str,
        program: String,
        argv: Vec<String>,
        cwd: Option<String>,
        env_keys: Vec<String>,
    ) -> Self {
        // An array, not an object: the encoding is positional, so two
        // different snapshots cannot serialize to the same bytes.
        let bound = serde_json::json!([flow_digest, capability, program, argv, cwd, env_keys]);
        Self {
            digest: pam_compact::sha256_hex(bound.to_string().as_bytes()),
            program,
            argv,
            cwd,
            env_keys,
        }
    }
}

/// Why `view` refuses remembering an approval of `capability` (which would
/// add a grant for it), or `None` when it may be remembered.
///
/// In order: the grants keys held ([`crate::managed_policy::CAUSE_POLICY_FROZEN`]),
/// `security.grants.remember: deny` and `security.grants.manual: deny`
/// ([`CAUSE_SETTING_LOCKED`]), a never-grant rule matching the capability
/// ([`CAUSE_POLICY_NOT_ALLOWED`]). `capability` is `None` when the caller
/// does not know which approval it is (nothing is pending under that id);
/// the never rules are then not consulted.
#[must_use]
pub fn remember_refusal(view: &PolicyView, capability: Option<&str>) -> Option<WriteRefusal> {
    if let Err(refusal) = view.check_remember() {
        return Some(refusal);
    }
    for key in [Key::GrantsManual, Key::GrantsNever, Key::GrantsNeverClasses] {
        if let Err(refusal) = view.guard_held(key) {
            return Some(refusal);
        }
    }
    if view.grants_manual_denied() {
        return Some(view.refusal(
            Key::GrantsManual,
            CAUSE_SETTING_LOCKED,
            "remembering an approval adds a grant, and your organization's policy does not allow \
             adding grants by hand",
        ));
    }
    let capability = capability?;
    let rule = view.never_match(capability, crate::policy::classify(capability))?;
    let key = if rule.starts_with("class:") {
        Key::GrantsNeverClasses
    } else {
        Key::GrantsNever
    };
    Some(view.refusal(
        key,
        CAUSE_POLICY_NOT_ALLOWED,
        &format!("the capability {capability:?} is never allowed on this machine"),
    ))
}

/// One live approval wait: how to reach the waiter, and what it waits on.
#[derive(Debug)]
struct PendingWait {
    /// The decision, with the channel the waiter acknowledges it on once
    /// the resolution is durable.
    tx: oneshot::Sender<(Resolution, oneshot::Sender<ApprovalOutcome>)>,
    /// The capability the wait is for.
    capability: String,
    snapshot: Option<StepSnapshot>,
    /// What a remembered answer binds the step's grant to, and what changed
    /// since an earlier grant, when one no longer covers the step.
    remember: Option<RememberScope>,
}

/// What remembering a flow step's approval records, shown on its card
/// (`remember` of an `admin.approvals.pending` entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RememberScope {
    /// The binding the grant gets: this step as defined now, in this
    /// repository.
    pub binding: GrantBinding,
    /// Why an earlier grant of this step no longer covers it, when that is
    /// why the step asks (see [`crate::policy::StepGrant::Changed`]).
    pub changed: Option<String>,
}

impl RememberScope {
    /// The card's view: the flow, the step, the repository, a digest prefix
    /// and the change, if any.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "flow": self.binding.flow_id,
            "step": self.binding.step_id,
            "repository": self.binding.repository,
            "effect_digest": digest_prefix(&self.binding.effect_digest),
            "effect_class": self.binding.effect_class,
            "changed": self.changed,
        })
    }
}

/// The first 12 characters of an effect digest: enough to tell two step
/// definitions apart on a card.
#[must_use]
pub fn digest_prefix(digest: &str) -> &str {
    digest.get(..12).unwrap_or(digest)
}

/// The approval service. One per daemon; see the module docs.
#[derive(Debug)]
pub struct ApprovalService {
    store: Arc<Store>,
    events: EventPublisher,
    timeout: Duration,
    /// request id → the waiting `request_approval` call's resolution
    /// channel and step snapshot. Entries live exactly as long as the wait.
    pending: Mutex<HashMap<String, PendingWait>>,
    /// The managed policy in force (see [`crate::managed_policy_service`]).
    policy: Arc<PolicyHandle>,
}

impl ApprovalService {
    /// Builds the service over `store`, publishing on `events`, with
    /// `timeout` as the unanswered-approval bound (tests inject a short
    /// one; the daemon default is [`DEFAULT_APPROVAL_TIMEOUT`]), holding the
    /// managed policy handle `policy`.
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        events: EventPublisher,
        timeout: Duration,
        policy: Arc<PolicyHandle>,
    ) -> Self {
        Self {
            store,
            events,
            timeout,
            pending: Mutex::new(HashMap::new()),
            policy,
        }
    }

    /// The managed policy handle this service reads through (see
    /// [`crate::managed_policy_service`]).
    #[must_use]
    pub fn policy(&self) -> &Arc<PolicyHandle> {
        &self.policy
    }

    /// Parks `request_id` until its approval is resolved: inserts the unresolved `approval` row
    /// and moves the request to `waiting_approval` (one transaction), publishes
    /// [`Event::ApprovalPending`], and waits for a resolution, the timeout, or `cancel` flipping
    /// to `true` (a closed `cancel` channel counts as cancellation — the caller lost its right to
    /// wait).
    ///
    /// Whatever ends the wait is recorded on the approval row and audited before this returns; the
    /// caller owns the request-state transition that follows (see the module docs for the split).
    ///
    /// # Errors
    ///
    /// Returns the underlying [`StoreError`] when the bookkeeping writes fail; the caller answers
    /// with an internal refusal.
    pub async fn request_approval(
        &self,
        request_id: &str,
        capability: &str,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<ApprovalOutcome, StoreError> {
        self.request_approval_with(request_id, capability, None, cancel)
            .await
    }

    /// [`Self::request_approval`] for a gated flow step: `snapshot` is what the step will run,
    /// kept for exactly as long as the wait and shown to the human through
    /// [`Self::snapshot`].
    ///
    /// # Errors
    ///
    /// As [`Self::request_approval`].
    pub async fn request_approval_with(
        &self,
        request_id: &str,
        capability: &str,
        snapshot: Option<StepSnapshot>,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<ApprovalOutcome, StoreError> {
        self.wait_for_approval(request_id, capability, snapshot, None, cancel)
            .await
    }

    /// [`Self::request_approval_with`] for a gated flow step whose grant is
    /// bound to what it runs: a remembered answer records `remember`'s
    /// binding ([`GrantChange::Bind`]), never a bare name.
    ///
    /// # Errors
    ///
    /// As [`Self::request_approval`].
    pub async fn request_step_approval(
        &self,
        request_id: &str,
        capability: &str,
        snapshot: StepSnapshot,
        remember: RememberScope,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<ApprovalOutcome, StoreError> {
        self.wait_for_approval(
            request_id,
            capability,
            Some(snapshot),
            Some(remember),
            cancel,
        )
        .await
    }

    async fn wait_for_approval(
        &self,
        request_id: &str,
        capability: &str,
        snapshot: Option<StepSnapshot>,
        remember_scope: Option<RememberScope>,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<ApprovalOutcome, StoreError> {
        let binding = remember_scope.as_ref().map(|scope| scope.binding.clone());
        self.store
            .insert_approval_waiting(request_id, capability)
            .await?;

        // Register the resolution channel before the event goes out, so
        // a GUI reacting to the event can always deliver its resolution.
        let rx = {
            let (tx, rx) = oneshot::channel();
            self.pending.lock().await.insert(
                request_id.to_owned(),
                PendingWait {
                    tx,
                    capability: capability.to_owned(),
                    snapshot,
                    remember: remember_scope,
                },
            );
            rx
        };
        let _ = self
            .events
            .publish(request_id, Event::ApprovalPending)
            .await;

        let mut acknowledge = None;
        let mut remember_refused = false;
        let outcome = tokio::select! {
            // Biased: a resolution that raced the timeout wins.
            biased;
            resolution = rx => match resolution {
                Ok((resolution, ack)) => {
                    acknowledge = Some(ack);
                    match resolution {
                        Resolution::Approve { remember } => {
                            // The policy in force now decides whether the
                            // approval may become a grant (see the module
                            // docs); a refused remember is a one-time approval.
                            remember_refused = remember
                                && remember_refusal(&self.policy.view(), Some(capability))
                                    .is_some();
                            ApprovalOutcome::Approved {
                                remember: remember && !remember_refused,
                            }
                        }
                        Resolution::Deny => ApprovalOutcome::Denied,
                    }
                }
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

        self.record_resolution(
            request_id,
            capability,
            binding.as_ref(),
            outcome,
            remember_refused,
        )
        .await?;
        // Only now is the human's answer true: the resolution is durable.
        // A failed write above returned early and dropped the channel, so
        // the resolver is told the approval is not pending.
        if let Some(ack) = acknowledge {
            let _ = ack.send(outcome);
        }
        Ok(outcome)
    }

    /// Delivers a human resolution to the waiting request — the
    /// daemon-internal path the GUI plumbing calls (see the module docs
    /// for why nothing agent-facing reaches this).
    ///
    /// The waiting [`Self::request_approval`] call performs the store
    /// writes and audit on receipt, and this returns once it has: `Ok`
    /// means the resolution is what the daemon recorded.
    ///
    /// # Errors
    ///
    /// [`ApprovalError::NotFound`] when no wait is pending for
    /// `request_id` — unknown id, already resolved, timed out, or
    /// cancelled — including a wait that timed out or was cancelled at
    /// the same moment.
    pub async fn resolve(
        &self,
        request_id: &str,
        resolution: Resolution,
    ) -> Result<(), ApprovalError> {
        self.resolve_pinned(request_id, resolution, None).await
    }

    /// [`Self::resolve`] pinned to what the human was shown:
    /// `expected_digest` is the [`StepSnapshot::digest`] of the card that
    /// was answered.
    ///
    /// # Errors
    ///
    /// [`ApprovalError::Changed`] when a digest is given and the pending
    /// wait has a different snapshot or none — the wait is left pending,
    /// nothing is resolved. Otherwise as [`Self::resolve`].
    pub async fn resolve_pinned(
        &self,
        request_id: &str,
        resolution: Resolution,
        expected_digest: Option<&str>,
    ) -> Result<(), ApprovalError> {
        let not_found = || ApprovalError::NotFound {
            request_id: request_id.to_owned(),
        };
        let wait = {
            let mut pending = self.pending.lock().await;
            let wait = pending.get(request_id).ok_or_else(not_found)?;
            if let Some(expected) = expected_digest
                && wait
                    .snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.digest.as_str())
                    != Some(expected)
            {
                return Err(ApprovalError::Changed {
                    request_id: request_id.to_owned(),
                });
            }
            pending.remove(request_id).ok_or_else(not_found)?
        };
        let (ack, acknowledged) = oneshot::channel();
        wait.tx.send((resolution, ack)).map_err(|_| not_found())?;
        // The waiter acknowledges only a resolution it acted on and
        // recorded. A dropped channel means it had already chosen the
        // timeout or the cancellation, or its bookkeeping failed.
        let recorded = acknowledged.await.map_err(|_| not_found())?;
        let as_decided = matches!(
            (resolution, recorded),
            (Resolution::Approve { .. }, ApprovalOutcome::Approved { .. })
                | (Resolution::Deny, ApprovalOutcome::Denied)
        );
        if as_decided { Ok(()) } else { Err(not_found()) }
    }

    /// The capability `request_id`'s pending wait is for, when one is
    /// pending.
    pub async fn waiting_capability(&self, request_id: &str) -> Option<String> {
        self.pending
            .lock()
            .await
            .get(request_id)
            .map(|wait| wait.capability.clone())
    }

    /// The step snapshot of `request_id`'s pending wait, when it has one.
    pub async fn snapshot(&self, request_id: &str) -> Option<StepSnapshot> {
        self.pending
            .lock()
            .await
            .get(request_id)
            .and_then(|wait| wait.snapshot.clone())
    }

    /// What remembering `request_id`'s pending flow step approval would
    /// record, when the wait has a binding.
    pub async fn remember_scope(&self, request_id: &str) -> Option<RememberScope> {
        self.pending
            .lock()
            .await
            .get(request_id)
            .and_then(|wait| wait.remember.clone())
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
    /// outcome). `remember_refused` records that the human asked to
    /// remember and the managed policy made it a one-time approval.
    /// `binding` is what a remembered flow step grant is bound to.
    async fn record_resolution(
        &self,
        request_id: &str,
        capability: &str,
        binding: Option<&GrantBinding>,
        outcome: ApprovalOutcome,
        remember_refused: bool,
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
        let remember = matches!(outcome, ApprovalOutcome::Approved { remember: true });
        let mut detail = serde_json::json!({
            "capability": capability,
            "resolution": resolution.as_str(),
        });
        if let ApprovalOutcome::Approved { .. } = outcome {
            detail["remember"] = serde_json::Value::Bool(remember);
            if remember_refused {
                detail["remember_refused"] = serde_json::Value::Bool(true);
            }
        }
        if let Some(note) = note {
            detail["note"] = serde_json::Value::String(note.to_owned());
        }
        let detail = detail.to_string();
        let mut grant_detail = serde_json::json!({ "capability": capability });
        if let Some(binding) = binding {
            grant_detail["flow"] = serde_json::json!(binding.flow_id);
            grant_detail["step"] = serde_json::json!(binding.step_id);
            grant_detail["repository"] = serde_json::json!(binding.repository);
            grant_detail["effect_digest"] = serde_json::json!(binding.effect_digest);
            grant_detail["effect_class"] = serde_json::json!(binding.effect_class);
        }
        let grant_detail = grant_detail.to_string();
        let change = match binding {
            Some(binding) => GrantChange::Bind(capability, binding),
            None => GrantChange::Add(capability),
        };
        // One transaction: the resolution, its audit row and (remembered)
        // the grant with its own audit row.
        self.store
            .resolve_approval_with_grant(
                request_id,
                resolution,
                note,
                AuditEntry {
                    action: ACTION_APPROVAL,
                    decision,
                    actor,
                    detail: Some(&detail),
                },
                remember.then_some((
                    change,
                    AuditEntry {
                        action: ACTION_GRANT_FROM_APPROVAL,
                        decision: Decision::Allow,
                        actor: Actor::Human,
                        detail: Some(&grant_detail),
                    },
                )),
            )
            .await?;
        Ok(())
    }
}
