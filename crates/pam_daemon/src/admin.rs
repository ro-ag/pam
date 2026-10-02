//! Privileged administration through a separate native daemon ingress.
//!
//! Public `ZeroMQ` refuses every `admin.*` envelope, including forged GUI labels; private ingress
//! checks kernel peer ownership, and the enterprise sandbox must exclude that endpoint, PAM state,
//! and trusted process/assets from agents. OS ownership does not prove GUI mode — unrestricted
//! same-user processes remain privileged and sit outside this boundary (see
//! `docs/admin-boundary.md`). The supported CLI has no administrative subcommands; the GUI's
//! `pam-gui` label is advisory only, never the source of authority, and no bearer credential
//! crosses the wire.
//! - **Structural guard**: admin ops are not capabilities — no [`crate::policy::classify`] entry,
//!   never pass the policy gate, never enter a queue lane, never granted/approved/auto-granted. The
//!   dispatcher intercepts [`ADMIN_PREFIX`] before admit/gate and hands the envelope to
//!   [`AdminService::handle`]; the normal pipeline never sees it, so a grant can't unlock
//!   administration and administration can't be smuggled through an approval.
//! - **Audit**: every admin op inserts a real `request` row (capability = op name, repo =
//!   [`ADMIN_REPO`], `caller_agent` from envelope) with arguments omitted — credentials/sensitive
//!   admin inputs must never enter the request ledger, including on refusal; operation-specific
//!   audit fields keep the non-secret change description. Finished immediately through
//!   [`pam_store::Store::finish_request`] (terminal state + audit row in one transaction, same
//!   invariant as every other request). Rows enter `running` atomically; crash recovery fails
//!   interrupted admin ops without replaying them, so effects may need reconciliation.
//! - **Outcomes**: success → `done`, [`ACTION_ADMIN`], `allow`, actor `human`; refusal (validation,
//!   unknown op, missing grant/approval) → `refused`, [`ACTION_ADMIN`], `refuse`, actor `system`;
//!   tripwire → `refused`, [`ACTION_ADMIN_DENIED`], `refuse`, `system`; deadline elapsed mid-op →
//!   `failed`, deadline-refusal row, `timeout`, `system`.
//! - Admin envelopes never touch the caller registry ([`pam_store::Store::upsert_caller`] runs on
//!   the admitted pipeline path only) — `pam-gui` on repo `gui` is not an observed workload.
//! - [`OP_PROFILE_SET`] changes the profile through the running [`crate::policy::PolicyGate`],
//!   the daemon's one source of truth for it: the setting is persisted and the live gate swapped,
//!   so the new profile governs from the next evaluation (response carries `"applies": "now"`).
//!   [`OP_PROFILE_GET`] reports the same live value — what is enforced, not what a file says.
//! - **Atomic security changes**: a grant added or revoked here is written in the same
//!   transaction as this op's terminal state and audit row
//!   ([`pam_store::Store::finish_request_with_grant_change`]); there is no window in which a
//!   grant changed and its audit row did not.
//! - **Terminal writes** go through [`crate::terminal::TerminalWriter`]: retried, logged, parked.
//!   An op whose success could not be recorded is answered with an internal refusal, never as a
//!   success without an audit row.
//! - [`OP_REQUESTS_CANCEL`] is the human's cancel: it reaches the pipeline as a `cancel` request
//!   of [`Origin::Admin`], which may cancel any ticket and is audited as `human`. A public
//!   `cancel` is always `system`, whatever its `caller.agent` claims.
//! - Op names are `OP_*` constants under [`ADMIN_PREFIX`]; an unrecognized `admin.*` capability is
//!   refused with [`CAUSE_UNKNOWN_ADMIN_OP`] — new ops are added here or in
//!   [`crate::admin_models`]/[`crate::admin_logs`]/[`crate::admin_retention`], nowhere else.
//! - [`crate::admin_models`] holds `admin.models.*`/`admin.curator.*`, [`crate::admin_logs`] holds
//!   `admin.log.*`/`admin.evidence.*`, [`crate::admin_connectors`] holds `admin.connectors.*`,
//!   [`crate::admin_retention`] holds `admin.retention.*` — dispatched from [`AdminService`] before
//!   this module's own `match`, under identical rules (same tripwire, deadline, request row, single
//!   terminal audit row, no classify entry, no grant, no approval); the split is file size, not
//!   privilege.

use std::sync::Arc;
use std::time::Duration;

use pam_proto::{Caller, Envelope, Outcome, PROTOCOL_VERSION, Response};
use pam_store::{
    Actor, AuditEntry, Decision, GrantChange, GrantChangeOutcome, RequestState, Store, StoreError,
};
use serde_json::json;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, timeout_at};

use crate::approval::{ApprovalError, ApprovalService, Resolution};
use crate::connector_service::ConnectorService;
use crate::daemon::{
    ACTION_DEADLINE_REFUSAL, CAUSE_DEADLINE_EXCEEDED, CAUSE_INTERNAL_ERROR, DAEMON_VERSION,
};
use crate::executor::outcome_str;
use crate::flow_service::FlowService;
use crate::ingress::Origin;
use crate::log_service::LogService;
use crate::model_service::ModelService;
use crate::policy::{CAP_CANCEL, Profile};
use crate::terminal::{TerminalWriter, Written};
use crate::transport::IncomingRequest;

/// Reserved capability prefix the dispatcher intercepts before the
/// normal pipeline (see the module docs on the structural guard).
pub const ADMIN_PREFIX: &str = "admin.";

/// The `caller.agent` every admin envelope must carry — the advisory
/// tripwire (see the module docs; this is not authentication).
pub const ADMIN_CALLER_AGENT: &str = "pam-gui";

/// The `request.repo` recorded for admin operations; admin ops belong
/// to the GUI, not to any workload repository.
pub const ADMIN_REPO: &str = "gui";

/// `admin.profile.get` → `{ profile }`.
pub const OP_PROFILE_GET: &str = "admin.profile.get";

/// `admin.profile.set { profile }` → persists `policy.profile` and swaps
/// the live gate's profile (applies at once; see the module docs).
pub const OP_PROFILE_SET: &str = "admin.profile.set";

/// `admin.grants.list` → every grant row, revoked history included.
pub const OP_GRANTS_LIST: &str = "admin.grants.list";

/// `admin.grants.add { capability }` → records a new global grant.
pub const OP_GRANTS_ADD: &str = "admin.grants.add";

/// `admin.grants.revoke { capability }` → revokes the active grant.
pub const OP_GRANTS_REVOKE: &str = "admin.grants.revoke";

/// `admin.approvals.pending` → the unresolved approvals, oldest first.
pub const OP_APPROVALS_PENDING: &str = "admin.approvals.pending";

/// `admin.approvals.resolve { request_id, resolution, remember?, note?,
/// expected_digest? }` → delivers a human resolution to the waiting
/// request. `expected_digest` is the `resolved.digest` of the pending entry
/// the human answered; a pending approval with a different snapshot (or
/// none) refuses with [`CAUSE_FLOW_CHANGED`] and stays pending.
pub const OP_APPROVALS_RESOLVE: &str = "admin.approvals.resolve";

/// `admin.requests.cancel { ticket }` → cancels a queued or running request
/// on the human's behalf (audited `human`; see the module docs). The body is
/// `{ ticket, result }` with `result` one of `cancelled_queued`,
/// `signalled_running`, `not_found`.
pub const OP_REQUESTS_CANCEL: &str = "admin.requests.cancel";

/// Deadline of the `cancel` request [`OP_REQUESTS_CANCEL`] submits.
const REQUESTS_CANCEL_DEADLINE_MS: u64 = 10_000;

/// Longest `note` [`OP_APPROVALS_RESOLVE`] records into its audit detail:
/// the detail column is a receipt, not a document.
pub const MAX_APPROVAL_NOTE_BYTES: usize = 1024;

/// `admin.activity.list { limit?, repo?, agent?, state?, capability? }`
/// → recent request rows, newest first, bounded.
pub const OP_ACTIVITY_LIST: &str = "admin.activity.list";

/// `admin.callers.list` → the observed agent+repo registry.
pub const OP_CALLERS_LIST: &str = "admin.callers.list";

/// `admin.audit.request { request_id }` — every audit row the daemon
/// wrote for one request, oldest first. Read-only; the GUI quotes
/// refusals with it ("why was that refused").
pub const OP_AUDIT_REQUEST: &str = "admin.audit.request";

/// `audit.action` recording an admin operation's terminal state
/// (success or refusal; the tripwire has its own action).
pub const ACTION_ADMIN: &str = "admin";

/// `audit.action` for an admin envelope refused by the caller tripwire.
pub const ACTION_ADMIN_DENIED: &str = "admin_denied";

/// Refusal cause when the caller tripwire fired (see the module docs).
pub const CAUSE_ADMIN_DENIED: &str = "admin_denied";

/// Refusal cause for an `admin.*` capability no op name matches.
pub const CAUSE_UNKNOWN_ADMIN_OP: &str = "unknown_admin_op";

/// Refusal cause for malformed or missing admin op arguments.
pub const CAUSE_INVALID_ADMIN_ARGS: &str = "invalid_admin_args";

/// Refusal cause for revoking a capability with no active grant.
pub const CAUSE_NO_ACTIVE_GRANT: &str = "no_active_grant";

/// Refusal cause for granting a capability that is already granted.
pub const CAUSE_ALREADY_GRANTED: &str = "already_granted";

/// Refusal cause for resolving a request with no pending approval.
pub const CAUSE_NO_PENDING_APPROVAL: &str = "no_pending_approval";

/// Refusal cause for an approval resolution pinned to a snapshot digest
/// that is not the pending approval's: the flow was edited, or the request
/// moved on to another step, after the card was shown. The same cause a
/// pinned `flow.run` refuses with, so the GUI handles both alike.
pub const CAUSE_FLOW_CHANGED: &str = crate::flow_service::CAUSE_FLOW_CHANGED;

/// Recovery line for [`CAUSE_FLOW_CHANGED`] on an approval resolution.
const RECOVERY_APPROVAL_CHANGED: &str =
    "Refresh the PAM GUI approvals view and review the request as it is now before answering.";

/// Recovery line when the pipeline ingress is gone (the daemon is draining).
const RECOVERY_SUBMIT: &str = "Retry shortly; the daemon may be shutting down.";

/// Recovery line for [`CAUSE_ADMIN_DENIED`] refusals.
const RECOVERY_ADMIN_DENIED: &str =
    "Administration is GUI-only; open the PAM GUI — agents have no security commands.";

/// Recovery line for argument/op-name refusals.
pub(crate) const RECOVERY_FIX_ARGS: &str = "Fix the admin request and retry from the PAM GUI.";

/// Recovery line for grant-state refusals.
const RECOVERY_GRANTS_VIEW: &str = "Check the capability's state in the PAM GUI grants view.";

/// Recovery line for [`CAUSE_NO_PENDING_APPROVAL`] refusals.
const RECOVERY_APPROVALS_VIEW: &str =
    "Refresh the PAM GUI approvals view; the request may have resolved or timed out.";

/// Recovery line for internal store failures.
pub(crate) const RECOVERY_INTERNAL: &str =
    "Retry; if it persists, restart the daemon from the PAM GUI.";

/// Recovery line for an admin op that outlived its deadline.
const RECOVERY_DEADLINE: &str =
    "Inspect state before retrying; an effect may already have started.";

/// What a successful admin op hands back: the response pieces plus a
/// compact audit detail (never the full body — list bodies are large).
pub(crate) struct AdminOk {
    pub(crate) outcome: Outcome,
    pub(crate) body: serde_json::Value,
    pub(crate) audit: serde_json::Value,
}

/// A refusal an admin op decided on; becomes the terminal `refused`
/// row, its audit row, and the [`Response::Refusal`].
pub(crate) struct AdminRefusal {
    pub(crate) cause: &'static str,
    pub(crate) detail: String,
    pub(crate) recovery: &'static str,
}

impl From<StoreError> for AdminRefusal {
    fn from(err: StoreError) -> Self {
        Self {
            cause: CAUSE_INTERNAL_ERROR,
            detail: format!("admin bookkeeping failed: {err}"),
            recovery: RECOVERY_INTERNAL,
        }
    }
}

/// The same refusal with owned text, which is what
/// [`AdminService::finish_refused`] writes.
///
/// Almost every admin refusal is decided here and its cause and recovery
/// line are compile-time constants. [`crate::admin_flows`]'s
/// `admin.flows.run` is the exception: it submits a real `flow.run`
/// envelope through the pipeline ingress and forwards whatever the
/// pipeline answers, refusal included — and the pipeline's causes and
/// recovery lines are built at run time. Rather than flatten a forwarded
/// refusal into a generic one (which would cost the GUI the actual
/// reason), the admin surface widens by exactly this one type.
pub(crate) struct OwnedRefusal {
    pub(crate) cause: String,
    pub(crate) detail: String,
    pub(crate) recovery: String,
}

impl From<AdminRefusal> for OwnedRefusal {
    fn from(refusal: AdminRefusal) -> Self {
        Self {
            cause: refusal.cause.to_owned(),
            detail: refusal.detail,
            recovery: refusal.recovery.to_owned(),
        }
    }
}

impl From<StoreError> for OwnedRefusal {
    fn from(err: StoreError) -> Self {
        AdminRefusal::from(err).into()
    }
}

/// One admin service per daemon. Native ingress executes operations; public
/// ingress records refusals. See module docs for the deployment boundary.
#[derive(Debug)]
pub struct AdminService {
    pub(crate) store: Arc<Store>,
    approvals: Arc<ApprovalService>,
    /// The model layer the `admin.models.*` / `admin.curator.*` ops act
    /// through (see [`crate::admin_models`]).
    pub(crate) models: Arc<ModelService>,
    /// The compression pipeline the `admin.log.*` / `admin.evidence.*` ops
    /// act through (see [`crate::admin_logs`]).
    pub(crate) logs: Arc<LogService>,
    /// The connector host the `admin.connectors.*` ops act through (see
    /// [`crate::admin_connectors`]).
    pub(crate) connectors: Arc<ConnectorService>,
    /// The flow engine the `admin.flows.*` ops act through (see
    /// [`crate::admin_flows`]).
    pub(crate) flows: Arc<FlowService>,
    /// The pipeline's own ingress. `admin.flows.run` builds a `flow.run`
    /// envelope and sends it through here rather than executing anything
    /// itself, so a run started from the GUI passes the same gate, lanes
    /// and audit as one an agent started — the GUI gets no shortcut.
    pub(crate) submit: mpsc::Sender<IncomingRequest>,
    /// The daemon's one writer of terminal rows outside the queue's lease
    /// paths. Created here and shared with the pipeline, whose maintenance
    /// loop retries whatever either of them parked.
    pub(crate) terminals: Arc<TerminalWriter>,
}

impl AdminService {
    /// Builds the service over the daemon's store, approval service,
    /// model service, log service, connector host, flow engine, and the
    /// pipeline ingress `admin.flows.run` submits through.
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        approvals: Arc<ApprovalService>,
        models: Arc<ModelService>,
        logs: Arc<LogService>,
        connectors: Arc<ConnectorService>,
        flows: Arc<FlowService>,
        submit: mpsc::Sender<IncomingRequest>,
    ) -> Self {
        Self {
            terminals: TerminalWriter::new(Arc::clone(&store)),
            store,
            approvals,
            models,
            logs,
            connectors,
            flows,
            submit,
        }
    }

    /// Handles one `admin.*` envelope end to end: records the request
    /// row, checks the caller tripwire, dispatches the op under the
    /// envelope's deadline, and finishes the row (terminal state +
    /// audit in one transaction) before answering.
    /// Trusted in-process entry point. Network dispatch must use ingress
    /// provenance; constructing this service already requires daemon authority.
    pub async fn handle(&self, envelope: &Envelope) -> Response {
        self.handle_from_ingress(envelope, true).await
    }

    pub(crate) async fn handle_from_ingress(
        &self,
        envelope: &Envelope,
        private_ingress: bool,
    ) -> Response {
        let deadline = Instant::now() + Duration::from_millis(envelope.deadline_ms.min(300_000));
        let id = &envelope.id;
        let inserted = self
            .store
            .insert_running_request(
                id,
                &envelope.capability,
                ADMIN_REPO,
                &envelope.caller.agent,
                // Admin arguments can carry credentials. Never persist them,
                // even before caller validation; each operation owns safe audit fields.
                "{}",
                envelope.idempotency_key.as_deref(),
            )
            .await;
        if inserted.is_err() {
            // No row, so nothing can be audited; answer legibly.
            return Response::Refusal {
                retryable: true,
                id: id.clone(),
                cause: CAUSE_INTERNAL_ERROR.to_owned(),
                detail: "the daemon could not record the admin request".to_owned(),
                recovery: RECOVERY_INTERNAL.to_owned(),
            };
        }

        if !private_ingress || envelope.caller.agent != ADMIN_CALLER_AGENT {
            return self.refuse_tripwire(envelope, private_ingress).await;
        }

        if Instant::now() >= deadline {
            return self.finish_deadline(envelope).await;
        }
        match timeout_at(deadline, self.dispatch(envelope)).await {
            Ok(Ok(ok)) => self.finish_ok(envelope, ok).await,
            Ok(Err(refusal)) => self.finish_refused(envelope, refusal).await,
            Err(_elapsed) => self.finish_deadline(envelope).await,
        }
    }

    /// Routes one (tripwire-cleared) envelope to its op.
    ///
    /// The flow, model, log, connector and retention surfaces get first
    /// refusal: [`Self::dispatch_flows`], [`Self::dispatch_models`],
    /// [`Self::dispatch_logs`], [`Self::dispatch_connectors`] and
    /// [`Self::dispatch_retention`] answer `None` for anything that is
    /// not one of their ops, and the match below takes over. The log and
    /// connector surfaces are handed the envelope's id because a compress
    /// files its evidence, and a configure its change, under this very
    /// request row.
    async fn dispatch(&self, envelope: &Envelope) -> Result<AdminOk, OwnedRefusal> {
        let args = &envelope.args;
        if let Some(answer) = self.dispatch_flows(&envelope.capability, args).await {
            return answer;
        }
        if let Some(answer) = self.dispatch_models(&envelope.capability, args).await {
            return answer.map_err(OwnedRefusal::from);
        }
        if let Some(answer) = self
            .dispatch_logs(&envelope.id, &envelope.capability, args)
            .await
        {
            return answer.map_err(OwnedRefusal::from);
        }
        if let Some(answer) = self
            .dispatch_connectors(&envelope.id, &envelope.capability, args)
            .await
        {
            return answer.map_err(OwnedRefusal::from);
        }
        if let Some(answer) = self.dispatch_retention(&envelope.capability, args).await {
            return answer.map_err(OwnedRefusal::from);
        }
        let answer: Result<AdminOk, AdminRefusal> = match envelope.capability.as_str() {
            OP_PROFILE_GET => Ok(self.profile_get()),
            OP_PROFILE_SET => self.profile_set(args).await,
            OP_GRANTS_LIST => self.grants_list().await,
            OP_GRANTS_ADD => self.grants_add(&envelope.id, args).await,
            OP_GRANTS_REVOKE => self.grants_revoke(&envelope.id, args).await,
            OP_REQUESTS_CANCEL => self.requests_cancel(args).await,
            OP_APPROVALS_PENDING => self.approvals_pending().await,
            OP_APPROVALS_RESOLVE => self.approvals_resolve(args).await,
            OP_ACTIVITY_LIST => self.activity_list(args).await,
            OP_CALLERS_LIST => self.callers_list().await,
            OP_AUDIT_REQUEST => self.audit_request(args).await,
            unknown => Err(AdminRefusal {
                cause: CAUSE_UNKNOWN_ADMIN_OP,
                detail: format!("no admin operation named {unknown:?} exists"),
                recovery: RECOVERY_FIX_ARGS,
            }),
        };
        answer.map_err(OwnedRefusal::from)
    }

    /// The active profile: what the running gate enforces, which is also
    /// what is persisted (the gate is the only writer; see the module docs).
    fn profile_get(&self) -> AdminOk {
        AdminOk {
            outcome: Outcome::Verified,
            body: json!({ "profile": self.flows.gate().profile().as_str() }),
            audit: json!({ "op": OP_PROFILE_GET }),
        }
    }

    /// Validates a new profile and makes it the enforced one: persisted,
    /// then live from the next gate evaluation. The body says so.
    async fn profile_set(&self, args: &serde_json::Value) -> Result<AdminOk, AdminRefusal> {
        let requested = required_str(args, "profile", OP_PROFILE_SET)?;
        let profile: Profile =
            serde_json::from_value(json!(requested)).map_err(|_| AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: format!(
                    "{requested:?} is not a profile; expected relaxed, standard or strict"
                ),
                recovery: RECOVERY_FIX_ARGS,
            })?;
        let previous = self.flows.gate().set_profile(profile).await?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({
                "profile": profile.as_str(),
                "applies": "now",
            }),
            audit: json!({
                "op": OP_PROFILE_SET,
                "profile": profile.as_str(),
                "previous": previous.as_str(),
            }),
        })
    }

    /// Every grant row, revoked history included.
    async fn grants_list(&self) -> Result<AdminOk, AdminRefusal> {
        let grants: Vec<serde_json::Value> = self
            .store
            .list_grants()
            .await?
            .into_iter()
            .map(|grant| {
                json!({
                    "id": grant.id,
                    "capability": grant.capability,
                    "scope": grant.scope,
                    "granted_ts": grant.granted_ts,
                    "revoked_ts": grant.revoked_ts,
                })
            })
            .collect();
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: json!({ "grants": grants }),
            audit: json!({ "op": OP_GRANTS_LIST }),
        })
    }

    /// Records a new global grant, refusing a duplicate active one (a
    /// second active row would only muddy the history). The grant, this
    /// op's terminal state and its audit row are one transaction.
    async fn grants_add(
        &self,
        request_id: &str,
        args: &serde_json::Value,
    ) -> Result<AdminOk, AdminRefusal> {
        let capability = required_str(args, "capability", OP_GRANTS_ADD)?;
        let audit = json!({ "op": OP_GRANTS_ADD, "capability": capability });
        match self
            .change_grant(request_id, GrantChange::Add(capability), &audit)
            .await?
        {
            GrantChangeOutcome::Applied => Ok(AdminOk {
                outcome: Outcome::Changed,
                body: json!({ "capability": capability, "granted": true }),
                audit,
            }),
            GrantChangeOutcome::Unchanged => Err(AdminRefusal {
                cause: CAUSE_ALREADY_GRANTED,
                detail: format!("capability {capability:?} already has an active grant"),
                recovery: RECOVERY_GRANTS_VIEW,
            }),
        }
    }

    /// Revokes the active grant (sets `revoked_ts`; history stays), in
    /// the same transaction as this op's terminal state and audit row.
    async fn grants_revoke(
        &self,
        request_id: &str,
        args: &serde_json::Value,
    ) -> Result<AdminOk, AdminRefusal> {
        let capability = required_str(args, "capability", OP_GRANTS_REVOKE)?;
        let audit = json!({ "op": OP_GRANTS_REVOKE, "capability": capability });
        match self
            .change_grant(request_id, GrantChange::Revoke(capability), &audit)
            .await?
        {
            GrantChangeOutcome::Applied => Ok(AdminOk {
                outcome: Outcome::Changed,
                body: json!({ "capability": capability, "revoked": true }),
                audit,
            }),
            GrantChangeOutcome::Unchanged => Err(AdminRefusal {
                cause: CAUSE_NO_ACTIVE_GRANT,
                detail: format!("capability {capability:?} has no active grant to revoke"),
                recovery: RECOVERY_GRANTS_VIEW,
            }),
        }
    }

    /// One grant change, atomic with the admin request's `done` state and
    /// its `admin`/`allow`/`human` audit row. `Applied` leaves the request
    /// terminal (the later [`Self::finish_ok`] is a first-wins no-op);
    /// `Unchanged` wrote nothing and the request is still in flight.
    async fn change_grant(
        &self,
        request_id: &str,
        change: GrantChange<'_>,
        audit: &serde_json::Value,
    ) -> Result<GrantChangeOutcome, AdminRefusal> {
        let detail = audit.to_string();
        self.store
            .finish_request_with_grant_change(
                request_id,
                change,
                Some(outcome_str(Outcome::Changed)),
                AuditEntry {
                    action: ACTION_ADMIN,
                    decision: Decision::Allow,
                    actor: Actor::Human,
                    detail: Some(&detail),
                },
            )
            .await
            .map_err(|error| match error {
                // Something finished the request first; the grant table
                // was not touched.
                StoreError::AlreadyTerminal { .. } => AdminRefusal {
                    cause: CAUSE_INTERNAL_ERROR,
                    detail: "the admin request was already finished; the grant was not changed"
                        .to_owned(),
                    recovery: RECOVERY_GRANTS_VIEW,
                },
                other => other.into(),
            })
    }

    /// Cancels `args.ticket` on the human's behalf by submitting a `cancel`
    /// request of [`Origin::Admin`] through the pipeline ingress: the same
    /// queue path an agent's `pam cancel` takes, minus the ownership
    /// binding (the human may cancel anything), audited as `human`.
    async fn requests_cancel(&self, args: &serde_json::Value) -> Result<AdminOk, AdminRefusal> {
        let ticket = required_str(args, "ticket", OP_REQUESTS_CANCEL)?;
        if ticket.len() > 128 {
            return Err(AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: format!("{OP_REQUESTS_CANCEL} needs a ticket of at most 128 bytes"),
                recovery: RECOVERY_FIX_ARGS,
            });
        }
        let submit_failed = || AdminRefusal {
            cause: CAUSE_INTERNAL_ERROR,
            detail: "the daemon could not submit the cancellation".to_owned(),
            recovery: RECOVERY_SUBMIT,
        };
        let envelope = Envelope {
            v: PROTOCOL_VERSION,
            id: format!("req_{}", ulid::Ulid::new()),
            capability: CAP_CANCEL.to_owned(),
            client_version: DAEMON_VERSION.to_owned(),
            caller: Caller {
                agent: ADMIN_CALLER_AGENT.to_owned(),
                repo: ADMIN_REPO.to_owned(),
                pid: std::process::id(),
            },
            args: json!({ "ticket": ticket }),
            idempotency_key: None,
            deadline_ms: REQUESTS_CANCEL_DEADLINE_MS,
            wait: true,
        };
        let (reply, answer) = oneshot::channel();
        self.submit
            .send(IncomingRequest {
                // No zmq peer: the reply comes back through the channel.
                identity: Vec::new(),
                origin: Origin::Admin,
                envelope,
                reply,
            })
            .await
            .map_err(|_| submit_failed())?;
        match answer.await {
            Ok(Response::Result { outcome, body, .. }) => Ok(AdminOk {
                outcome,
                audit: json!({
                    "op": OP_REQUESTS_CANCEL,
                    "ticket": ticket,
                    "result": body.get("result"),
                }),
                body,
            }),
            Ok(Response::Refusal { cause, detail, .. }) => Err(AdminRefusal {
                cause: CAUSE_INTERNAL_ERROR,
                detail: format!("the cancellation was refused ({cause}): {detail}"),
                recovery: RECOVERY_SUBMIT,
            }),
            Ok(Response::Ticket { .. }) | Err(_) => Err(submit_failed()),
        }
    }

    /// The unresolved approvals, oldest first. A gated flow step's row
    /// carries `resolved` (see [`crate::approval::StepSnapshot`]): the
    /// program, arguments, directory and environment names the waiting run
    /// resolved, and the digest an answer must return. Each row carries what the
    /// agent submitted (`args`, the request's own JSON), the remote
    /// repository the work names (`repository`: the flow's correlation
    /// repository resolved against the inputs, or the `repository` argument
    /// of a plain request, else null) and the gated step's declared
    /// `effect` (`read_only` / `stateful`; null for a capability that is
    /// not a flow step), so the GUI card needs no join against the
    /// activity list.
    async fn approvals_pending(&self) -> Result<AdminOk, AdminRefusal> {
        let mut pending = Vec::new();
        for approval in self.approvals.pending().await? {
            let args = serde_json::from_str::<serde_json::Value>(&approval.args_json)
                .unwrap_or(serde_json::Value::Null);
            // The digest of the flow the waiting request is actually
            // running, from its journal; a store that cannot say reads as
            // "no journal", and nothing is claimed about the flow.
            let running = self
                .store
                .read_flow_journal(&approval.request_id)
                .await
                .ok()
                .flatten()
                .map(|journal| journal.identity.flow_digest);
            let (repository, effect, flow_edited) =
                self.approval_context(&approval, &args, running.as_deref());
            let mut entry = json!({
                "request_id": approval.request_id,
                "capability": approval.capability,
                "repo": approval.repo,
                "agent": approval.caller_agent,
                "requested_ts": approval.requested_ts,
                "args": args,
                "repository": repository,
                "effect": effect,
            });
            if flow_edited {
                // The library's flow is no longer the one this request
                // runs: describing it would describe something else.
                entry["flow_edited"] = json!(true);
            }
            // What the waiting run will actually execute, captured when
            // its wait began — not a re-reading of the flow file now. The
            // GUI returns `resolved.digest` with the answer.
            if let Some(snapshot) = self.approvals.snapshot(&approval.request_id).await {
                entry["resolved"] = json!(snapshot);
            }
            pending.push(entry);
        }
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: json!({ "pending": pending }),
            audit: json!({ "op": OP_APPROVALS_PENDING }),
        })
    }

    /// What a pending approval acts on, read off the installed flow: the
    /// correlation repository resolved against the submitted inputs (and
    /// the flow's own input defaults), and the gated step's declared
    /// effect. A request that is not a flow run may name a `repository`
    /// argument directly. Anything unresolvable is null, never a guess —
    /// and that includes a flow edited after the request started
    /// (`running_digest`, from the request's journal, no longer matches the
    /// library): the third value says so, and nothing is read off the new
    /// file on the old request's behalf.
    fn approval_context(
        &self,
        approval: &pam_store::PendingApproval,
        args: &serde_json::Value,
        running_digest: Option<&str>,
    ) -> (Option<String>, Option<pam_flow::Effect>, bool) {
        let argument = |key: &str| args.get(key).and_then(serde_json::Value::as_str);
        if approval.request_capability != "flow.run" {
            return (argument("repository").map(str::to_owned), None, false);
        }
        let Some(flow) = argument("id")
            .and_then(|id| self.flows.entry(id).ok())
            .and_then(|entry| entry.parsed.ok())
        else {
            return (None, None, false);
        };
        if running_digest.is_some_and(|running| running != pam_flow::digest(&flow)) {
            return (None, None, true);
        }
        let effect = approval
            .capability
            .strip_prefix(crate::flow_service::STEP_CAPABILITY_PREFIX)
            .and_then(|rest| rest.strip_prefix(flow.id.as_str()))
            .and_then(|rest| rest.strip_prefix('/'))
            .and_then(|step_id| flow.steps.iter().find(|step| step.id == step_id))
            .map(|step| step.effect);
        let Some(correlation) = flow.correlation.as_ref() else {
            return (None, effect, false);
        };
        let mut vars = pam_flow::Vars::new();
        for (name, input) in &flow.inputs {
            let submitted = args
                .get("inputs")
                .and_then(|inputs| inputs.get(name))
                .and_then(serde_json::Value::as_str);
            if let Some(value) = submitted.or(input.default.as_deref()) {
                vars.set(&format!("inputs.{name}"), value);
            }
        }
        let repository = pam_flow::substitute(&correlation.repository, &vars).ok();
        (repository, effect, false)
    }

    /// Delivers a human resolution to the waiting request through
    /// [`ApprovalService::resolve`]. The optional `note` is recorded in
    /// this admin op's audit detail (the approval row's own note column
    /// is reserved for service-side resolutions such as cancellation).
    async fn approvals_resolve(&self, args: &serde_json::Value) -> Result<AdminOk, AdminRefusal> {
        let request_id = required_str(args, "request_id", OP_APPROVALS_RESOLVE)?;
        let resolution = required_str(args, "resolution", OP_APPROVALS_RESOLVE)?;
        let remember = args
            .get("remember")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let note = args.get("note").and_then(serde_json::Value::as_str);
        let expected_digest = match args.get("expected_digest") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(digest)) => Some(digest.as_str()),
            Some(other) => {
                return Err(AdminRefusal {
                    cause: CAUSE_INVALID_ADMIN_ARGS,
                    detail: format!("{other} is not a string expected_digest"),
                    recovery: RECOVERY_FIX_ARGS,
                });
            }
        };
        if let Some(note) = note
            && note.len() > MAX_APPROVAL_NOTE_BYTES
        {
            return Err(AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: format!(
                    "note is {} bytes; the audit detail keeps at most {MAX_APPROVAL_NOTE_BYTES}",
                    note.len()
                ),
                recovery: RECOVERY_FIX_ARGS,
            });
        }
        let decision = match resolution {
            "approved" => Resolution::Approve { remember },
            "denied" => Resolution::Deny,
            other => {
                return Err(AdminRefusal {
                    cause: CAUSE_INVALID_ADMIN_ARGS,
                    detail: format!(
                        "{other:?} is not a resolution; expected \"approved\" or \"denied\""
                    ),
                    recovery: RECOVERY_FIX_ARGS,
                });
            }
        };
        match self
            .approvals
            .resolve_pinned(request_id, decision, expected_digest)
            .await
        {
            Ok(()) => {}
            Err(ApprovalError::Changed { .. }) => {
                return Err(AdminRefusal {
                    cause: CAUSE_FLOW_CHANGED,
                    detail: format!(
                        "the approval pending for request {request_id} is not the one that was \
                         shown: its flow was edited or the request moved to another step; \
                         nothing was resolved"
                    ),
                    recovery: RECOVERY_APPROVAL_CHANGED,
                });
            }
            Err(ApprovalError::NotFound { .. }) => {
                return Err(AdminRefusal {
                    cause: CAUSE_NO_PENDING_APPROVAL,
                    detail: format!(
                        "no approval is pending for request {request_id} \
                         (unknown id, already resolved, timed out, or cancelled)"
                    ),
                    recovery: RECOVERY_APPROVALS_VIEW,
                });
            }
        }
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({
                "request_id": request_id,
                "resolution": resolution,
                "remember": remember,
            }),
            audit: json!({
                "op": OP_APPROVALS_RESOLVE,
                "request_id": request_id,
                "resolution": resolution,
                "remember": remember,
                "note": note,
                "pinned": expected_digest.is_some(),
            }),
        })
    }

    /// Recent request rows, newest first, optionally filtered; bounded
    /// by the store's limit clamp.
    async fn activity_list(&self, args: &serde_json::Value) -> Result<AdminOk, AdminRefusal> {
        let limit = args.get("limit").and_then(serde_json::Value::as_u64);
        let repo = args.get("repo").and_then(serde_json::Value::as_str);
        let agent = args.get("agent").and_then(serde_json::Value::as_str);
        let state = args
            .get("state")
            .and_then(serde_json::Value::as_str)
            .map(|raw| {
                RequestState::parse(raw).map_err(|_| AdminRefusal {
                    cause: CAUSE_INVALID_ADMIN_ARGS,
                    detail: format!("{raw:?} is not a request state"),
                    recovery: RECOVERY_FIX_ARGS,
                })
            })
            .transpose()?;
        // The Flows screen's run history is this list narrowed to
        // `flow.run`, which is why the filter exists at all.
        let capability = args.get("capability").and_then(serde_json::Value::as_str);
        // The GUI polls this very op (and `status`) every few seconds;
        // asked to, the store drops that self-traffic so real agent work
        // is not pushed out of the newest-N window.
        let hide_probes = match args.get("hide_probes") {
            None | Some(serde_json::Value::Null) => false,
            Some(serde_json::Value::Bool(flag)) => *flag,
            Some(other) => {
                return Err(AdminRefusal {
                    cause: CAUSE_INVALID_ADMIN_ARGS,
                    detail: format!("{other} is not a boolean hide_probes"),
                    recovery: RECOVERY_FIX_ARGS,
                });
            }
        };
        let requests: Vec<serde_json::Value> = self
            .store
            .list_requests_filtered(limit, repo, agent, state, capability, hide_probes)
            .await?
            .into_iter()
            .map(|row| {
                json!({
                    "id": row.id,
                    "capability": row.capability,
                    "repo": row.repo,
                    "agent": row.caller_agent,
                    // Parsed back to JSON so the GUI's detail view renders
                    // structured args, not a doubly-encoded string.
                    "args": serde_json::from_str::<serde_json::Value>(&row.args_json)
                        .unwrap_or(serde_json::Value::Null),
                    "state": row.state.as_str(),
                    "outcome": row.outcome,
                    "created_ts": row.created_ts,
                    "updated_ts": row.updated_ts,
                })
            })
            .collect();
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: json!({ "requests": requests }),
            audit: json!({ "op": OP_ACTIVITY_LIST }),
        })
    }

    /// The observed agent+repo registry, most recently seen first.
    async fn callers_list(&self) -> Result<AdminOk, AdminRefusal> {
        let callers: Vec<serde_json::Value> = self
            .store
            .list_callers()
            .await?
            .into_iter()
            .map(|caller| {
                json!({
                    "agent": caller.agent,
                    "repo": caller.repo,
                    "first_seen": caller.first_seen,
                    "last_seen": caller.last_seen,
                })
            })
            .collect();
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: json!({ "callers": callers }),
            audit: json!({ "op": OP_CALLERS_LIST }),
        })
    }

    /// The audit trail of one request, oldest first. Unknown ids answer
    /// an empty list: a pruned or mistyped id is a state to render, not
    /// a refusal.
    async fn audit_request(&self, args: &serde_json::Value) -> Result<AdminOk, AdminRefusal> {
        let request_id = args
            .get("request_id")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or(AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: "request_id (non-empty string) is required".to_owned(),
                recovery: RECOVERY_FIX_ARGS,
            })?;
        let rows: Vec<serde_json::Value> = self
            .store
            .audit_for_request(request_id)
            .await?
            .into_iter()
            .map(|row| {
                // Parsed back to JSON when it is JSON, so the GUI reads
                // `detail.cause` instead of a doubly-encoded string; a
                // free-form detail survives as the raw string.
                let detail = row.detail.map(|raw| {
                    serde_json::from_str::<serde_json::Value>(&raw)
                        .unwrap_or(serde_json::Value::String(raw))
                });
                json!({
                    "id": row.id,
                    "action": row.action,
                    "decision": row.decision.as_str(),
                    "actor": row.actor.as_str(),
                    "detail": detail,
                    "ts": row.ts,
                })
            })
            .collect();
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: json!({ "request_id": request_id, "rows": rows }),
            audit: json!({ "op": OP_AUDIT_REQUEST, "request_id": request_id }),
        })
    }

    /// Finishes a successful op: state `done`, action [`ACTION_ADMIN`],
    /// decision `allow`, actor `human`. A success whose terminal row the
    /// store would not take is not reported as one: the verdict is parked
    /// for retry and the caller gets an internal refusal telling it to
    /// inspect state.
    async fn finish_ok(&self, envelope: &Envelope, ok: AdminOk) -> Response {
        let detail = ok.audit.to_string();
        let written = self
            .terminals
            .finish(
                &envelope.id,
                RequestState::Done,
                Some(outcome_str(ok.outcome)),
                AuditEntry {
                    action: ACTION_ADMIN,
                    decision: Decision::Allow,
                    actor: Actor::Human,
                    detail: Some(&detail),
                },
            )
            .await;
        if written == Written::Parked {
            return Response::refusal(
                envelope.id.clone(),
                CAUSE_INTERNAL_ERROR,
                "the admin operation ran but its audit row could not be recorded yet; \
                 it is queued to be recorded",
                RECOVERY_DEADLINE,
            );
        }
        Response::Result {
            id: envelope.id.clone(),
            outcome: ok.outcome,
            body: ok.body,
            evidence: Vec::new(),
        }
    }

    /// Finishes a refused op: state `refused`, action [`ACTION_ADMIN`],
    /// decision `refuse`, actor `system`.
    async fn finish_refused(&self, envelope: &Envelope, refusal: OwnedRefusal) -> Response {
        let detail = json!({
            "op": envelope.capability,
            "cause": refusal.cause,
            "detail": refusal.detail,
        })
        .to_string();
        self.terminals
            .finish(
                &envelope.id,
                RequestState::Refused,
                Some(&refusal.cause),
                AuditEntry {
                    action: ACTION_ADMIN,
                    decision: Decision::Refuse,
                    actor: Actor::System,
                    detail: Some(&detail),
                },
            )
            .await;
        Response::refusal(
            envelope.id.clone(),
            refusal.cause,
            refusal.detail,
            refusal.recovery,
        )
    }

    /// Finishes a tripwire hit: state `refused`, its own audit action
    /// ([`ACTION_ADMIN_DENIED`]) so the trace stands out in the trail.
    async fn refuse_tripwire(&self, envelope: &Envelope, private_ingress: bool) -> Response {
        let agent = &envelope.caller.agent;
        let detail = json!({
            "op": envelope.capability,
            "caller_agent": agent,
            "expected": ADMIN_CALLER_AGENT,
            "private_ingress": private_ingress,
        })
        .to_string();
        self.terminals
            .finish(
                &envelope.id,
                RequestState::Refused,
                Some(CAUSE_ADMIN_DENIED),
                AuditEntry {
                    action: ACTION_ADMIN_DENIED,
                    decision: Decision::Refuse,
                    actor: Actor::System,
                    detail: Some(&detail),
                },
            )
            .await;
        Response::refusal(
            envelope.id.clone(),
            CAUSE_ADMIN_DENIED,
            if private_ingress {
                format!("admin operations are GUI-only; caller {agent:?} is not the PAM GUI")
            } else {
                "admin operations require the private native channel; public IPC cannot administer PAM".to_owned()
            },
            RECOVERY_ADMIN_DENIED,
        )
    }

    /// Finishes an op the deadline cut off: state `failed`, the daemon's
    /// deadline-refusal audit row (decision `timeout`, actor `system`).
    /// Not `retryable`: an admin op is never replayed blind — an effect may
    /// already have started.
    async fn finish_deadline(&self, envelope: &Envelope) -> Response {
        let detail = json!({ "deadline_ms": envelope.deadline_ms }).to_string();
        self.terminals
            .finish(
                &envelope.id,
                RequestState::Failed,
                Some(CAUSE_DEADLINE_EXCEEDED),
                AuditEntry {
                    action: ACTION_DEADLINE_REFUSAL,
                    decision: Decision::Timeout,
                    actor: Actor::System,
                    detail: Some(&detail),
                },
            )
            .await;
        Response::refusal(
            envelope.id.clone(),
            CAUSE_DEADLINE_EXCEEDED,
            format!(
                "admin operation exceeded its {} ms deadline",
                envelope.deadline_ms
            ),
            RECOVERY_DEADLINE,
        )
    }
}

/// Reads a required non-empty string argument, refusing legibly.
pub(crate) fn required_str<'a>(
    args: &'a serde_json::Value,
    key: &str,
    op: &str,
) -> Result<&'a str, AdminRefusal> {
    match args.get(key).and_then(serde_json::Value::as_str) {
        Some(value) if !value.is_empty() => Ok(value),
        _ => Err(AdminRefusal {
            cause: CAUSE_INVALID_ADMIN_ARGS,
            detail: format!("{op} needs a non-empty string argument {key:?}"),
            recovery: RECOVERY_FIX_ARGS,
        }),
    }
}
