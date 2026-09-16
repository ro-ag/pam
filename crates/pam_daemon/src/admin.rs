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
//! - [`OP_PROFILE_SET`] persists `policy.profile`, but the running [`crate::policy::PolicyGate`]
//!   reads it once at construction, so the new profile governs only from the next daemon start
//!   (response carries `"applies": "next_daemon_start"`); the GUI owns telling the human /
//!   restarting.
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

use pam_proto::{Envelope, Outcome, Response};
use pam_store::{Actor, AuditEntry, Decision, RequestState, Store, StoreError};
use serde_json::json;
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout_at};

use crate::approval::{ApprovalService, Resolution};
use crate::connector_service::ConnectorService;
use crate::daemon::{ACTION_DEADLINE_REFUSAL, CAUSE_DEADLINE_EXCEEDED, CAUSE_INTERNAL_ERROR};
use crate::executor::outcome_str;
use crate::flow_service::FlowService;
use crate::log_service::LogService;
use crate::model_service::ModelService;
use crate::policy::{PROFILE_SETTING_KEY, Profile};
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

/// `admin.profile.set { profile }` → persists `policy.profile`
/// (applies at the next daemon start; see the module docs).
pub const OP_PROFILE_SET: &str = "admin.profile.set";

/// `admin.grants.list` → every grant row, revoked history included.
pub const OP_GRANTS_LIST: &str = "admin.grants.list";

/// `admin.grants.add { capability }` → records a new global grant.
pub const OP_GRANTS_ADD: &str = "admin.grants.add";

/// `admin.grants.revoke { capability }` → revokes the active grant.
pub const OP_GRANTS_REVOKE: &str = "admin.grants.revoke";

/// `admin.approvals.pending` → the unresolved approvals, oldest first.
pub const OP_APPROVALS_PENDING: &str = "admin.approvals.pending";

/// `admin.approvals.resolve { request_id, resolution, remember?, note? }`
/// → delivers a human resolution to the waiting request.
pub const OP_APPROVALS_RESOLVE: &str = "admin.approvals.resolve";

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
            OP_PROFILE_GET => self.profile_get().await,
            OP_PROFILE_SET => self.profile_set(args).await,
            OP_GRANTS_LIST => self.grants_list().await,
            OP_GRANTS_ADD => self.grants_add(args).await,
            OP_GRANTS_REVOKE => self.grants_revoke(args).await,
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

    /// The active profile: the persisted setting, or the platform
    /// default when unset (mirroring the gate's construction).
    async fn profile_get(&self) -> Result<AdminOk, AdminRefusal> {
        let profile = match self.store.get_setting(PROFILE_SETTING_KEY).await? {
            Some(raw) => serde_json::from_str::<Profile>(&raw).map_err(|_| AdminRefusal {
                cause: CAUSE_INTERNAL_ERROR,
                detail: format!("stored profile {raw:?} is not a profile this binary knows"),
                recovery: RECOVERY_INTERNAL,
            })?,
            None => Profile::platform_default(),
        };
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: json!({ "profile": profile.as_str() }),
            audit: json!({ "op": OP_PROFILE_GET }),
        })
    }

    /// Validates and persists a new profile. Applies at the next daemon
    /// start (see the module docs); the body says so.
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
        let previous = self.store.get_setting(PROFILE_SETTING_KEY).await?;
        let raw =
            serde_json::to_string(&profile).expect("a Profile always serializes to a JSON string");
        self.store.set_setting(PROFILE_SETTING_KEY, &raw).await?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({
                "profile": profile.as_str(),
                "applies": "next_daemon_start",
            }),
            audit: json!({
                "op": OP_PROFILE_SET,
                "profile": profile.as_str(),
                "previous": previous,
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
    /// second active row would only muddy the history).
    async fn grants_add(&self, args: &serde_json::Value) -> Result<AdminOk, AdminRefusal> {
        let capability = required_str(args, "capability", OP_GRANTS_ADD)?;
        if self.store.active_grant(capability).await? {
            return Err(AdminRefusal {
                cause: CAUSE_ALREADY_GRANTED,
                detail: format!("capability {capability:?} already has an active grant"),
                recovery: RECOVERY_GRANTS_VIEW,
            });
        }
        self.store.insert_grant(capability).await?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({ "capability": capability, "granted": true }),
            audit: json!({ "op": OP_GRANTS_ADD, "capability": capability }),
        })
    }

    /// Revokes the active grant (sets `revoked_ts`; history stays).
    async fn grants_revoke(&self, args: &serde_json::Value) -> Result<AdminOk, AdminRefusal> {
        let capability = required_str(args, "capability", OP_GRANTS_REVOKE)?;
        match self.store.revoke_grant(capability).await {
            Ok(()) => Ok(AdminOk {
                outcome: Outcome::Changed,
                body: json!({ "capability": capability, "revoked": true }),
                audit: json!({ "op": OP_GRANTS_REVOKE, "capability": capability }),
            }),
            Err(StoreError::NotFound { .. }) => Err(AdminRefusal {
                cause: CAUSE_NO_ACTIVE_GRANT,
                detail: format!("capability {capability:?} has no active grant to revoke"),
                recovery: RECOVERY_GRANTS_VIEW,
            }),
            Err(err) => Err(err.into()),
        }
    }

    /// The unresolved approvals, oldest first. Each row carries what the
    /// agent submitted (`args`, the request's own JSON), the remote
    /// repository the work names (`repository`: the flow's correlation
    /// repository resolved against the inputs, or the `repository` argument
    /// of a plain request, else null) and the gated step's declared
    /// `effect` (`read_only` / `stateful`; null for a capability that is
    /// not a flow step), so the GUI card needs no join against the
    /// activity list.
    async fn approvals_pending(&self) -> Result<AdminOk, AdminRefusal> {
        let pending: Vec<serde_json::Value> = self
            .approvals
            .pending()
            .await?
            .into_iter()
            .map(|approval| {
                let args = serde_json::from_str::<serde_json::Value>(&approval.args_json)
                    .unwrap_or(serde_json::Value::Null);
                let (repository, effect) = self.approval_context(&approval, &args);
                json!({
                    "request_id": approval.request_id,
                    "capability": approval.capability,
                    "repo": approval.repo,
                    "agent": approval.caller_agent,
                    "requested_ts": approval.requested_ts,
                    "args": args,
                    "repository": repository,
                    "effect": effect,
                })
            })
            .collect();
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
    /// argument directly. Anything unresolvable is null, never a guess.
    fn approval_context(
        &self,
        approval: &pam_store::PendingApproval,
        args: &serde_json::Value,
    ) -> (Option<String>, Option<pam_flow::Effect>) {
        let argument = |key: &str| args.get(key).and_then(serde_json::Value::as_str);
        if approval.request_capability != "flow.run" {
            return (argument("repository").map(str::to_owned), None);
        }
        let Some(flow) = argument("id")
            .and_then(|id| self.flows.entry(id).ok())
            .and_then(|entry| entry.parsed.ok())
        else {
            return (None, None);
        };
        let effect = approval
            .capability
            .strip_prefix(crate::flow_service::STEP_CAPABILITY_PREFIX)
            .and_then(|rest| rest.strip_prefix(flow.id.as_str()))
            .and_then(|rest| rest.strip_prefix('/'))
            .and_then(|step_id| flow.steps.iter().find(|step| step.id == step_id))
            .map(|step| step.effect);
        let Some(correlation) = flow.correlation.as_ref() else {
            return (None, effect);
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
        (repository, effect)
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
        if self.approvals.resolve(request_id, decision).await.is_err() {
            return Err(AdminRefusal {
                cause: CAUSE_NO_PENDING_APPROVAL,
                detail: format!(
                    "no approval is pending for request {request_id} \
                     (unknown id, already resolved, timed out, or cancelled)"
                ),
                recovery: RECOVERY_APPROVALS_VIEW,
            });
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
    /// decision `allow`, actor `human`.
    async fn finish_ok(&self, envelope: &Envelope, ok: AdminOk) -> Response {
        let detail = ok.audit.to_string();
        let _ = self
            .store
            .finish_request(
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
        let _ = self
            .store
            .finish_request(
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
        Response::Refusal {
            id: envelope.id.clone(),
            cause: refusal.cause,
            detail: refusal.detail,
            recovery: refusal.recovery,
        }
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
        let _ = self
            .store
            .finish_request(
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
        Response::Refusal {
            id: envelope.id.clone(),
            cause: CAUSE_ADMIN_DENIED.to_owned(),
            detail: if private_ingress {
                format!("admin operations are GUI-only; caller {agent:?} is not the PAM GUI")
            } else {
                "admin operations require the private native channel; public IPC cannot administer PAM".to_owned()
            },
            recovery: RECOVERY_ADMIN_DENIED.to_owned(),
        }
    }

    /// Finishes an op the deadline cut off: state `failed`, the daemon's
    /// deadline-refusal audit row (decision `timeout`, actor `system`).
    async fn finish_deadline(&self, envelope: &Envelope) -> Response {
        let detail = json!({ "deadline_ms": envelope.deadline_ms }).to_string();
        let _ = self
            .store
            .finish_request(
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
        Response::Refusal {
            id: envelope.id.clone(),
            cause: CAUSE_DEADLINE_EXCEEDED.to_owned(),
            detail: format!(
                "admin operation exceeded its {} ms deadline",
                envelope.deadline_ms
            ),
            recovery: RECOVERY_DEADLINE.to_owned(),
        }
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
