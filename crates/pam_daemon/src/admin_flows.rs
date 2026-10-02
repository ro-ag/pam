//! The flow half of the admin surface: `admin.flows.list`, `.get`, `.save`, `.delete`, `.run`,
//! `.normalize`, and the two settings ops. Ordinary admin ops — see [`crate::admin`] for the
//! security model: GUI tripwire, request row, single terminal audit row, deadline, structural guard
//! (no [`crate::policy::classify`] entry, never a capability, never grantable). A flow file *is*
//! the command list pam will run: writing one is human-only; running one is not — `flow.run` is a
//! normal capability gated per step (see [`crate::flow_service`]).
//!
//! [`OP_FLOWS_RUN`] (the GUI's Run button) builds a genuine `flow.run` envelope — caller agent
//! `pam-gui`, the repo the human picked — through the pipeline's ingress channel: classified,
//! admitted, deduped, gated, laned and audited as an agent's would be. Starting a flow from the GUI
//! is not privileged; only editing one is.
//!
//! A remembered step approval is a grant on `flow.step:<flow>/<step>` — a name, not what the step
//! runs. Every op here that changes what a flow id answers to (`.save`, `.delete`) therefore
//! revokes, in the same operation and before the library changes, the active grants of every step
//! whose effective definition is no longer the one that was approved, and says which in its reply
//! and audit row ([`GRANTS_REVOKED`]). An edited step asks a human again.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use pam_flow::{Action, ArgValue, Entry, Flow, FlowError, Source, Step};
use pam_proto::{Caller, Envelope, Outcome, PROTOCOL_VERSION, Response};
use pam_store::StoreError;
use serde_json::{Value, json};
use tokio::sync::oneshot;

use crate::admin::{
    ADMIN_CALLER_AGENT, AdminOk, AdminRefusal, AdminService, CAUSE_INVALID_ADMIN_ARGS,
    OwnedRefusal, RECOVERY_FIX_ARGS, RECOVERY_INTERNAL, required_str,
};
use crate::daemon::DAEMON_VERSION;
use crate::flow_service::{
    ArtifactsRootPatch, CAP_FLOW_INSPECT, CAP_FLOW_RUN, CAUSE_FLOW_INVALID, FlowRefusal,
    RECOVERY_FLOW_EDIT, STEP_CAPABILITY_PREFIX, SettingsPatch,
};
use crate::scope_policy::{CAUSE_SCOPE_INVALID, RECOVERY_SCOPE, ScopePolicy};
use crate::transport::IncomingRequest;

/// `admin.flows.list` → every flow, builtins and library merged.
pub const OP_FLOWS_LIST: &str = "admin.flows.list";

/// `admin.flows.get { id }` → one flow's text, canonical rendering,
/// digest and parsed shape.
pub const OP_FLOWS_GET: &str = "admin.flows.get";

/// `admin.flows.save { id, yaml }` → the saved flow's list entry, plus
/// [`GRANTS_REVOKED`] and [`REAPPROVAL_REQUIRED`].
pub const OP_FLOWS_SAVE: &str = "admin.flows.save";

/// `admin.flows.delete { id }` → `{ id, revealed_builtin, grants_revoked,
/// reapproval_required }`.
pub const OP_FLOWS_DELETE: &str = "admin.flows.delete";

/// `admin.flows.normalize { yaml } | { flow }` → canonical rendering +
/// validation of a flow that lives only in the GUI: the designer canvas
/// sends its model here after every edit and shows the YAML it gets
/// back. Valid: `{ valid: true, yaml, flow, digest }`; invalid: a normal
/// reply `{ valid: false, error: { path, message } }`, so the canvas
/// keeps drawing. Never touches disk; never a capability.
pub const OP_FLOWS_NORMALIZE: &str = "admin.flows.normalize";

/// `admin.flows.run { id, repo, inputs?, expected_digest? }` → `{ ticket,
/// position }`. `expected_digest` pins the run to the flow the human was
/// shown; a flow edited since refuses `flow_changed`.
pub const OP_FLOWS_RUN: &str = "admin.flows.run";

/// `admin.flows.inspect { id, repo, inputs? }` → the `flow.inspect`
/// body (`readiness`, `blockers`, `steps`, `inputs`, …) for that
/// repository, exactly as the CLI's `pam flow inspect` sees it. A read:
/// the run overview shows what would block before anyone presses Run.
pub const OP_FLOWS_INSPECT: &str = "admin.flows.inspect";

/// `admin.flows.settings.get` → `{ allowed_programs, extra_path,
/// artifacts_root, read_cache_roots, scope_policy }`.
pub const OP_FLOWS_SETTINGS_GET: &str = "admin.flows.settings.get";

/// `admin.flows.settings.set { allowed_programs?, extra_path?,
/// artifacts_root?, read_cache_roots?, scope_policy? }` → the settings as
/// they now stand. `artifacts_root: null` clears the build output directory.
pub const OP_FLOWS_SETTINGS_SET: &str = "admin.flows.settings.set";

/// GUI-only landing recipe and mutation-scope inspection.
pub const OP_LANDING_GET: &str = "admin.flows.landing.get";
/// GUI-only compare-and-swap update of landing authority.
pub const OP_LANDING_SET: &str = "admin.flows.landing.set";

/// Every op this module answers — the GUI bridge's whitelist reads it so
/// the two can never drift.
pub const FLOW_ADMIN_OPS: &[&str] = &[
    OP_FLOWS_LIST,
    OP_FLOWS_GET,
    OP_FLOWS_SAVE,
    OP_FLOWS_NORMALIZE,
    OP_FLOWS_DELETE,
    OP_FLOWS_RUN,
    OP_FLOWS_INSPECT,
    OP_FLOWS_SETTINGS_GET,
    OP_FLOWS_SETTINGS_SET,
    OP_LANDING_GET,
    OP_LANDING_SET,
];

/// The deadline an `admin.flows.run` envelope carries: half an hour,
/// because a flow that runs `cargo test` is not a sixty second request.
pub const FLOW_RUN_DEADLINE_MS: u64 = 1_800_000;
/// The deadline an `admin.flows.inspect` envelope carries: inspection
/// is a bounded read the GUI waits for, and it must expire before the
/// GUI bridge's own 30 s admin deadline so the refusal reaches the human.
pub const FLOW_INSPECT_DEADLINE_MS: u64 = 20_000;

/// Refusal cause: the YAML declares a different id than it is saved as.
pub const CAUSE_ID_MISMATCH: &str = "id_mismatch";

/// Refusal cause: the library directory could not be written.
pub const CAUSE_LIBRARY_UNWRITABLE: &str = "library_unwritable";

/// Refusal cause: nothing to delete under that id.
pub const CAUSE_NOT_FOUND: &str = "not_found";

/// Refusal cause: the pipeline never answered the submitted run.
pub const CAUSE_SUBMIT_FAILED: &str = "submit_failed";

/// Reply and audit key: the step capabilities whose remembered approval a
/// library change revoked, sorted. Empty when nothing a human approved changed.
pub const GRANTS_REVOKED: &str = "grants_revoked";

/// Reply key: `true` when [`GRANTS_REVOKED`] is not empty, so the GUI can say
/// in one glance that the changed steps will ask for approval again.
pub const REAPPROVAL_REQUIRED: &str = "reapproval_required";

/// Recovery line for a delete that has nothing to remove.
const RECOVERY_DELETE: &str = "open Pam → Flows: only a library file can be deleted, and a builtin has none until you save one";

/// Recovery line for a library the daemon cannot write.
const RECOVERY_UNWRITABLE: &str =
    "make ~/.pam/flows writable by the user the daemon runs as, then save again";

impl AdminService {
    /// Answers one `admin.flows.*` op, or `None` when the capability
    /// belongs to another part of the admin surface.
    pub(crate) async fn dispatch_flows(
        &self,
        op: &str,
        args: &Value,
    ) -> Option<Result<AdminOk, OwnedRefusal>> {
        Some(match op {
            OP_LANDING_GET | OP_LANDING_SET => self
                .landing_settings(op, args)
                .await
                .map_err(OwnedRefusal::from),
            OP_FLOWS_LIST => self.flows_list().map_err(OwnedRefusal::from),
            OP_FLOWS_GET => self.flows_get(args).map_err(OwnedRefusal::from),
            OP_FLOWS_SAVE => self.flows_save(args).await.map_err(OwnedRefusal::from),
            OP_FLOWS_DELETE => self.flows_delete(args).await.map_err(OwnedRefusal::from),
            OP_FLOWS_NORMALIZE => Self::flows_normalize(args).map_err(OwnedRefusal::from),
            OP_FLOWS_RUN => self.flows_run(args).await,
            OP_FLOWS_INSPECT => self.flows_inspect(args).await,
            OP_FLOWS_SETTINGS_GET => self.flows_settings_get().await.map_err(OwnedRefusal::from),
            OP_FLOWS_SETTINGS_SET => self
                .flows_settings_set(args)
                .await
                .map_err(OwnedRefusal::from),
            _ => return None,
        })
    }

    async fn landing_settings(&self, op: &str, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let snapshot = if op == OP_LANDING_SET {
            crate::landing_policy::Snapshot::save(&self.store, args, self.flows.protected_base()).await
        } else {
            crate::landing_policy::Snapshot::load(&self.store).await
        }.map_err(|error| AdminRefusal {
            cause: error.cause, detail: error.to_string(),
            recovery: "Open PAM Settings → Flows → Landing; reload and correct the approved recipe and targets.",
        })?;
        Ok(AdminOk {
            outcome: if op == OP_LANDING_SET {
                Outcome::Changed
            } else {
                Outcome::Verified
            },
            body: snapshot.response(),
            audit: json!({"op":op,"revision":snapshot.revision}),
        })
    }

    /// Every flow, with the file path and digest the GUI list shows.
    fn flows_list(&self) -> Result<AdminOk, AdminRefusal> {
        let entries = self.flows.entries().map_err(|refusal| refuse(&refusal))?;
        let flows: Vec<Value> = entries.iter().map(admin_entry_json).collect();
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: json!({ "flows": flows }),
            audit: json!({ "op": OP_FLOWS_LIST, "count": flows.len() }),
        })
    }

    /// One flow, text and all, for the YAML editor.
    fn flows_get(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let id = required_str(args, "id", OP_FLOWS_GET)?;
        let entry = self.flows.entry(id).map_err(|refusal| refuse(&refusal))?;
        let mut body = self
            .flows
            .show(id)
            .map_err(|refusal| refuse(&refusal))?
            .body
            .as_object()
            .cloned()
            .unwrap_or_default();
        body.insert(
            "path".to_owned(),
            json!(entry.path.as_ref().map(|path| path.display().to_string())),
        );
        body.insert(
            "flow".to_owned(),
            entry
                .parsed
                .as_ref()
                .ok()
                .and_then(|flow| serde_json::to_value(flow).ok())
                .unwrap_or(Value::Null),
        );
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: Value::Object(body),
            audit: json!({ "op": OP_FLOWS_GET, "id": id, "source": entry.source.as_str() }),
        })
    }

    /// Renders one flow canonically, or names the first rule it breaks.
    /// Needs no library: the flow exists only in the request.
    fn flows_normalize(args: &Value) -> Result<AdminOk, AdminRefusal> {
        let yaml = args.get("yaml").and_then(Value::as_str);
        let flow = args.get("flow").filter(|value| value.is_object());
        let parsed = match (yaml, flow) {
            (Some(text), None) => pam_flow::parse(text),
            (None, Some(raw)) => pam_flow::parse_value(raw),
            _ => {
                return Err(AdminRefusal {
                    cause: CAUSE_INVALID_ADMIN_ARGS,
                    detail: format!(
                        "{OP_FLOWS_NORMALIZE} takes exactly one of `yaml` (text) or `flow` (object)"
                    ),
                    recovery: RECOVERY_FLOW_EDIT,
                });
            }
        };
        // The audit row records what the GUI sent, in either spelling:
        // the YAML text's length, or the object's serialized length.
        let bytes = match (yaml, flow) {
            (Some(text), _) => text.len(),
            (None, Some(raw)) => raw.to_string().len(),
            (None, None) => 0,
        };
        let valid = parsed.is_ok();
        let body = match parsed {
            Ok(flow) => json!({
                "valid": true,
                "yaml": pam_flow::to_normalized_yaml(&flow),
                "flow": flow,
                "digest": pam_flow::digest(&flow),
            }),
            Err(error) => {
                let (path, message) = match &error {
                    FlowError::Invalid { path, message } => (path.clone(), message.clone()),
                    other => ("yaml".to_owned(), other.to_string()),
                };
                json!({ "valid": false, "error": { "path": path, "message": message } })
            }
        };
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body,
            audit: json!({ "op": OP_FLOWS_NORMALIZE, "valid": valid, "bytes": bytes }),
        })
    }

    /// Validates and writes one library file, shadowing a builtin of the
    /// same id. Grants of the steps the save changes are revoked first (see
    /// the module docs): were the write to land and the revocation fail, the
    /// edited step would run on its old approval.
    async fn flows_save(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let id = required_str(args, "id", OP_FLOWS_SAVE)?;
        let yaml = required_str(args, "yaml", OP_FLOWS_SAVE)?;
        let create_only = save_flag(args, "create_only")?;
        let allow_builtin_override = save_flag(args, "allow_builtin_override")?;
        if allow_builtin_override && !create_only {
            return Err(AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: "allow_builtin_override requires create_only".into(),
                recovery: RECOVERY_FIX_ARGS,
            });
        }
        let library = self.flows.library();
        // What the id answers to right now: the library file, or the builtin
        // this save would shadow. An unreadable or invalid one keeps no grant.
        let previous = library.get(id).ok().flatten();
        let previous_flow = previous
            .as_ref()
            .and_then(|entry| entry.parsed.as_ref().ok());
        // A save the library is certain to refuse changes nothing, so it must
        // not cost the existing flow its approvals either.
        let candidate = pam_flow::parse(yaml).ok().filter(|flow| flow.id == id);
        let collides = create_only
            && previous
                .as_ref()
                .is_some_and(|entry| entry.source == Source::Library || !allow_builtin_override);
        let revoked = match &candidate {
            Some(flow) if !collides => {
                self.revoke_step_grants(id, previous_flow, Some(flow))
                    .await?
            }
            _ => Vec::new(),
        };
        let entry = if create_only {
            library.create(id, yaml, allow_builtin_override)
        } else {
            library.save(id, yaml)
        }
        .map_err(|error| {
            let mut refusal = save_refusal(id, &error);
            note_revoked(&mut refusal.detail, &revoked);
            refusal
        })?;
        let mut body = admin_entry_json(&entry);
        let object = body.as_object_mut().expect("the entry is a JSON object");
        object.insert(GRANTS_REVOKED.to_owned(), json!(revoked));
        object.insert(REAPPROVAL_REQUIRED.to_owned(), json!(!revoked.is_empty()));
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body,
            audit: json!({
                "op": OP_FLOWS_SAVE,
                "id": id,
                "bytes": yaml.len(),
                "digest": entry.parsed.as_ref().map(pam_flow::digest).unwrap_or_default(),
                "previous_digest": previous_flow.map(pam_flow::digest),
                GRANTS_REVOKED: revoked,
            }),
        })
    }

    /// Removes one library file. Deleting a shadow reveals the builtin
    /// again, which is why a starter flow can never be lost. The revealed
    /// builtin (or nothing at all) is what the id answers to afterwards, so
    /// the grants of every step that differs from it are revoked first.
    async fn flows_delete(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let id = required_str(args, "id", OP_FLOWS_DELETE)?;
        let library = self.flows.library();
        let previous = library
            .get(id)
            .ok()
            .flatten()
            .filter(|entry| entry.source == Source::Library);
        let revoked = match &previous {
            // No library file: the delete below refuses and nothing changes.
            None => Vec::new(),
            Some(entry) => {
                let revealed =
                    pam_flow::builtin_yaml(id).and_then(|yaml| pam_flow::parse(yaml).ok());
                self.revoke_step_grants(id, entry.parsed.as_ref().ok(), revealed.as_ref())
                    .await?
            }
        };
        let revealed = library.delete(id).map_err(|_| {
            let mut detail = format!("no library flow named {id:?} exists to delete");
            note_revoked(&mut detail, &revoked);
            AdminRefusal {
                cause: CAUSE_NOT_FOUND,
                detail,
                recovery: RECOVERY_DELETE,
            }
        })?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({
                "id": id,
                "revealed_builtin": revealed,
                GRANTS_REVOKED: revoked,
                REAPPROVAL_REQUIRED: !revoked.is_empty(),
            }),
            audit: json!({
                "op": OP_FLOWS_DELETE,
                "id": id,
                "revealed_builtin": revealed,
                GRANTS_REVOKED: revoked,
            }),
        })
    }

    /// Revokes every active `flow.step:<id>/…` grant whose step is not
    /// exactly what it was: changed, removed, or never part of `previous` at
    /// all (a grant left behind by an earlier flow of the same id). Returns
    /// the revoked capabilities, sorted.
    async fn revoke_step_grants(
        &self,
        id: &str,
        previous: Option<&Flow>,
        next: Option<&Flow>,
    ) -> Result<Vec<String>, AdminRefusal> {
        let unchanged = unchanged_steps(previous, next);
        let prefix = format!("{STEP_CAPABILITY_PREFIX}{id}/");
        let mut revoked = Vec::new();
        for grant in self.store.list_grants().await? {
            let Some(step) = grant.capability.strip_prefix(&prefix) else {
                continue;
            };
            if grant.revoked_ts.is_some()
                || unchanged.contains(step)
                || revoked.contains(&grant.capability)
            {
                continue;
            }
            match self.store.revoke_grant(&grant.capability).await {
                Ok(()) => revoked.push(grant.capability),
                // Revoked by someone else since the listing: already what we want.
                Err(StoreError::NotFound { .. }) => {}
                Err(error) => return Err(error.into()),
            }
        }
        revoked.sort();
        Ok(revoked)
    }

    /// Submits a real `flow.run` through the pipeline ingress and
    /// forwards its answer (see the module docs).
    async fn flows_run(&self, args: &Value) -> Result<AdminOk, OwnedRefusal> {
        let id = required_str(args, "id", OP_FLOWS_RUN)?;
        let repo = required_str(args, "repo", OP_FLOWS_RUN)?;
        let inputs = args.get("inputs").cloned().unwrap_or_else(|| json!({}));
        if !inputs.is_object() {
            return Err(AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: format!("{OP_FLOWS_RUN} needs \"inputs\" to be an object of name → value"),
                recovery: RECOVERY_FIX_ARGS,
            }
            .into());
        }

        // The digest the human was shown, when the GUI pins the run to it;
        // `flow.run` validates the shape and refuses a flow edited since.
        let mut run_args = json!({ "id": id, "inputs": inputs });
        if let Some(digest) = args.get("expected_digest").filter(|value| !value.is_null()) {
            run_args["expected_digest"] = digest.clone();
        }

        let request_id = format!("req_{}", ulid::Ulid::new());
        let envelope = Envelope {
            v: PROTOCOL_VERSION,
            id: request_id.clone(),
            capability: CAP_FLOW_RUN.to_owned(),
            client_version: DAEMON_VERSION.to_owned(),
            caller: Caller {
                agent: ADMIN_CALLER_AGENT.to_owned(),
                repo: repo.to_owned(),
                pid: std::process::id(),
            },
            args: run_args,
            idempotency_key: None,
            deadline_ms: FLOW_RUN_DEADLINE_MS,
            // The GUI follows the ticket's events; a waiting admin op
            // would sit on the admin deadline for half an hour.
            wait: false,
        };
        let (reply, answer) = oneshot::channel();
        self.submit
            .send(IncomingRequest {
                // No zmq peer: this envelope never came off a socket, and
                // the reply goes back through the channel, not the router.
                identity: Vec::new(),
                origin: crate::ingress::Origin::Admin,
                envelope,
                reply,
            })
            .await
            .map_err(|_| submit_failed())?;

        match answer.await {
            Ok(Response::Ticket {
                ticket, position, ..
            }) => Ok(AdminOk {
                outcome: Outcome::Changed,
                body: json!({ "ticket": ticket, "position": position }),
                audit: json!({ "op": OP_FLOWS_RUN, "id": id, "repo": repo, "ticket": ticket }),
            }),
            // A gate refusal reaches the human verbatim; flattening it
            // would cost the GUI the actual reason and the recovery line.
            Ok(Response::Refusal {
                cause,
                detail,
                recovery,
                ..
            }) => Err(OwnedRefusal {
                cause,
                detail,
                recovery,
            }),
            Ok(Response::Result { .. }) | Err(_) => Err(submit_failed()),
        }
    }

    /// Submits a genuine `flow.inspect` request for the GUI and waits for
    /// its body, so the run overview shows the same readiness and blockers
    /// an agent's `pam flow inspect` would.
    async fn flows_inspect(&self, args: &Value) -> Result<AdminOk, OwnedRefusal> {
        let id = required_str(args, "id", OP_FLOWS_INSPECT)?;
        let repo = required_str(args, "repo", OP_FLOWS_INSPECT)?;
        let inputs = args.get("inputs").cloned().unwrap_or_else(|| json!({}));
        if !inputs.is_object() {
            return Err(AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: format!(
                    "{OP_FLOWS_INSPECT} needs \"inputs\" to be an object of name → value"
                ),
                recovery: RECOVERY_FIX_ARGS,
            }
            .into());
        }
        let request_id = format!("req_{}", ulid::Ulid::new());
        let envelope = Envelope {
            v: PROTOCOL_VERSION,
            id: request_id,
            capability: CAP_FLOW_INSPECT.to_owned(),
            client_version: DAEMON_VERSION.to_owned(),
            caller: Caller {
                agent: ADMIN_CALLER_AGENT.to_owned(),
                repo: repo.to_owned(),
                pid: std::process::id(),
            },
            args: json!({ "id": id, "inputs": inputs }),
            idempotency_key: None,
            deadline_ms: FLOW_INSPECT_DEADLINE_MS,
            wait: true,
        };
        let (reply, answer) = oneshot::channel();
        self.submit
            .send(IncomingRequest {
                identity: Vec::new(),
                origin: crate::ingress::Origin::Admin,
                envelope,
                reply,
            })
            .await
            .map_err(|_| submit_failed())?;
        match answer.await {
            Ok(Response::Result { body, .. }) => Ok(AdminOk {
                outcome: Outcome::Verified,
                body,
                audit: json!({ "op": OP_FLOWS_INSPECT, "id": id, "repo": repo }),
            }),
            Ok(Response::Refusal {
                cause,
                detail,
                recovery,
                ..
            }) => Err(OwnedRefusal {
                cause,
                detail,
                recovery,
            }),
            Ok(Response::Ticket { .. }) | Err(_) => Err(submit_failed()),
        }
    }

    /// The flow settings, as the Settings › Flows panel edits them.
    async fn flows_settings_get(&self) -> Result<AdminOk, AdminRefusal> {
        let settings = self.flows.settings().await?;
        let scope_policy = self
            .flows
            .scope_policy()
            .await
            .map_err(|error| refuse(&error))?;
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: json!({
                "allowed_programs": settings.allowed_programs,
                "extra_path": settings.extra_path,
                "artifacts_root": settings.artifacts_root,
                "read_cache_roots": settings.read_cache_roots,
                "scope_policy": scope_policy,
            }),
            audit: json!({ "op": OP_FLOWS_SETTINGS_GET }),
        })
    }

    /// Replaces the named settings, refusing a shell in the allowlist.
    ///
    /// Everything refusable about the arguments — the scope policy's shape
    /// and its repository paths, the settings' own checks — is validated
    /// before the first write, so an argument refusal leaves both settings
    /// untouched. The two are still separate settings rows: if the scope
    /// write itself fails after the settings landed, the refusal says so.
    async fn flows_settings_set(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let scope_policy = match args.get("scope_policy") {
            None => None,
            Some(value) => {
                let policy =
                    serde_json::from_value::<ScopePolicy>(value.clone()).map_err(|_| {
                        AdminRefusal {
                            cause: CAUSE_SCOPE_INVALID,
                            detail: "scope_policy must be a versioned policy object".to_owned(),
                            recovery: RECOVERY_SCOPE,
                        }
                    })?;
                Some(
                    policy
                        .normalize_blocking()
                        .await
                        .map_err(|error| AdminRefusal {
                            cause: error.cause(),
                            detail: error.to_string(),
                            recovery: RECOVERY_SCOPE,
                        })?,
                )
            }
        };
        let patch = SettingsPatch {
            allowed_programs: string_list(args, "allowed_programs", OP_FLOWS_SETTINGS_SET)?,
            extra_path: string_list(args, "extra_path", OP_FLOWS_SETTINGS_SET)?,
            artifacts_root: optional_string(args, "artifacts_root", OP_FLOWS_SETTINGS_SET)?,
            read_cache_roots: string_list(args, "read_cache_roots", OP_FLOWS_SETTINGS_SET)?,
        };
        let settings = self
            .flows
            .set_settings(patch)
            .await
            .map_err(|refusal| refuse(&refusal))?;
        let scope_policy = match scope_policy {
            Some(policy) => self.flows.set_scope_policy(policy).await.map_err(|error| {
                let mut refusal = refuse(&error);
                refusal.detail = format!(
                    "{}; the other flow settings in this request were already applied and stand",
                    refusal.detail
                );
                refusal
            }),
            None => self
                .flows
                .scope_policy()
                .await
                .map_err(|error| refuse(&error)),
        }?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({
                "allowed_programs": settings.allowed_programs,
                "extra_path": settings.extra_path,
                "artifacts_root": settings.artifacts_root,
                "read_cache_roots": settings.read_cache_roots,
                "scope_policy": scope_policy,
            }),
            audit: json!({
                "op": OP_FLOWS_SETTINGS_SET,
                "allowed_programs": settings.allowed_programs.len(),
                "extra_path": settings.extra_path.len(),
                "artifacts_root": settings.artifacts_root.is_some(),
                "read_cache_roots": settings.read_cache_roots.len(),
                "approved_repositories": scope_policy.repositories.len(),
            }),
        })
    }
}

/// The ids of the steps that are, in `next`, exactly what a human approved in
/// `previous`. Everything that decides what a step does counts — its action,
/// effect, condition, dependencies, environment, timeout, retry — and so does
/// the default of every input it reads, since a default is part of the
/// command line the approval covered. Only the `note` is free to change.
fn unchanged_steps(previous: Option<&Flow>, next: Option<&Flow>) -> BTreeSet<String> {
    let (Some(previous), Some(next)) = (previous, next) else {
        return BTreeSet::new();
    };
    next.steps
        .iter()
        .filter(|step| {
            previous
                .steps
                .iter()
                .find(|earlier| earlier.id == step.id)
                .is_some_and(|earlier| {
                    effective_step(previous, earlier) == effective_step(next, step)
                })
        })
        .map(|step| step.id.clone())
        .collect()
}

/// What an approval of `step` covered: the step without its note, and the
/// defaults of the inputs it reads.
fn effective_step(flow: &Flow, step: &Step) -> (Step, BTreeMap<String, Option<String>>) {
    let mut texts: Vec<&str> = step.env.values().map(String::as_str).collect();
    match &step.action {
        Action::Landing { .. } => {}
        Action::Command { argv } => texts.extend(argv.iter().map(String::as_str)),
        Action::Connector { with, .. } => {
            texts.extend(with.values().filter_map(|value| match value {
                ArgValue::Text(text) => Some(text.as_str()),
                ArgValue::Int(_) => None,
            }));
        }
    }
    let defaults = texts
        .into_iter()
        .flat_map(pam_flow::references)
        .filter_map(|key| key.strip_prefix("inputs.").map(str::to_owned))
        .map(|name| {
            let default = flow
                .inputs
                .get(&name)
                .and_then(|input| input.default.clone());
            (name, default)
        })
        .collect();
    let mut step = step.clone();
    step.note.clear();
    (step, defaults)
}

/// Says in a refusal that approvals were already revoked: the revocation
/// precedes the write, and a write that then fails must not hide it.
fn note_revoked(detail: &mut String, revoked: &[String]) {
    if !revoked.is_empty() {
        let _ = write!(
            detail,
            "; {} remembered step approval(s) were already revoked and will be asked for again: {}",
            revoked.len(),
            revoked.join(", ")
        );
    }
}

/// One flow list entry with the GUI's extra fields (path, digest).
fn admin_entry_json(entry: &Entry) -> Value {
    let mut value = match &entry.parsed {
        Ok(flow) => json!({
            "id": entry.id,
            "name": flow.name,
            "description": flow.description,
            "valid": true,
            "steps": flow.steps.len(),
            "inputs": flow.inputs.iter().map(|(name, input)| json!({
                "name": name,
                "description": input.description,
                "default": input.default,
            })).collect::<Vec<Value>>(),
            "digest": pam_flow::digest(flow),
        }),
        Err(error) => json!({
            "id": entry.id,
            "name": entry.id,
            "description": "",
            "valid": false,
            "error": error.to_string(),
            "steps": 0,
            "inputs": Vec::<Value>::new(),
            "digest": "",
        }),
    };
    let object = value.as_object_mut().expect("the entry is a JSON object");
    object.insert(
        "source".to_owned(),
        json!(match entry.source {
            Source::Builtin => "builtin",
            Source::Library => "library",
        }),
    );
    object.insert(
        "path".to_owned(),
        json!(entry.path.as_ref().map(|path| path.display().to_string())),
    );
    value
}

/// Turns a flow-engine refusal into an admin refusal, keeping the cause
/// (which is already a `'static` constant) and the recovery line.
fn refuse(refusal: &FlowRefusal) -> AdminRefusal {
    AdminRefusal {
        cause: refusal.cause,
        // `FlowRefusal::recovery` is owned because a run builds some of
        // them per step; the admin surface's are all constants, so the
        // detail carries the line and the recovery names the screen.
        detail: format!("{} ({})", refusal.detail, refusal.recovery),
        recovery: RECOVERY_FLOW_EDIT,
    }
}

/// The refusal a failed save produces: a validation message names its
/// YAML path, an id clash is its own cause, and an IO error is the
/// library being unwritable.
fn save_refusal(id: &str, error: &FlowError) -> AdminRefusal {
    match error {
        FlowError::Invalid { path, message } if path == "id" => AdminRefusal {
            cause: CAUSE_ID_MISMATCH,
            detail: format!("saving {id:?}: {message}"),
            recovery: RECOVERY_FLOW_EDIT,
        },
        FlowError::Invalid { .. } | FlowError::TooLarge { .. } => AdminRefusal {
            cause: CAUSE_FLOW_INVALID,
            detail: format!("saving {id:?}: {error}"),
            recovery: RECOVERY_FLOW_EDIT,
        },
        FlowError::Io(detail) => AdminRefusal {
            cause: CAUSE_LIBRARY_UNWRITABLE,
            detail: format!("saving {id:?}: {detail}"),
            recovery: RECOVERY_UNWRITABLE,
        },
    }
}

/// The refusal for a run the pipeline never took or never answered.
fn submit_failed() -> OwnedRefusal {
    OwnedRefusal {
        cause: CAUSE_SUBMIT_FAILED.to_owned(),
        detail: "the daemon could not submit the flow run to its own pipeline".to_owned(),
        recovery: RECOVERY_INTERNAL.to_owned(),
    }
}

/// Reads an optional array-of-strings argument.
fn string_list(args: &Value, key: &str, op: &str) -> Result<Option<Vec<String>>, AdminRefusal> {
    let malformed = || AdminRefusal {
        cause: CAUSE_INVALID_ADMIN_ARGS,
        detail: format!("{op} needs {key:?} to be an array of strings"),
        recovery: RECOVERY_FIX_ARGS,
    };
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| value.as_str().map(str::to_owned).ok_or_else(malformed))
            .collect::<Result<Vec<String>, AdminRefusal>>()
            .map(Some),
        Some(_) => Err(malformed()),
    }
}

/// The build output directory argument: absent leaves it alone, `null`
/// clears it, a string sets it, anything else is malformed.
fn optional_string(args: &Value, key: &str, op: &str) -> Result<ArtifactsRootPatch, AdminRefusal> {
    match args.get(key) {
        None => Ok(ArtifactsRootPatch::Keep),
        Some(Value::Null) => Ok(ArtifactsRootPatch::Clear),
        Some(Value::String(value)) => Ok(ArtifactsRootPatch::Set(value.clone())),
        Some(_) => Err(AdminRefusal {
            cause: CAUSE_INVALID_ADMIN_ARGS,
            detail: format!("{op} needs {key:?} to be a string or null"),
            recovery: RECOVERY_FIX_ARGS,
        }),
    }
}

fn save_flag(args: &Value, key: &str) -> Result<bool, AdminRefusal> {
    match args.get(key) {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(AdminRefusal {
            cause: CAUSE_INVALID_ADMIN_ARGS,
            detail: format!("{OP_FLOWS_SAVE} needs {key} to be a boolean"),
            recovery: RECOVERY_FIX_ARGS,
        }),
    }
}
