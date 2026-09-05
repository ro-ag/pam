//! The flow half of the admin surface: `admin.flows.list`, `.get`,
//! `.save`, `.delete`, `.run`, `.normalize`, and the two settings ops.
//!
//! These are ordinary admin ops — read [`crate::admin`]'s module docs for
//! the security model, because every word of it applies here: the GUI
//! tripwire, the request row, the single terminal audit row, the
//! deadline, and the structural guard (no [`crate::policy::classify`]
//! entry, never a capability, never grantable).
//!
//! # Why editing flows is GUI-only, and running them is not
//!
//! A flow file *is* the list of commands pam will run. An agent that
//! could write one could run anything the allowlist permits without ever
//! naming it in a request — so writing flows is a human act, behind this
//! surface. *Running* one is not: `flow.run` is a normal capability an
//! agent names like any other, and every step it takes is gated on its
//! own (see [`crate::flow_service`]).
//!
//! # `admin.flows.run` takes the front door
//!
//! The GUI's Run button does not execute anything here. [`OP_FLOWS_RUN`]
//! builds a genuine `flow.run` envelope — caller agent `pam-gui`, the
//! repo the human picked — and pushes it through the pipeline's own
//! ingress channel, then forwards whatever comes back (a ticket, or the
//! gate's refusal). The run is therefore classified, admitted, deduped,
//! gated, laned and audited exactly as an agent's would be, and the GUI
//! follows its ticket's events like any other subscriber. Nothing about
//! starting a flow from the GUI is privileged; only editing one is.

use pam_flow::{Entry, FlowError, Source};
use pam_proto::{Caller, Envelope, Outcome, PROTOCOL_VERSION, Response};
use serde_json::{Value, json};
use tokio::sync::oneshot;

use crate::admin::{
    ADMIN_CALLER_AGENT, AdminOk, AdminRefusal, AdminService, CAUSE_INVALID_ADMIN_ARGS,
    OwnedRefusal, RECOVERY_FIX_ARGS, RECOVERY_INTERNAL, required_str,
};
use crate::daemon::DAEMON_VERSION;
use crate::flow_service::{
    CAP_FLOW_RUN, CAUSE_FLOW_INVALID, FlowRefusal, RECOVERY_FLOW_EDIT, SettingsPatch,
};
use crate::transport::IncomingRequest;

/// `admin.flows.list` → every flow, builtins and library merged.
pub const OP_FLOWS_LIST: &str = "admin.flows.list";

/// `admin.flows.get { id }` → one flow's text, canonical rendering,
/// digest and parsed shape.
pub const OP_FLOWS_GET: &str = "admin.flows.get";

/// `admin.flows.save { id, yaml }` → the saved flow's list entry.
pub const OP_FLOWS_SAVE: &str = "admin.flows.save";

/// `admin.flows.delete { id }` → `{ id, revealed_builtin }`.
pub const OP_FLOWS_DELETE: &str = "admin.flows.delete";

/// `admin.flows.normalize { yaml } | { flow }` → canonical rendering +
/// validation of a flow that lives only in the GUI: the designer canvas
/// sends its model here after every edit and shows the YAML it gets
/// back. Valid: `{ valid: true, yaml, flow, digest }`; invalid: a normal
/// reply `{ valid: false, error: { path, message } }`, so the canvas
/// keeps drawing. Never touches disk; never a capability.
pub const OP_FLOWS_NORMALIZE: &str = "admin.flows.normalize";

/// `admin.flows.run { id, repo, inputs? }` → `{ ticket, position }`.
pub const OP_FLOWS_RUN: &str = "admin.flows.run";

/// `admin.flows.settings.get` → `{ allowed_programs, extra_path }`.
pub const OP_FLOWS_SETTINGS_GET: &str = "admin.flows.settings.get";

/// `admin.flows.settings.set { allowed_programs?, extra_path? }` → the
/// settings as they now stand.
pub const OP_FLOWS_SETTINGS_SET: &str = "admin.flows.settings.set";

/// Every op this module answers — the GUI bridge's whitelist reads it so
/// the two can never drift.
pub const FLOW_ADMIN_OPS: &[&str] = &[
    OP_FLOWS_LIST,
    OP_FLOWS_GET,
    OP_FLOWS_SAVE,
    OP_FLOWS_NORMALIZE,
    OP_FLOWS_DELETE,
    OP_FLOWS_RUN,
    OP_FLOWS_SETTINGS_GET,
    OP_FLOWS_SETTINGS_SET,
];

/// The deadline an `admin.flows.run` envelope carries: half an hour,
/// because a flow that runs `cargo test` is not a sixty second request.
pub const FLOW_RUN_DEADLINE_MS: u64 = 1_800_000;

/// Refusal cause: the YAML declares a different id than it is saved as.
pub const CAUSE_ID_MISMATCH: &str = "id_mismatch";

/// Refusal cause: the library directory could not be written.
pub const CAUSE_LIBRARY_UNWRITABLE: &str = "library_unwritable";

/// Refusal cause: nothing to delete under that id.
pub const CAUSE_NOT_FOUND: &str = "not_found";

/// Refusal cause: the pipeline never answered the submitted run.
pub const CAUSE_SUBMIT_FAILED: &str = "submit_failed";

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
            OP_FLOWS_LIST => self.flows_list().map_err(OwnedRefusal::from),
            OP_FLOWS_GET => self.flows_get(args).map_err(OwnedRefusal::from),
            OP_FLOWS_SAVE => self.flows_save(args).map_err(OwnedRefusal::from),
            OP_FLOWS_DELETE => self.flows_delete(args).map_err(OwnedRefusal::from),
            OP_FLOWS_NORMALIZE => Self::flows_normalize(args).map_err(OwnedRefusal::from),
            OP_FLOWS_RUN => self.flows_run(args).await,
            OP_FLOWS_SETTINGS_GET => self.flows_settings_get().await.map_err(OwnedRefusal::from),
            OP_FLOWS_SETTINGS_SET => self
                .flows_settings_set(args)
                .await
                .map_err(OwnedRefusal::from),
            _ => return None,
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
        let bytes = yaml.map_or(0, str::len);
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
    /// same id.
    fn flows_save(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
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
        let entry = if create_only {
            library.create(id, yaml, allow_builtin_override)
        } else {
            library.save(id, yaml)
        }
        .map_err(|error| save_refusal(id, &error))?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: admin_entry_json(&entry),
            audit: json!({ "op": OP_FLOWS_SAVE, "id": id, "bytes": yaml.len() }),
        })
    }

    /// Removes one library file. Deleting a shadow reveals the builtin
    /// again, which is why a starter flow can never be lost.
    fn flows_delete(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let id = required_str(args, "id", OP_FLOWS_DELETE)?;
        let revealed = self.flows.library().delete(id).map_err(|_| AdminRefusal {
            cause: CAUSE_NOT_FOUND,
            detail: format!("no library flow named {id:?} exists to delete"),
            recovery: RECOVERY_DELETE,
        })?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({ "id": id, "revealed_builtin": revealed }),
            audit: json!({ "op": OP_FLOWS_DELETE, "id": id, "revealed_builtin": revealed }),
        })
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
            args: json!({ "id": id, "inputs": inputs }),
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

    /// The flow settings, as the Settings › Flows panel edits them.
    async fn flows_settings_get(&self) -> Result<AdminOk, AdminRefusal> {
        let settings = self.flows.settings().await?;
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: json!({
                "allowed_programs": settings.allowed_programs,
                "extra_path": settings.extra_path,
            }),
            audit: json!({ "op": OP_FLOWS_SETTINGS_GET }),
        })
    }

    /// Replaces the named settings, refusing a shell in the allowlist.
    async fn flows_settings_set(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let patch = SettingsPatch {
            allowed_programs: string_list(args, "allowed_programs", OP_FLOWS_SETTINGS_SET)?,
            extra_path: string_list(args, "extra_path", OP_FLOWS_SETTINGS_SET)?,
        };
        let settings = self
            .flows
            .set_settings(patch)
            .await
            .map_err(|refusal| refuse(&refusal))?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: json!({
                "allowed_programs": settings.allowed_programs,
                "extra_path": settings.extra_path,
            }),
            audit: json!({
                "op": OP_FLOWS_SETTINGS_SET,
                "allowed_programs": settings.allowed_programs.len(),
                "extra_path": settings.extra_path.len(),
            }),
        })
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
