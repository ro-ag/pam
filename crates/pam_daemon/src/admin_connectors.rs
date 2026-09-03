//! The connector half of the admin surface: `admin.connectors.list`,
//! `.configure`, and `.test`.
//!
//! These are ordinary admin ops — read [`crate::admin`]'s module docs for
//! the security model, because every word of it applies here: the GUI
//! tripwire, the request row, the single terminal audit row, the deadline,
//! and the structural guard (no [`crate::policy::classify`] entry, never a
//! capability, never grantable).
//!
//! # Why connectors are GUI-only
//!
//! Configuring a connector means handing pam a credential and pointing it
//! at a service. An agent that could do that could grant itself reach it
//! does not have — so it cannot, by construction: no `pam` subcommand
//! builds one of these envelopes, and an envelope that arrives from any
//! caller but the GUI trips the wire and is audited as
//! [`crate::admin::ACTION_ADMIN_DENIED`]. What an agent *can* do is run a
//! flow step whose connector a human already enabled, which goes through
//! [`crate::connector_service::ConnectorService::invoke`] and the policy
//! gate, never through this file.
//!
//! # Bridge deadlines
//!
//! [`OP_CONNECTORS_TEST`] talks to a remote service under a ten second
//! deadline ([`CONNECTOR_TEST_DEADLINE`]), so the GUI bridge allows it 15 s
//! and the other two ops the usual 30 s.
//!
//! # The secret is never in the bookkeeping
//!
//! [`OP_CONNECTORS_CONFIGURE`] writes exactly one
//! [`ACTION_CONNECTOR_CONFIGURE`] audit row, whose detail says *that* a
//! credential was set, cleared, or left alone — never the credential. The
//! envelope's own args are the GUI's business: it sends the secret once,
//! over the same unix socket, and the daemon puts it straight into the OS
//! keychain.

use pam_connectors::{ConnectorId, descriptor};
use pam_proto::Outcome;
use pam_store::{Actor, Decision};
use serde_json::{Value, json};

use crate::admin::{
    AdminOk, AdminRefusal, AdminService, CAUSE_INVALID_ADMIN_ARGS, RECOVERY_FIX_ARGS,
};
use crate::connector_service::{
    CONNECTOR_TEST_DEADLINE, ConfigurePatch, ConnectorSummary, CredentialAction, InvokeError,
};

/// `admin.connectors.list` → every connector, merged with its row.
pub const OP_CONNECTORS_LIST: &str = "admin.connectors.list";

/// `admin.connectors.configure { id, enabled?, base_url?, username?,
/// credential? }` → the connector's entry.
pub const OP_CONNECTORS_CONFIGURE: &str = "admin.connectors.configure";

/// `admin.connectors.test { id }` → `{ status, detail, ts }`.
pub const OP_CONNECTORS_TEST: &str = "admin.connectors.test";

/// Every op this module answers — the GUI bridge's whitelist reads it so
/// the two can never drift.
pub const CONNECTOR_ADMIN_OPS: &[&str] = &[
    OP_CONNECTORS_LIST,
    OP_CONNECTORS_CONFIGURE,
    OP_CONNECTORS_TEST,
];

/// `audit.action` recording a connector's configuration change.
///
/// Written in addition to the op's own terminal [`crate::admin::ACTION_ADMIN`]
/// row (it is not a terminal action), so the trail shows *what* changed
/// about a connector, not merely that an admin op ran.
pub const ACTION_CONNECTOR_CONFIGURE: &str = "connector.configure";

impl AdminService {
    /// Answers one `admin.connectors.*` op, or `None` when the capability
    /// belongs to another part of the admin surface.
    ///
    /// `envelope_id` is the admin request's own id: the
    /// [`ACTION_CONNECTOR_CONFIGURE`] row hangs off it, which puts the
    /// change on the request the GUI's Activity screen is already showing.
    pub(crate) async fn dispatch_connectors(
        &self,
        envelope_id: &str,
        op: &str,
        args: &Value,
    ) -> Option<Result<AdminOk, AdminRefusal>> {
        Some(match op {
            OP_CONNECTORS_LIST => self.connectors_list().await,
            OP_CONNECTORS_CONFIGURE => self.connectors_configure(envelope_id, args).await,
            OP_CONNECTORS_TEST => self.connectors_test(args).await,
            _ => return None,
        })
    }

    /// Every connector, in the order the GUI lists them.
    async fn connectors_list(&self) -> Result<AdminOk, AdminRefusal> {
        let connectors = self.connectors.list().await?;
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: json!({ "connectors": connectors }),
            audit: json!({ "op": OP_CONNECTORS_LIST, "count": connectors.len() }),
        })
    }

    /// Saves one connector's configuration and records what changed.
    async fn connectors_configure(
        &self,
        envelope_id: &str,
        args: &Value,
    ) -> Result<AdminOk, AdminRefusal> {
        let id = connector_arg(args, OP_CONNECTORS_CONFIGURE)?;
        // `ConfigurePatch` spells a text field's three states as nested
        // options, the same shape `pam_store::ConnectorPatch` uses.
        let as_patch = |change| match change {
            TextChange::Keep => None,
            TextChange::Clear => Some(None),
            TextChange::Set(value) => Some(Some(value)),
        };
        let patch = ConfigurePatch {
            enabled: optional_bool(args, "enabled", OP_CONNECTORS_CONFIGURE)?,
            base_url: as_patch(optional_text(args, "base_url", OP_CONNECTORS_CONFIGURE)?),
            username: as_patch(optional_text(args, "username", OP_CONNECTORS_CONFIGURE)?),
            credential: credential_arg(args, OP_CONNECTORS_CONFIGURE)?,
        };
        let credential = CredentialAction::audit_word(patch.credential.as_ref());
        let summary = self
            .connectors
            .configure(id, patch)
            .await
            .map_err(|error| refuse(id, &error))?;

        let detail = json!({
            "id": summary.id,
            "enabled": summary.enabled,
            "base_url": summary.base_url,
            "username": summary.username,
            "credential": credential,
        })
        .to_string();
        self.store
            .append_audit(
                envelope_id,
                ACTION_CONNECTOR_CONFIGURE,
                Decision::Allow,
                Actor::Human,
                Some(&detail),
            )
            .await?;

        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: summary_json(&summary),
            audit: json!({
                "op": OP_CONNECTORS_CONFIGURE,
                "id": summary.id,
                "credential": credential,
            }),
        })
    }

    /// Proves one connector's credential still works.
    ///
    /// A test that fails is an answer, not a refusal: the verdict lands on
    /// the row and the GUI shows it next to the connector. Only a
    /// connector that could not be *tried* — no credential, no base URL, an
    /// unreachable keychain — refuses.
    async fn connectors_test(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        let id = connector_arg(args, OP_CONNECTORS_TEST)?;
        let (passed, detail) = self
            .connectors
            .test(id)
            .await
            .map_err(|error| refuse(id, &error))?;
        let status = if passed { "passed" } else { "failed" };
        let ts = self
            .connectors
            .get(id)
            .await?
            .last_test
            .map_or(0, |last| last.ts);
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: json!({ "status": status, "detail": detail, "ts": ts }),
            audit: json!({
                "op": OP_CONNECTORS_TEST,
                "id": id.as_str(),
                "status": status,
                "deadline_secs": CONNECTOR_TEST_DEADLINE.as_secs(),
            }),
        })
    }
}

/// One connector entry as the GUI reads it.
fn summary_json(summary: &ConnectorSummary) -> Value {
    serde_json::to_value(summary).expect("a connector summary always serializes")
}

/// Turns a connector-host refusal into an admin refusal, naming the
/// connector a human would recognize.
fn refuse(id: ConnectorId, error: &InvokeError) -> AdminRefusal {
    AdminRefusal {
        cause: error.cause(),
        detail: format!("{}: {}", descriptor(id).name, error.detail()),
        recovery: error.recovery_line(id),
    }
}

/// Reads the required `id` argument as a connector.
fn connector_arg(args: &Value, op: &str) -> Result<ConnectorId, AdminRefusal> {
    let raw = crate::admin::required_str(args, "id", op)?;
    ConnectorId::parse(raw).ok_or_else(|| {
        let known: Vec<&str> = ConnectorId::ALL.iter().map(|id| id.as_str()).collect();
        AdminRefusal {
            cause: CAUSE_INVALID_ADMIN_ARGS,
            detail: format!("{raw:?} is not a connector; pam has {}", known.join(", ")),
            recovery: RECOVERY_FIX_ARGS,
        }
    })
}

/// Reads an optional boolean argument.
fn optional_bool(args: &Value, key: &str, op: &str) -> Result<Option<bool>, AdminRefusal> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(other) => Err(AdminRefusal {
            cause: CAUSE_INVALID_ADMIN_ARGS,
            detail: format!("{op} needs {key:?} to be true or false, not {other}"),
            recovery: RECOVERY_FIX_ARGS,
        }),
    }
}

/// What a text argument asks of the field it names.
enum TextChange {
    /// The key was absent: leave the stored value alone.
    Keep,
    /// The key was `null`: clear the stored value.
    Clear,
    /// The key carried a string: store it.
    Set(String),
}

/// Reads an optional text argument, where an explicit `null` clears the
/// stored value and an absent key leaves it alone.
fn optional_text(args: &Value, key: &str, op: &str) -> Result<TextChange, AdminRefusal> {
    match args.get(key) {
        None => Ok(TextChange::Keep),
        Some(Value::Null) => Ok(TextChange::Clear),
        Some(Value::String(value)) => Ok(TextChange::Set(value.clone())),
        Some(other) => Err(AdminRefusal {
            cause: CAUSE_INVALID_ADMIN_ARGS,
            detail: format!("{op} needs {key:?} to be a string or null, not {other}"),
            recovery: RECOVERY_FIX_ARGS,
        }),
    }
}

/// Reads the optional `credential` argument: `{ "set": "…" }` writes one,
/// `{ "clear": true }` deletes one, and an absent key leaves the stored
/// credential exactly as it is.
fn credential_arg(args: &Value, op: &str) -> Result<Option<CredentialAction>, AdminRefusal> {
    let malformed = || AdminRefusal {
        cause: CAUSE_INVALID_ADMIN_ARGS,
        detail: format!(
            "{op} needs \"credential\" to be {{\"set\": \"<secret>\"}} or {{\"clear\": true}}"
        ),
        recovery: RECOVERY_FIX_ARGS,
    };
    let value = match args.get("credential") {
        None | Some(Value::Null) => return Ok(None),
        Some(value) => value,
    };
    let object = value.as_object().ok_or_else(malformed)?;
    if object.len() != 1 {
        return Err(malformed());
    }
    if let Some(secret) = object.get("set") {
        let secret = secret.as_str().ok_or_else(malformed)?;
        if secret.is_empty() {
            return Err(malformed());
        }
        return Ok(Some(CredentialAction::Set(secret.to_owned())));
    }
    if object.get("clear").and_then(Value::as_bool) == Some(true) {
        return Ok(Some(CredentialAction::Clear));
    }
    Err(malformed())
}
