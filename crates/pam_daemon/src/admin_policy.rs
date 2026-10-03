//! The managed-policy half of the admin surface: `admin.policy.get` and `admin.policy.reload`.
//!
//! Ordinary admin ops — see [`crate::admin`] for the security model: GUI tripwire, request row,
//! single terminal audit row, deadline, structural guard (no [`crate::policy::classify`] entry,
//! never a capability, never grantable). The policy itself is
//! [`crate::managed_policy_service`]'s; this module is the door. Neither op can change what the
//! policy says: the file is the administrator's, and nothing here writes it.
//!
//! [`OP_POLICY_GET`] answers the merged view the Settings › Policy screen draws: whether a policy
//! is in force and in which state, where it is read from and how its trust check went, its digest
//! and labels, when it was loaded and last checked, the last-known-good copy, the per-key table
//! (tier, modes, `applied` / `held` / `rejected`, with the code and sentence of anything not
//! plainly applied), every diagnostic, and the compliance block (`service.require_login_unit`
//! against whether the login unit is installed). It is
//! [`PolicyStatus::admin_json`](crate::managed_policy_service::PolicyStatus::admin_json) plus
//! `origin.trust` and `compliance`.
//!
//! [`OP_POLICY_RELOAD`] re-reads the file now (the GUI's "Check now") and answers the same body.
//! No confirmation phrase: it reads the file the administrator delivered and cannot loosen what
//! the administrator did not. The `policy.load` / `policy.reject` / `policy.clear` rows a changed
//! file causes are written on the op's own request row (their `trigger` is `reload`, the spec's
//! word for an explicit re-read); the terminal `admin` row records `trigger: admin` with the
//! state and digest before and after.

use std::path::Path;

use pam_proto::Outcome;
use serde_json::{Value, json};

use crate::admin::{
    AdminOk, AdminRefusal, AdminService, CAUSE_INVALID_ADMIN_ARGS, RECOVERY_FIX_ARGS,
};
use crate::managed_policy::{PolicyView, TargetPlatform};
use crate::managed_policy_service::{PolicyState, PolicyStatus, Trigger};
use crate::managed_policy_trust::UntrustedReason;

/// `admin.policy.get {}` → the merged policy view (see the module docs).
pub const OP_POLICY_GET: &str = "admin.policy.get";

/// `admin.policy.reload {}` → re-reads the file now; the same body as
/// [`OP_POLICY_GET`].
pub const OP_POLICY_RELOAD: &str = "admin.policy.reload";

/// Every op this module answers; the GUI bridge splices it into its
/// whitelist as `POLICY_ADMIN_OPS`.
pub const POLICY_ADMIN_OPS: &[&str] = &[OP_POLICY_GET, OP_POLICY_RELOAD];

/// The launchd label of PAM's login unit, the one `pam service install`
/// writes (`pam_client::service::LAUNCHD_LABEL`; the GUI bridge's tests keep
/// the two equal, since this crate does not depend on that one).
pub const LOGIN_UNIT_LABEL: &str = "com.github.ro-ag.pam.daemon";

/// The trust facts `origin.trust` reports, each with the trust-check
/// reason that fails it.
const TRUST_FACTS: [(&str, UntrustedReason); 4] = [
    ("owner", UntrustedReason::NotOwnedByRoot),
    ("writable_by_user", UntrustedReason::WritableByUser),
    ("symlink", UntrustedReason::Symlink),
    ("parents", UntrustedReason::ParentWritable),
];

impl AdminService {
    /// Answers one `admin.policy.*` op, or `None` when the capability
    /// belongs to another part of the admin surface. `envelope_id` is the
    /// admin request's own id: a reload's `policy.*` rows hang off it.
    pub(crate) async fn dispatch_policy(
        &self,
        envelope_id: &str,
        op: &str,
        args: &Value,
    ) -> Option<Result<AdminOk, AdminRefusal>> {
        Some(match op {
            OP_POLICY_GET => self.policy_get(args),
            OP_POLICY_RELOAD => self.policy_reload(envelope_id, args).await,
            _ => return None,
        })
    }

    /// The policy as it stands, from memory: no file is read.
    fn policy_get(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        refuse_any_argument(args, OP_POLICY_GET)?;
        let status = self.policy.status();
        let body = policy_body(&status, &self.policy.view(), login_unit_present_here());
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body,
            audit: json!({ "op": OP_POLICY_GET }),
        })
    }

    /// Re-reads the file now, on this request row, and answers the new
    /// view.
    async fn policy_reload(
        &self,
        envelope_id: &str,
        args: &Value,
    ) -> Result<AdminOk, AdminRefusal> {
        refuse_any_argument(args, OP_POLICY_RELOAD)?;
        let before = self.policy.status();
        let status = self
            .policy
            .reload(Trigger::Reload {
                request_id: Some(envelope_id.to_owned()),
            })
            .await;
        let body = policy_body(&status, &self.policy.view(), login_unit_present_here());
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body,
            audit: json!({
                "op": OP_POLICY_RELOAD,
                "trigger": "admin",
                "prior_state": before.state.as_str(),
                "prior_digest": before.digest,
                "state": status.state.as_str(),
                "digest": status.digest,
            }),
        })
    }
}

/// The `admin.policy.get` / `.reload` body: `status.admin_json()` plus
/// `origin.trust` and `compliance`. `login_unit` is whether PAM's login
/// unit is installed, `None` when this daemon cannot tell.
#[must_use]
pub fn policy_body(status: &PolicyStatus, view: &PolicyView, login_unit: Option<bool>) -> Value {
    let mut body = status.admin_json();
    body["origin"]["trust"] = trust_json(status);
    body["compliance"] = json!({
        "login_unit": {
            "required": view.require_login_unit(),
            "present": login_unit,
        },
    });
    body
}

/// How the last read's trust check went. The check stops at the first fact
/// that fails, so a refused file names that fact `failed` and the others
/// `unknown`; a trusted file has every fact `ok`; with no file read (none,
/// or a read that was busy) every fact is `unknown`.
///
/// `verdict`: `trusted` (the bytes passed the check, whether or not they
/// then parsed), `untrusted`, `busy` (a writer was replacing the file), or
/// `absent` (no file, or one that is gone and waits for its confirming
/// check).
#[must_use]
pub fn trust_json(status: &PolicyStatus) -> Value {
    let reason = status.reason_code.and_then(|code| {
        UntrustedReason::ALL
            .into_iter()
            .find(|reason| reason.code() == code)
    });
    let absent = status.absence_pending || status.state == PolicyState::None;
    let verdict = match reason {
        Some(UntrustedReason::Busy) => "busy",
        Some(_) => "untrusted",
        None if absent => "absent",
        None => "trusted",
    };
    let otherwise = if verdict == "trusted" {
        "ok"
    } else {
        "unknown"
    };
    let mut trust = json!({
        "verdict": verdict,
        "code": reason.map(UntrustedReason::code),
        "recovery": reason.map(UntrustedReason::recovery),
    });
    for (name, fails_it) in TRUST_FACTS {
        trust[name] = json!(if reason == Some(fails_it) {
            "failed"
        } else {
            otherwise
        });
    }
    trust
}

/// Whether PAM's login unit is installed for `platform`, looking under
/// `home` (the user's) and the machine-wide location an MDM pushes. macOS:
/// `~/Library/LaunchAgents/<label>.plist` or
/// `/Library/LaunchAgents/<label>.plist`. Windows: `None` — the task is
/// registered with the Task Scheduler, which only `schtasks` can query, and
/// a read-only admin op does not spawn a program; the GUI's own service
/// status answers it there. `None` too when there is no home directory.
#[must_use]
pub fn login_unit_present(
    platform: TargetPlatform,
    home: Option<&Path>,
    machine_root: &Path,
) -> Option<bool> {
    match platform {
        TargetPlatform::Macos => {
            let file = format!("{LOGIN_UNIT_LABEL}.plist");
            let user = home?.join("Library/LaunchAgents").join(&file);
            let machine = machine_root.join("Library/LaunchAgents").join(&file);
            Some(user.is_file() || machine.is_file())
        }
        TargetPlatform::Windows => None,
    }
}

/// [`login_unit_present`] for the machine this daemon runs on.
fn login_unit_present_here() -> Option<bool> {
    login_unit_present(
        TargetPlatform::host(),
        std::env::home_dir().as_deref(),
        Path::new("/"),
    )
}

/// Both ops take no arguments; anything else is refused, so nothing can be
/// smuggled in as a path or a digest.
fn refuse_any_argument(args: &Value, op: &str) -> Result<(), AdminRefusal> {
    match args {
        Value::Null => Ok(()),
        Value::Object(object) => match object.keys().next() {
            None => Ok(()),
            Some(unknown) => Err(AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: format!("{op} takes no arguments, not {unknown:?}"),
                recovery: RECOVERY_FIX_ARGS,
            }),
        },
        other => Err(AdminRefusal {
            cause: CAUSE_INVALID_ADMIN_ARGS,
            detail: format!("{op} takes an empty object of arguments, not {other}"),
            recovery: RECOVERY_FIX_ARGS,
        }),
    }
}
