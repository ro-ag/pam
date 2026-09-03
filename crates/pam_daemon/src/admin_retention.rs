//! The retention half of the admin surface: `admin.retention.get`,
//! `.set`, and `.prune`.
//!
//! These are ordinary admin ops — read [`crate::admin`]'s module docs for
//! the security model, because every word of it applies here: the GUI
//! tripwire, the request row, the single terminal audit row, the 30 s
//! deadline, and the structural guard (no [`crate::policy::classify`]
//! entry, never a capability, never grantable).
//!
//! # Why deleting history is GUI-only
//!
//! Everything else the admin surface does can be undone by doing it
//! again. Pruning cannot: the evidence and the audit rows are gone, and
//! nothing in pam can bring them back. That makes choosing the windows —
//! and pressing Prune now — the most human act the daemon has, and it
//! belongs behind the same door as editing a flow. An agent can never
//! reach it: `admin.*` is refused structurally on the request path.
//!
//! # A save prunes at once
//!
//! [`OP_RETENTION_SET`] runs a pass as soon as the windows are stored, so
//! the panel's answer already carries the figures for what the new
//! setting removed. The alternative — telling the human the window
//! changed and letting the hourly tick do the work — leaves the screen
//! saying one thing and the database another for up to an hour.
//!
//! The service itself, the windows, the validation rule and the schedule
//! live in [`crate::retention`]; this module is only the door.

use pam_proto::Outcome;
use serde_json::{Value, json};

use crate::admin::{
    AdminOk, AdminRefusal, AdminService, CAUSE_INVALID_ADMIN_ARGS, RECOVERY_FIX_ARGS,
    RECOVERY_INTERNAL,
};
use crate::daemon::CAUSE_INTERNAL_ERROR;
use crate::retention::{
    CAUSE_RETENTION_INVALID, PruneReport, RECOVERY_RETENTION_INVALID, RetentionPatch,
    RetentionRefusal, RetentionService, RetentionSettings, now_ts,
};

/// `admin.retention.get` → `{ evidence_days, audit_days, last_run }`.
pub const OP_RETENTION_GET: &str = "admin.retention.get";

/// `admin.retention.set { evidence_days?, audit_days? }` → the same
/// shape, after an immediate prune. Each field is a number of days or
/// `null` for forever; an absent field leaves that window alone.
pub const OP_RETENTION_SET: &str = "admin.retention.set";

/// `admin.retention.prune` → the [`PruneReport`] of a pass run now.
pub const OP_RETENTION_PRUNE: &str = "admin.retention.prune";

/// Every op this module answers — the GUI bridge's whitelist reads it so
/// the two can never drift.
pub const RETENTION_ADMIN_OPS: &[&str] = &[OP_RETENTION_GET, OP_RETENTION_SET, OP_RETENTION_PRUNE];

impl AdminService {
    /// Answers one `admin.retention.*` op, or `None` when the capability
    /// belongs to another part of the admin surface.
    pub(crate) async fn dispatch_retention(
        &self,
        op: &str,
        args: &Value,
    ) -> Option<Result<AdminOk, AdminRefusal>> {
        Some(match op {
            OP_RETENTION_GET => self.retention_get().await,
            OP_RETENTION_SET => self.retention_set(args).await,
            OP_RETENTION_PRUNE => self.retention_prune().await,
            _ => return None,
        })
    }

    /// The retention service for this call. Building one is an
    /// `Arc` clone, so the daemon carries no field for it.
    fn retention(&self) -> RetentionService {
        RetentionService::new(std::sync::Arc::clone(&self.store))
    }

    /// Both windows and the last pass's figures, as the panel opens.
    async fn retention_get(&self) -> Result<AdminOk, AdminRefusal> {
        let retention = self.retention();
        let settings = retention.settings().await?;
        let last_run = retention.last_run().await?;
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: state_body(settings, last_run)?,
            audit: audit_detail(OP_RETENTION_GET, settings),
        })
    }

    /// Stores the named windows, then prunes at once (see the module
    /// docs) and answers with the fresh figures.
    async fn retention_set(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
        // `RetentionPatch` spells a window's three states as nested
        // options, the same shape `admin.connectors.configure` uses.
        let as_patch = |change| match change {
            WindowChange::Keep => None,
            WindowChange::Forever => Some(None),
            WindowChange::Days(days) => Some(Some(days)),
        };
        let patch = RetentionPatch {
            evidence_days: as_patch(optional_window(args, "evidence_days")?),
            audit_days: as_patch(optional_window(args, "audit_days")?),
        };
        let retention = self.retention();
        let settings = retention.set_settings(patch).await.map_err(refuse)?;
        let last_run = retention.prune(now_ts()).await?;
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: state_body(settings, Some(last_run))?,
            audit: audit_detail(OP_RETENTION_SET, settings),
        })
    }

    /// One pass now: the GUI's Prune now button.
    ///
    /// A pass that removed nothing is [`Outcome::Verified`], not
    /// [`Outcome::Changed`] — the store is exactly as it was, and the
    /// outcome should not claim otherwise.
    async fn retention_prune(&self) -> Result<AdminOk, AdminRefusal> {
        let report = self.retention().prune(now_ts()).await?;
        let changed = report.evidence_rows > 0 || report.requests > 0;
        Ok(AdminOk {
            outcome: if changed {
                Outcome::Changed
            } else {
                Outcome::Verified
            },
            body: report_body(report)?,
            audit: json!({
                "op": OP_RETENTION_PRUNE,
                "evidence_rows": report.evidence_rows,
                "evidence_bytes": report.evidence_bytes,
                "requests": report.requests,
                "audit_rows": report.audit_rows,
            }),
        })
    }
}

/// What a window argument asks of the setting it names.
enum WindowChange {
    /// The key was absent: leave the stored window alone.
    Keep,
    /// The key was `null`: keep this kind of row forever.
    Forever,
    /// The key carried a whole number of days: store it.
    Days(u32),
}

/// Reads one window argument, where an explicit `null` is the human
/// choosing forever and an absent key leaves the window alone.
fn optional_window(args: &Value, key: &str) -> Result<WindowChange, AdminRefusal> {
    match args.get(key) {
        None => Ok(WindowChange::Keep),
        Some(Value::Null) => Ok(WindowChange::Forever),
        Some(value) => value
            .as_u64()
            .and_then(|days| u32::try_from(days).ok())
            .map(WindowChange::Days)
            .ok_or_else(|| AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: format!("{OP_RETENTION_SET}: {key} must be a whole number of days or null"),
                recovery: RECOVERY_FIX_ARGS,
            }),
    }
}

/// The body `get` and `set` share.
fn state_body(
    settings: RetentionSettings,
    last_run: Option<PruneReport>,
) -> Result<Value, AdminRefusal> {
    let last_run = match last_run {
        Some(report) => report_body(report)?,
        None => Value::Null,
    };
    Ok(json!({
        "evidence_days": settings.evidence_days,
        "audit_days": settings.audit_days,
        "last_run": last_run,
    }))
}

/// One prune report as JSON.
fn report_body(report: PruneReport) -> Result<Value, AdminRefusal> {
    serde_json::to_value(report).map_err(|error| AdminRefusal {
        cause: CAUSE_INTERNAL_ERROR,
        detail: format!("the prune report could not be rendered: {error}"),
        recovery: RECOVERY_INTERNAL,
    })
}

/// The audit detail a settings op leaves: the windows, never a body.
fn audit_detail(op: &str, settings: RetentionSettings) -> Value {
    json!({
        "op": op,
        "evidence_days": settings.evidence_days,
        "audit_days": settings.audit_days,
    })
}

/// Turns a retention refusal into an admin one, keeping the rule's own
/// recovery line for the violation the human can act on.
fn refuse(refusal: RetentionRefusal) -> AdminRefusal {
    match refusal {
        RetentionRefusal::Invalid { detail } => AdminRefusal {
            cause: CAUSE_RETENTION_INVALID,
            detail,
            recovery: RECOVERY_RETENTION_INVALID,
        },
        RetentionRefusal::Store(detail) => AdminRefusal {
            cause: CAUSE_INTERNAL_ERROR,
            detail,
            recovery: RECOVERY_INTERNAL,
        },
    }
}
