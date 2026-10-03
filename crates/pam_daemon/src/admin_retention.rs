//! The retention half of the admin surface: `admin.retention.get`, `.set`, and `.prune`. Ordinary
//! admin ops — see [`crate::admin`] for the security model: GUI tripwire, request row, single
//! terminal audit row, 30 s deadline, structural guard (no [`crate::policy::classify`] entry, never
//! a capability, never grantable; `admin.*` is refused structurally on the request path, so an
//! agent can never reach pruning). Pruning is the one admin act that cannot be undone — the
//! evidence and audit rows are gone for good — which is why it sits behind the same door as editing
//! a flow.
//!
//! [`OP_RETENTION_SET`] prunes at once rather than waiting for the hourly tick, so the panel's
//! answer already carries the figures for what the new window removed instead of leaving the screen
//! and the database disagreeing for up to an hour. The windows, validation rule, and schedule live
//! in [`crate::retention`]; this module is only the door.
//!
//! The windows every reply carries are the ones in force: what the human saved under the managed policy's
//! bounds (see [`crate::retention`]), with an `effective` entry per window saying where it came from and
//! whether the human can change it. [`OP_RETENTION_SET`] refuses a window the policy locks
//! (`setting_locked`) or a value outside its bounds (`policy_not_allowed`, forever included under a
//! ceiling), writes the `policy.locked_write` audit row, and stores nothing.
//!
//! Every reply carries `clock_guard`: `null`, or the notice of a pass the forward-clock-jump guard
//! held back (cause `retention_clock_jump`, with its recovery line). [`OP_RETENTION_PRUNE`] is the
//! human's confirmation and always runs; its audit row says when it overrode the guard.
//! [`OP_RETENTION_SET`] is not: it can be held back like a scheduled pass.

use pam_proto::Outcome;
use serde_json::{Value, json};

use crate::admin::{
    AdminOk, AdminRefusal, AdminService, CAUSE_INVALID_ADMIN_ARGS, RECOVERY_FIX_ARGS,
    RECOVERY_INTERNAL,
};
use crate::daemon::CAUSE_INTERNAL_ERROR;
use crate::managed_policy::EffectiveEntry;
use crate::retention::{
    CAUSE_CLOCK_JUMP, CAUSE_RETENTION_INVALID, ClockGuardNotice, PassOutcome, PruneReport,
    RECOVERY_CLOCK_JUMP, RECOVERY_RETENTION_INVALID, RetentionPatch, RetentionRefusal,
    RetentionService, RetentionSettings, Trigger,
};

/// `admin.retention.get` → `{ evidence_days, audit_days, effective, last_run, clock_guard }`.
/// The windows are the ones in force (the managed policy's bounds applied);
/// `effective` says, per window, where each came from.
pub const OP_RETENTION_GET: &str = "admin.retention.get";

/// `admin.retention.set { evidence_days?, audit_days? }` → the same
/// shape, after an immediate prune. Each field is a number of days or
/// `null` for forever; an absent field leaves that window alone.
pub const OP_RETENTION_SET: &str = "admin.retention.set";

/// `admin.retention.prune` → the [`PruneReport`] of a pass run now, plus
/// `clock_guard_overridden`. Always runs: it is the human's confirmation.
pub const OP_RETENTION_PRUNE: &str = "admin.retention.prune";

/// Every op this module answers — the GUI bridge's whitelist reads it so
/// the two can never drift.
pub const RETENTION_ADMIN_OPS: &[&str] = &[OP_RETENTION_GET, OP_RETENTION_SET, OP_RETENTION_PRUNE];

impl AdminService {
    /// Answers one `admin.retention.*` op, or `None` when the capability
    /// belongs to another part of the admin surface.
    ///
    /// `envelope_id` is the admin request's own id: a refusal by the managed
    /// policy writes its `policy.locked_write` row on it.
    pub(crate) async fn dispatch_retention(
        &self,
        envelope_id: &str,
        op: &str,
        args: &Value,
    ) -> Option<Result<AdminOk, AdminRefusal>> {
        Some(match op {
            OP_RETENTION_GET => self.retention_get().await,
            OP_RETENTION_SET => self.retention_set(envelope_id, args).await,
            OP_RETENTION_PRUNE => self.retention_prune().await,
            _ => return None,
        })
    }

    /// The retention service for this call. Building one is an
    /// `Arc` clone, so the daemon carries no field for it.
    fn retention(&self) -> RetentionService {
        let service = RetentionService::new(
            std::sync::Arc::clone(&self.store),
            std::sync::Arc::clone(&self.policy),
        );
        // Tests move the clock these ops read; production reads the system's.
        #[cfg(test)]
        let service = {
            let ahead = self
                .retention_clock_ahead
                .load(std::sync::atomic::Ordering::SeqCst);
            service.with_clock(std::sync::Arc::new(move || {
                crate::retention::now_ts().saturating_add(ahead)
            }))
        };
        service
    }

    /// Both windows and the last pass's figures, as the panel opens.
    async fn retention_get(&self) -> Result<AdminOk, AdminRefusal> {
        let retention = self.retention();
        let (settings, entries) = retention.effective().await?;
        let last_run = retention.last_run().await?;
        let guard = retention.clock_guard().await?;
        Ok(AdminOk {
            outcome: Outcome::Verified,
            body: state_body(settings, &entries, last_run, guard)?,
            audit: audit_detail(OP_RETENTION_GET, settings),
        })
    }

    /// Stores the named windows, then prunes at once (see the module
    /// docs) and answers with the fresh figures.
    async fn retention_set(
        &self,
        envelope_id: &str,
        args: &Value,
    ) -> Result<AdminOk, AdminRefusal> {
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
        let settings = match retention.set_settings(patch).await {
            Ok(settings) => settings,
            Err(RetentionRefusal::Policy { refusal, view }) => {
                return Err(self
                    .policy_refusal(envelope_id, OP_RETENTION_SET, refusal, &view)
                    .await);
            }
            Err(other) => return Err(refuse(other)),
        };
        let (_, entries) = retention.effective().await?;
        // The save itself is a human act, but not a decision about the
        // clock, so the pass it triggers can still be held back.
        let (last_run, guard) = match retention.run_pass(Trigger::Settings).await? {
            PassOutcome::Ran { report, .. } => (Some(report), None),
            PassOutcome::Skipped(notice) => (retention.last_run().await?, Some(notice)),
        };
        let mut audit = audit_detail(OP_RETENTION_SET, settings);
        audit["clock_guard_held_back"] = json!(guard.is_some());
        Ok(AdminOk {
            outcome: Outcome::Changed,
            body: state_body(settings, &entries, last_run, guard)?,
            audit,
        })
    }

    /// One pass now: the GUI's Prune now button.
    ///
    /// A pass that removed nothing is [`Outcome::Verified`], not
    /// [`Outcome::Changed`] — the store is exactly as it was, and the
    /// outcome should not claim otherwise.
    async fn retention_prune(&self) -> Result<AdminOk, AdminRefusal> {
        let PassOutcome::Ran {
            report,
            overrode_guard,
        } = self.retention().run_pass(Trigger::Manual).await?
        else {
            return Err(AdminRefusal {
                cause: CAUSE_INTERNAL_ERROR,
                detail: "a manual retention pass was held back, which it never is".to_owned(),
                recovery: RECOVERY_INTERNAL,
            });
        };
        let changed = report.evidence_rows > 0 || report.requests > 0;
        Ok(AdminOk {
            outcome: if changed {
                Outcome::Changed
            } else {
                Outcome::Verified
            },
            body: {
                let mut body = report_body(report)?;
                body["clock_guard_overridden"] = json!(overrode_guard);
                body
            },
            audit: json!({
                "op": OP_RETENTION_PRUNE,
                "evidence_rows": report.evidence_rows,
                "evidence_bytes": report.evidence_bytes,
                "requests": report.requests,
                "audit_rows": report.audit_rows,
                "clock_guard_overridden": overrode_guard,
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
    entries: &[EffectiveEntry; 2],
    last_run: Option<PruneReport>,
    guard: Option<ClockGuardNotice>,
) -> Result<Value, AdminRefusal> {
    let last_run = match last_run {
        Some(report) => report_body(report)?,
        None => Value::Null,
    };
    Ok(json!({
        "evidence_days": settings.evidence_days,
        "audit_days": settings.audit_days,
        "effective": {
            "evidence_days": entries[0].to_json(),
            "audit_days": entries[1].to_json(),
        },
        "last_run": last_run,
        "clock_guard": guard.map(guard_body),
    }))
}

/// A held-back pass as the panel reads it: the cause and recovery line the
/// refusal style uses, the plain-language detail, and the figures behind it.
fn guard_body(notice: ClockGuardNotice) -> Value {
    json!({
        "cause": CAUSE_CLOCK_JUMP,
        "detail": notice.detail(),
        "recovery": RECOVERY_CLOCK_JUMP,
        "ts": notice.ts,
        "watermark_ts": notice.watermark_ts,
        "jump_secs": notice.jump_secs,
        "threshold_secs": notice.threshold_secs,
        "eligible_rows": notice.eligible_rows,
        "total_rows": notice.total_rows,
    })
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
        // `retention_set` answers a policy refusal itself (it audits it);
        // this arm keeps the cause and text if another caller reaches here.
        RetentionRefusal::Policy { refusal, .. } => AdminRefusal {
            cause: refusal.cause,
            detail: refusal.detail,
            recovery: refusal.recovery,
        },
    }
}
