//! Retention: how long pam keeps what it saw.
//!
//! Two windows, both age-based, both edited from Settings › Retention:
//! how long evidence blobs live, and how long the audit record of a
//! request lives. Both default to *forever* — a store that has never
//! been told a window loses nothing when this code lands — and both are
//! stored as JSON in the `setting` table (`null` for forever), so an
//! unset key and a deliberate "keep everything" read the same.
//!
//! # Evidence first, audit last
//!
//! The spine spec's phrase is the whole design. A pass prunes evidence
//! before it prunes records, and it never removes a request's
//! [`KEEP_KIND`] row while the request is still there: the verdict is
//! what makes activity history readable, and it costs a few dozen bytes
//! next to the logs it summarizes. The verdict does leave — with its
//! request, its audit rows and its approval — when the *audit* window
//! catches up with it, because a record leaves whole or not at all.
//! Evidence belonging to a request that has not finished is never
//! touched, however old it looks: the executor may still be writing it.
//!
//! # Evidence may not outlive the audit trail
//!
//! [`validate`] refuses a pair whose evidence window is longer than its
//! audit window. Keeping blobs past the record that explains them is
//! storage without meaning, and the daemon says so rather than quietly
//! clamping the number — the human learns the rule from pam, the same
//! posture Settings › Flows takes with its allowlist. `forever` evidence
//! is not that violation: nothing outlives its record, so a finite audit
//! window bounds the evidence under it whatever the evidence window
//! says. Only two finite windows in the wrong order can go wrong, and a
//! human editing one select at a time must be able to set either first.
//!
//! # When a pass runs
//!
//! [`RetentionService::run_scheduler`] prunes on its first tick — which
//! is immediate, so the daemon prunes at boot after crash recovery — and
//! every [`PRUNE_INTERVAL`] after that. A settings save prunes at once
//! (see [`crate::admin_retention`]), and so does the GUI's Prune now
//! button. Every pass writes [`SETTING_LAST_RUN`], even one that removed
//! nothing: "I looked and there was nothing to take" is a fact the panel
//! shows.
//!
//! # Concurrency
//!
//! The service is a handle over the shared [`Store`]; each prune is two
//! store calls, and each of those holds the store's connection lock
//! across its own `BEGIN`..`COMMIT` (turso refuses concurrent use of one
//! connection). Nothing here holds a lock of its own.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pam_store::{EvidencePrune, RequestPrune, Store, StoreError};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

/// Setting key: how many days evidence blobs are kept, JSON `null` for
/// forever.
pub const SETTING_EVIDENCE_DAYS: &str = "retention.evidence_days";

/// Setting key: how many days a request's whole record is kept, JSON
/// `null` for forever.
pub const SETTING_AUDIT_DAYS: &str = "retention.audit_days";

/// Setting key: the [`PruneReport`] of the last pass, as JSON.
pub const SETTING_LAST_RUN: &str = "retention.last_run";

/// Longest window either setting accepts: ten years. Past that, "forever"
/// is the honest answer and the select offers it.
pub const MAX_DAYS: u32 = 3650;

/// Number of seconds a retention day is worth.
const SECS_PER_DAY: i64 = 86_400;

/// How often the scheduler prunes once the daemon is up.
pub const PRUNE_INTERVAL: Duration = Duration::from_hours(1);

/// Refusal cause: the two windows break the evidence-≤-audit rule, or a
/// window is out of range.
pub const CAUSE_RETENTION_INVALID: &str = "retention_invalid";

/// Recovery line for [`CAUSE_RETENTION_INVALID`].
pub const RECOVERY_RETENTION_INVALID: &str = "Keep evidence no longer than audit rows: shorten \
     the evidence window or lengthen the audit one.";

/// The evidence kind an evidence-window pass never removes: the flow
/// verdict, which lives exactly as long as its audit rows.
pub const KEEP_KIND: &str = crate::flow_service::EVIDENCE_KIND_FLOW_RESULT;

/// The two retention windows, in days; `None` is forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RetentionSettings {
    /// How long evidence blobs are kept.
    pub evidence_days: Option<u32>,
    /// How long a finished request's whole record is kept.
    pub audit_days: Option<u32>,
}

/// A partial update to [`RetentionSettings`].
///
/// The double option is the point: an absent field (`None`) leaves the
/// setting alone, and `Some(None)` sets it to forever. A select that
/// sends `null` means the second, not the first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetentionPatch {
    /// New evidence window, when the caller named one.
    pub evidence_days: Option<Option<u32>>,
    /// New audit window, when the caller named one.
    pub audit_days: Option<Option<u32>>,
}

/// What one prune pass removed, and when it ran.
///
/// The evidence figures are the two halves added together: what the
/// evidence window took, plus what left with the records the audit
/// window took.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruneReport {
    /// Unix seconds the pass ran at.
    pub ts: i64,
    /// Evidence rows removed, both halves together.
    pub evidence_rows: u64,
    /// Bytes of blob those rows held.
    pub evidence_bytes: u64,
    /// Whole request records removed.
    pub requests: u64,
    /// Audit rows that left with them.
    pub audit_rows: u64,
}

/// Why a settings save was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetentionRefusal {
    /// The windows themselves are wrong; `detail` names both values.
    Invalid {
        /// Human-readable reason, naming the two windows.
        detail: String,
    },
    /// The settings could not be read or written.
    Store(String),
}

/// Reads and writes the retention windows, and runs the prune pass.
///
/// Cheap to build (it holds one `Arc<Store>`), so the admin ops make one
/// per call rather than the daemon carrying a field for it.
#[derive(Debug, Clone)]
pub struct RetentionService {
    store: Arc<Store>,
}

impl RetentionService {
    /// A service over `store`.
    #[must_use]
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    /// Both windows as they stand. An unset — or unreadable — key reads
    /// as forever, never as a window: a garbled setting must not start
    /// deleting things.
    pub async fn settings(&self) -> Result<RetentionSettings, StoreError> {
        Ok(RetentionSettings {
            evidence_days: self.window(SETTING_EVIDENCE_DAYS).await?,
            audit_days: self.window(SETTING_AUDIT_DAYS).await?,
        })
    }

    /// One window setting, or `None` when it is unset or unreadable.
    async fn window(&self, key: &str) -> Result<Option<u32>, StoreError> {
        let Some(raw) = self.store.get_setting(key).await? else {
            return Ok(None);
        };
        match serde_json::from_str::<Option<u32>>(&raw) {
            Ok(days) => Ok(days),
            Err(error) => {
                tracing::warn!(
                    setting = key,
                    %error,
                    "the stored retention window is unreadable; treating it as forever"
                );
                Ok(None)
            }
        }
    }

    /// Applies `patch` and answers the windows as they now stand.
    ///
    /// The merged pair is validated before anything is written, so a
    /// refusal leaves the stored settings exactly as they were.
    pub async fn set_settings(
        &self,
        patch: RetentionPatch,
    ) -> Result<RetentionSettings, RetentionRefusal> {
        let current = self
            .settings()
            .await
            .map_err(|error| store_refusal(&error))?;
        let merged = RetentionSettings {
            evidence_days: patch.evidence_days.unwrap_or(current.evidence_days),
            audit_days: patch.audit_days.unwrap_or(current.audit_days),
        };
        validate(merged).map_err(|detail| RetentionRefusal::Invalid { detail })?;
        for (key, days) in [
            (SETTING_EVIDENCE_DAYS, patch.evidence_days),
            (SETTING_AUDIT_DAYS, patch.audit_days),
        ] {
            let Some(days) = days else { continue };
            self.store
                .set_setting(key, &encode(days))
                .await
                .map_err(|error| store_refusal(&error))?;
        }
        Ok(merged)
    }

    /// Runs one pass as of `now_ts`: evidence first, records last.
    ///
    /// A window that is `None` skips its half. The report is stored under
    /// [`SETTING_LAST_RUN`] whatever it says — an empty pass still
    /// happened.
    pub async fn prune(&self, now_ts: i64) -> Result<PruneReport, StoreError> {
        let settings = self.settings().await?;
        let evidence = match settings.evidence_days {
            Some(days) => {
                self.store
                    .prune_evidence_before(cutoff(now_ts, days), KEEP_KIND)
                    .await?
            }
            None => EvidencePrune::default(),
        };
        let records = match settings.audit_days {
            Some(days) => {
                self.store
                    .prune_requests_before(cutoff(now_ts, days))
                    .await?
            }
            None => RequestPrune::default(),
        };
        let report = PruneReport {
            ts: now_ts,
            evidence_rows: evidence.rows.saturating_add(records.evidence_rows),
            evidence_bytes: evidence.bytes.saturating_add(records.evidence_bytes),
            requests: records.requests,
            audit_rows: records.audit_rows,
        };
        self.record(report).await?;
        if report.evidence_rows > 0 || report.requests > 0 {
            tracing::info!(
                evidence_rows = report.evidence_rows,
                evidence_bytes = report.evidence_bytes,
                requests = report.requests,
                audit_rows = report.audit_rows,
                "retention pruned"
            );
        } else {
            tracing::debug!("retention found nothing to prune");
        }
        Ok(report)
    }

    /// Stores `report` as the last run. A report that will not serialize
    /// is a bug in this module, not a reason to fail a prune that already
    /// happened, so it is logged and dropped.
    async fn record(&self, report: PruneReport) -> Result<(), StoreError> {
        match serde_json::to_string(&report) {
            Ok(raw) => self.store.set_setting(SETTING_LAST_RUN, &raw).await,
            Err(error) => {
                tracing::warn!(%error, "the retention report could not be recorded");
                Ok(())
            }
        }
    }

    /// The last pass's figures, or `None` when none has run yet.
    pub async fn last_run(&self) -> Result<Option<PruneReport>, StoreError> {
        let Some(raw) = self.store.get_setting(SETTING_LAST_RUN).await? else {
            return Ok(None);
        };
        match serde_json::from_str::<PruneReport>(&raw) {
            Ok(report) => Ok(Some(report)),
            Err(error) => {
                tracing::warn!(%error, "the stored retention report is unreadable");
                Ok(None)
            }
        }
    }

    /// Spawns the background pruner: one pass now — the interval's first
    /// tick fires immediately, which is how boot pruning happens — and
    /// one every `interval` until `shutdown` changes (or its sender
    /// drops).
    ///
    /// A failed pass is logged and retried on the next tick; retention is
    /// housekeeping, and a store hiccup must not take the daemon with it.
    #[must_use]
    pub fn run_scheduler(
        self,
        interval: Duration,
        mut shutdown: watch::Receiver<bool>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if let Err(error) = self.prune(now_ts()).await {
                            tracing::warn!(%error, "retention prune failed");
                        }
                    }
                    _ = shutdown.changed() => break,
                }
            }
        })
    }
}

/// The rule both the daemon and the GUI's refusal message quote: each
/// window is forever or `1..=MAX_DAYS`, and evidence may not outlive the
/// audit trail that explains it.
///
/// # Errors
///
/// The human-readable reason, which becomes the refusal's detail.
pub fn validate(settings: RetentionSettings) -> Result<(), String> {
    for (name, days) in [
        ("evidence", settings.evidence_days),
        ("audit", settings.audit_days),
    ] {
        if let Some(days) = days
            && !(1..=MAX_DAYS).contains(&days)
        {
            return Err(format!(
                "the {name} window must be between 1 and {MAX_DAYS} days, not {days}"
            ));
        }
    }
    let evidence_outlives = match (settings.evidence_days, settings.audit_days) {
        (Some(evidence), Some(audit)) => evidence > audit,
        // Forever evidence is bounded by the record it hangs off: when
        // the audit window takes the request, the evidence goes with it.
        (None, Some(_)) | (Some(_) | None, None) => false,
    };
    if evidence_outlives {
        return Err(format!(
            "evidence window ({}) exceeds audit window ({})",
            describe(settings.evidence_days),
            describe(settings.audit_days)
        ));
    }
    Ok(())
}

/// Current time as unix seconds.
#[must_use]
pub fn now_ts() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    i64::try_from(secs).unwrap_or(i64::MAX)
}

/// The timestamp a window of `days` makes old, seen from `now_ts`.
fn cutoff(now_ts: i64, days: u32) -> i64 {
    now_ts.saturating_sub(i64::from(days).saturating_mul(SECS_PER_DAY))
}

/// One window as the `setting` table stores it: the JSON of an
/// `Option<u32>`, written by hand because that JSON cannot fail.
fn encode(days: Option<u32>) -> String {
    days.map_or_else(|| "null".to_owned(), |days| days.to_string())
}

/// One window as a refusal message names it.
fn describe(days: Option<u32>) -> String {
    days.map_or_else(|| "forever".to_owned(), |days| format!("{days} days"))
}

/// A store failure a settings save reports as a refusal.
fn store_refusal(error: &StoreError) -> RetentionRefusal {
    RetentionRefusal::Store(format!(
        "the retention settings could not be saved: {error}"
    ))
}
