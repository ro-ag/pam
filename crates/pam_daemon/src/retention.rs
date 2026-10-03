//! Retention: how long pam keeps what it saw.
//!
//! Two windows, both age-based, edited from Settings › Retention: how long evidence blobs live, and
//! how long a request's audit record lives. Both default to forever (a store never told a window
//! loses nothing) and are stored as JSON in the `setting` table (`null` = forever), so unset and
//! deliberate "keep everything" read the same.
//! - **Managed policy**: the windows the human saved are bounded at read time by the organization's
//!   `retention.evidence_days` / `retention.audit_days` ([`PolicyView::effective_retention`]):
//!   `locked` forces a value, `min` lengthens a shorter window, `max` is a ceiling that also turns
//!   "forever" (a stored `null`, or nothing stored) into the ceiling, and `default` applies until
//!   the human stores a value of their own. [`RetentionService::settings`] is that clamped pair, so
//!   the scheduler, [`RetentionService::run_pass`] and the GUI all read it; the stored rows are never
//!   rewritten, so removing the policy restores what the human had. A save outside the bounds is
//!   refused ([`RetentionRefusal::Policy`]) before anything is written, and the clock-jump guard below
//!   applies to a policy-forced window exactly as to a chosen one.
//! - **Evidence first, audit last**: a pass prunes evidence before records, and never removes a
//!   request's [`KEEP_KIND`] row while the request is still there (the verdict makes activity
//!   history readable). The verdict leaves — with its request, audit rows, and approval — only when
//!   the audit window catches up with it, because a record leaves whole or not at all. Evidence for
//!   an unfinished request is never touched, however old, since the executor may still be writing
//!   it.
//! - **Evidence may not outlive audit**: [`validate`] refuses a pair whose evidence window is
//!   longer than its audit window — the daemon says so rather than quietly clamping. `forever`
//!   evidence is not that violation: a finite audit window still bounds the evidence under it
//!   regardless of the evidence window's own value; only two finite windows in the wrong order can
//!   go wrong, and either select must be settable first.
//! - **When a pass runs**: [`RetentionService::run_scheduler`] prunes on its first tick (immediate,
//!   so a boot prunes right after crash recovery) and every [`PRUNE_INTERVAL`] after; a settings
//!   save and the GUI's Prune now button also prune at once ([`crate::admin_retention`]). Every
//!   pass writes [`SETTING_LAST_RUN`], even a no-op one.
//! - **Forward clock jump**: age is read off the wall clock, and a clock that jumps forward (a bad
//!   NTP answer, a VM resume, a manual change) makes everything look old at once, and a prune
//!   cannot be undone. Every pass that is not a human's explicit request therefore runs the guard
//!   in [`RetentionService::run_pass`]. It keeps a high-water mark ([`SETTING_WATERMARK`], the
//!   clock reading of the last completed pass) and skips the pass, deleting nothing, when
//!   `now - watermark` exceeds `max(24 h, 2 x interval)` AND the pass would remove more than a
//!   tenth of the rows (and at least fifty of them). The newest row's timestamp is deliberately
//!   not a reference: a row written after the jump carries the jumped time, so the daemon's own
//!   traffic would walk the reference forward with the clock and defeat the check. A skip keeps
//!   the watermark, records [`SETTING_CLOCK_GUARD`] with cause [`CAUSE_CLOCK_JUMP`], and the
//!   retention status reply carries it with [`RECOVERY_CLOCK_JUMP`]; the GUI's Prune now
//!   ([`Trigger::Manual`]) is the human confirmation and always proceeds. A backward jump only
//!   shrinks the cutoff, so it deletes nothing it would not have, and the watermark never moves
//!   backwards on a guarded pass. See [`GuardPolicy`] for the constants.
//! - **Concurrency**: the service is a handle over the shared [`Store`]; each prune is two store
//!   calls, each working oldest first in bounded batches — one transaction per batch, the store's
//!   connection lock released between them — so a pass over a long backlog never holds every
//!   other store call behind it. Nothing here holds a lock of its own.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pam_store::{EvidencePrune, RequestPrune, Store, StoreError};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use crate::managed_policy::{EffectiveEntry, Key, PolicyView, WriteRefusal};
use crate::managed_policy_service::PolicyHandle;

/// Setting key: how many days evidence blobs are kept, JSON `null` for
/// forever.
pub const SETTING_EVIDENCE_DAYS: &str = "retention.evidence_days";

/// Setting key: how many days a request's whole record is kept, JSON
/// `null` for forever.
pub const SETTING_AUDIT_DAYS: &str = "retention.audit_days";

/// Setting key: the [`PruneReport`] of the last pass, as JSON.
pub const SETTING_LAST_RUN: &str = "retention.last_run";

/// Setting key: the wall-clock reading (unix seconds, JSON) of the last
/// completed pass — the high-water mark the clock-jump guard measures from.
pub const SETTING_WATERMARK: &str = "retention.watermark_ts";

/// Setting key: the [`ClockGuardNotice`] of the pass the guard last skipped,
/// as JSON; `null` once a pass completes.
pub const SETTING_CLOCK_GUARD: &str = "retention.clock_guard";

/// Cause of a pass the clock-jump guard skipped.
pub const CAUSE_CLOCK_JUMP: &str = "retention_clock_jump";

/// Recovery line for [`CAUSE_CLOCK_JUMP`].
pub const RECOVERY_CLOCK_JUMP: &str =
    "Check the system clock; run retention manually from Settings to confirm.";

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

/// The constants of the forward-clock-jump guard.
///
/// A pass is skipped only when both halves hold: the clock moved forward by
/// more than [`Self::threshold_secs`], and the pass would remove more than
/// `max_share_percent` of the rows (and at least `min_rows`). The second half
/// is what keeps a laptop that slept over a weekend, or a daemon that was off
/// for a few days, from asking for a click: those passes are merely late, and
/// remove a day or two of an old window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardPolicy {
    /// The smallest forward jump the guard ever looks at.
    pub min_jump: Duration,
    /// How many scheduler intervals of silence are an ordinary gap.
    pub interval_factor: u32,
    /// The share of rows (percent) a pass may remove after such a jump.
    pub max_share_percent: u64,
    /// A pass removing fewer rows than this is never held back.
    pub min_rows: u64,
}

impl Default for GuardPolicy {
    fn default() -> Self {
        Self {
            min_jump: Duration::from_hours(24),
            interval_factor: 2,
            max_share_percent: 10,
            min_rows: 50,
        }
    }
}

impl GuardPolicy {
    /// The forward jump, in seconds, beyond which the share check runs:
    /// `max(min_jump, interval_factor x interval)`.
    #[must_use]
    pub fn threshold_secs(&self, interval: Duration) -> i64 {
        let widest = self
            .min_jump
            .max(interval.saturating_mul(self.interval_factor));
        i64::try_from(widest.as_secs()).unwrap_or(i64::MAX)
    }

    /// Whether `eligible` of `total` rows is too large a share to remove
    /// after a jump.
    fn too_many(&self, eligible: u64, total: u64) -> bool {
        eligible >= self.min_rows
            && u128::from(eligible) * 100 > u128::from(total) * u128::from(self.max_share_percent)
    }
}

/// Why a pass was skipped. Stored under [`SETTING_CLOCK_GUARD`] and carried
/// by the retention status reply until a pass completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockGuardNotice {
    /// The clock reading of the skipped pass.
    pub ts: i64,
    /// The watermark the pass was measured from.
    pub watermark_ts: i64,
    /// `ts - watermark_ts`, in seconds.
    pub jump_secs: i64,
    /// The jump beyond which the share check runs, in seconds.
    pub threshold_secs: i64,
    /// Rows the pass would have removed; `None` when they could not be counted.
    pub eligible_rows: Option<u64>,
    /// Rows the pass looked at; `None` when they could not be counted.
    pub total_rows: Option<u64>,
}

impl ClockGuardNotice {
    /// One sentence saying what was held back and why.
    #[must_use]
    pub fn detail(&self) -> String {
        let hours = |secs: i64| secs / 3600;
        let rows = match (self.eligible_rows, self.total_rows) {
            (Some(eligible), Some(total)) => {
                format!("this pass would remove {eligible} of {total} rows")
            }
            _ => "the rows this pass would remove could not be counted".to_owned(),
        };
        format!(
            "the system clock is {} h ahead of the last retention pass (limit {} h) and {rows}; \
             nothing was deleted",
            hours(self.jump_secs),
            hours(self.threshold_secs),
        )
    }
}

/// What a pass would remove, counted without removing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassCensus {
    /// Rows the pass would remove at the current cutoffs.
    pub eligible_rows: u64,
    /// Rows the windows could ever remove: evidence plus finished requests.
    pub total_rows: u64,
}

/// A boxed future, so the guard's two reads can sit behind a trait object.
type Reading<'a, T> = Pin<Box<dyn Future<Output = Result<T, StoreError>> + Send + 'a>>;

/// Where the guard reads the store's row counts from.
pub trait CensusSource: Send + Sync + fmt::Debug {
    /// What a pass over `settings` would remove as of `now_ts`, or `None`
    /// when this source cannot count it (the guard then treats the pass as
    /// too large, never as small).
    fn census(&self, settings: RetentionSettings, now_ts: i64) -> Reading<'_, Option<PassCensus>>;
}

/// The production source: the store's own count of what the two prune
/// statements would remove at the cutoffs `settings` gives as of `now_ts`
/// ([`Store::retention_census`]), read without removing anything. It always
/// counts; a store that cannot be read is an error, and the pass that asked
/// does not run.
#[derive(Debug)]
struct StoreCensus(Arc<Store>);

impl CensusSource for StoreCensus {
    fn census(&self, settings: RetentionSettings, now_ts: i64) -> Reading<'_, Option<PassCensus>> {
        Box::pin(async move {
            // The same cutoffs, and the same kept kind, as `prune` uses.
            let census = self
                .0
                .retention_census(
                    settings.evidence_days.map(|days| cutoff(now_ts, days)),
                    KEEP_KIND,
                    settings.audit_days.map(|days| cutoff(now_ts, days)),
                )
                .await?;
            Ok(Some(PassCensus {
                eligible_rows: census.eligible_rows,
                total_rows: census.total_rows,
            }))
        })
    }
}

/// The wall clock, injectable so tests can move it.
#[derive(Clone)]
struct Clock(Arc<dyn Fn() -> i64 + Send + Sync>);

impl fmt::Debug for Clock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Clock")
    }
}

/// What asked for a pass, which decides whether the guard may hold it back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// The scheduler's tick, at this interval.
    Scheduled(Duration),
    /// A settings save: it prunes at once, but is not a decision about the clock.
    Settings,
    /// The human's Prune now: the confirmation that overrides the guard.
    Manual,
}

/// What [`RetentionService::run_pass`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassOutcome {
    /// The pass ran and was recorded.
    Ran {
        /// What it removed.
        report: PruneReport,
        /// Whether the guard would have held it back had it not been manual.
        overrode_guard: bool,
    },
    /// The guard held the pass back; nothing was deleted.
    Skipped(ClockGuardNotice),
}

/// Why a settings save was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetentionRefusal {
    /// The windows themselves are wrong; `detail` names both values.
    Invalid {
        /// Human-readable reason, naming the two windows.
        detail: String,
    },
    /// The managed policy refuses the change (a locked window, a value
    /// outside the policy's bounds, a held key). `view` is the snapshot the
    /// refusal was decided on, so the audit row names the digest that refused.
    Policy {
        /// What the policy refused, with its cause and recovery line.
        refusal: WriteRefusal,
        /// The policy in force when the save was checked.
        view: Arc<PolicyView>,
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
    clock: Clock,
    census: Arc<dyn CensusSource>,
    guard: GuardPolicy,
    /// The managed policy in force (see [`crate::managed_policy_service`]).
    policy: Arc<PolicyHandle>,
}

impl RetentionService {
    /// A service over `store`, holding the managed policy handle `policy`.
    #[must_use]
    pub fn new(store: Arc<Store>, policy: Arc<PolicyHandle>) -> Self {
        Self {
            census: Arc::new(StoreCensus(Arc::clone(&store))),
            store,
            policy,
            clock: Clock(Arc::new(now_ts)),
            guard: GuardPolicy::default(),
        }
    }

    /// The managed policy handle this service reads through (see
    /// [`crate::managed_policy_service`]).
    #[must_use]
    pub fn policy(&self) -> &Arc<PolicyHandle> {
        &self.policy
    }

    /// Replaces the wall clock the passes read.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        self.clock = Clock(clock);
        self
    }

    /// Replaces where the guard reads row counts from.
    #[must_use]
    pub fn with_census(mut self, census: Arc<dyn CensusSource>) -> Self {
        self.census = census;
        self
    }

    /// Replaces the guard's constants.
    #[must_use]
    pub fn with_guard_policy(mut self, guard: GuardPolicy) -> Self {
        self.guard = guard;
        self
    }

    /// Both windows as they are in force: what the human stored, bounded
    /// by the managed policy ([`PolicyView::effective_retention`]). The
    /// scheduler, [`Self::run_pass`] and the GUI all read this pair, so a
    /// policy ceiling clamps a stored "forever" before anything is pruned.
    ///
    /// With no policy this is the stored pair, and an unset — or unreadable
    /// — key reads as forever, never as a window: a garbled setting must
    /// not start deleting things.
    pub async fn settings(&self) -> Result<RetentionSettings, StoreError> {
        Ok(self.effective().await?.0)
    }

    /// The windows in force with, per window, where each came from (the
    /// `effective` entries of `admin.retention.get`).
    pub async fn effective(&self) -> Result<(RetentionSettings, [EffectiveEntry; 2]), StoreError> {
        let evidence = self.stored_window(SETTING_EVIDENCE_DAYS).await?;
        let audit = self.stored_window(SETTING_AUDIT_DAYS).await?;
        Ok(self.policy.view().effective_retention(evidence, audit))
    }

    /// What the human stored, before any policy bound: `None` for a key
    /// with no stored value (so a policy `default` can apply), `Some(None)`
    /// for forever.
    async fn stored_window(&self, key: &str) -> Result<Option<Option<u32>>, StoreError> {
        let Some(raw) = self.store.get_setting(key).await? else {
            return Ok(None);
        };
        match serde_json::from_str::<Option<u32>>(&raw) {
            Ok(Some(days)) if !(1..=MAX_DAYS).contains(&days) => {
                tracing::warn!(
                    setting = key,
                    days,
                    "the stored retention window is out of range; treating it as forever"
                );
                Ok(Some(None))
            }
            Ok(days) => Ok(Some(days)),
            Err(error) => {
                tracing::warn!(
                    setting = key,
                    %error,
                    "the stored retention window is unreadable; treating it as forever"
                );
                Ok(Some(None))
            }
        }
    }

    /// Applies `patch` and answers the windows as they now stand in force.
    ///
    /// The named windows are checked against the managed policy (locked,
    /// outside its bounds, held) and the merged stored pair is validated
    /// before anything is written, so a refusal leaves the stored settings
    /// exactly as they were. The stored windows are then written in one
    /// transaction, the untouched one included when the human had set it:
    /// the stored pair is always one that passed [`validate`] as a whole,
    /// even when two saves race or the daemon stops mid-save.
    pub async fn set_settings(
        &self,
        patch: RetentionPatch,
    ) -> Result<RetentionSettings, RetentionRefusal> {
        let view = self.policy.view();
        for (key, requested) in [
            (Key::RetentionEvidenceDays, patch.evidence_days),
            (Key::RetentionAuditDays, patch.audit_days),
        ] {
            let checked = match requested {
                Some(days) => view.check_window(key, days.map(u64::from)),
                // A window the save does not name is not the save's to
                // refuse: the policy still bounds it when it is read.
                None => Ok(()),
            };
            checked.map_err(|refusal| RetentionRefusal::Policy {
                refusal,
                view: Arc::clone(&view),
            })?;
        }
        // The stored pair: what the human saved, which is what a patch
        // edits and what the pair rule applies to.
        let stored_evidence = self
            .stored_window(SETTING_EVIDENCE_DAYS)
            .await
            .map_err(|error| store_refusal(&error))?;
        let stored_audit = self
            .stored_window(SETTING_AUDIT_DAYS)
            .await
            .map_err(|error| store_refusal(&error))?;
        let merged = RetentionSettings {
            evidence_days: patch.evidence_days.unwrap_or(stored_evidence.flatten()),
            audit_days: patch.audit_days.unwrap_or(stored_audit.flatten()),
        };
        validate(merged).map_err(|detail| RetentionRefusal::Invalid { detail })?;
        // The untouched window is written as the value the validation saw,
        // except a window the human never set that the policy manages: it
        // stays unset, so the policy's `default` keeps applying to it.
        let evidence_row = (patch.evidence_days.is_some()
            || stored_evidence.is_some()
            || view.status(Key::RetentionEvidenceDays).is_none())
        .then(|| encode(merged.evidence_days));
        let audit_row = (patch.audit_days.is_some()
            || stored_audit.is_some()
            || view.status(Key::RetentionAuditDays).is_none())
        .then(|| encode(merged.audit_days));
        let mut rows: Vec<(&str, &str)> = Vec::with_capacity(2);
        if let Some(row) = &evidence_row {
            rows.push((SETTING_EVIDENCE_DAYS, row));
        }
        if let Some(row) = &audit_row {
            rows.push((SETTING_AUDIT_DAYS, row));
        }
        self.store
            .set_settings(&rows)
            .await
            .map_err(|error| store_refusal(&error))?;
        self.settings().await.map_err(|error| store_refusal(&error))
    }

    /// Runs one pass as `trigger` asked for it, behind the clock-jump guard.
    ///
    /// The scheduler and a settings save can be held back; the human's
    /// [`Trigger::Manual`] never is, and says whether it overrode the guard.
    /// A completed pass moves the watermark to the clock reading it ran at
    /// (a manual one unconditionally; a guarded one never backwards) and
    /// clears the stored notice. A held-back pass writes only the notice.
    pub async fn run_pass(&self, trigger: Trigger) -> Result<PassOutcome, StoreError> {
        let now = (self.clock.0)();
        let interval = match trigger {
            Trigger::Scheduled(interval) => interval,
            Trigger::Settings | Trigger::Manual => PRUNE_INTERVAL,
        };
        let notice = self.evaluate_guard(interval, now).await?;
        if let Some(notice) = notice
            && trigger != Trigger::Manual
        {
            self.store
                .set_setting(SETTING_CLOCK_GUARD, &encode_notice(&notice))
                .await?;
            tracing::warn!(
                cause = CAUSE_CLOCK_JUMP,
                recovery = RECOVERY_CLOCK_JUMP,
                jump_secs = notice.jump_secs,
                eligible_rows = notice.eligible_rows,
                total_rows = notice.total_rows,
                "{}",
                notice.detail()
            );
            return Ok(PassOutcome::Skipped(notice));
        }
        let overrode_guard = notice.is_some();
        if overrode_guard {
            tracing::warn!(
                cause = CAUSE_CLOCK_JUMP,
                "a human confirmed a retention pass after a forward clock jump"
            );
        }
        let report = self.prune(now).await?;
        self.advance_watermark(now, trigger == Trigger::Manual)
            .await?;
        if self.clock_guard().await?.is_some() {
            self.store.set_setting(SETTING_CLOCK_GUARD, "null").await?;
        }
        Ok(PassOutcome::Ran {
            report,
            overrode_guard,
        })
    }

    /// The notice for a pass the guard would hold back as of `now`, or
    /// `None` when it may run.
    ///
    /// No watermark (a store that never completed a pass) behaves as before
    /// the guard existed. Otherwise only a jump past the policy's threshold
    /// goes on to the share check, which counts rows and so is not paid for
    /// on an ordinary hourly pass. A source that cannot count fails closed.
    async fn evaluate_guard(
        &self,
        interval: Duration,
        now: i64,
    ) -> Result<Option<ClockGuardNotice>, StoreError> {
        let Some(watermark) = self.watermark().await? else {
            return Ok(None);
        };
        let jump = now.saturating_sub(watermark);
        let threshold = self.guard.threshold_secs(interval);
        if jump <= threshold {
            // On time, or the clock went backwards: a smaller `now` only
            // shrinks the cutoffs, so nothing newly qualifies.
            return Ok(None);
        }
        let settings = self.settings().await?;
        if settings == RetentionSettings::default() {
            return Ok(None);
        }
        let counted = self.census.census(settings, now).await?;
        if let Some(census) = counted
            && !self.guard.too_many(census.eligible_rows, census.total_rows)
        {
            return Ok(None);
        }
        Ok(Some(ClockGuardNotice {
            ts: now,
            watermark_ts: watermark,
            jump_secs: jump,
            threshold_secs: threshold,
            eligible_rows: counted.map(|census| census.eligible_rows),
            total_rows: counted.map(|census| census.total_rows),
        }))
    }

    /// The high-water mark: the stored watermark, else the timestamp of the
    /// last recorded pass (an install from before the guard existed), else
    /// `None`.
    async fn watermark(&self) -> Result<Option<i64>, StoreError> {
        if let Some(raw) = self.store.get_setting(SETTING_WATERMARK).await? {
            match serde_json::from_str::<i64>(&raw) {
                Ok(ts) => return Ok(Some(ts)),
                Err(error) => tracing::warn!(
                    setting = SETTING_WATERMARK,
                    %error,
                    "the stored retention watermark is unreadable; using the last recorded pass"
                ),
            }
        }
        Ok(self.last_run().await?.map(|report| report.ts))
    }

    /// Records that a pass completed at `now`. A guarded pass never lowers
    /// the mark (a backward jump must not make the return to the true time
    /// look like a forward one); a manual pass resets it, because a human
    /// has just vouched for this clock.
    async fn advance_watermark(&self, now: i64, reset: bool) -> Result<(), StoreError> {
        let next = match self.watermark().await? {
            Some(previous) if !reset => previous.max(now),
            Some(_) | None => now,
        };
        self.store
            .set_setting(SETTING_WATERMARK, &next.to_string())
            .await
    }

    /// The notice of the pass the guard last held back, until a pass
    /// completes; `None` when the last pass was not held back or the stored
    /// notice is unreadable.
    pub async fn clock_guard(&self) -> Result<Option<ClockGuardNotice>, StoreError> {
        let Some(raw) = self.store.get_setting(SETTING_CLOCK_GUARD).await? else {
            return Ok(None);
        };
        match serde_json::from_str::<Option<ClockGuardNotice>>(&raw) {
            Ok(notice) => Ok(notice),
            Err(error) => {
                tracing::warn!(%error, "the stored retention clock-guard notice is unreadable");
                Ok(None)
            }
        }
    }

    /// Runs one unguarded pass as of `now_ts`: evidence first, records last.
    ///
    /// This is the primitive under [`Self::run_pass`], which every daemon
    /// path goes through; it neither consults nor moves the watermark. A
    /// window that is `None` skips its half. The report is stored under
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
                        // A held-back pass has already logged its cause.
                        if let Err(error) = self.run_pass(Trigger::Scheduled(interval)).await {
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

/// A notice as the `setting` table stores it: its JSON, which cannot fail
/// for this all-integer shape.
fn encode_notice(notice: &ClockGuardNotice) -> String {
    serde_json::to_string(notice).unwrap_or_else(|_| "null".to_owned())
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
