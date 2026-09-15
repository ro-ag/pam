//! Queue manager: per-repo ordered lanes, executor leases, cancellation,
//! and in-flight deduplication.
//!
//! - **Design**: lanes serialize work per repo (one leased request per lane at a time) while
//!   different repos run in parallel; they are an in-memory index over the `request` table (state
//!   `queued` is the durable truth), so [`QueueManager::rebuild_from_store`] reconstructs every
//!   lane on boot. Read-only capabilities never enter a lane ([`AdmitOutcome::Bypass`]).
//! - **Bypass rows**: a read-only bypass still inserts a `request` row (audit trail + GUI feed need
//!   it) but is born `running` atomically with an admission expiry and never enters a lane; the
//!   caller executes it and records the terminal state itself.
//! - **Admission vs placement**: split in two so [`PolicyGate::evaluate`](crate::policy::PolicyGate::evaluate)
//!   can run between, needing the `request` row to exist
//!   first — (1) [`QueueManager::admit`]: dedupe check + row insert (`running`, absolute expiry)
//!   under the internal mutex; (2) [`QueueManager::place_in_lane`]: persists authorization +
//!   `queued`, pushes onto the repo's lane, once the gate allows. A gate refusal between the two
//!   sends the row straight to `refused` (never reaches a lane); a concurrent duplicate arriving in
//!   that window attaches and is forwarded the same terminal response, refusals included.
//! - **Deduplication**: before inserting a laned request, look for an in-flight duplicate
//!   (`queued`/`running`/`waiting_approval`) by `idempotency_key` when present, else by shape —
//!   byte equality of capability + repo + serialized args (`serde_json` sorts map keys, so this is
//!   deterministic). A hit returns [`AdmitOutcome::Attached`]; the caller subscribes instead of
//!   re-executing. Terminal requests never match, so retries after completion run fresh. The mutex
//!   is held across check-then-insert so concurrent admissions cannot both miss the check.
//! - **Leases**: [`QueueManager::take_next`] marks the request `running` with a deadline from
//!   `deadline_ms`, clamped to [`MAX_LEASE`]. An expired lease is reaped
//!   ([`QueueManager::reap_expired`], driven by [`QueueManager::run_reaper`]): terminal
//!   `failed`/[`CAUSE_LEASE_EXPIRED`], audited ([`ACTION_LEASE_REAPED`], decision `timeout`, actor
//!   `system`), the holder's cancel signal fires, and the lane is freed.
//! - **Cancellation**: [`QueueManager::cancel`] serves `pam cancel <ticket>` and the GUI, acting as
//!   the caller-supplied [`Actor`] (the CLI passes the identity the pipeline assigned the ticket holder, the GUI [`Actor::Human`]). A queued request is removed from
//!   its lane and terminal `failed`/[`CAUSE_CANCELLED`], audited ([`ACTION_CANCEL`], `deny`). A
//!   running request is signalled cooperatively via the lease's cancel signal; its terminal
//!   write/audit happen through [`QueueManager::complete`].
//! - **Audit invariant**: every terminal transition the queue performs — queued-cancellation, lease
//!   reaping, executor completion via [`QueueManager::complete`] — goes through
//!   [`Store::finish_request`], the choke point writing terminal state + audit row in one
//!   transaction. The queue never calls `update_request_state` with a terminal state; the
//!   already-terminal guard makes reaper-vs-executor double-finish races a first-wins no-op with no
//!   duplicate audit row.
//! - **Concurrency**: one `QueueManager` behind `&self`, a single `tokio::sync::Mutex` over the
//!   in-memory maps (low-contention monolith); no lock is ever held across an `.await` on anything
//!   but the store. There are no lane worker tasks — the executor loop drives
//!   [`QueueManager::take_next`]/[`QueueManager::complete`].
//! - **Boot**: [`QueueManager::rebuild_from_store`] reloads `queued` rows into lanes, oldest first.
//!   Crash recovery of `running`/`waiting_approval` rows left by a dead daemon (failed with cause
//!   `daemon_restart`) happens elsewhere, not here.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use pam_proto::Envelope;
use pam_store::{Actor, AuditEntry, Decision, RequestState, Store, StoreError};
use thiserror::Error;
use tokio::sync::{Mutex, Notify, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

/// Upper bound on any lease: an envelope `deadline_ms` beyond this is
/// clamped. Admission persists the absolute expiry for placement and recovery.
pub const MAX_LEASE: Duration = Duration::from_hours(1);
/// Global active admission cap, including approval waits and read-only bypasses.
pub const MAX_ADMITTED_REQUESTS: u64 = 128;
/// Maximum cumulative persisted identity and argument bytes for active admissions.
pub const MAX_ADMITTED_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum parked terminal tickets waiting for executor/router notification.
pub const MAX_PARKED_TERMINALS: usize = 128;

/// `request.outcome` recorded when a queued request is cancelled.
pub const CAUSE_CANCELLED: &str = "cancelled";

/// `request.outcome` recorded when a lease outlives its deadline.
pub const CAUSE_LEASE_EXPIRED: &str = "lease_expired";

/// `audit.action` for a cancellation the queue performed.
pub const ACTION_CANCEL: &str = "cancel";

/// `audit.action` for a lease the reaper collected.
pub const ACTION_LEASE_REAPED: &str = "lease_reaped";

/// What [`QueueManager::admit`] did with a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitOutcome {
    /// A new request row was inserted in state `running`. The caller gates
    /// it and, on allow, calls [`QueueManager::place_in_lane`].
    Admitted,
    /// An in-flight duplicate exists; no row was inserted. The caller
    /// attaches to the existing request's events and result.
    Attached {
        /// Id of the in-flight request to attach to.
        existing_request_id: String,
    },
    /// Read-only capability: a `running` request row was inserted but no
    /// lane entry — the caller executes immediately.
    Bypass,
}

/// What [`QueueManager::cancel`] did with a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelOutcome {
    /// The request was still queued: removed from its lane, terminal
    /// `failed` (cause [`CAUSE_CANCELLED`]), audited.
    CancelledQueued,
    /// The request runs under a lease: its cancel signal fired; the
    /// executor observes it and finishes via [`QueueManager::complete`].
    SignalledRunning,
    /// No queued or leased request with that id exists (terminal
    /// requests included — there is nothing left to cancel).
    NotFound,
}

/// Work handed to an executor under a lease.
#[derive(Debug)]
pub struct LeasedWork {
    /// The leased request's id.
    pub request_id: String,
    /// When the lease expires; past it the reaper fails the request.
    pub lease_deadline: Instant,
    /// Flips to `true` when the request is cancelled or its lease is
    /// reaped; the executor watches it and stops cooperatively. A closed
    /// channel also means the lease is gone.
    pub cancel: watch::Receiver<bool>,
}

/// Why a queue operation failed.
#[derive(Debug, Error)]
pub enum QueueError {
    /// An old queued row cannot be read within the startup recovery byte bound.
    #[error(
        "legacy_queue_oversized: a queued row exceeds the recovery byte limit; stop PAM, back up its state database, and have the operator repair the oversized legacy row before restarting"
    )]
    LegacyQueueOversized,
    /// The original request deadline elapsed before work could begin.
    #[error("request admission deadline expired")]
    Expired,
    /// No matching unplaced admission exists for this repository.
    #[error("request has no valid unplaced admission")]
    NotAdmitted,
    /// Admission was refused before inserting more retained work.
    #[error("{cause}: admission maximum is {maximum}")]
    Capacity { cause: &'static str, maximum: u64 },
    /// [`QueueManager::complete`] was handed a non-terminal state.
    #[error("state {state:?} is not terminal; complete() records only done, refused or failed")]
    NotTerminal {
        /// The offending state.
        state: RequestState,
    },
    /// Underlying store failure.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl QueueError {
    /// Stable refusal cause for the daemon response.
    #[must_use]
    pub fn cause(&self) -> &'static str {
        match self {
            Self::LegacyQueueOversized => "legacy_queue_oversized",
            Self::Expired => "deadline_exceeded",
            Self::NotAdmitted => "admission_invalid",
            Self::Capacity { cause, .. } => cause,
            Self::NotTerminal { .. } | Self::Store(_) => "internal_error",
        }
    }

    /// Caller recovery without retrying denied work in a loop.
    #[must_use]
    pub fn recovery(&self) -> &'static str {
        match self {
            Self::LegacyQueueOversized => {
                "Stop PAM and back up its state database; operator repair of the oversized legacy queued row is required before restart."
            }
            Self::Expired => "Submit a fresh request with enough time for the authorized work.",
            Self::Capacity { .. } => {
                "Wait for active work to finish or cancel an existing request, then retry."
            }
            Self::NotAdmitted => "Submit a fresh request through PAM admission.",
            Self::NotTerminal { .. } | Self::Store(_) => {
                "Inspect the PAM daemon status and audit before retrying."
            }
        }
    }
}

/// One request waiting in a lane.
struct QueuedEntry {
    id: String,
    /// Fixed expiry converted to a monotonic deadline when admitted to a lane.
    deadline: Instant,
}

/// A checkpoint waiting outside ready lanes while retaining its admission.
struct ParkedEntry {
    repo: String,
    entry: QueuedEntry,
    resume_at_ms: i64,
}

/// An outstanding lease.
struct Lease {
    repo: String,
    deadline: Instant,
    cancel_tx: watch::Sender<bool>,
}

/// The in-memory queue state, all guarded by one mutex.
#[derive(Default)]
struct Inner {
    /// repo → queued request entries, oldest first.
    lanes: HashMap<String, VecDeque<QueuedEntry>>,
    /// request id → its outstanding lease.
    leases: HashMap<String, Lease>,
    /// repo → the leased request id keeping the lane busy.
    busy: HashMap<String, String>,
    /// Original request id → durable watch waiting for its next poll.
    parked: HashMap<String, ParkedEntry>,
    /// Terminal parked tickets whose original waiting caller must be finished.
    parked_terminals: Vec<String>,
}

/// The queue manager service. See the module docs for the design.
pub struct QueueManager {
    store: Arc<Store>,
    inner: Mutex<Inner>,
    work: Notify,
}

impl std::fmt::Debug for QueueManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueueManager").finish_non_exhaustive()
    }
}

impl QueueManager {
    /// Builds an empty queue manager over `store`. Call
    /// [`Self::rebuild_from_store`] afterwards to restore lanes on boot.
    #[must_use]
    pub fn new(store: Arc<Store>) -> Self {
        Self {
            store,
            inner: Mutex::new(Inner::default()),
            work: Notify::new(),
        }
    }

    /// Admits `envelope` (classified as `class`) into the queue: dedupe
    /// check plus `request` row insert, but **no** lane placement — the
    /// caller gates the admitted request first, then calls
    /// [`Self::place_in_lane`] (see the module docs on admission vs
    /// placement).
    ///
    /// Read-only capabilities bypass lanes and dedupe entirely (see the
    /// module docs for the bypass row semantics).
    pub async fn admit(
        &self,
        envelope: &Envelope,
        class: crate::policy::CapabilityClass,
    ) -> Result<AdmitOutcome, QueueError> {
        let args_json = envelope.args.to_string();
        let _inner = self.inner.lock().await;
        let now = wall_clock_ms();
        let duration = clamp_lease(envelope.deadline_ms);
        if duration.is_zero() {
            return Err(QueueError::Expired);
        }
        let expires_at_ms =
            now.saturating_add(i64::try_from(duration.as_millis()).unwrap_or(i64::MAX));
        if class != crate::policy::CapabilityClass::ReadOnly {
            let existing = self
                .store
                .find_admitted_by_shape(
                    &envelope.capability,
                    &envelope.caller.repo,
                    &args_json,
                    envelope.idempotency_key.as_deref(),
                    now,
                )
                .await?;
            if let Some(row) = existing {
                return Ok(AdmitOutcome::Attached {
                    existing_request_id: row.id,
                });
            }
        }
        let (count, bytes) = self.store.admission_usage().await?;
        if count >= MAX_ADMITTED_REQUESTS {
            return Err(QueueError::Capacity {
                cause: "queue_count_limit",
                maximum: MAX_ADMITTED_REQUESTS,
            });
        }
        let incoming = [
            &envelope.id,
            &envelope.capability,
            &envelope.caller.repo,
            &envelope.caller.agent,
            &args_json,
        ]
        .iter()
        .map(|v| v.len() as u64)
        .sum::<u64>()
        .saturating_add(
            envelope
                .idempotency_key
                .as_ref()
                .map_or(0, |v| v.len() as u64),
        );
        if bytes.saturating_add(incoming) > MAX_ADMITTED_BYTES {
            return Err(QueueError::Capacity {
                cause: "queue_bytes_limit",
                maximum: MAX_ADMITTED_BYTES,
            });
        }
        self.store
            .insert_admitted_request(
                &envelope.id,
                &envelope.capability,
                &envelope.caller.repo,
                &envelope.caller.agent,
                &args_json,
                envelope.idempotency_key.as_deref(),
                expires_at_ms,
            )
            .await?;
        Ok(if class == crate::policy::CapabilityClass::ReadOnly {
            AdmitOutcome::Bypass
        } else {
            AdmitOutcome::Admitted
        })
    }

    /// Places an admitted (and gate-allowed) request onto `repo`'s lane,
    /// preserving the expiry recorded at admission. The deadline argument cannot
    /// extend it. Returns the number of requests already waiting
    /// ahead of it (0 = lane head; a currently leased request is not
    /// counted).
    pub async fn place_in_lane(
        &self,
        request_id: &str,
        repo: &str,
        _deadline_ms: u64,
    ) -> Result<usize, QueueError> {
        let mut inner = self.inner.lock().await;
        let row = self
            .store
            .get_request(request_id)
            .await?
            .ok_or(QueueError::NotAdmitted)?;
        let expires = row.expires_at_ms.ok_or(QueueError::NotAdmitted)?;
        let remaining = expires.saturating_sub(wall_clock_ms());
        if remaining <= 0 {
            return Err(QueueError::Expired);
        }
        if !self
            .store
            .authorize_queued_request(request_id, repo, wall_clock_ms())
            .await?
        {
            return Err(QueueError::NotAdmitted);
        }
        let lane = inner.lanes.entry(repo.to_owned()).or_default();
        let position = lane.len();
        lane.push_back(QueuedEntry {
            id: request_id.to_owned(),
            deadline: Instant::now() + Duration::from_millis(u64::try_from(remaining).unwrap_or(0)),
        });
        Ok(position)
    }

    /// Repos whose lane has waiting work and no outstanding lease — the
    /// lanes a [`Self::take_next`] call would currently serve. The
    /// executor loop polls this to know where to look.
    pub async fn ready_repos(&self) -> Vec<String> {
        let inner = self.inner.lock().await;
        inner
            .lanes
            .keys()
            .filter(|repo| !inner.busy.contains_key(*repo))
            .cloned()
            .collect()
    }

    /// Takes the next request from `repo`'s lane under a fresh lease, or
    /// `None` when the lane is empty or already has a leased request
    /// (one running per lane is the serialization guarantee).
    ///
    /// The request row is moved to `running` before the lease is handed
    /// out.
    pub async fn take_next(&self, repo: &str) -> Result<Option<LeasedWork>, QueueError> {
        let mut inner = self.inner.lock().await;
        if inner.busy.contains_key(repo) {
            return Ok(None);
        }
        // Capacity is reserved before any terminal write; admission remains in
        // its lane on every database failure or notification backpressure.
        let Some(entry) = inner.lanes.get(repo).and_then(VecDeque::front) else {
            return Ok(None);
        };
        let entry = QueuedEntry {
            id: entry.id.clone(),
            deadline: entry.deadline,
        };
        let cause = if entry.deadline <= Instant::now() {
            Some(CAUSE_LEASE_EXPIRED)
        } else if self
            .store
            .start_queued_request(&entry.id, wall_clock_ms())
            .await?
        {
            None
        } else if self
            .store
            .request_admission_expired(&entry.id, wall_clock_ms())
            .await?
        {
            Some(CAUSE_LEASE_EXPIRED)
        } else {
            Some("authorization_changed")
        };
        if let Some(cause) = cause {
            if inner.parked_terminals.len() >= MAX_PARKED_TERMINALS {
                self.work.notify_one();
                return Ok(None);
            }
            let finished = self.fail_recovered(&entry.id, cause).await?;
            if let Some(lane) = inner.lanes.get_mut(repo) {
                lane.pop_front();
            }
            if inner.lanes.get(repo).is_some_and(VecDeque::is_empty) {
                inner.lanes.remove(repo);
            }
            if finished {
                inner.parked_terminals.push(entry.id);
                self.work.notify_one();
            }
            return Ok(None);
        }
        if let Some(lane) = inner.lanes.get_mut(repo) {
            lane.pop_front();
        }
        if inner.lanes.get(repo).is_some_and(VecDeque::is_empty) {
            inner.lanes.remove(repo);
        }

        let (cancel_tx, cancel) = watch::channel(false);
        let lease_deadline = entry.deadline;
        let request_id = entry.id;
        inner.leases.insert(
            request_id.clone(),
            Lease {
                repo: repo.to_owned(),
                deadline: lease_deadline,
                cancel_tx,
            },
        );
        inner.busy.insert(repo.to_owned(), request_id.clone());
        Ok(Some(LeasedWork {
            request_id,
            lease_deadline,
            cancel,
        }))
    }

    /// Ids of every outstanding lease — the in-flight work a graceful
    /// drain waits for (and, past the drain bound, cancels).
    pub async fn leased_ids(&self) -> Vec<String> {
        let inner = self.inner.lock().await;
        inner.leases.keys().cloned().collect()
    }

    /// Wait for a parked request becoming ready or releasing its repository lane.
    /// The executor selects this alongside its existing admission notification.
    pub async fn work_available(&self) {
        self.work.notified().await;
    }

    /// Drain bounded terminal notices for the executor to publish and finish
    /// through the original ticket's router. Explicit cancellation is separate.
    pub async fn take_parked_terminals(&self) -> Vec<String> {
        let mut inner = self.inner.lock().await;
        std::mem::take(&mut inner.parked_terminals)
    }

    /// Persist a future poll before releasing the current lease. Failure leaves
    /// lease ownership intact; parked admissions still count against store caps.
    pub async fn park(&self, request_id: &str, resume_at_ms: i64) -> Result<bool, QueueError> {
        let mut inner = self.inner.lock().await;
        let Some(lease) = inner.leases.get(request_id) else {
            return Ok(false);
        };
        if lease.deadline <= Instant::now() || *lease.cancel_tx.borrow() {
            return Ok(false);
        }
        let repo = lease.repo.clone();
        let deadline = lease.deadline;
        if !self
            .store
            .park_flow_request(request_id, resume_at_ms, wall_clock_ms())
            .await?
        {
            return Ok(false);
        }
        inner.leases.remove(request_id);
        inner.busy.remove(&repo);
        inner.parked.insert(
            request_id.to_owned(),
            ParkedEntry {
                repo,
                entry: QueuedEntry {
                    id: request_id.to_owned(),
                    deadline,
                },
                resume_at_ms,
            },
        );
        self.work.notify_one();
        Ok(true)
    }

    /// Move due parked checkpoints into ordinary lanes, retaining the original
    /// monotonic expiry. Authorization changes and expiry fail without dispatch.
    pub async fn wake_due(&self, now: Instant, now_ms: i64) -> Result<usize, QueueError> {
        let mut inner = self.inner.lock().await;
        let mut due: Vec<_> = inner
            .parked
            .iter()
            .filter(|(_, parked)| parked.entry.deadline <= now || parked.resume_at_ms <= now_ms)
            .map(|(id, parked)| (parked.resume_at_ms, id.clone()))
            .collect();
        due.sort();
        let mut ready = 0;
        for (_, id) in due {
            // Retain admissions until the executor has consumed older notices.
            // Never terminalize a parked request whose notification cannot fit.
            if inner.parked_terminals.len() >= MAX_PARKED_TERMINALS {
                self.work.notify_one();
                break;
            }
            let Some(parked) = inner.parked.get(&id) else {
                continue;
            };
            if parked.entry.deadline <= now {
                if self.expire_locked(&mut inner, &id).await? {
                    inner.parked_terminals.push(id);
                    self.work.notify_one();
                }
                continue;
            }
            if !self.store.wake_parked_flow_request(&id, now_ms).await? {
                let cause = if self.store.request_admission_expired(&id, now_ms).await? {
                    CAUSE_LEASE_EXPIRED
                } else {
                    "authorization_changed"
                };
                let finished = self.fail_recovered(&id, cause).await?;
                inner.parked.remove(&id);
                if finished {
                    inner.parked_terminals.push(id);
                    self.work.notify_one();
                }
                continue;
            }
            let Some(parked) = inner.parked.remove(&id) else {
                continue;
            };
            inner
                .lanes
                .entry(parked.repo)
                .or_default()
                .push_back(parked.entry);
            ready += 1;
            // A later store failure must not strand work already made ready.
            self.work.notify_one();
        }
        Ok(ready)
    }

    /// Releases `request_id`'s lease and records its terminal
    /// `final_state` / `outcome` together with the executor's `audit`
    /// row (one transaction, via [`Store::finish_request`]), freeing the
    /// lane for the next request.
    ///
    /// Returns `true` when the lease was still held and the terminal
    /// state was written; `false` when the lease was already gone
    /// (reaped or cancelled after the executor finished) or the row was
    /// already terminal — the row and audit trail are left alone, since
    /// whoever finished first already recorded the terminal state.
    pub async fn complete(
        &self,
        request_id: &str,
        final_state: RequestState,
        outcome: Option<&str>,
        audit: AuditEntry<'_>,
    ) -> Result<bool, QueueError> {
        if !final_state.is_terminal() {
            return Err(QueueError::NotTerminal { state: final_state });
        }
        let mut inner = self.inner.lock().await;
        let Some(lease) = inner.leases.get(request_id) else {
            return Ok(false);
        };
        let repo = lease.repo.clone();
        // A failed terminal write must retain ownership so completion can be
        // retried or reaped; it is not evidence that another writer finished.
        let finished = self
            .store
            .finish_request(request_id, final_state, outcome, audit)
            .await?;
        inner.leases.remove(request_id);
        inner.busy.remove(&repo);
        Ok(finished)
    }

    /// Cancels `request_id` on behalf of `actor` (see the module docs
    /// for who passes what). Queued requests are cancelled outright and
    /// audited here; running requests are signalled cooperatively and
    /// reach their terminal state through the executor.
    pub async fn cancel(
        &self,
        request_id: &str,
        actor: Actor,
    ) -> Result<CancelOutcome, QueueError> {
        let mut inner = self.inner.lock().await;
        if let Some(lease) = inner.leases.get(request_id) {
            // Receiver may already be dropped; the signal is best-effort
            // and the reaper backstops a holder that never listens.
            let _ = lease.cancel_tx.send(true);
            return Ok(CancelOutcome::SignalledRunning);
        }
        let found = inner.parked.contains_key(request_id)
            || inner
                .lanes
                .values()
                .any(|lane| lane.iter().any(|entry| entry.id == request_id));
        if !found {
            return Ok(CancelOutcome::NotFound);
        }
        let detail = serde_json::json!({ "actor": actor.as_str() }).to_string();
        self.store
            .finish_request(
                request_id,
                RequestState::Failed,
                Some(CAUSE_CANCELLED),
                AuditEntry {
                    action: ACTION_CANCEL,
                    decision: Decision::Deny,
                    actor,
                    detail: Some(&detail),
                },
            )
            .await?;
        inner.parked.remove(request_id);
        for lane in inner.lanes.values_mut() {
            lane.retain(|entry| entry.id != request_id);
        }
        inner.lanes.retain(|_, lane| !lane.is_empty());
        Ok(CancelOutcome::CancelledQueued)
    }

    /// Reaps every lease whose deadline is at or before `now`: the
    /// request becomes terminal `failed` (cause [`CAUSE_LEASE_EXPIRED`]),
    /// an audit row is written (action [`ACTION_LEASE_REAPED`], decision
    /// `timeout`, actor `system`), the holder's cancel signal fires, and
    /// the lane is freed. Returns the reaped request ids.
    pub async fn reap_expired(&self, now: Instant) -> Result<Vec<String>, QueueError> {
        let mut inner = self.inner.lock().await;
        let expired: Vec<String> = inner
            .leases
            .iter()
            .filter(|(_, lease)| lease.deadline <= now)
            .map(|(id, _)| id.clone())
            .collect();
        let mut reaped = Vec::with_capacity(expired.len());
        for id in expired {
            if self.expire_locked(&mut inner, &id).await? {
                reaped.push(id);
            }
        }
        Ok(reaped)
    }

    /// Finish an admitted request whose absolute deadline elapsed. Both the
    /// original waiter and lease reaper use the same durable timeout cause.
    /// Explicit user cancellation continues through [`Self::cancel`].
    pub async fn expire(&self, request_id: &str) -> Result<bool, QueueError> {
        let mut inner = self.inner.lock().await;
        self.expire_locked(&mut inner, request_id).await
    }

    async fn expire_locked(&self, inner: &mut Inner, request_id: &str) -> Result<bool, QueueError> {
        let detail = serde_json::json!({ "cause": "timeout" }).to_string();
        // Persist first: a store failure must leave ownership intact for retry.
        // The queue mutex excludes executor completion until this terminal write.
        let finished = self
            .store
            .finish_request(
                request_id,
                RequestState::Failed,
                Some(CAUSE_LEASE_EXPIRED),
                AuditEntry {
                    action: ACTION_LEASE_REAPED,
                    decision: Decision::Timeout,
                    actor: Actor::System,
                    detail: Some(&detail),
                },
            )
            .await?;
        if let Some(lease) = inner.leases.remove(request_id) {
            inner.busy.remove(&lease.repo);
            let _ = lease.cancel_tx.send(true);
        }
        for lane in inner.lanes.values_mut() {
            lane.retain(|entry| entry.id != request_id);
        }
        inner.lanes.retain(|_, lane| !lane.is_empty());
        inner.parked.remove(request_id);
        Ok(finished)
    }

    /// Background-only expiry delivery. Explicit `reap_expired` callers own
    /// their returned ids; this path reserves notice capacity before releasing
    /// leases whose executor may already have exited after a store failure.
    pub(crate) async fn reap_expired_notifying(&self, now: Instant) -> Result<usize, QueueError> {
        let mut inner = self.inner.lock().await;
        let mut expired: Vec<_> = inner
            .leases
            .iter()
            .filter(|(_, lease)| lease.deadline <= now)
            .map(|(id, _)| id.clone())
            .collect();
        expired.sort();
        let mut count = 0;
        for id in expired {
            if inner.parked_terminals.len() >= MAX_PARKED_TERMINALS {
                self.work.notify_one();
                break;
            }
            if self.expire_locked(&mut inner, &id).await? {
                inner.parked_terminals.push(id);
                count += 1;
                self.work.notify_one();
            }
        }
        Ok(count)
    }

    /// Spawns the background reaper: calls [`Self::reap_expired`] every
    /// `interval` until `shutdown` changes (or its sender drops).
    ///
    /// A store failure during one sweep is swallowed and retried on the
    /// next tick — the daemon's tracing setup (a later task) will log it.
    pub fn run_reaper(
        self: Arc<Self>,
        interval: Duration,
        mut shutdown: watch::Receiver<bool>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let _ = self.reap_expired_notifying(Instant::now()).await;
                        let _ = self.wake_due(Instant::now(), wall_clock_ms()).await;
                    }
                    _ = shutdown.changed() => break,
                }
            }
        })
    }

    /// Rebuilds every lane from the store's `queued` rows, oldest first,
    /// replacing the in-memory lanes. Missing authorization or expiry fails closed;
    /// restored entries retain only the time remaining on their original deadline.
    /// Reads keyset pages bounded by row count and aggregate text bytes. An
    /// oversized legacy row stops startup for operator backup/repair; recovery
    /// does not fetch or silently delete its payload.
    ///
    /// Crash recovery of `running` / `waiting_approval` rows left behind
    /// by a dead daemon is task #12, not handled here.
    pub async fn rebuild_from_store(&self) -> Result<usize, QueueError> {
        let mut inner = self.inner.lock().await;
        inner.lanes.clear();
        inner.parked.clear();
        let revision = self.store.grant_revocation_revision().await?;
        let mut restored = 0;
        let mut retained_bytes = 0u64;
        let mut after: Option<(i64, String)> = None;
        loop {
            let queued = self
                .store
                .queued_recovery_page(
                    after.as_ref().map(|(ts, id)| (*ts, id.as_str())),
                    MAX_ADMITTED_BYTES,
                )
                .await?
                .ok_or(QueueError::LegacyQueueOversized)?;
            let Some(last) = queued.last() else { break };
            after = Some((last.created_ts, last.id.clone()));
            for row in queued {
                let remaining = row
                    .expires_at_ms
                    .map_or(0, |expires| expires.saturating_sub(wall_clock_ms()));
                let bytes = [
                    &row.id,
                    &row.capability,
                    &row.repo,
                    &row.caller_agent,
                    &row.args_json,
                ]
                .iter()
                .map(|v| v.len() as u64)
                .sum::<u64>()
                .saturating_add(row.idempotency_key.as_ref().map_or(0, |v| v.len() as u64));
                let cause = if !row.queue_authorized || row.expires_at_ms.is_none() {
                    Some("admission_invalid")
                } else if row.authorization_revision != Some(revision) {
                    Some("authorization_changed")
                } else if remaining <= 0 {
                    Some(CAUSE_LEASE_EXPIRED)
                } else if restored >= MAX_ADMITTED_REQUESTS
                    || retained_bytes.saturating_add(bytes) > MAX_ADMITTED_BYTES
                {
                    Some("queue_recovery_limit")
                } else {
                    None
                };
                if let Some(cause) = cause {
                    self.fail_recovered(&row.id, cause).await?;
                    continue;
                }
                if row.resume_at_ms.is_some()
                    && !self
                        .store
                        .validate_parked_flow_request(&row.id, wall_clock_ms())
                        .await?
                {
                    self.fail_recovered(&row.id, "admission_invalid").await?;
                    continue;
                }
                retained_bytes += bytes;
                restored += 1;
                restore_queued_entry(&mut inner, row, remaining);
            }
        }
        Ok(usize::try_from(restored).unwrap_or(usize::MAX))
    }

    async fn fail_recovered(&self, id: &str, cause: &str) -> Result<bool, StoreError> {
        self.store
            .finish_request(
                id,
                RequestState::Failed,
                Some(cause),
                AuditEntry {
                    action: ACTION_LEASE_REAPED,
                    decision: Decision::Refuse,
                    actor: Actor::System,
                    detail: Some(cause),
                },
            )
            .await
    }
}

/// The lease duration an envelope deadline earns, clamped to
/// [`MAX_LEASE`]. The pipeline validates `deadline_ms` before enqueue, so
/// no lower bound is applied here.
fn clamp_lease(deadline_ms: u64) -> Duration {
    Duration::from_millis(deadline_ms).min(MAX_LEASE)
}

fn wall_clock_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Restore the bounded index without replacing the persisted poll/deadline times.
fn restore_queued_entry(inner: &mut Inner, row: pam_store::RequestRow, remaining: i64) {
    let entry = QueuedEntry {
        id: row.id.clone(),
        deadline: Instant::now() + Duration::from_millis(u64::try_from(remaining).unwrap_or(0)),
    };
    if let Some(resume_at_ms) = row.resume_at_ms {
        inner.parked.insert(
            row.id,
            ParkedEntry {
                repo: row.repo,
                entry,
                resume_at_ms,
            },
        );
    } else {
        inner.lanes.entry(row.repo).or_default().push_back(entry);
    }
}
