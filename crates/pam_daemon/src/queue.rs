//! Queue manager: per-repo ordered lanes, executor leases, cancellation,
//! and in-flight deduplication.
//!
//! # Design
//!
//! Lanes serialize work **per repo** — one leased request per lane at a
//! time — while different repos run in parallel. The lanes are an
//! in-memory index over the `request` table: the table is the durable
//! truth (state `queued`), so [`QueueManager::rebuild_from_store`]
//! reconstructs every lane on boot. Read-only capabilities never enter a
//! lane at all ([`AdmitOutcome::Bypass`]).
//!
//! # Bypass row semantics
//!
//! A read-only bypass still inserts a `request` row — the audit trail and
//! the GUI activity feed need every request on record — but the row is
//! born `queued` and immediately moved to `running`, and its id is never
//! pushed into a lane. The caller executes it straight away and records
//! the terminal state itself.
//!
//! # Admission vs placement
//!
//! Admission is split in two so the policy gate can run in between with
//! every contract intact ([`PolicyGate::evaluate`] needs the `request`
//! row to exist; the spec wants the gate before enqueue):
//!
//! 1. [`QueueManager::admit`] — dedupe check + `request` row insert
//!    (state `queued`), atomically under the internal mutex.
//! 2. [`QueueManager::place_in_lane`] — pushes the admitted request onto
//!    its repo's lane, once the gate has allowed it.
//!
//! A gate refusal between the two moves the row straight to `refused`;
//! the id never reaches a lane. A concurrent duplicate arriving in that
//! window attaches to the admitted request and is forwarded whatever
//! terminal response it gets — refusals included — which is exactly what
//! running the duplicate itself would have produced.
//!
//! [`PolicyGate::evaluate`]: crate::policy::PolicyGate::evaluate
//!
//! # Deduplication
//!
//! Before inserting a laned request, the manager looks for an *in-flight*
//! duplicate (state `queued`, `running`, or `waiting_approval`): by
//! `idempotency_key` when the envelope carries one, otherwise by shape —
//! byte equality of capability + repo + serialized args (deterministic:
//! `serde_json` serializes maps with sorted keys). A hit returns
//! [`AdmitOutcome::Attached`] naming the existing request; the caller
//! subscribes to that request's events and result instead of starting a
//! second execution. Terminal requests never match, so retries after
//! completion run fresh. The internal mutex is held across the
//! check-then-insert, so concurrent admissions cannot both miss the
//! check.
//!
//! # Leases
//!
//! [`QueueManager::take_next`] hands work out under a lease: the request
//! is marked `running` and gets a deadline derived from the envelope's
//! `deadline_ms`, clamped to [`MAX_LEASE`]. A lease that outlives its
//! deadline is reaped ([`QueueManager::reap_expired`], driven
//! periodically by [`QueueManager::run_reaper`]): the request becomes
//! terminal `failed` with cause [`CAUSE_LEASE_EXPIRED`], an audit row
//! (action [`ACTION_LEASE_REAPED`], decision `timeout`, actor `system`)
//! is written, the holder's cancel signal fires, and the lane is freed.
//!
//! # Cancellation
//!
//! [`QueueManager::cancel`] serves both `pam cancel <ticket>` and the
//! GUI; the caller passes the [`Actor`] the cancellation acts as (the
//! GUI passes [`Actor::Human`]; the CLI passes whatever identity the
//! pipeline assigns the ticket holder). A queued request is cancelled
//! outright: removed from its lane, terminal `failed` with cause
//! [`CAUSE_CANCELLED`], audited (action [`ACTION_CANCEL`], decision
//! `deny`). A running request is signalled cooperatively — the lease's
//! cancel signal flips and the executor finishes through
//! [`QueueManager::complete`]; its terminal write and audit happen on
//! that path.
//!
//! # Audit invariant
//!
//! Every terminal transition the queue performs — queued-cancellation,
//! lease reaping, and executor completion via [`QueueManager::complete`]
//! (which takes the executor's audit fields) — goes through
//! [`Store::finish_request`], the store-level choke point that writes
//! the terminal state and its audit row in one transaction. The queue
//! never calls `update_request_state` with a terminal state, and
//! `finish_request`'s already-terminal guard makes double-finish races
//! (reaper vs executor) a first-wins no-op with no duplicate audit row.
//!
//! # Concurrency
//!
//! One `QueueManager` behind `&self` with a single `tokio::sync::Mutex`
//! over the in-memory maps — the daemon is a monolith with low
//! contention, and no lock is ever held across an `.await` that waits on
//! anything but the store. There are no lane worker tasks here; the
//! executor loop (task #9) drives [`QueueManager::take_next`] /
//! [`QueueManager::complete`].
//!
//! # Boot
//!
//! [`QueueManager::rebuild_from_store`] reloads `queued` rows into lanes,
//! oldest first. Crash recovery of `running` / `waiting_approval` rows
//! left by a dead daemon (fail with cause `daemon_restart`) is task #12
//! and deliberately not handled here.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use pam_proto::Envelope;
use pam_store::{Actor, AuditEntry, Decision, RequestState, Store, StoreError};
use thiserror::Error;
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

/// Upper bound on any lease: an envelope `deadline_ms` beyond this is
/// clamped. Also the lease budget for requests rebuilt from the store,
/// whose original deadline is not persisted.
pub const MAX_LEASE: Duration = Duration::from_hours(1);

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
    /// A new request row was inserted in state `queued`. The caller gates
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

/// One request waiting in a lane.
struct QueuedEntry {
    id: String,
    /// Lease duration granted when the entry is taken, derived from the
    /// envelope's `deadline_ms` (clamped to [`MAX_LEASE`]).
    lease_budget: Duration,
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
}

/// The queue manager service. See the module docs for the design.
pub struct QueueManager {
    store: Arc<Store>,
    inner: Mutex<Inner>,
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
        if class == crate::policy::CapabilityClass::ReadOnly {
            // Bypass: on record for the audit trail, never in a lane.
            self.insert_row(envelope, &args_json).await?;
            self.store
                .update_request_state(&envelope.id, RequestState::Running, None)
                .await?;
            return Ok(AdmitOutcome::Bypass);
        }

        // The lock spans dedupe-check + insert so two concurrent
        // duplicates cannot both miss the check and both insert.
        let _inner = self.inner.lock().await;
        let existing = match &envelope.idempotency_key {
            Some(key) => self.store.find_inflight_by_key(key).await?,
            None => {
                self.store
                    .find_inflight_by_shape(&envelope.capability, &envelope.caller.repo, &args_json)
                    .await?
            }
        };
        if let Some(row) = existing {
            return Ok(AdmitOutcome::Attached {
                existing_request_id: row.id,
            });
        }

        self.insert_row(envelope, &args_json).await?;
        Ok(AdmitOutcome::Admitted)
    }

    /// Places an admitted (and gate-allowed) request onto `repo`'s lane,
    /// with a lease budget derived from `deadline_ms` (clamped to
    /// [`MAX_LEASE`]). Returns the number of requests already waiting
    /// ahead of it (0 = lane head; a currently leased request is not
    /// counted).
    pub async fn place_in_lane(&self, request_id: &str, repo: &str, deadline_ms: u64) -> usize {
        let mut inner = self.inner.lock().await;
        let lane = inner.lanes.entry(repo.to_owned()).or_default();
        let position = lane.len();
        lane.push_back(QueuedEntry {
            id: request_id.to_owned(),
            lease_budget: clamp_lease(deadline_ms),
        });
        position
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
        let Some(entry) = inner.lanes.get_mut(repo).and_then(VecDeque::pop_front) else {
            return Ok(None);
        };
        if let Err(err) = self
            .store
            .update_request_state(&entry.id, RequestState::Running, None)
            .await
        {
            // Leave the lane as it was so the request is not lost.
            inner
                .lanes
                .entry(repo.to_owned())
                .or_default()
                .push_front(entry);
            return Err(err.into());
        }
        if inner.lanes.get(repo).is_some_and(VecDeque::is_empty) {
            inner.lanes.remove(repo);
        }

        let (cancel_tx, cancel) = watch::channel(false);
        let lease_deadline = Instant::now() + entry.lease_budget;
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
        let Some(lease) = inner.leases.remove(request_id) else {
            return Ok(false);
        };
        inner.busy.remove(&lease.repo);
        let finished = self
            .store
            .finish_request(request_id, final_state, outcome, audit)
            .await?;
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
        let mut found = false;
        for lane in inner.lanes.values_mut() {
            if let Some(index) = lane.iter().position(|entry| entry.id == request_id) {
                lane.remove(index);
                found = true;
                break;
            }
        }
        if !found {
            return Ok(CancelOutcome::NotFound);
        }
        inner.lanes.retain(|_, lane| !lane.is_empty());
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
            let Some(lease) = inner.leases.remove(&id) else {
                continue;
            };
            inner.busy.remove(&lease.repo);
            // Tell a still-running holder to stop; best-effort.
            let _ = lease.cancel_tx.send(true);
            let detail = serde_json::json!({ "cause": "timeout" }).to_string();
            let finished = self
                .store
                .finish_request(
                    &id,
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
            // An already-terminal row means someone else finished first;
            // the lane is freed either way but nothing was reaped.
            if finished {
                reaped.push(id);
            }
        }
        Ok(reaped)
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
                        let _ = self.reap_expired(Instant::now()).await;
                    }
                    _ = shutdown.changed() => break,
                }
            }
        })
    }

    /// Rebuilds every lane from the store's `queued` rows, oldest first,
    /// replacing the in-memory lanes. Rebuilt entries get [`MAX_LEASE`]
    /// as their lease budget — the envelope's `deadline_ms` is not
    /// persisted. Returns how many requests were restored.
    ///
    /// Crash recovery of `running` / `waiting_approval` rows left behind
    /// by a dead daemon is task #12, not handled here.
    pub async fn rebuild_from_store(&self) -> Result<usize, QueueError> {
        let queued = self.store.list_queued_ordered().await?;
        let mut inner = self.inner.lock().await;
        inner.lanes.clear();
        let restored = queued.len();
        for row in queued {
            inner
                .lanes
                .entry(row.repo)
                .or_default()
                .push_back(QueuedEntry {
                    id: row.id,
                    lease_budget: MAX_LEASE,
                });
        }
        Ok(restored)
    }

    /// Inserts the envelope's `request` row in the `queued` state.
    async fn insert_row(&self, envelope: &Envelope, args_json: &str) -> Result<(), StoreError> {
        self.store
            .insert_request(
                &envelope.id,
                &envelope.capability,
                &envelope.caller.repo,
                &envelope.caller.agent,
                args_json,
                envelope.idempotency_key.as_deref(),
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
