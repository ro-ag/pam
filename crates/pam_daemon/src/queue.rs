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
//!   re-executing. Terminal requests never match, so retries after completion run fresh. The
//!   admission mutex (not the lane lock) is held across check-then-insert so concurrent admissions
//!   cannot both miss the check, and the caps are counted against the rows already inserted.
//! - **Leases**: [`QueueManager::take_next`] marks the request `running` with a deadline from
//!   `deadline_ms`, clamped to [`MAX_LEASE`]. An expired lease is reaped
//!   (`QueueManager::reap_expired_notifying`, driven by [`QueueManager::run_reaper`]): terminal
//!   `failed`/[`CAUSE_LEASE_EXPIRED`], audited ([`ACTION_LEASE_REAPED`], decision `timeout`, actor
//!   `system`), the holder's cancel signal fires, and the lane is freed.
//! - **Drain**: the daemon's graceful stop calls [`QueueManager::stop_leasing`], after which
//!   `take_next` hands out nothing and the lanes keep their `queued` rows for the next boot, and
//!   then waits on [`QueueManager::in_flight_ids`]. That set is the lanes' `busy` holders: the
//!   outstanding leases **and** the lease a `take_next` is granting, whose row is already
//!   `running` before the lease exists. Waiting on the leases alone let a stop that began in that
//!   window close the store under the execution, which then met [`StoreError::Closed`] at its
//!   terminal write and left the row for crash recovery.
//! - **Cancellation**: [`QueueManager::cancel`] serves `pam cancel <ticket>` and the GUI, acting as
//!   the caller-supplied [`Actor`]. The actor is decided by where the request entered the daemon,
//!   never by a label: the `cancel` capability passes [`Actor::Human`] only for a request the
//!   private admin plane submitted ([`crate::ingress::Origin::Admin`], `admin.requests.cancel`) and
//!   [`Actor::System`] for every public `cancel`, whatever its `caller.agent` says; the drain at
//!   shutdown passes [`Actor::System`].
//!   A queued request is removed from its lane and terminal `failed`/[`CAUSE_CANCELLED`], audited
//!   ([`ACTION_CANCEL`], `deny`). A running request is signalled cooperatively via the lease's
//!   cancel signal; its terminal write/audit happen through [`QueueManager::complete`].
//! - **Audit invariant**: every terminal transition the queue performs — queued-cancellation, lease
//!   reaping, executor completion via [`QueueManager::complete`] — goes through
//!   [`Store::finish_request`], the choke point writing terminal state + audit row in one
//!   transaction. The queue never calls `update_request_state` with a terminal state; the
//!   already-terminal guard makes reaper-vs-executor double-finish races a first-wins no-op with no
//!   duplicate audit row.
//! - **Concurrency (the lock invariant)**: one `QueueManager` behind `&self`. Three things guard
//!   it, each for one job, taken in this order and never the other way round:
//!   1. the **admission mutex** (async) serializes [`QueueManager::admit_from`]'s dedupe check,
//!      cap count and row insert, which are store calls; it guards no in-memory state and nothing
//!      else waits on it;
//!   2. the **lane lock** (a synchronous mutex, so it cannot be held across an `.await`) guards
//!      only the in-memory index: lanes, leases, busy lanes, parked checkpoints, terminal notices,
//!      and the claims below. It is held for map updates only, never across store I/O;
//!   3. the **store** guards durable truth: every state change is one store call whose own guard
//!      (`queued` → `running` only from `queued`, the already-terminal refusal, first terminal
//!      write wins) decides a race between two writers.
//!
//!   Every operation that changes a request in the store follows the same three steps: under the
//!   lane lock it decides and **claims** the request (and, for a lease, reserves the lane as busy
//!   and, for a terminal, one terminal-notice slot); it releases the lock and calls the store; it
//!   re-takes the lock and applies the result. A claimed request is owned by its claimant until
//!   it settles: any other operation on the same request waits for the claim to settle and starts
//!   over from what it then sees, so operations on one request are still linearized while every
//!   other lane carries on. The one writer that cannot claim first is the stranded-row
//!   reconciler, whose store sweep chooses its own rows: when it finishes a request that another
//!   operation holds, it marks the claim **withdrawn**, and the claimant, applying its result,
//!   sees the mark and takes the outcome it would have had if the reconciler had run first (no
//!   lease, no lane entry, no parked checkpoint). Apply steps only remove what they own: a lane
//!   is freed only if it is busy with that request, an entry is removed by id, never by
//!   position. A claim dropped mid-call (a cancelled future) releases itself, rolling back its
//!   reservations, and the store guard decides what the interrupted call left behind, exactly as
//!   when the queue held its lock across the call. There are no lane worker tasks — the
//!   executor loop drives [`QueueManager::take_next`]/[`QueueManager::complete`].
//! - **Boot**: [`QueueManager::rebuild_from_store`] reloads `queued` rows into lanes, oldest first.
//!   It runs once at boot, before any other queue operation: its store reads happen without the
//!   lane lock and the rebuilt index replaces the in-memory one in a single locked swap at the end.
//!   Crash recovery of `running`/`waiting_approval` rows left by a dead daemon (failed with cause
//!   `daemon_restart`) happens elsewhere, not here.
//! - **Stranded rows**: a row can outlive every in-memory owner — a terminal write the store
//!   refused, a handler that was cut off, a panic. Such a row is `running` with a deadline in the
//!   past and nothing that will ever finish it. Two things keep it from doing harm: admission
//!   counts only rows whose deadline is still ahead ([`Store::admission_usage_at`]), so a stranded
//!   row cannot hold one of the [`MAX_ADMITTED_REQUESTS`] slots; and
//!   [`QueueManager::reconcile_expired`] (every couple of seconds from the reaper, and once at
//!   boot) fails every
//!   in-flight row whose deadline passed more than the reconcile grace ago, with the lease-expiry
//!   outcome and audit row, drops it from the in-memory index and hands it to the executor loop to
//!   release its waiters. The grace exists so a handler still writing its own verdict a moment
//!   past the deadline wins.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::sync::{Arc, MutexGuard, PoisonError};
use std::time::Duration;

use pam_proto::Envelope;
use pam_store::{Actor, AuditEntry, Decision, RequestOrigin, RequestState, Store, StoreError};
use thiserror::Error;
use tokio::sync::{Mutex, Notify, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

use crate::request_state::{self, RequestEvent};

/// Upper bound on any lease: an envelope `deadline_ms` beyond this is
/// clamped. Admission persists the absolute expiry for placement and recovery.
pub const MAX_LEASE: Duration = Duration::from_hours(1);
/// Global active admission cap, including approval waits and read-only bypasses.
pub const MAX_ADMITTED_REQUESTS: u64 = 128;
/// Maximum cumulative persisted identity and argument bytes for active admissions.
pub const MAX_ADMITTED_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum parked terminal tickets waiting for executor/router notification.
pub const MAX_PARKED_TERMINALS: usize = 128;
/// How often the reaper runs the stranded-row sweep.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(2);
/// How long past its deadline an in-flight row is left alone before
/// [`QueueManager::reconcile_expired`] fails it, unless the daemon sets
/// another ([`QueueManager::with_reconcile_grace`]). It must exceed the
/// handler grace so a handler that is merely late writes its own verdict.
pub const DEFAULT_RECONCILE_GRACE: Duration = Duration::from_secs(45);

/// `request.outcome` recorded when a queued request is cancelled.
pub const CAUSE_CANCELLED: &str = "cancelled";

/// `request.outcome` recorded when a lease outlives its deadline.
pub const CAUSE_LEASE_EXPIRED: &str = "lease_expired";

/// `audit.action` for a cancellation the queue performed.
pub const ACTION_CANCEL: &str = "cancel";

/// `audit.action` for a lease the reaper collected.
pub const ACTION_LEASE_REAPED: &str = "lease_reaped";

/// `audit.action` for a queued row boot recovery refused to restore
/// (`authorization_changed`, `admission_invalid`, `queue_recovery_limit`):
/// nothing timed out, so it is not a reaped lease.
pub const ACTION_RECOVERY_REFUSAL: &str = "recovery_refusal";

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
            // The store refusing on purpose (its queue bound, the shutdown)
            // has a cause of its own; the detail is the store's sentence.
            Self::Store(error) => crate::daemon::store_refusal_cause(error)
                .map_or("internal_error", |(cause, _)| cause),
            Self::NotTerminal { .. } => "internal_error",
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
            Self::Store(error) => crate::daemon::store_refusal_cause(error).map_or(
                "Inspect the PAM daemon status and audit before retrying.",
                |(_, recovery)| recovery,
            ),
            Self::NotTerminal { .. } => "Inspect the PAM daemon status and audit before retrying.",
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

/// The in-memory queue index, all guarded by the lane lock (see the module
/// docs on the lock invariant).
#[derive(Default)]
struct Inner {
    /// repo → queued request entries, oldest first.
    lanes: HashMap<String, VecDeque<QueuedEntry>>,
    /// request id → its outstanding lease.
    leases: HashMap<String, Lease>,
    /// repo → the leased request id keeping the lane busy, or the request a
    /// claim is about to lease.
    busy: HashMap<String, String>,
    /// Original request id → durable watch waiting for its next poll.
    parked: HashMap<String, ParkedEntry>,
    /// Terminal parked tickets whose original waiting caller must be finished.
    parked_terminals: Vec<String>,
    /// Requests an operation is changing in the store right now.
    claimed: HashSet<String>,
    /// Claimed requests the reconciler finished while their claimant was in
    /// the store.
    withdrawn: HashSet<String>,
    /// Terminal-notice slots promised to operations that are in the store.
    reserved_terminals: usize,
    /// Set by [`QueueManager::stop_leasing`]: no further lease is handed
    /// out, the lanes keep their `queued` rows for the next boot.
    draining: bool,
}

impl Inner {
    /// Room left for terminal notices, counting the slots already promised.
    fn terminal_room(&self) -> usize {
        MAX_PARKED_TERMINALS
            .saturating_sub(self.parked_terminals.len())
            .saturating_sub(self.reserved_terminals)
    }

    /// Frees `repo`'s lane if, and only if, `request_id` keeps it busy.
    fn free_lane(&mut self, repo: &str, request_id: &str) {
        if self
            .busy
            .get(repo)
            .is_some_and(|holder| holder == request_id)
        {
            self.busy.remove(repo);
        }
    }

    /// Removes `request_id`'s entry from `repo`'s lane by id (never by
    /// position), dropping the lane once it is empty.
    fn remove_from_lane(&mut self, repo: &str, request_id: &str) {
        if let Some(lane) = self.lanes.get_mut(repo) {
            lane.retain(|entry| entry.id != request_id);
            if lane.is_empty() {
                self.lanes.remove(repo);
            }
        }
    }

    /// Drops every in-memory trace of a request that is now terminal: its
    /// lease (signalling the holder and freeing its lane), its lane entry and
    /// its parked checkpoint.
    fn forget(&mut self, request_id: &str) {
        if let Some(lease) = self.leases.remove(request_id) {
            self.free_lane(&lease.repo, request_id);
            let _ = lease.cancel_tx.send(true);
        }
        for lane in self.lanes.values_mut() {
            lane.retain(|entry| entry.id != request_id);
        }
        self.lanes.retain(|_, lane| !lane.is_empty());
        self.parked.remove(request_id);
    }
}

/// What one operation holds while it is in the store with the lane lock
/// released (see the module docs on claims). Settled under the lock when
/// the result is applied; dropped unsettled (an error or a cancelled
/// future), it settles itself and rolls its reservations back.
struct Claim<'q> {
    queue: &'q QueueManager,
    /// The claimed request; `None` for the reconciler, which only reserves
    /// notice slots.
    id: Option<String>,
    /// A lane this claim reserved as busy for the lease it is handing out.
    lane: Option<String>,
    /// Terminal-notice slots promised to this claim.
    slots: usize,
    settled: bool,
}

impl<'q> Claim<'q> {
    /// Claims `id`, which the caller has just seen unclaimed under `inner`.
    fn on(queue: &'q QueueManager, inner: &mut Inner, id: &str) -> Self {
        inner.claimed.insert(id.to_owned());
        Self {
            queue,
            id: Some(id.to_owned()),
            lane: None,
            slots: 0,
            settled: false,
        }
    }

    /// Promises `slots` terminal-notice slots and claims no request.
    fn slots(queue: &'q QueueManager, inner: &mut Inner, slots: usize) -> Self {
        inner.reserved_terminals += slots;
        Self {
            queue,
            id: None,
            lane: None,
            slots,
            settled: false,
        }
    }

    /// Keeps `repo`'s lane busy for the claimed request until it is leased
    /// or the claim settles without a lease.
    fn reserve_lane(&mut self, inner: &mut Inner, repo: &str) {
        if let Some(id) = &self.id {
            inner.busy.insert(repo.to_owned(), id.clone());
            self.lane = Some(repo.to_owned());
        }
    }

    /// Promises one terminal-notice slot to this claim.
    fn reserve_slot(&mut self, inner: &mut Inner) {
        inner.reserved_terminals += 1;
        self.slots += 1;
    }

    /// The reserved lane now belongs to a lease: settling keeps it busy.
    fn keep_lane(&mut self) {
        self.lane = None;
    }

    /// Whether the reconciler finished the claimed request while it was in
    /// the store.
    fn withdrawn(&self, inner: &Inner) -> bool {
        self.id
            .as_ref()
            .is_some_and(|id| inner.withdrawn.contains(id))
    }

    /// Releases what the claim still holds, under the lock: the claim and
    /// its withdrawn mark, a lane reservation that did not become a lease,
    /// and the promised notice slots.
    fn settle(&mut self, inner: &mut Inner) {
        if self.settled {
            return;
        }
        self.settled = true;
        if let Some(id) = &self.id {
            inner.claimed.remove(id);
            inner.withdrawn.remove(id);
            if let Some(repo) = self.lane.take()
                && !inner.leases.contains_key(id)
            {
                inner.free_lane(&repo, id);
            }
        }
        inner.reserved_terminals = inner.reserved_terminals.saturating_sub(self.slots);
        self.slots = 0;
    }
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        if !self.settled {
            let mut inner = self.queue.lock();
            self.settle(&mut inner);
        }
        self.queue.settled.notify_waiters();
    }
}

/// What a decision taken under the lane lock tells its operation to do.
enum Step<T, R> {
    /// Another operation holds the request: wait for it to settle, then
    /// decide again.
    Wait,
    /// Nothing to do in the store: return this.
    Done(R),
    /// Claimed: go to the store with this.
    Go(T),
}

/// Whether a sweep over many requests may claim the next one.
enum Sweep<'q> {
    /// Claimed, with a notice slot promised; the flag says the request's
    /// deadline has passed.
    Claimed(Claim<'q>, bool),
    /// Gone or held by another operation, which settles it: skip it.
    Skip,
    /// No room for another terminal notice: stop this sweep.
    Full,
}

#[cfg(test)]
type Entered<'a> = tokio::sync::RwLockReadGuard<'a, ()>;
#[cfg(not(test))]
type Entered<'a> = std::marker::PhantomData<&'a ()>;

/// A test's hold on the store calls the queue makes for one request: they
/// wait inside `QueueManager::io`, with the lane lock released, until the
/// hold is released or dropped.
#[cfg(test)]
pub(crate) struct StoreHold {
    release: watch::Sender<bool>,
    reached: watch::Receiver<usize>,
}

#[cfg(test)]
impl StoreHold {
    /// Waits until a store call for the held request is waiting on the hold.
    pub(crate) async fn reached(&mut self) {
        let _ = self.reached.wait_for(|calls| *calls > 0).await;
    }

    /// Lets the held calls, and every later one, through.
    pub(crate) fn release(self) {
        let _ = self.release.send(true);
    }
}

/// The queue manager service. See the module docs for the design.
pub struct QueueManager {
    store: Arc<Store>,
    /// The lane lock: the in-memory index only, never held across store I/O.
    inner: std::sync::Mutex<Inner>,
    /// Serializes admission's check-then-insert in the store.
    admission: Mutex<()>,
    /// Fires whenever a claim settles; an operation waiting on a claimed
    /// request waits on it.
    settled: Notify,
    work: Notify,
    /// See [`DEFAULT_RECONCILE_GRACE`].
    reconcile_grace: Duration,
    /// Test seam: see `fail_next_completes`.
    #[cfg(test)]
    injected_complete_failures: std::sync::atomic::AtomicUsize,
    /// Test seam: see `stall`.
    #[cfg(test)]
    stall_gate: tokio::sync::RwLock<()>,
    /// Test seam: see `hold_store`.
    #[cfg(test)]
    #[allow(clippy::type_complexity, reason = "a test seam's private map")]
    store_holds: std::sync::Mutex<HashMap<String, (watch::Receiver<bool>, watch::Sender<usize>)>>,
    /// Test seam: see `with_paused_clock`.
    #[cfg(test)]
    clock: Option<(i64, Instant)>,
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
            inner: std::sync::Mutex::new(Inner::default()),
            admission: Mutex::new(()),
            settled: Notify::new(),
            work: Notify::new(),
            reconcile_grace: DEFAULT_RECONCILE_GRACE,
            #[cfg(test)]
            injected_complete_failures: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            stall_gate: tokio::sync::RwLock::new(()),
            #[cfg(test)]
            store_holds: std::sync::Mutex::new(HashMap::new()),
            #[cfg(test)]
            clock: None,
        }
    }

    /// Sets how long past its deadline a row is left to its own handler
    /// before the reconciler fails it (see the module docs).
    #[must_use]
    pub fn with_reconcile_grace(mut self, grace: Duration) -> Self {
        self.reconcile_grace = grace;
        self
    }

    /// The lane lock. A poisoned lock is taken over: every update under it
    /// is a handful of map operations that leave the index consistent.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Entered at the top of every public operation; a test's `stall`
    /// holds it shut.
    #[cfg_attr(
        not(test),
        allow(clippy::unused_self, reason = "only the test build reads its seam")
    )]
    fn enter(&self) -> impl Future<Output = Entered<'_>> {
        #[cfg(test)]
        {
            self.stall_gate.read()
        }
        #[cfg(not(test))]
        {
            std::future::ready(std::marker::PhantomData)
        }
    }

    /// Every store call the queue makes goes through here, with the lane
    /// lock released; a test can hold the calls made for one request (see
    /// `hold_store`).
    async fn io<T>(&self, request_id: &str, call: impl Future<Output = T>) -> T {
        #[cfg(test)]
        {
            self.store_latency(request_id).await;
        }
        #[cfg(not(test))]
        {
            let _ = request_id;
        }
        call.await
    }

    /// Milliseconds since the epoch: the wall clock, or in a test the
    /// paused Tokio clock (see `with_paused_clock`).
    #[cfg_attr(
        not(test),
        allow(clippy::unused_self, reason = "only the test build reads its seam")
    )]
    fn now_ms(&self) -> i64 {
        #[cfg(test)]
        {
            if let Some((base_ms, base)) = self.clock {
                return base_ms
                    .saturating_add(i64::try_from(base.elapsed().as_millis()).unwrap_or(i64::MAX));
            }
        }
        wall_clock_ms()
    }

    /// Waits until no other operation holds `request_id`, then claims it.
    async fn claim(&self, request_id: &str) -> Claim<'_> {
        loop {
            let settled = self.settled.notified();
            if let Some(claim) = self.try_claim(request_id) {
                return claim;
            }
            settled.await;
        }
    }

    fn try_claim(&self, request_id: &str) -> Option<Claim<'_>> {
        let mut inner = self.lock();
        if inner.claimed.contains(request_id) {
            return None;
        }
        Some(Claim::on(self, &mut inner, request_id))
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
        self.admit_from(envelope, class, &RequestOrigin::PUBLIC)
            .await
    }

    /// [`Self::admit`] recording where the request entered the daemon: the
    /// plane and the kernel's view of the connection go onto the row in the
    /// same INSERT that admits it. Attribution only — admission, dedupe and
    /// the caps are the same whoever asked.
    pub async fn admit_from(
        &self,
        envelope: &Envelope,
        class: crate::policy::CapabilityClass,
        origin: &RequestOrigin,
    ) -> Result<AdmitOutcome, QueueError> {
        let _entered = self.enter().await;
        let id = envelope.id.as_str();
        let args_json = envelope.args.to_string();
        // Admission touches no lane state: its own mutex serializes the
        // store's check-then-insert, and no other queue operation waits on it.
        let _admission = self.admission.lock().await;
        let now = self.now_ms();
        let duration = clamp_lease(envelope.deadline_ms);
        if duration.is_zero() {
            return Err(QueueError::Expired);
        }
        let expires_at_ms =
            now.saturating_add(i64::try_from(duration.as_millis()).unwrap_or(i64::MAX));
        if !class.bypasses_lanes() {
            let existing = self
                .io(
                    id,
                    self.store.find_admitted_by_shape(
                        &envelope.capability,
                        &envelope.caller.repo,
                        &args_json,
                        envelope.idempotency_key.as_deref(),
                        now,
                    ),
                )
                .await?;
            if let Some(row) = existing {
                return Ok(AdmitOutcome::Attached {
                    existing_request_id: row.id,
                });
            }
        }
        // Only admissions whose deadline is still ahead: a row stranded past
        // its deadline can no longer run and must not hold a slot.
        let (count, bytes) = self.io(id, self.store.admission_usage_at(now)).await?;
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
        self.io(
            id,
            self.store.insert_admitted_request_from(
                &envelope.id,
                &envelope.capability,
                &envelope.caller.repo,
                &envelope.caller.agent,
                &args_json,
                envelope.idempotency_key.as_deref(),
                expires_at_ms,
                origin,
            ),
        )
        .await?;
        Ok(if class.bypasses_lanes() {
            AdmitOutcome::Bypass
        } else {
            AdmitOutcome::Admitted
        })
    }

    /// Places an admitted (and gate-allowed) request onto `repo`'s lane,
    /// preserving the expiry recorded at admission; nothing at placement can
    /// extend it. Returns the number of requests already waiting
    /// ahead of it (0 = lane head; a currently leased request is not
    /// counted).
    pub async fn place_in_lane(&self, request_id: &str, repo: &str) -> Result<usize, QueueError> {
        let _entered = self.enter().await;
        let mut claim = self.claim(request_id).await;
        let row = self
            .io(request_id, self.store.get_request(request_id))
            .await?
            .ok_or(QueueError::NotAdmitted)?;
        let expires = row.expires_at_ms.ok_or(QueueError::NotAdmitted)?;
        let remaining = expires.saturating_sub(self.now_ms());
        if remaining <= 0 {
            return Err(QueueError::Expired);
        }
        let authorized = self
            .io(
                request_id,
                self.store
                    .authorize_queued_request(request_id, repo, self.now_ms()),
            )
            .await?;
        let mut inner = self.lock();
        // The reconciler failed the row past its deadline while it was being
        // placed: placement after it would have found it expired.
        if claim.withdrawn(&inner) {
            claim.settle(&mut inner);
            return Err(QueueError::Expired);
        }
        if !authorized {
            claim.settle(&mut inner);
            return Err(QueueError::NotAdmitted);
        }
        let lane = inner.lanes.entry(repo.to_owned()).or_default();
        let position = lane.len();
        lane.push_back(QueuedEntry {
            id: request_id.to_owned(),
            deadline: Instant::now() + Duration::from_millis(u64::try_from(remaining).unwrap_or(0)),
        });
        claim.settle(&mut inner);
        Ok(position)
    }

    /// Repos whose lane has waiting work and no outstanding lease — the
    /// lanes a [`Self::take_next`] call would currently serve. The
    /// executor loop polls this to know where to look.
    pub async fn ready_repos(&self) -> Vec<String> {
        let _entered = self.enter().await;
        let inner = self.lock();
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
        let _entered = self.enter().await;
        // The lane stays reserved as busy while the head is in the store, so
        // no second lease can be taken off it meanwhile.
        let (mut claim, id, deadline) = loop {
            let settled = self.settled.notified();
            match self.claim_lane_head(repo) {
                Step::Go(head) => break head,
                Step::Done(()) => return Ok(None),
                Step::Wait => settled.await,
            }
        };
        // Capacity is reserved before any terminal write; admission remains in
        // its lane on every database failure or notification backpressure.
        let cause = if deadline <= Instant::now() {
            Some(CAUSE_LEASE_EXPIRED)
        } else if self
            .io(&id, self.store.start_queued_request(&id, self.now_ms()))
            .await?
        {
            None
        } else if self
            .io(
                &id,
                self.store.request_admission_expired(&id, self.now_ms()),
            )
            .await?
        {
            Some(CAUSE_LEASE_EXPIRED)
        } else {
            Some("authorization_changed")
        };
        let Some(cause) = cause else {
            return Ok(self.lease_out(claim, repo, id, deadline));
        };
        {
            let mut inner = self.lock();
            if claim.withdrawn(&inner) {
                claim.settle(&mut inner);
                return Ok(None);
            }
            if inner.terminal_room() == 0 {
                self.work.notify_one();
                claim.settle(&mut inner);
                return Ok(None);
            }
            claim.reserve_slot(&mut inner);
        }
        let finished = self.io(&id, self.fail_recovered(&id, cause)).await?;
        let mut inner = self.lock();
        inner.remove_from_lane(repo, &id);
        claim.settle(&mut inner);
        if finished {
            inner.parked_terminals.push(id);
            self.work.notify_one();
        }
        Ok(None)
    }

    /// Under the lock: claims `repo`'s head and reserves the lane for it.
    fn claim_lane_head(&self, repo: &str) -> Step<(Claim<'_>, String, Instant), ()> {
        let mut inner = self.lock();
        if inner.draining || inner.busy.contains_key(repo) {
            return Step::Done(());
        }
        let Some(head) = inner.lanes.get(repo).and_then(VecDeque::front) else {
            return Step::Done(());
        };
        if inner.claimed.contains(&head.id) {
            return Step::Wait;
        }
        let (id, deadline) = (head.id.clone(), head.deadline);
        let mut claim = Claim::on(self, &mut inner, &id);
        claim.reserve_lane(&mut inner, repo);
        Step::Go((claim, id, deadline))
    }

    /// Under the lock: turns a started head into a lease, unless the
    /// reconciler finished it meanwhile.
    fn lease_out(
        &self,
        mut claim: Claim<'_>,
        repo: &str,
        request_id: String,
        lease_deadline: Instant,
    ) -> Option<LeasedWork> {
        let mut inner = self.lock();
        if claim.withdrawn(&inner) {
            claim.settle(&mut inner);
            return None;
        }
        inner.remove_from_lane(repo, &request_id);
        let (cancel_tx, cancel) = watch::channel(false);
        inner.leases.insert(
            request_id.clone(),
            Lease {
                repo: repo.to_owned(),
                deadline: lease_deadline,
                cancel_tx,
            },
        );
        claim.keep_lane();
        claim.settle(&mut inner);
        Some(LeasedWork {
            request_id,
            lease_deadline,
            cancel,
        })
    }

    /// Ids of every outstanding lease. A lease being granted — its row
    /// already `running`, [`Self::take_next`] still in the store — is not
    /// one yet; the drain waits on [`Self::in_flight_ids`], which counts it.
    pub async fn leased_ids(&self) -> Vec<String> {
        let _entered = self.enter().await;
        let inner = self.lock();
        inner.leases.keys().cloned().collect()
    }

    /// Ids of the work in flight: every outstanding lease and every lease
    /// being granted (the request a [`Self::take_next`] has moved, or is
    /// moving, to `running` and will hand out when it returns). This is
    /// what a graceful drain waits for and, past its bound, cancels: a
    /// request that is `running` on disk must reach its terminal row while
    /// the store is still open, whether or not its lease is out yet.
    /// Sorted.
    pub async fn in_flight_ids(&self) -> Vec<String> {
        let _entered = self.enter().await;
        let inner = self.lock();
        let mut ids: Vec<String> = inner.busy.values().cloned().collect();
        ids.sort();
        ids
    }

    /// Stops handing out leases: from now on [`Self::take_next`] answers
    /// `None` and every lane keeps its `queued` rows, which are the
    /// restart-safe checkpoint the next boot reloads. Decided under the lane
    /// lock, like a lease grant, so once this returns no new grant can
    /// start and [`Self::in_flight_ids`] can only shrink. Cancellation,
    /// completion and expiry of the work already in flight go on as before.
    pub async fn stop_leasing(&self) {
        let _entered = self.enter().await;
        self.lock().draining = true;
    }

    /// Wait for a parked request becoming ready or releasing its repository lane.
    /// The executor selects this alongside its existing admission notification.
    pub async fn work_available(&self) {
        self.work.notified().await;
    }

    /// Drain bounded terminal notices for the executor to publish and finish
    /// through the original ticket's router. Explicit cancellation is separate.
    pub async fn take_parked_terminals(&self) -> Vec<String> {
        let _entered = self.enter().await;
        let mut inner = self.lock();
        std::mem::take(&mut inner.parked_terminals)
    }

    /// Persist a future poll before releasing the current lease. Failure leaves
    /// lease ownership intact; parked admissions still count against store caps.
    pub async fn park(&self, request_id: &str, resume_at_ms: i64) -> Result<bool, QueueError> {
        let _entered = self.enter().await;
        let (mut claim, repo, deadline) = loop {
            let settled = self.settled.notified();
            match self.claim_lease_to_park(request_id) {
                Step::Go(lease) => break lease,
                Step::Done(parked) => return Ok(parked),
                Step::Wait => settled.await,
            }
        };
        let parked = self
            .io(
                request_id,
                self.store
                    .park_flow_request(request_id, resume_at_ms, self.now_ms()),
            )
            .await?;
        let mut inner = self.lock();
        if !parked {
            claim.settle(&mut inner);
            return Ok(false);
        }
        // Parked in the store: the lease is over either way. Withdrawn, the
        // reconciler has already failed the checkpoint and parked its notice.
        if inner.leases.remove(request_id).is_some() {
            inner.free_lane(&repo, request_id);
        }
        if !claim.withdrawn(&inner) {
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
        }
        claim.settle(&mut inner);
        self.work.notify_one();
        Ok(true)
    }

    /// Under the lock: claims a live, uncancelled lease to park it.
    fn claim_lease_to_park(&self, request_id: &str) -> Step<(Claim<'_>, String, Instant), bool> {
        let mut inner = self.lock();
        if inner.claimed.contains(request_id) {
            return Step::Wait;
        }
        let Some(lease) = inner.leases.get(request_id) else {
            return Step::Done(false);
        };
        if lease.deadline <= Instant::now() || *lease.cancel_tx.borrow() {
            return Step::Done(false);
        }
        let (repo, deadline) = (lease.repo.clone(), lease.deadline);
        Step::Go((Claim::on(self, &mut inner, request_id), repo, deadline))
    }

    /// Move due parked checkpoints into ordinary lanes, retaining the original
    /// monotonic expiry. Authorization changes and expiry fail without dispatch.
    pub async fn wake_due(&self, now: Instant, now_ms: i64) -> Result<usize, QueueError> {
        let _entered = self.enter().await;
        let due = {
            let inner = self.lock();
            let mut due: Vec<_> = inner
                .parked
                .iter()
                .filter(|(_, parked)| parked.entry.deadline <= now || parked.resume_at_ms <= now_ms)
                .map(|(id, parked)| (parked.resume_at_ms, id.clone()))
                .collect();
            due.sort();
            due
        };
        let mut ready = 0;
        for (_, id) in due {
            // Retain admissions until the executor has consumed older notices.
            // Never terminalize a parked request whose notification cannot fit.
            let (mut claim, expired) = match self.claim_due(&id, now) {
                Sweep::Claimed(claim, expired) => (claim, expired),
                Sweep::Skip => continue,
                Sweep::Full => break,
            };
            if expired {
                let finished = self.io(&id, self.finish_expired(&id)).await?;
                let mut inner = self.lock();
                inner.forget(&id);
                claim.settle(&mut inner);
                if finished {
                    inner.parked_terminals.push(id);
                    self.work.notify_one();
                }
                continue;
            }
            if !self
                .io(&id, self.store.wake_parked_flow_request(&id, now_ms))
                .await?
            {
                let cause = if self
                    .io(&id, self.store.request_admission_expired(&id, now_ms))
                    .await?
                {
                    CAUSE_LEASE_EXPIRED
                } else {
                    "authorization_changed"
                };
                let finished = self.io(&id, self.fail_recovered(&id, cause)).await?;
                let mut inner = self.lock();
                inner.parked.remove(&id);
                claim.settle(&mut inner);
                if finished {
                    inner.parked_terminals.push(id);
                    self.work.notify_one();
                }
                continue;
            }
            let mut inner = self.lock();
            if !claim.withdrawn(&inner)
                && let Some(parked) = inner.parked.remove(&id)
            {
                inner
                    .lanes
                    .entry(parked.repo)
                    .or_default()
                    .push_back(parked.entry);
                ready += 1;
            }
            claim.settle(&mut inner);
            // A later store failure must not strand work already made ready.
            self.work.notify_one();
        }
        Ok(ready)
    }

    /// Under the lock: claims a due parked checkpoint with a notice slot.
    fn claim_due(&self, request_id: &str, now: Instant) -> Sweep<'_> {
        let mut inner = self.lock();
        if inner.terminal_room() == 0 {
            self.work.notify_one();
            return Sweep::Full;
        }
        if inner.claimed.contains(request_id) {
            return Sweep::Skip;
        }
        let Some(parked) = inner.parked.get(request_id) else {
            return Sweep::Skip;
        };
        let expired = parked.entry.deadline <= now;
        let mut claim = Claim::on(self, &mut inner, request_id);
        claim.reserve_slot(&mut inner);
        Sweep::Claimed(claim, expired)
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
        let final_state = request_state::target(RequestEvent::Finish(final_state))
            .map_err(|_| QueueError::NotTerminal { state: final_state })?;
        let _entered = self.enter().await;
        let mut claim = loop {
            let settled = self.settled.notified();
            match self.claim_lease(request_id) {
                Step::Go(claim) => break claim,
                Step::Done(()) => return Ok(false),
                Step::Wait => settled.await,
            }
        };
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering;
            if self
                .injected_complete_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                    left.checked_sub(1)
                })
                .is_ok()
            {
                return Err(QueueError::Store(StoreError::AbandonedTransaction));
            }
        }
        // A failed terminal write must retain ownership so completion can be
        // retried or reaped; it is not evidence that another writer finished.
        let finished = self
            .io(
                request_id,
                self.store
                    .finish_request(request_id, final_state, outcome, audit),
            )
            .await?;
        let mut inner = self.lock();
        if let Some(lease) = inner.leases.remove(request_id) {
            inner.free_lane(&lease.repo, request_id);
        }
        claim.settle(&mut inner);
        Ok(finished)
    }

    /// Under the lock: claims an outstanding lease.
    fn claim_lease(&self, request_id: &str) -> Step<Claim<'_>, ()> {
        let mut inner = self.lock();
        if inner.claimed.contains(request_id) {
            return Step::Wait;
        }
        if !inner.leases.contains_key(request_id) {
            return Step::Done(());
        }
        Step::Go(Claim::on(self, &mut inner, request_id))
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
        let _entered = self.enter().await;
        // A request another operation holds is cancelled once that settles,
        // as it would have been had the operation held the whole queue.
        let mut claim = loop {
            let settled = self.settled.notified();
            match self.claim_to_cancel(request_id) {
                Step::Go(claim) => break claim,
                Step::Done(outcome) => return Ok(outcome),
                Step::Wait => settled.await,
            }
        };
        let detail = serde_json::json!({ "actor": actor.as_str() }).to_string();
        self.io(
            request_id,
            self.store.finish_request(
                request_id,
                RequestState::Failed,
                Some(CAUSE_CANCELLED),
                AuditEntry {
                    action: ACTION_CANCEL,
                    decision: Decision::Deny,
                    actor,
                    detail: Some(&detail),
                },
            ),
        )
        .await?;
        let mut inner = self.lock();
        inner.parked.remove(request_id);
        for lane in inner.lanes.values_mut() {
            lane.retain(|entry| entry.id != request_id);
        }
        inner.lanes.retain(|_, lane| !lane.is_empty());
        claim.settle(&mut inner);
        Ok(CancelOutcome::CancelledQueued)
    }

    /// Under the lock: signals a lease, or claims a queued or parked
    /// request to cancel it.
    fn claim_to_cancel(&self, request_id: &str) -> Step<Claim<'_>, CancelOutcome> {
        let mut inner = self.lock();
        if inner.claimed.contains(request_id) {
            return Step::Wait;
        }
        if let Some(lease) = inner.leases.get(request_id) {
            // Receiver may already be dropped; the signal is best-effort
            // and the reaper backstops a holder that never listens.
            let _ = lease.cancel_tx.send(true);
            return Step::Done(CancelOutcome::SignalledRunning);
        }
        let found = inner.parked.contains_key(request_id)
            || inner
                .lanes
                .values()
                .any(|lane| lane.iter().any(|entry| entry.id == request_id));
        if !found {
            return Step::Done(CancelOutcome::NotFound);
        }
        Step::Go(Claim::on(self, &mut inner, request_id))
    }

    /// Reaps every lease whose deadline is at or before `now`: the
    /// request becomes terminal `failed` (cause [`CAUSE_LEASE_EXPIRED`]),
    /// an audit row is written (action [`ACTION_LEASE_REAPED`], decision
    /// `timeout`, actor `system`), the holder's cancel signal fires, and
    /// the lane is freed. Returns the reaped request ids. Test-only: the
    /// daemon reaps through [`Self::reap_expired_notifying`], which also
    /// parks the terminal for the executor loop to finish.
    #[cfg(test)]
    pub async fn reap_expired(&self, now: Instant) -> Result<Vec<String>, QueueError> {
        let _entered = self.enter().await;
        let expired = self.expired_lease_ids(now);
        let mut reaped = Vec::with_capacity(expired.len());
        for id in expired {
            let mut claim = match self.claim_expired_lease(&id, now, false) {
                Sweep::Claimed(claim, _) => claim,
                Sweep::Skip => continue,
                Sweep::Full => break,
            };
            let finished = self.io(&id, self.finish_expired(&id)).await?;
            let mut inner = self.lock();
            inner.forget(&id);
            claim.settle(&mut inner);
            if finished {
                reaped.push(id);
            }
        }
        Ok(reaped)
    }

    /// Finish an admitted request whose absolute deadline elapsed. Both the
    /// original waiter and lease reaper use the same durable timeout cause.
    /// Explicit user cancellation continues through [`Self::cancel`].
    pub async fn expire(&self, request_id: &str) -> Result<bool, QueueError> {
        let _entered = self.enter().await;
        let mut claim = self.claim(request_id).await;
        // Persist first: a store failure must leave ownership intact for retry.
        // The claim excludes executor completion until this terminal write.
        let finished = self.io(request_id, self.finish_expired(request_id)).await?;
        let mut inner = self.lock();
        inner.forget(request_id);
        claim.settle(&mut inner);
        Ok(finished)
    }

    /// The lease-expiry terminal write and audit row, shared by expiry,
    /// parked-checkpoint expiry and the lease reaper.
    async fn finish_expired(&self, request_id: &str) -> Result<bool, StoreError> {
        let detail = serde_json::json!({ "cause": "timeout" }).to_string();
        self.store
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
            .await
    }

    /// Ids of the leases whose deadline is at or before `now`, sorted.
    fn expired_lease_ids(&self, now: Instant) -> Vec<String> {
        let inner = self.lock();
        let mut expired: Vec<_> = inner
            .leases
            .iter()
            .filter(|(_, lease)| lease.deadline <= now)
            .map(|(id, _)| id.clone())
            .collect();
        expired.sort();
        expired
    }

    /// Under the lock: claims an expired lease for the reaper, with a
    /// notice slot when `notice`.
    fn claim_expired_lease(&self, request_id: &str, now: Instant, notice: bool) -> Sweep<'_> {
        let mut inner = self.lock();
        if notice && inner.terminal_room() == 0 {
            self.work.notify_one();
            return Sweep::Full;
        }
        // A claimed lease is being completed, parked or expired: whoever
        // holds it settles it, and a lease still out is reaped next sweep.
        if inner.claimed.contains(request_id)
            || inner
                .leases
                .get(request_id)
                .is_none_or(|lease| lease.deadline > now)
        {
            return Sweep::Skip;
        }
        let mut claim = Claim::on(self, &mut inner, request_id);
        if notice {
            claim.reserve_slot(&mut inner);
        }
        Sweep::Claimed(claim, true)
    }

    /// Background-only expiry delivery. Explicit `reap_expired` callers own
    /// their returned ids; this path reserves notice capacity before releasing
    /// leases whose executor may already have exited after a store failure.
    pub(crate) async fn reap_expired_notifying(&self, now: Instant) -> Result<usize, QueueError> {
        let _entered = self.enter().await;
        let mut count = 0;
        for id in self.expired_lease_ids(now) {
            let mut claim = match self.claim_expired_lease(&id, now, true) {
                Sweep::Claimed(claim, _) => claim,
                Sweep::Skip => continue,
                Sweep::Full => break,
            };
            let finished = self.io(&id, self.finish_expired(&id)).await?;
            let mut inner = self.lock();
            inner.forget(&id);
            claim.settle(&mut inner);
            if finished {
                inner.parked_terminals.push(id);
                count += 1;
                self.work.notify_one();
            }
        }
        Ok(count)
    }

    /// Fails every in-flight row whose admission deadline passed more than
    /// the reconcile grace before `now_ms` (see the module docs on stranded
    /// rows): terminal `failed`/[`CAUSE_LEASE_EXPIRED`], one
    /// [`ACTION_LEASE_REAPED`] audit row each, removed from the lanes, the
    /// parked set and the leases, and parked for the executor loop to
    /// release its waiters. Returns how many rows it finished; call again
    /// while it returns [`pam_store::MAX_EXPIRY_BATCH`].
    ///
    /// Bounded by the room left for terminal notices: with none, it does
    /// nothing this tick rather than finish a row nobody would be told
    /// about. A row it finishes while another operation holds it is marked
    /// withdrawn for that operation (see the module docs).
    pub async fn reconcile_expired(&self, now_ms: i64) -> Result<usize, QueueError> {
        let _entered = self.enter().await;
        let (mut claim, limit) = {
            let mut inner = self.lock();
            let room = inner.terminal_room();
            if room == 0 {
                self.work.notify_one();
                return Ok(0);
            }
            let limit = u32::try_from(room)
                .unwrap_or(u32::MAX)
                .min(pam_store::MAX_EXPIRY_BATCH);
            let slots = usize::try_from(limit).unwrap_or(room);
            (Claim::slots(self, &mut inner, slots), limit)
        };
        let grace_ms = i64::try_from(self.reconcile_grace.as_millis()).unwrap_or(i64::MAX);
        let detail = serde_json::json!({ "cause": "reconciled_past_deadline" }).to_string();
        let finished = self
            .io(
                "",
                self.store.fail_expired_requests(
                    now_ms.saturating_sub(grace_ms),
                    limit,
                    CAUSE_LEASE_EXPIRED,
                    AuditEntry {
                        action: ACTION_LEASE_REAPED,
                        decision: Decision::Timeout,
                        actor: Actor::System,
                        detail: Some(&detail),
                    },
                ),
            )
            .await?;
        let count = finished.len();
        let mut inner = self.lock();
        claim.settle(&mut inner);
        for id in finished {
            if inner.claimed.contains(&id) {
                inner.withdrawn.insert(id.clone());
            }
            inner.forget(&id);
            tracing::warn!(request = %id, "closed an in-flight request stranded past its deadline");
            inner.parked_terminals.push(id);
        }
        if count != 0 {
            self.work.notify_one();
        }
        Ok(count)
    }

    /// Releases `request_id`'s lease and lane **without** a terminal write:
    /// the last resort when the store keeps refusing the executor's
    /// terminal row. The lane is free for the next request at once; the
    /// row's verdict is the caller's to retry, and the reconciler closes it
    /// if nothing ever does. Returns whether a lease was held.
    pub async fn abandon_lease(&self, request_id: &str) -> bool {
        let _entered = self.enter().await;
        let mut inner = self.lock();
        let Some(lease) = inner.leases.remove(request_id) else {
            return false;
        };
        inner.free_lane(&lease.repo, request_id);
        self.work.notify_one();
        true
    }

    /// Holds every queue operation at its entry for as long as the returned
    /// guard lives. For tests of what the daemon does when its bookkeeping
    /// is wedged.
    #[cfg(test)]
    pub(crate) async fn stall(&self) -> impl Drop + '_ {
        self.stall_gate.write().await
    }

    /// Makes the next `count` [`Self::complete`] calls fail before they
    /// reach the store, standing in for a store that refuses the write.
    #[cfg(test)]
    pub(crate) fn fail_next_completes(&self, count: usize) {
        self.injected_complete_failures
            .store(count, std::sync::atomic::Ordering::SeqCst);
    }

    /// Holds every store call the queue makes for `request_id` until the
    /// returned hold is released: a store that is slow for one request.
    #[cfg(test)]
    pub(crate) fn hold_store(&self, request_id: &str) -> StoreHold {
        let (release, release_rx) = watch::channel(false);
        let (reached_tx, reached) = watch::channel(0);
        self.store_holds
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(request_id.to_owned(), (release_rx, reached_tx));
        StoreHold { release, reached }
    }

    #[cfg(test)]
    async fn store_latency(&self, request_id: &str) {
        let hold = self
            .store_holds
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(request_id)
            .map(|(release, reached)| (release.clone(), reached.clone()));
        if let Some((mut release, reached)) = hold {
            reached.send_modify(|calls| *calls += 1);
            // A dropped hold lets the call through as well.
            let _ = release.wait_for(|released| *released).await;
        }
    }

    /// Ties this queue's wall clock to Tokio's clock, so a paused test
    /// clock moves admission, placement and lease deadlines together and
    /// no real time can pass between them.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_paused_clock(mut self) -> Self {
        self.clock = Some((wall_clock_ms(), Instant::now()));
        self
    }

    /// Spawns the background reaper: every `interval` until `shutdown`
    /// changes (or its sender drops), reaps expired leases through
    /// `Self::reap_expired_notifying`, wakes parked watches that are due
    /// through [`Self::wake_due`], and closes stranded rows through
    /// [`Self::reconcile_expired`].
    ///
    /// A store failure during one sweep is logged and retried on the next
    /// tick.
    pub fn run_reaper(
        self: Arc<Self>,
        interval: Duration,
        mut shutdown: watch::Receiver<bool>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            // The stranded-row sweep is a backstop measured in tens of
            // seconds; it does not need the lease reaper's cadence.
            let reconcile_every = interval.max(RECONCILE_INTERVAL);
            let mut reconciled_at: Option<Instant> = None;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if let Err(error) = self.reap_expired_notifying(Instant::now()).await {
                            tracing::error!(%error, "reaping expired leases failed; retrying next tick");
                        }
                        if let Err(error) = self.wake_due(Instant::now(), self.now_ms()).await {
                            tracing::error!(%error, "waking due watches failed; retrying next tick");
                        }
                        if reconciled_at.is_none_or(|at| at.elapsed() >= reconcile_every) {
                            reconciled_at = Some(Instant::now());
                            if let Err(error) = self.reconcile_expired(self.now_ms()).await {
                                tracing::error!(%error, "closing stranded requests failed; retrying next pass");
                            }
                        }
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
    /// Boot-only (see the module docs): the store is read without the lane
    /// lock and the rebuilt lanes replace the in-memory ones at the end.
    ///
    /// Crash recovery of `running` / `waiting_approval` rows left behind
    /// by a dead daemon is task #12, not handled here.
    pub async fn rebuild_from_store(&self) -> Result<usize, QueueError> {
        let _entered = self.enter().await;
        let mut rebuilt = Inner::default();
        let mut restored = 0;
        let mut retained_bytes = 0u64;
        let mut after: Option<(i64, String)> = None;
        loop {
            let queued = self
                .io(
                    "",
                    self.store.queued_recovery_page(
                        after.as_ref().map(|(ts, id)| (*ts, id.as_str())),
                        MAX_ADMITTED_BYTES,
                    ),
                )
                .await?
                .ok_or(QueueError::LegacyQueueOversized)?;
            let Some(last) = queued.last() else { break };
            after = Some((last.created_ts, last.id.clone()));
            for row in queued {
                let remaining = row
                    .expires_at_ms
                    .map_or(0, |expires| expires.saturating_sub(self.now_ms()));
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
                } else if !self
                    .io(&row.id, self.store.request_authorization_current(&row.id))
                    .await?
                {
                    // Scoped: only a revocation of a grant this request
                    // depends on voids it, and re-granting never restores.
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
                    self.io(&row.id, self.fail_recovered(&row.id, cause))
                        .await?;
                    continue;
                }
                if row.resume_at_ms.is_some()
                    && !self
                        .io(
                            &row.id,
                            self.store
                                .validate_parked_flow_request(&row.id, self.now_ms()),
                        )
                        .await?
                {
                    self.io(&row.id, self.fail_recovered(&row.id, "admission_invalid"))
                        .await?;
                    continue;
                }
                retained_bytes += bytes;
                restored += 1;
                restore_queued_entry(&mut rebuilt, row, remaining);
            }
        }
        let mut inner = self.lock();
        inner.lanes = rebuilt.lanes;
        inner.parked = rebuilt.parked;
        drop(inner);
        Ok(usize::try_from(restored).unwrap_or(usize::MAX))
    }

    async fn fail_recovered(&self, id: &str, cause: &str) -> Result<bool, StoreError> {
        self.store
            .finish_request(
                id,
                RequestState::Failed,
                Some(cause),
                AuditEntry {
                    action: ACTION_RECOVERY_REFUSAL,
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

pub(crate) fn wall_clock_ms() -> i64 {
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
