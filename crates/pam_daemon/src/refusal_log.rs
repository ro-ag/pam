//! Refusals that happen before a request row exists.
//!
//! The ledger promises one audit row per operation, refusals included, but an
//! audit row needs a request row, and a refusal decided before admission has
//! none: the dispatcher's capacity and rate refusals, a repository that cannot
//! be normalised, a deadline that expired at admission, a malformed envelope,
//! a refused hello (protocol or version), an oversized frame, the connection
//! cap, the drain. This module is the place those are recorded instead: the
//! store's `refusal` table (migration 18), read back by `admin.activity.list`
//! and shown in the GUI's Activity screen.
//!
//! **Never on the reply path.** [`RefusalLog::record`] is synchronous, takes
//! one short mutex and notifies a writer task; it never touches the store, so a
//! refusal reply never waits for the write, and a slow or stuck store cannot
//! slow a refusal down. The writer task owns every store call.
//!
//! **Flood control, bounded in memory.** Identical refusals (same plane,
//! cause, peer pid and capability) are one *run*: the first attempt makes the
//! row, every later one inside [`RefusalLimits::window`] only adds to the run's
//! count, and the writer folds the increments into the row in batches
//! ([`RefusalLimits::flush_delay`]). A client that is refused a thousand times
//! therefore costs one row and a handful of writes. At most
//! [`RefusalLimits::max_runs`] runs are held; a refusal that would start one
//! more, while none can be retired, is not recorded and moves
//! [`RefusalLog::dropped`], which `status` reports. That counter is the whole
//! price of the bound: the reply was still sent.
//!
//! **What a run remembers.** The first attempt's detail and claims (the agent,
//! repository, request id and capability the client named, all bounded) are
//! kept; the peer is the kernel's view of the connection, and its executable is
//! resolved by the writer, off the reply path, once per new row (a miss is
//! null). Everything here is attribution: nothing is authorized by a refusal
//! row and no gate reads one.
//!
//! **Retention.** The newest [`pam_store::MAX_REFUSALS`] rows are kept (each
//! write prunes) and the retention service's audit window removes older ones
//! ([`pam_store::Store::prune_refusals_before`]).
//!
//! **What is not recorded.** A connection that closes before it sends a byte,
//! a connection reset, and a refusal that happens after a request row exists
//! (those have their audit rows). Windows has no kernel peer on the public
//! plane, so its rows carry no uid, pid or executable.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pam_proto::Envelope;
use pam_store::{
    MAX_AGENT_BYTES, MAX_CAPABILITY_BYTES, MAX_CAUSE_BYTES, MAX_DETAIL_BYTES, MAX_REPO_BYTES,
    MAX_REQUEST_ID_BYTES, RefusalRecord, RefusalWrite, RequestIngress, Store, StoreError, bounded,
};
use serde_json::json;
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;

use crate::boundary::PeerResolver;
use crate::framed::HandshakeError;
use crate::ingress::{Origin, PeerIdentity};

/// Refusal cause: a pre-migration client greeted in ZMTP and was closed
/// unanswered.
pub const CAUSE_LEGACY_CLIENT: &str = "legacy_client";

/// Refusal cause: the request's identity or scope fields exceed their limits,
/// or its envelope does not parse (the wire's `bad_request`).
pub const CAUSE_BAD_REQUEST: &str = "bad_request";

/// How long identical refusals fold into one row.
pub const COALESCE_WINDOW: Duration = Duration::from_secs(10);

/// How long the writer waits after the first unwritten refusal before it
/// writes, so a burst is one transaction.
pub const FLUSH_DELAY: Duration = Duration::from_millis(250);

/// How many distinct runs are held at once.
pub const MAX_OPEN_RUNS: usize = 256;

/// How long the writer waits before it retries a write the store refused.
pub const RETRY_DELAY: Duration = Duration::from_secs(1);

/// How long the writer waits for the process table when it resolves the
/// executables of a batch of new rows.
pub const RESOLVE_BUDGET: Duration = Duration::from_millis(500);

/// The knobs of one log; production uses [`Self::default`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefusalLimits {
    /// How long identical refusals fold into one row ([`COALESCE_WINDOW`]).
    pub window: Duration,
    /// Writer batching delay ([`FLUSH_DELAY`]).
    pub flush_delay: Duration,
    /// Runs held at once ([`MAX_OPEN_RUNS`]).
    pub max_runs: usize,
    /// Retry pause after a failed write ([`RETRY_DELAY`]).
    pub retry_delay: Duration,
    /// Budget for resolving a batch's executables ([`RESOLVE_BUDGET`]).
    pub resolve_budget: Duration,
}

impl Default for RefusalLimits {
    fn default() -> Self {
        Self {
            window: COALESCE_WINDOW,
            flush_delay: FLUSH_DELAY,
            max_runs: MAX_OPEN_RUNS,
            retry_delay: RETRY_DELAY,
            resolve_budget: RESOLVE_BUDGET,
        }
    }
}

/// A boxed store write, so the log can sit over a trait object.
pub type Writing<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<Option<i64>>, StoreError>> + Send + 'a>>;

/// Where the writer task puts rows. The production backend is the [`Store`];
/// tests inject a slow or a failing one.
pub trait RefusalBackend: Send + Sync + fmt::Debug + 'static {
    /// Applies one batch, answering what each write landed on
    /// ([`Store::write_refusals`]).
    fn write(&self, writes: Vec<RefusalWrite>) -> Writing<'_>;
}

impl RefusalBackend for Store {
    fn write(&self, writes: Vec<RefusalWrite>) -> Writing<'_> {
        Box::pin(self.write_refusals(writes))
    }
}

/// One refusal as a site reports it. Borrowed: a coalesced attempt copies
/// nothing.
#[derive(Debug, Clone, Copy)]
pub struct Refusal<'a> {
    /// The plane it happened on.
    pub plane: RequestIngress,
    /// The cause the client was refused with.
    pub cause: &'a str,
    /// One short line of context.
    pub detail: &'a str,
    /// The kernel's view of the peer, where the platform has one.
    pub peer: Option<PeerIdentity>,
    /// The agent label the client claimed.
    pub agent: Option<&'a str>,
    /// The repository the client claimed.
    pub repo: Option<&'a str>,
    /// The request id the client supplied.
    pub request_id: Option<&'a str>,
    /// The capability the client named.
    pub capability: Option<&'a str>,
}

impl<'a> Refusal<'a> {
    /// A refusal with a cause and a detail and nothing known about the peer.
    #[must_use]
    pub fn new(plane: RequestIngress, cause: &'a str, detail: &'a str) -> Self {
        Self {
            plane,
            cause,
            detail,
            peer: None,
            agent: None,
            repo: None,
            request_id: None,
            capability: None,
        }
    }

    /// The same refusal from `origin`'s plane.
    #[must_use]
    pub fn from_origin(origin: Origin, cause: &'a str, detail: &'a str) -> Self {
        Self::new(plane_of(origin), cause, detail)
    }

    /// Adds the peer the kernel reported.
    #[must_use]
    pub fn peer(mut self, peer: PeerIdentity) -> Self {
        self.peer = Some(peer);
        self
    }

    /// Adds what an envelope claims: the agent, the repository, the request
    /// id and the capability. Attribution only.
    #[must_use]
    pub fn claimed(mut self, envelope: &'a Envelope) -> Self {
        self.agent = Some(&envelope.caller.agent);
        self.repo = Some(&envelope.caller.repo);
        self.request_id = Some(&envelope.id);
        self.capability = Some(&envelope.capability);
        self
    }

    /// Adds a request id the client supplied.
    #[must_use]
    pub fn request_id(mut self, id: &'a str) -> Self {
        self.request_id = Some(id);
        self
    }
}

/// The store's name for a request's plane.
#[must_use]
pub const fn plane_of(origin: Origin) -> RequestIngress {
    match origin {
        Origin::Public => RequestIngress::Public,
        Origin::Admin => RequestIngress::Admin,
    }
}

/// The cause and detail a failed handshake is recorded under, or `None` when
/// it is not a refusal (the peer went away, a read failed).
#[must_use]
pub fn of_handshake(error: &HandshakeError) -> Option<(&'static str, String)> {
    match error {
        HandshakeError::LegacyZmtp => Some((
            CAUSE_LEGACY_CLIENT,
            "a pre-migration pam client greeted in ZMTP and was closed unanswered".to_owned(),
        )),
        HandshakeError::Reserved(byte) => Some((
            pam_proto::wire::cause::BAD_FRAME,
            format!("the first byte {byte:#04x} is reserved"),
        )),
        HandshakeError::Untyped(_) => Some((
            pam_proto::wire::cause::BAD_FRAME,
            "the first frame has no \"t\" member".to_owned(),
        )),
        HandshakeError::BadFrame(detail) => {
            Some((pam_proto::wire::cause::BAD_FRAME, detail.clone()))
        }
        HandshakeError::ProtocolMismatch(proto) => Some((
            pam_proto::wire::cause::PROTOCOL_MISMATCH,
            format!("the hello carried wire protocol {proto}"),
        )),
        HandshakeError::Timeout => Some((
            pam_proto::wire::cause::HANDSHAKE_TIMEOUT,
            "the hello and the request frame were not delivered in time".to_owned(),
        )),
        HandshakeError::Io(_) => None,
    }
}

/// What makes two refusals one run.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    plane: u8,
    cause: String,
    pid: Option<u32>,
    capability: Option<String>,
}

/// A run of identical refusals: the first attempt's record and where the
/// counting stands.
#[derive(Debug)]
struct Run {
    template: RefusalRecord,
    started: Instant,
    /// Attempts in the run, the first included.
    total: u64,
    /// Attempts the store already has.
    written: u64,
    /// The row, once the first write landed.
    row: Option<i64>,
    last_ts: i64,
}

impl Run {
    fn clean(&self) -> bool {
        self.written >= self.total
    }
}

#[derive(Debug, Default)]
struct State {
    runs: HashMap<Key, Run>,
}

struct Inner {
    backend: Arc<dyn RefusalBackend>,
    resolver: Arc<dyn PeerResolver>,
    limits: RefusalLimits,
    state: Mutex<State>,
    wake: Notify,
    /// One flush at a time: the writer task and an explicit [`RefusalLog::flush`].
    flushing: tokio::sync::Mutex<()>,
    recorded: AtomicU64,
    dropped: AtomicU64,
}

impl fmt::Debug for Inner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RefusalLog")
            .field("limits", &self.limits)
            .field("recorded", &self.recorded.load(Ordering::Relaxed))
            .field("dropped", &self.dropped.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// The handle every refusal site holds. Cheap to clone; the default is
/// [`Self::disabled`], which records nothing.
#[derive(Debug, Clone, Default)]
pub struct RefusalLog {
    inner: Option<Arc<Inner>>,
}

fn now_ts() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    i64::try_from(secs).unwrap_or(i64::MAX)
}

fn clip(text: &str, max: usize) -> String {
    bounded(text, max).to_owned()
}

fn clip_opt(text: Option<&str>, max: usize) -> Option<String> {
    text.map(|text| clip(text, max))
}

const fn plane_tag(plane: RequestIngress) -> u8 {
    match plane {
        RequestIngress::Public => 0,
        RequestIngress::Admin => 1,
    }
}

impl RefusalLog {
    /// A log that records nothing: what a context with no store behind it
    /// (a test harness, a plane built by hand) holds.
    #[must_use]
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    /// A log over `backend` and its writer task. The task runs until `stop`
    /// is set (or its sender is gone), writes what is pending one last time
    /// and ends; the caller joins the handle before the store closes.
    #[must_use]
    pub fn spawn(
        backend: Arc<dyn RefusalBackend>,
        resolver: Arc<dyn PeerResolver>,
        limits: RefusalLimits,
        stop: watch::Receiver<bool>,
    ) -> (Self, JoinHandle<()>) {
        let inner = Arc::new(Inner {
            backend,
            resolver,
            limits,
            state: Mutex::new(State::default()),
            wake: Notify::new(),
            flushing: tokio::sync::Mutex::new(()),
            recorded: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        });
        let task = tokio::spawn(run(Arc::clone(&inner), stop));
        (Self { inner: Some(inner) }, task)
    }

    /// Whether this log writes anywhere.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Records one refusal attempt. Synchronous and never blocking on the
    /// store: a refusal reply does not wait for this. See the module docs.
    pub fn record(&self, refusal: &Refusal<'_>) {
        if let Some(inner) = &self.inner {
            inner.record(refusal);
        }
    }

    /// Writes everything recorded so far and returns when the store has it
    /// (or refused it: the attempts then stay pending for the writer's
    /// retry). The shutdown path and tests use this; the reply path never
    /// does.
    pub async fn flush(&self) {
        if let Some(inner) = &self.inner {
            inner.flush().await;
        }
    }

    /// Attempts that were not recorded because every run slot was in use.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.inner
            .as_ref()
            .map_or(0, |inner| inner.dropped.load(Ordering::Relaxed))
    }

    /// Attempts the log accepted since the daemon started.
    #[must_use]
    pub fn recorded(&self) -> u64 {
        self.inner
            .as_ref()
            .map_or(0, |inner| inner.recorded.load(Ordering::Relaxed))
    }

    /// The `refusals` block of `status`: what was accepted, what was dropped
    /// to keep the log bounded, and what is not yet in the store.
    #[must_use]
    pub fn status_block(&self) -> serde_json::Value {
        let pending = self.inner.as_ref().map_or(0, |inner| {
            inner
                .lock()
                .runs
                .values()
                .map(|run| run.total.saturating_sub(run.written))
                .sum::<u64>()
        });
        json!({
            "recorded": self.recorded(),
            "dropped": self.dropped(),
            "pending": pending,
        })
    }
}

impl Inner {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn record(&self, refusal: &Refusal<'_>) {
        let now = Instant::now();
        let key = Key {
            plane: plane_tag(refusal.plane),
            cause: clip(refusal.cause, MAX_CAUSE_BYTES),
            pid: refusal.peer.and_then(|peer| peer.pid()),
            capability: clip_opt(refusal.capability, MAX_CAPABILITY_BYTES),
        };
        let ts = now_ts();
        let mut state = self.lock();
        if let Some(run) = state.runs.get_mut(&key) {
            if run.clean() && now.saturating_duration_since(run.started) >= self.limits.window {
                // The run is over and everything it counted is durable: this
                // attempt starts the next one, and its own row.
                state.runs.remove(&key);
            } else {
                run.total = run.total.saturating_add(1);
                run.last_ts = ts;
                drop(state);
                self.recorded.fetch_add(1, Ordering::Relaxed);
                self.wake.notify_one();
                return;
            }
        }
        if state.runs.len() >= self.limits.max_runs {
            let window = self.limits.window;
            state.runs.retain(|_, run| {
                !(run.clean() && now.saturating_duration_since(run.started) >= window)
            });
        }
        if state.runs.len() >= self.limits.max_runs {
            drop(state);
            let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped == 1 || dropped.is_multiple_of(1000) {
                tracing::warn!(
                    dropped,
                    "refusals are arriving faster than they can be recorded; some were not"
                );
            }
            return;
        }
        let template = RefusalRecord {
            ts,
            last_ts: ts,
            ingress: refusal.plane,
            cause: key.cause.clone(),
            detail: clip(refusal.detail, MAX_DETAIL_BYTES),
            count: 1,
            peer_uid: refusal.peer.and_then(|peer| peer.uid()),
            peer_pid: key.pid,
            peer_exe: None,
            agent: clip_opt(refusal.agent, MAX_AGENT_BYTES),
            repo: clip_opt(refusal.repo, MAX_REPO_BYTES),
            request_id: clip_opt(refusal.request_id, MAX_REQUEST_ID_BYTES),
            capability: key.capability.clone(),
        };
        state.runs.insert(
            key,
            Run {
                template,
                started: now,
                total: 1,
                written: 0,
                row: None,
                last_ts: ts,
            },
        );
        drop(state);
        self.recorded.fetch_add(1, Ordering::Relaxed);
        self.wake.notify_one();
    }

    /// What one write cycle did.
    async fn flush_once(&self) -> Flushed {
        let _one_at_a_time = self.flushing.lock().await;
        let mut writes = Vec::new();
        let mut pending: Vec<(Key, u64, bool)> = Vec::new();
        {
            let state = self.lock();
            // At most `max_runs` runs exist, so one batch is all of them.
            for (key, run) in &state.runs {
                if run.clean() {
                    continue;
                }
                let count = run.total - run.written;
                let write = if let Some(id) = run.row {
                    RefusalWrite::Bump {
                        id,
                        count,
                        last_ts: run.last_ts,
                    }
                } else {
                    let mut record = run.template.clone();
                    record.count = count;
                    record.last_ts = run.last_ts;
                    RefusalWrite::Insert(record)
                };
                pending.push((key.clone(), run.total, run.row.is_none()));
                writes.push(write);
            }
            if pending.is_empty() {
                return Flushed::Idle;
            }
        }
        self.resolve_executables(&mut writes).await;
        let landed = match self.backend.write(writes).await {
            Ok(landed) => landed,
            Err(error) => {
                tracing::warn!(%error, "refusals could not be written; they stay pending");
                return Flushed::Failed(error);
            }
        };
        let mut state = self.lock();
        for ((key, total, inserted), landed) in pending.into_iter().zip(landed) {
            let Some(run) = state.runs.get_mut(&key) else {
                continue;
            };
            match (inserted, landed) {
                (true, Some(id)) => {
                    run.row = Some(id);
                    run.written = total;
                }
                (false, Some(_)) => run.written = total,
                // The row was pruned from under the run: the rest of its
                // attempts go to a row of their own at the next write.
                (false, None) => run.row = None,
                (true, None) => {}
            }
        }
        let window = self.limits.window;
        let now = Instant::now();
        state.runs.retain(|_, run| {
            !(run.clean() && now.saturating_duration_since(run.started) >= window)
        });
        Flushed::Wrote
    }

    /// Fills `peer_exe` of the batch's inserts from the process table, in one
    /// blocking job under one budget. A miss leaves it null.
    async fn resolve_executables(&self, writes: &mut [RefusalWrite]) {
        let mut pids: Vec<u32> = writes
            .iter()
            .filter_map(|write| match write {
                RefusalWrite::Insert(record) if record.peer_exe.is_none() => record.peer_pid,
                _ => None,
            })
            .collect();
        pids.sort_unstable();
        pids.dedup();
        if pids.is_empty() {
            return;
        }
        let resolver = Arc::clone(&self.resolver);
        let job = tokio::task::spawn_blocking(move || {
            pids.into_iter()
                .map(|pid| {
                    let exe = resolver
                        .resolve(pid)
                        .exe
                        .map(|exe| exe.to_string_lossy().into_owned());
                    (pid, exe)
                })
                .collect::<HashMap<u32, Option<String>>>()
        });
        let Ok(Ok(found)) = tokio::time::timeout(self.limits.resolve_budget, job).await else {
            return;
        };
        for write in writes {
            if let RefusalWrite::Insert(record) = write
                && let Some(pid) = record.peer_pid
            {
                record.peer_exe = found.get(&pid).cloned().flatten();
            }
        }
    }

    /// Writes until nothing is pending, a write fails, or the store is
    /// closed.
    async fn flush(&self) -> Option<StoreError> {
        loop {
            match self.flush_once().await {
                Flushed::Wrote => {}
                Flushed::Idle => return None,
                Flushed::Failed(error) => return Some(error),
            }
        }
    }
}

enum Flushed {
    Idle,
    Wrote,
    Failed(StoreError),
}

/// The writer task: wakes when a refusal is recorded, lets a burst gather,
/// writes it, and writes what is left once more when the daemon stops.
async fn run(inner: Arc<Inner>, mut stop: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            () = inner.wake.notified() => {}
            () = stopped(&mut stop) => break,
        }
        tokio::select! {
            () = tokio::time::sleep(inner.limits.flush_delay) => {}
            () = stopped(&mut stop) => break,
        }
        if let Some(error) = inner.flush().await {
            if matches!(error, StoreError::Closed) {
                return;
            }
            // Retry after a pause, with no new refusal needed to start it.
            tokio::select! {
                () = tokio::time::sleep(inner.limits.retry_delay) => inner.wake.notify_one(),
                () = stopped(&mut stop) => break,
            }
        }
    }
    let _ = inner.flush().await;
}

async fn stopped(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|stop| *stop).await;
}
