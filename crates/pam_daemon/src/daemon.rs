//! Pipeline assembly: the request path from `pam.sock` to a response.
//!
//! # Request path
//!
//! ```text
//! transport → classify → admit (dedupe + row insert) → policy gate
//!           → lane placement → executor → audit → response
//! ```
//!
//! [`run_daemon`] wires the existing services (transport, policy gate,
//! queue manager, store) into long-lived tokio tasks:
//!
//! - a **dispatcher** that spawns one pipeline task per incoming
//!   request ([`Pipeline::handle`]);
//! - an **executor loop** that leases queued work from the lanes and
//!   runs it through [`BuiltinCapability`] dispatch;
//! - the queue's **lease reaper**.
//!
//! # Ordering constraints
//!
//! The gate needs the `request` row to exist (audit foreign key) but
//! must run before anything is placed in a lane, and dedupe must run
//! before the row insert. [`QueueManager::admit`] therefore does
//! dedupe + insert atomically, the gate runs next, and only an allowed
//! request reaches [`QueueManager::place_in_lane`]. A crash between
//! admit and placement can resurrect a not-yet-gated `queued` row on
//! restart; such a row re-enters a lane on rebuild and executes without
//! a fresh gate pass — an accepted, narrow window (the capability was
//! at worst one auto-grant away from allowed).
//!
//! # Boot order and lifecycle
//!
//! [`run_daemon_with`] boots in a fixed order: **instance lock** →
//! store open → **crash recovery** ([`crate::lifecycle::recover_stuck_rows`])
//! → lane rebuild → transport bind (which removes stale socket files —
//! safe, because the lock is already held; see the lifecycle module's
//! lock-first ordering) → serve.
//!
//! Shutdown is a **graceful drain**, driven by an internal lifecycle
//! task once the caller's shutdown watch flips (or the daemon requests
//! its own restart): the phase leaves
//! [`LifecyclePhase::Serving`] so the pipeline refuses new requests
//! ([`CAUSE_DAEMON_SHUTTING_DOWN`]), the executor loop and reaper stop
//! (no new leases; `queued` rows are the restart-safe checkpoint and
//! stay put for the next boot), in-flight leases get a bounded drain
//! ([`DaemonConfig::drain_timeout`]) and are cancelled cooperatively
//! past it, then the dispatcher stops. The store needs no explicit
//! flush — every write (audit included) is per-statement durable — so
//! closing it is dropping it. A request parked in `waiting_approval`
//! is not drained; the next boot's crash recovery fails it legibly.
//!
//! # Version handshake
//!
//! Every envelope carries the client binary's build version. The single
//! `pam` binary ships client and daemon at the same workspace version,
//! so a mismatch means the binary on disk was replaced while this
//! daemon process kept running — the client is the **newer** build.
//! The pipeline checks before anything else: a mismatched request is
//! refused ([`CAUSE_DAEMON_OUTDATED`], with a retry hint — no request
//! row is recorded; the retry lands on the new daemon) and the daemon
//! moves to [`LifecyclePhase::Restarting`], which triggers the same
//! graceful drain. The process shell (`pam daemon`) observes the phase
//! through [`DaemonHandle::lifecycle`] and re-spawns the new binary
//! after the drain; the client-side retry is the client module's job.
//!
//! # Replies and attachment
//!
//! For `wait: true` the pipeline task parks on the [`CompletionRouter`]
//! until the executor finishes the request — duplicate callers attached
//! to the same request register with the same router entry and every
//! waiter receives the terminal [`Response`] (fan-out). The router keeps
//! each terminal response for a short grace period so an attacher that
//! registers just after completion still gets its answer instead of
//! hanging to its deadline. For `wait: false` the pipeline answers with
//! a [`Response::Ticket`] immediately; results reach the store and the
//! event stream only.
//!
//! # Deadlines
//!
//! The envelope's `deadline_ms` is enforced at the pipeline level for
//! waiting callers: past it, the request is cancelled through the queue
//! (the executor observes the signal and records the terminal state on
//! its own path), a [`ACTION_DEADLINE_REFUSAL`] audit row is written,
//! and the caller gets a [`CAUSE_DEADLINE_EXCEEDED`] refusal. Executor-side
//! runaways are reaped by the queue's lease reaper independently.
//!
//! # Audit invariant: every terminal state writes its own audit row
//!
//! Every transition into a terminal request state (`done`, `refused`,
//! `failed`) goes through **one choke point**:
//! [`pam_store::Store::finish_request`], which writes the state, the
//! outcome, and the terminal audit row in a single `SQLite` transaction
//! — crash-safe (no window where the state is terminal but the audit
//! row missing) and race-safe (an already-terminal row is a first-wins
//! no-op, so a reaper/executor double-finish never writes a duplicate
//! audit row). No code path may call
//! [`pam_store::Store::update_request_state`] with a terminal state; the
//! store enforces that with a `debug_assert`, and the laned paths reach
//! the choke point through [`QueueManager::complete`] (which takes the
//! executor's audit fields). The v1 issue #49 lesson — silent terminal
//! paths — is thereby structural, not conventional.
//!
//! The terminal audit row per path ([`TERMINAL_ACTIONS`] lists the
//! action names):
//!
//! - gate refusal (unknown capability, ungranted capability) and every
//!   approval-path refusal (denied, timed out, cancelled while waiting)
//!   → [`ACTION_GATE_REFUSAL`], decision `refuse`, actor `policy`;
//! - execution success → [`ACTION_EXECUTE`], decision `allow`, actor
//!   `system`;
//! - execution failure → [`ACTION_EXECUTE`], decision `refuse`, actor
//!   `system`;
//! - cancelled execution → the queue's `cancel` action, decision `deny`,
//!   actor `system` (queued-side cancellation is audited by the queue
//!   itself, lease reaping by the reaper);
//! - bypass deadline expiry → [`ACTION_DEADLINE_REFUSAL`], decision
//!   `timeout`, actor `system`;
//! - daemon-side bookkeeping failure → [`ACTION_INTERNAL_FAILURE`],
//!   decision `refuse`, actor `system`.
//!
//! On the laned deadline path the [`ACTION_DEADLINE_REFUSAL`] row is
//! written *in addition to* the cancellation row of whichever side tears
//! the request down — the deadline row records the refusal sent to the
//! caller, the cancellation row is the terminal one.
//!
//! Store failures on these bookkeeping writes are swallowed (`let _`)
//! for now: without the tracing setup (a later task) there is nowhere
//! legible to report them, and the caller still gets its response.
//!
//! # Approval pause
//!
//! [`GateDecision::RequireApproval`] parks the admitted request in the
//! approval service ([`crate::approval`]) before lane placement: the
//! request row moves to `waiting_approval`, `approval_pending` goes out
//! on PUB, and the GUI resolves it through
//! [`DaemonHandle::approvals`]. On approval the pipeline moves the row
//! back to `queued` and continues into lane placement exactly as an
//! allow; a denial, timeout, or cancellation refuses with its own cause
//! ([`CAUSE_APPROVAL_DENIED`], [`CAUSE_APPROVAL_TIMEOUT`], the queue's
//! `cancelled`) and a GUI recovery line. A waiting caller whose
//! `deadline_ms` elapses mid-approval cancels the wait (the service
//! resolves the row `denied` with note `cancelled`); a `wait: false`
//! caller gets its ticket immediately and the approval wait runs in a
//! background task, bounded by the approval timeout alone. The
//! request-state transitions around the wait belong to the pipeline —
//! see the approval module docs for the writer split.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pam_proto::{Envelope, Event, Response};
use pam_store::{Actor, AuditEntry, Decision, RequestState, Store, StoreError};
use thiserror::Error;
use tokio::sync::{Mutex, Notify, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::approval::{ApprovalOutcome, ApprovalService, DEFAULT_APPROVAL_TIMEOUT};
use crate::executor::{BuiltinCapability, CapabilityFailure, ExecContext, outcome_str};
use crate::lifecycle::{
    InstanceLock, LifecycleError, LifecyclePhase, acquire_instance_lock, recover_stuck_rows,
};
use crate::policy::{GateDecision, PolicyError, PolicyGate, classify};
use crate::queue::{
    AdmitOutcome, CAUSE_CANCELLED, CAUSE_LEASE_EXPIRED, LeasedWork, QueueError, QueueManager,
};
use crate::runtime_dir::{RuntimeDir, RuntimeDirError};
use crate::transport::{EventPublisher, IncomingRequest, Transport, TransportError};

/// Refusal cause when a waiting caller's `deadline_ms` elapsed.
pub const CAUSE_DEADLINE_EXCEEDED: &str = "deadline_exceeded";

/// Refusal cause when a human denied the required approval.
pub const CAUSE_APPROVAL_DENIED: &str = "approval_denied";

/// Refusal cause when the required approval expired unanswered.
pub const CAUSE_APPROVAL_TIMEOUT: &str = "approval_timeout";

/// Refusal cause (and `request.outcome`) when a capability ran and
/// failed.
pub const CAUSE_EXECUTION_FAILED: &str = "execution_failed";

/// Refusal cause when the daemon's own bookkeeping failed mid-pipeline.
pub const CAUSE_INTERNAL_ERROR: &str = "internal_error";

/// Refusal cause when the envelope's client version does not match the
/// daemon's — the binary on disk is newer; the daemon restarts itself.
pub const CAUSE_DAEMON_OUTDATED: &str = "daemon_outdated";

/// Refusal cause for a request arriving while the daemon drains.
pub const CAUSE_DAEMON_SHUTTING_DOWN: &str = "daemon_shutting_down";

/// `audit.action` for a refusal decided at the policy gate.
pub const ACTION_GATE_REFUSAL: &str = "gate_refusal";

/// `audit.action` for an execution outcome (success or failure).
pub const ACTION_EXECUTE: &str = "execute";

/// `audit.action` for a deadline refusal sent to a waiting caller.
pub const ACTION_DEADLINE_REFUSAL: &str = "deadline_refusal";

/// `audit.action` for a request the daemon failed on its own
/// bookkeeping ([`CAUSE_INTERNAL_ERROR`]).
pub const ACTION_INTERNAL_FAILURE: &str = "internal_failure";

/// Every `audit.action` that records a terminal request state. A
/// terminal request with no audit row among these actions is an audit
/// invariant violation — feed this list to
/// [`pam_store::Store::terminal_requests_missing_audit`].
pub const TERMINAL_ACTIONS: &[&str] = &[
    ACTION_GATE_REFUSAL,
    ACTION_EXECUTE,
    ACTION_DEADLINE_REFUSAL,
    ACTION_INTERNAL_FAILURE,
    crate::queue::ACTION_CANCEL,
    crate::queue::ACTION_LEASE_REAPED,
    crate::lifecycle::ACTION_DAEMON_RESTART,
];

/// This daemon build's version, compared against every envelope's
/// `client_version` (see the module docs on the version handshake).
pub const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");

/// GUI recovery line for [`CAUSE_APPROVAL_DENIED`] refusals.
const RECOVERY_APPROVAL_DENIED: &str =
    "The operation was denied in the PAM GUI; ask the human to approve a retry.";

/// GUI recovery line for [`CAUSE_APPROVAL_TIMEOUT`] refusals.
const RECOVERY_APPROVAL_TIMEOUT: &str =
    "Nobody answered the approval in the PAM GUI in time; retry when a human is available.";

/// Recovery line for a request cancelled while waiting for approval.
const RECOVERY_APPROVAL_CANCELLED: &str =
    "The wait for approval was cancelled; re-run the pam command to ask again.";

/// Recovery line for [`CAUSE_DEADLINE_EXCEEDED`] refusals.
const RECOVERY_DEADLINE: &str =
    "Retry with a larger deadline, or without wait to poll the ticket instead.";

/// Recovery line for [`CAUSE_EXECUTION_FAILED`] refusals.
const RECOVERY_FAILED: &str = "Inspect the failure in the PAM GUI activity view, then retry.";

/// Recovery line for [`CAUSE_INTERNAL_ERROR`] refusals.
const RECOVERY_INTERNAL: &str = "Retry; if it persists, restart the daemon from the PAM GUI.";

/// Recovery line for [`CAUSE_DAEMON_OUTDATED`] refusals.
const RECOVERY_OUTDATED: &str = "The daemon is restarting with the new binary; retry your command.";

/// Recovery line for [`CAUSE_DAEMON_SHUTTING_DOWN`] refusals.
const RECOVERY_SHUTTING_DOWN: &str =
    "Retry shortly; the next pam command starts a fresh daemon automatically.";

/// How long the completion router remembers a terminal response, to
/// close the attach-after-finish race.
const FINISHED_TTL: Duration = Duration::from_mins(1);

/// How often the lease reaper sweeps.
const REAP_INTERVAL: Duration = Duration::from_millis(500);

/// Fallback poll interval of the executor loop; the loop is normally
/// woken by placement/completion notifications, the tick backstops
/// reaper-freed lanes.
const EXECUTOR_TICK: Duration = Duration::from_millis(100);

/// Capacity of the transport → dispatcher channel.
const INCOMING_CAPACITY: usize = 256;

/// Default bound on the graceful drain (see [`DaemonConfig::drain_timeout`]).
pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the lifecycle task re-checks the outstanding leases while
/// draining.
const DRAIN_POLL: Duration = Duration::from_millis(25);

/// Extra budget granted after the drain bound for cancelled executors
/// to observe their cancel signal and record their terminal state.
const CANCEL_GRACE: Duration = Duration::from_secs(2);

/// Why the daemon could not be assembled.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// The runtime directory could not be prepared.
    #[error(transparent)]
    RuntimeDir(#[from] RuntimeDirError),
    /// The transport sockets could not be bound.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The store could not be opened or queried.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The policy gate could not be constructed.
    #[error(transparent)]
    Policy(#[from] PolicyError),
    /// The queue could not be rebuilt.
    #[error(transparent)]
    Queue(#[from] QueueError),
    /// The instance lock could not be taken (another daemon runs, or
    /// the lock file is unusable).
    #[error(transparent)]
    Lifecycle(#[from] LifecycleError),
}

/// Routes each request's single terminal [`Response`] to every pipeline
/// task waiting for it (the requester plus any attached duplicates).
#[derive(Debug, Clone, Default)]
pub struct CompletionRouter {
    inner: Arc<Mutex<RouterInner>>,
}

#[derive(Debug, Default)]
struct RouterInner {
    /// request id → the waiters to answer on completion.
    waiting: HashMap<String, Vec<oneshot::Sender<Response>>>,
    /// Recently finished requests, kept for [`FINISHED_TTL`] so a waiter
    /// registering just after the finish still gets its answer.
    finished: HashMap<String, (Instant, Response)>,
}

/// What [`CompletionRouter::register`] handed back.
#[derive(Debug)]
pub enum Registration {
    /// The request already finished; here is its response.
    Ready(Box<Response>),
    /// The request is still in flight; the receiver resolves with its
    /// terminal response.
    Pending(oneshot::Receiver<Response>),
}

impl CompletionRouter {
    /// An empty router.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers interest in `request_id`'s terminal response.
    pub async fn register(&self, request_id: &str) -> Registration {
        let mut inner = self.inner.lock().await;
        if let Some((_, response)) = inner.finished.get(request_id) {
            return Registration::Ready(Box::new(response.clone()));
        }
        let (tx, rx) = oneshot::channel();
        inner
            .waiting
            .entry(request_id.to_owned())
            .or_default()
            .push(tx);
        Registration::Pending(rx)
    }

    /// Delivers `response` to every waiter registered for `request_id`
    /// and remembers it for late registrants (see [`FINISHED_TTL`]).
    pub async fn finish(&self, request_id: &str, response: Response) {
        let mut inner = self.inner.lock().await;
        if let Some(waiters) = inner.waiting.remove(request_id) {
            for waiter in waiters {
                // A dropped receiver (deadline elapsed) is fine.
                let _ = waiter.send(response.clone());
            }
        }
        let now = Instant::now();
        inner
            .finished
            .insert(request_id.to_owned(), (now, response));
        inner
            .finished
            .retain(|_, (finished_at, _)| now.duration_since(*finished_at) < FINISHED_TTL);
    }
}

/// A running daemon: instance lock held, sockets bound, pipeline tasks
/// pumping.
#[derive(Debug)]
pub struct DaemonHandle {
    dirs: RuntimeDir,
    store: Arc<Store>,
    approvals: Arc<ApprovalService>,
    transport: Transport,
    tasks: Vec<JoinHandle<()>>,
    phase: watch::Sender<LifecyclePhase>,
    /// Held for the daemon's lifetime; dropping the handle releases it.
    _lock: InstanceLock,
}

impl DaemonHandle {
    /// The runtime directory (socket paths) this daemon serves on.
    #[must_use]
    pub fn runtime_dir(&self) -> &RuntimeDir {
        &self.dirs
    }

    /// A handle to the daemon's store, for inspection.
    #[must_use]
    pub fn store(&self) -> Arc<Store> {
        Arc::clone(&self.store)
    }

    /// The approval service — the daemon-internal resolution surface the
    /// GUI plumbing (and integration tests) approve or deny through. No
    /// agent-facing capability reaches it; see [`crate::approval`].
    #[must_use]
    pub fn approvals(&self) -> Arc<ApprovalService> {
        Arc::clone(&self.approvals)
    }

    /// The daemon's lifecycle phase, as a watch: the process shell
    /// observes [`LifecyclePhase::Restarting`] here to know it must
    /// re-spawn the (newer) binary after [`Self::shutdown`] completes.
    #[must_use]
    pub fn lifecycle(&self) -> watch::Receiver<LifecyclePhase> {
        self.phase.subscribe()
    }

    /// Waits for the graceful drain, then stops the transport and joins
    /// every daemon task (see the module docs on the drain).
    ///
    /// The drain starts when the shutdown watch handed to [`run_daemon`]
    /// flips (or its sender drops), or when the daemon requested its own
    /// restart — trigger one of those first, or this call never returns.
    pub async fn shutdown(self) {
        // The lifecycle task is among these; joining it means the drain
        // ran to completion (waiting callers got their answers through
        // the still-live transport) before the sockets close.
        for task in self.tasks {
            let _ = task.await;
        }
        self.transport.shutdown().await;
    }
}

/// Configuration for [`run_daemon_with`]. [`run_daemon`] uses the
/// defaults.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Base directory for the runtime dir and store; `None` means
    /// `~/.pam`.
    pub base_dir: Option<PathBuf>,
    /// How long a pending approval waits before it times out
    /// (default [`DEFAULT_APPROVAL_TIMEOUT`]; tests inject a short one).
    pub approval_timeout: Duration,
    /// How long a graceful shutdown waits for in-flight leases before
    /// cancelling them (default [`DEFAULT_DRAIN_TIMEOUT`]).
    pub drain_timeout: Duration,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            base_dir: None,
            approval_timeout: DEFAULT_APPROVAL_TIMEOUT,
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
        }
    }
}

/// Assembles and starts the daemon with the default configuration
/// (see [`run_daemon_with`]).
pub async fn run_daemon(
    base_dir: Option<PathBuf>,
    shutdown: watch::Receiver<bool>,
) -> Result<DaemonHandle, DaemonError> {
    run_daemon_with(
        DaemonConfig {
            base_dir,
            ..DaemonConfig::default()
        },
        shutdown,
    )
    .await
}

/// Assembles and starts the daemon.
///
/// Boot order (see the module docs): takes the instance lock under
/// `<base>/run` (erroring [`LifecycleError::AlreadyRunning`] when
/// another daemon holds it), opens the store at `<base>/state.sqlite3`
/// (constructing the policy gate from the profile persisted there),
/// fails the rows a dead daemon left mid-flight, rebuilds the queue
/// lanes, binds the transport (stale socket cleanup inside — safe under
/// the held lock), builds the approval service, and spawns the
/// dispatcher, executor loop, lease reaper, and lifecycle task.
/// `config.base_dir` defaults to `~/.pam`. Flip `shutdown` to start the
/// graceful drain, then await [`DaemonHandle::shutdown`].
pub async fn run_daemon_with(
    config: DaemonConfig,
    shutdown: watch::Receiver<bool>,
) -> Result<DaemonHandle, DaemonError> {
    let base = match config.base_dir {
        Some(base) => base,
        None => std::env::home_dir()
            .ok_or(RuntimeDirError::HomeNotFound)?
            .join(".pam"),
    };
    let dirs = RuntimeDir::at_base(&base)?;
    let lock = acquire_instance_lock(dirs.run_dir())?;
    let store = Arc::new(Store::open(&base.join("state.sqlite3")).await?);
    let recovered = recover_stuck_rows(&store).await?;
    if !recovered.is_empty() {
        tracing::info!(
            count = recovered.len(),
            "crash recovery failed stuck in-flight rows from a previous daemon"
        );
    }
    let gate = PolicyGate::new(Arc::clone(&store)).await?;
    let queue = Arc::new(QueueManager::new(Arc::clone(&store)));
    queue.rebuild_from_store().await?;

    let (incoming_tx, incoming_rx) = mpsc::channel(INCOMING_CAPACITY);
    let transport = Transport::bind(&dirs, incoming_tx).await?;

    let approvals = Arc::new(ApprovalService::new(
        Arc::clone(&store),
        transport.event_publisher(),
        config.approval_timeout,
    ));
    let (phase, _) = watch::channel(LifecyclePhase::Serving);
    // Drain stops the lease-granting side (executor loop, reaper);
    // dispatch keeps answering (with refusals) until the drain is done.
    let (drain_tx, drain_rx) = watch::channel(false);
    let (dispatch_stop_tx, dispatch_stop_rx) = watch::channel(false);
    let pipeline = Arc::new(Pipeline {
        store: Arc::clone(&store),
        gate,
        queue: Arc::clone(&queue),
        approvals: Arc::clone(&approvals),
        events: transport.event_publisher(),
        router: CompletionRouter::new(),
        work: Notify::new(),
        started_at: Instant::now(),
        phase: phase.clone(),
    });

    let tasks = vec![
        Arc::clone(&queue).run_reaper(REAP_INTERVAL, drain_rx.clone()),
        tokio::spawn(dispatch_loop(
            Arc::clone(&pipeline),
            incoming_rx,
            dispatch_stop_rx,
        )),
        tokio::spawn(executor_loop(pipeline, drain_rx)),
        tokio::spawn(lifecycle_task(
            shutdown,
            phase.clone(),
            drain_tx,
            dispatch_stop_tx,
            Arc::clone(&queue),
            config.drain_timeout,
        )),
    ];
    tracing::info!(version = DAEMON_VERSION, base = %base.display(), "daemon serving");

    Ok(DaemonHandle {
        dirs,
        store,
        approvals,
        transport,
        tasks,
        phase,
        _lock: lock,
    })
}

/// Drives the graceful drain (see the module docs): waits for the
/// caller's shutdown flip or a self-restart request, refuses new work
/// via the phase, stops the lease-granting tasks, waits (bounded) for
/// in-flight leases, cancels leftovers cooperatively, then stops the
/// dispatcher.
async fn lifecycle_task(
    mut shutdown: watch::Receiver<bool>,
    phase: watch::Sender<LifecyclePhase>,
    drain: watch::Sender<bool>,
    dispatch_stop: watch::Sender<bool>,
    queue: Arc<QueueManager>,
    drain_timeout: Duration,
) {
    let mut phase_rx = phase.subscribe();
    tokio::select! {
        () = signalled(&mut shutdown) => {
            let _ = phase.send_if_modified(|current| {
                if *current == LifecyclePhase::Serving {
                    *current = LifecyclePhase::Draining;
                    true
                } else {
                    false
                }
            });
        }
        // The pipeline moved the phase itself (version handshake).
        _ = phase_rx.wait_for(|current| *current != LifecyclePhase::Serving) => {}
    }
    let _ = drain.send(true);
    tracing::info!(phase = ?*phase.borrow(), "daemon draining");

    let drain_deadline = Instant::now() + drain_timeout;
    while !queue.leased_ids().await.is_empty() && Instant::now() < drain_deadline {
        tokio::time::sleep(DRAIN_POLL).await;
    }
    let leftovers = queue.leased_ids().await;
    if !leftovers.is_empty() {
        tracing::warn!(
            count = leftovers.len(),
            "drain bound hit; cancelling in-flight leases"
        );
        for id in leftovers {
            let _ = queue.cancel(&id, Actor::System).await;
        }
        let grace_deadline = Instant::now() + CANCEL_GRACE;
        while !queue.leased_ids().await.is_empty() && Instant::now() < grace_deadline {
            tokio::time::sleep(DRAIN_POLL).await;
        }
    }
    let _ = dispatch_stop.send(true);
    tracing::info!("daemon drained");
}

/// The services one request flows through, shared by every pipeline
/// task.
struct Pipeline {
    store: Arc<Store>,
    gate: PolicyGate,
    queue: Arc<QueueManager>,
    approvals: Arc<ApprovalService>,
    events: EventPublisher,
    router: CompletionRouter,
    /// Kicked on lane placement and execution completion; wakes the
    /// executor loop.
    work: Notify,
    started_at: Instant,
    /// Read to refuse requests while draining; written to request the
    /// self-restart the version handshake calls for.
    phase: watch::Sender<LifecyclePhase>,
}

/// Resolves when the shutdown flag flips to `true` (a dropped sender
/// counts as shutdown).
async fn signalled(shutdown: &mut watch::Receiver<bool>) {
    let _ = shutdown.wait_for(|stop| *stop).await;
}

/// Receives transport requests and spawns one pipeline task each.
async fn dispatch_loop(
    pipeline: Arc<Pipeline>,
    mut incoming: mpsc::Receiver<IncomingRequest>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let request = tokio::select! {
            () = signalled(&mut shutdown) => break,
            request = incoming.recv() => match request {
                Some(request) => request,
                None => break,
            },
        };
        let pipeline = Arc::clone(&pipeline);
        tokio::spawn(async move {
            pipeline.handle(request.envelope, request.reply).await;
        });
    }
}

/// Leases ready work off the lanes and spawns an execution task per
/// lease. Woken by [`Pipeline::work`]; the tick backstops lanes freed by
/// the reaper.
async fn executor_loop(pipeline: Arc<Pipeline>, mut shutdown: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(EXECUTOR_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        for repo in pipeline.queue.ready_repos().await {
            if let Ok(Some(work)) = pipeline.queue.take_next(&repo).await {
                let pipeline = Arc::clone(&pipeline);
                tokio::spawn(async move {
                    pipeline.execute_leased(work).await;
                });
            }
        }
        tokio::select! {
            () = signalled(&mut shutdown) => break,
            () = pipeline.work.notified() => {}
            _ = ticker.tick() => {}
        }
    }
}

impl Pipeline {
    /// Runs one request through classify → admit → gate → queue/execute
    /// and answers `reply` with its single [`Response`]. Takes the
    /// pipeline by `Arc` so the approval path can spawn a background
    /// wait for `wait: false` callers.
    async fn handle(self: Arc<Self>, envelope: Envelope, reply: oneshot::Sender<Response>) {
        let id = envelope.id.clone();

        // Lifecycle gates run before anything is recorded: neither a
        // drain refusal nor a version-handshake refusal gets a request
        // row — the retry lands on the next (or new) daemon and is
        // recorded there.
        if *self.phase.borrow() != LifecyclePhase::Serving {
            let _ = reply.send(shutting_down_refusal(&id));
            return;
        }
        if envelope.client_version != DAEMON_VERSION {
            // The single binary ships client and daemon at the same
            // version, so a mismatch means the binary on disk was
            // replaced: the client is the newer build. Answer this
            // request, then hand over to the new binary.
            tracing::info!(
                client_version = %envelope.client_version,
                daemon_version = DAEMON_VERSION,
                "client build differs; restarting with the binary on disk"
            );
            let _ = reply.send(outdated_refusal(&id, &envelope.client_version));
            let _ = self.phase.send_if_modified(|current| {
                if *current == LifecyclePhase::Serving {
                    *current = LifecyclePhase::Restarting;
                    true
                } else {
                    false
                }
            });
            return;
        }

        // Unknown capability: no class, no dedupe — record the request,
        // let the gate produce the refusal.
        let Some(class) = classify(&envelope.capability) else {
            let response = self.refuse_unadmitted(&envelope).await;
            let _ = reply.send(response);
            return;
        };

        let Ok(admitted) = self.queue.admit(&envelope, class).await else {
            let _ = reply.send(internal_refusal(&id));
            return;
        };

        match admitted {
            AdmitOutcome::Attached {
                existing_request_id,
            } => {
                if envelope.wait {
                    let registration = self.router.register(&existing_request_id).await;
                    let response = await_registration(registration, envelope.deadline_ms)
                        .await
                        .unwrap_or_else(|timed_out| attach_refusal(&id, timed_out));
                    let _ = reply.send(response);
                } else {
                    let _ = reply.send(Response::Ticket {
                        id,
                        ticket: existing_request_id,
                        position: 0,
                    });
                }
            }
            AdmitOutcome::Bypass => {
                if envelope.wait {
                    let response = self.execute_bypass(&envelope).await;
                    let _ = reply.send(response);
                } else {
                    let _ = reply.send(Response::Ticket {
                        id: id.clone(),
                        ticket: id,
                        position: 0,
                    });
                    // Result reaches the store and event stream only.
                    let _ = self.execute_bypass(&envelope).await;
                }
            }
            AdmitOutcome::Admitted => {
                let response = self.gate_and_place(&envelope).await;
                let _ = reply.send(response);
            }
        }
    }

    /// The laned path after admission: gate, then place (pausing for an
    /// approval when the gate requires one) and, for waiting callers,
    /// park on the completion router under the deadline.
    async fn gate_and_place(self: Arc<Self>, envelope: &Envelope) -> Response {
        let id = &envelope.id;
        let Ok(decision) = self.gate.evaluate(id, &envelope.capability).await else {
            // Keep the not-yet-placed row out of the lanes forever.
            return self.fail_internal(id).await;
        };
        match decision {
            GateDecision::Refuse {
                cause,
                detail,
                recovery,
            } => self.refuse(id, cause, detail, recovery).await,
            GateDecision::RequireApproval { reason } => self.approval_pause(envelope, reason).await,
            GateDecision::Allow { .. } => self.place_and_wait(envelope, envelope.deadline_ms).await,
        }
    }

    /// Places an allowed (or approved) request on its lane and, for a
    /// waiting caller, parks on the completion router with `deadline_ms`
    /// of budget left.
    async fn place_and_wait(&self, envelope: &Envelope, deadline_ms: u64) -> Response {
        let id = &envelope.id;
        // Register before placement so the completion cannot slip
        // between the two.
        let registration = self.router.register(id).await;
        let position = self
            .queue
            .place_in_lane(id, &envelope.caller.repo, envelope.deadline_ms)
            .await;
        let _ = self.events.publish(id, Event::Queued).await;
        self.work.notify_one();
        if envelope.wait {
            match await_registration(registration, deadline_ms).await {
                Ok(response) => response,
                Err(true) => self.deadline_refusal(envelope).await,
                Err(false) => internal_refusal(id),
            }
        } else {
            Response::Ticket {
                id: id.clone(),
                ticket: id.clone(),
                position: u64::try_from(position).unwrap_or(u64::MAX),
            }
        }
    }

    /// The approval pause (see the module docs): parks the request in
    /// the approval service, then continues into placement (approved) or
    /// refuses (denied, timed out, cancelled). A `wait: false` caller
    /// gets its ticket immediately while the wait runs in a background
    /// task bounded by the approval timeout.
    async fn approval_pause(self: Arc<Self>, envelope: &Envelope, reason: String) -> Response {
        if envelope.wait {
            return self.approval_wait_inline(envelope, &reason).await;
        }
        let ticket = Response::Ticket {
            id: envelope.id.clone(),
            ticket: envelope.id.clone(),
            position: 0,
        };
        let envelope = envelope.clone();
        tokio::spawn(async move {
            // The cancel signal never fires here — the sender is held
            // until the wait ends; the approval timeout is the bound.
            let (_cancel_tx, mut cancel) = watch::channel(false);
            let outcome = self
                .approvals
                .request_approval(&envelope.id, &envelope.capability, &mut cancel)
                .await;
            // The response reaches the store, events, and any attached
            // waiters; the ticket holder polls those.
            let _ = self
                .conclude_approval(&envelope, &reason, outcome, envelope.deadline_ms)
                .await;
        });
        ticket
    }

    /// The waiting caller's approval pause: the wait is additionally
    /// bounded by the envelope's `deadline_ms` — past it the wait is
    /// cancelled (the service resolves the approval row as denied with
    /// note `cancelled`) and the caller gets a refusal.
    async fn approval_wait_inline(&self, envelope: &Envelope, reason: &str) -> Response {
        let id = &envelope.id;
        let waited_from = Instant::now();
        let (cancel_tx, mut cancel) = watch::channel(false);
        let fut = self
            .approvals
            .request_approval(id, &envelope.capability, &mut cancel);
        tokio::pin!(fut);
        let outcome = tokio::select! {
            outcome = &mut fut => outcome,
            () = tokio::time::sleep(Duration::from_millis(envelope.deadline_ms)) => {
                let _ = cancel_tx.send(true);
                // Resolves promptly: the service observes the signal,
                // records the cancellation, and returns.
                fut.await
            }
        };
        let elapsed_ms = u64::try_from(waited_from.elapsed().as_millis()).unwrap_or(u64::MAX);
        let remaining_ms = envelope.deadline_ms.saturating_sub(elapsed_ms);
        self.conclude_approval(envelope, reason, outcome, remaining_ms)
            .await
    }

    /// Acts on an approval wait's outcome: approved requests move back
    /// to `queued` and continue into placement with `deadline_ms` of
    /// budget left; everything else becomes a terminal refusal (audited
    /// via [`Self::refuse`], released to attached waiters through the
    /// router).
    async fn conclude_approval(
        &self,
        envelope: &Envelope,
        reason: &str,
        outcome: Result<ApprovalOutcome, StoreError>,
        deadline_ms: u64,
    ) -> Response {
        let id = &envelope.id;
        let capability = &envelope.capability;
        match outcome {
            Ok(ApprovalOutcome::Approved { .. }) => {
                // The pipeline owns the transition out of
                // waiting_approval (see the approval module docs):
                // back to queued, then placement as any allow.
                if self
                    .store
                    .update_request_state(id, RequestState::Queued, None)
                    .await
                    .is_err()
                {
                    return self.fail_internal(id).await;
                }
                self.place_and_wait(envelope, deadline_ms).await
            }
            Ok(ApprovalOutcome::Denied) => {
                self.refuse_approval(
                    id,
                    CAUSE_APPROVAL_DENIED,
                    format!("approval for capability {capability:?} was denied ({reason})"),
                    RECOVERY_APPROVAL_DENIED,
                )
                .await
            }
            Ok(ApprovalOutcome::TimedOut) => {
                self.refuse_approval(
                    id,
                    CAUSE_APPROVAL_TIMEOUT,
                    format!("approval for capability {capability:?} expired unanswered ({reason})"),
                    RECOVERY_APPROVAL_TIMEOUT,
                )
                .await
            }
            Ok(ApprovalOutcome::Cancelled) => {
                self.refuse_approval(
                    id,
                    CAUSE_CANCELLED,
                    format!(
                        "request was cancelled while waiting for approval \
                         of capability {capability:?}"
                    ),
                    RECOVERY_APPROVAL_CANCELLED,
                )
                .await
            }
            Err(_) => self.fail_internal(id).await,
        }
    }

    /// Refuses a request whose approval wait did not end in an approval,
    /// and releases any attached duplicate callers with the same refusal
    /// (they may have attached during the long `waiting_approval` window).
    async fn refuse_approval(
        &self,
        id: &str,
        cause: &str,
        detail: String,
        recovery: &str,
    ) -> Response {
        let response = self
            .refuse(id, cause.to_owned(), detail, recovery.to_owned())
            .await;
        self.router.finish(id, response.clone()).await;
        response
    }

    /// Executes a read-only bypass request inline, under the envelope's
    /// deadline, and records its terminal state.
    async fn execute_bypass(&self, envelope: &Envelope) -> Response {
        let id = &envelope.id;
        let _ = self.events.publish(id, Event::Started).await;
        // No lease exists for a bypass; the sender is held so the cancel
        // signal simply never fires. The deadline timeout below dropping
        // the future is the cancellation mechanism on this path.
        let (_cancel_tx, cancel) = watch::channel(false);
        let Some(capability) = BuiltinCapability::from_name(&envelope.capability) else {
            return self
                .fail_bypass(
                    id,
                    &envelope.capability,
                    "capability classified but not dispatchable",
                )
                .await;
        };
        let ctx = self.exec_context(id.clone(), envelope.args.clone(), cancel);
        match timeout(
            Duration::from_millis(envelope.deadline_ms),
            capability.execute(ctx),
        )
        .await
        {
            Ok(Ok(output)) => {
                let detail = execute_success_detail(&envelope.capability, output.outcome);
                let _ = self
                    .store
                    .finish_request(
                        id,
                        RequestState::Done,
                        Some(outcome_str(output.outcome)),
                        execute_success_entry(&detail),
                    )
                    .await;
                let _ = self.events.publish(id, Event::Done).await;
                Response::Result {
                    id: id.clone(),
                    outcome: output.outcome,
                    body: output.body,
                    evidence: output.evidence,
                }
            }
            Ok(Err(CapabilityFailure::Cancelled)) => {
                // Unreachable without a lease, but handled legibly.
                let detail = cancelled_detail();
                let _ = self
                    .store
                    .finish_request(
                        id,
                        RequestState::Failed,
                        Some(CAUSE_CANCELLED),
                        cancelled_entry(&detail),
                    )
                    .await;
                let _ = self.events.publish(id, Event::Refused).await;
                cancelled_refusal(id)
            }
            Ok(Err(CapabilityFailure::Failed { detail })) => {
                self.fail_bypass(id, &envelope.capability, &detail).await
            }
            Err(_elapsed) => {
                let detail = serde_json::json!({ "deadline_ms": envelope.deadline_ms }).to_string();
                let _ = self
                    .store
                    .finish_request(
                        id,
                        RequestState::Failed,
                        Some(CAUSE_DEADLINE_EXCEEDED),
                        AuditEntry {
                            action: ACTION_DEADLINE_REFUSAL,
                            decision: Decision::Timeout,
                            actor: Actor::System,
                            detail: Some(&detail),
                        },
                    )
                    .await;
                let _ = self.events.publish(id, Event::Refused).await;
                deadline_refusal_response(id, envelope.deadline_ms)
            }
        }
    }

    /// Executes one leased (laned) request and records its terminal
    /// state, audit row, events, and router completion.
    async fn execute_leased(&self, work: LeasedWork) {
        let LeasedWork {
            request_id: id,
            cancel,
            ..
        } = work;
        let Ok(Some(row)) = self.store.get_request(&id).await else {
            // A vanished row is unanswerable; free the lane and move on.
            let detail = serde_json::json!({ "cause": "request row missing" }).to_string();
            let _ = self
                .queue
                .complete(
                    &id,
                    RequestState::Failed,
                    Some(CAUSE_INTERNAL_ERROR),
                    internal_failure_entry(&detail),
                )
                .await;
            self.work.notify_one();
            return;
        };
        let _ = self.events.publish(&id, Event::Started).await;

        let result = match BuiltinCapability::from_name(&row.capability) {
            Some(capability) => {
                let args = serde_json::from_str(&row.args_json).unwrap_or(serde_json::Value::Null);
                let ctx = self.exec_context(id.clone(), args, cancel);
                capability.execute(ctx).await
            }
            // The gate classified it, so this only fires on registry
            // drift between classify() and from_name().
            None => Err(CapabilityFailure::Failed {
                detail: "capability classified but not dispatchable".to_owned(),
            }),
        };

        match result {
            Ok(output) => {
                let audit_detail = execute_success_detail(&row.capability, output.outcome);
                let terminal = self
                    .queue
                    .complete(
                        &id,
                        RequestState::Done,
                        Some(outcome_str(output.outcome)),
                        execute_success_entry(&audit_detail),
                    )
                    .await;
                if matches!(terminal, Ok(true)) {
                    let _ = self.events.publish(&id, Event::Done).await;
                    self.router
                        .finish(
                            &id,
                            Response::Result {
                                id: id.clone(),
                                outcome: output.outcome,
                                body: output.body,
                                evidence: output.evidence,
                            },
                        )
                        .await;
                } else {
                    // The lease was reaped first: the reaper wrote the
                    // terminal row and audit; release any waiters.
                    self.finish_reaped(&id).await;
                }
            }
            Err(CapabilityFailure::Cancelled) => {
                let audit_detail = cancelled_detail();
                let terminal = self
                    .queue
                    .complete(
                        &id,
                        RequestState::Failed,
                        Some(CAUSE_CANCELLED),
                        cancelled_entry(&audit_detail),
                    )
                    .await;
                if matches!(terminal, Ok(true)) {
                    let _ = self.events.publish(&id, Event::Refused).await;
                    self.router.finish(&id, cancelled_refusal(&id)).await;
                } else {
                    self.finish_reaped(&id).await;
                }
            }
            Err(CapabilityFailure::Failed { detail }) => {
                let audit_detail = execute_failure_detail(&row.capability, &detail);
                let terminal = self
                    .queue
                    .complete(
                        &id,
                        RequestState::Failed,
                        Some(CAUSE_EXECUTION_FAILED),
                        execute_failure_entry(&audit_detail),
                    )
                    .await;
                if matches!(terminal, Ok(true)) {
                    let _ = self.events.publish(&id, Event::Refused).await;
                    self.router.finish(&id, failure_refusal(&id, detail)).await;
                } else {
                    self.finish_reaped(&id).await;
                }
            }
        }
        // The lane is free again.
        self.work.notify_one();
    }

    /// Builds the execution context for one request.
    fn exec_context(
        &self,
        request_id: String,
        args: serde_json::Value,
        cancel: watch::Receiver<bool>,
    ) -> ExecContext {
        ExecContext {
            request_id,
            args,
            cancel,
            events: self.events.clone(),
            store: Arc::clone(&self.store),
            queue: Arc::clone(&self.queue),
            router: self.router.clone(),
            started_at: self.started_at,
        }
    }

    /// Inserts the row for a request that never passed admission (an
    /// unknown capability) and refuses it through the gate.
    async fn refuse_unadmitted(&self, envelope: &Envelope) -> Response {
        let inserted = self
            .store
            .insert_request(
                &envelope.id,
                &envelope.capability,
                &envelope.caller.repo,
                &envelope.caller.agent,
                &envelope.args.to_string(),
                envelope.idempotency_key.as_deref(),
            )
            .await;
        if inserted.is_err() {
            return internal_refusal(&envelope.id);
        }
        match self.gate.evaluate(&envelope.id, &envelope.capability).await {
            Ok(GateDecision::Refuse {
                cause,
                detail,
                recovery,
            }) => self.refuse(&envelope.id, cause, detail, recovery).await,
            // classify() said None, so the gate must refuse; anything
            // else is an internal inconsistency.
            _ => internal_refusal(&envelope.id),
        }
    }

    /// Marks a request refused — terminal state and gate-refusal audit
    /// row in one transaction — publishes the `refused` event, and
    /// builds the refusal response.
    async fn refuse(&self, id: &str, cause: String, detail: String, recovery: String) -> Response {
        let audit_detail = serde_json::json!({
            "cause": cause,
            "detail": detail,
            "profile": self.gate.profile().as_str(),
        })
        .to_string();
        let _ = self
            .store
            .finish_request(
                id,
                RequestState::Refused,
                Some(&cause),
                AuditEntry {
                    action: ACTION_GATE_REFUSAL,
                    decision: Decision::Refuse,
                    actor: Actor::Policy,
                    detail: Some(&audit_detail),
                },
            )
            .await;
        let _ = self.events.publish(id, Event::Refused).await;
        Response::Refusal {
            id: id.to_owned(),
            cause,
            detail,
            recovery,
        }
    }

    /// Terminal handling for a daemon-side bookkeeping failure: fail the
    /// request with its [`ACTION_INTERNAL_FAILURE`] audit row and answer
    /// with the internal refusal.
    async fn fail_internal(&self, id: &str) -> Response {
        let detail = serde_json::json!({ "cause": CAUSE_INTERNAL_ERROR }).to_string();
        let _ = self
            .store
            .finish_request(
                id,
                RequestState::Failed,
                Some(CAUSE_INTERNAL_ERROR),
                internal_failure_entry(&detail),
            )
            .await;
        internal_refusal(id)
    }

    /// Terminal handling for a bypass execution failure.
    async fn fail_bypass(&self, id: &str, capability: &str, detail: &str) -> Response {
        let audit_detail = execute_failure_detail(capability, detail);
        let _ = self
            .store
            .finish_request(
                id,
                RequestState::Failed,
                Some(CAUSE_EXECUTION_FAILED),
                execute_failure_entry(&audit_detail),
            )
            .await;
        let _ = self.events.publish(id, Event::Refused).await;
        failure_refusal(id, detail.to_owned())
    }

    /// Tears a deadline-expired waiting request down: cancel through the
    /// queue (whichever side holds it records the terminal state), audit
    /// the refusal, tell subscribers, answer the caller.
    async fn deadline_refusal(&self, envelope: &Envelope) -> Response {
        let id = &envelope.id;
        let _ = self.queue.cancel(id, Actor::System).await;
        self.audit_deadline(id, envelope.deadline_ms).await;
        let _ = self.events.publish(id, Event::Refused).await;
        deadline_refusal_response(id, envelope.deadline_ms)
    }

    /// Releases waiters of a request whose lease was reaped mid-flight
    /// (the reaper already wrote the terminal row and audit).
    async fn finish_reaped(&self, id: &str) {
        let _ = self.events.publish(id, Event::Refused).await;
        self.router
            .finish(
                id,
                Response::Refusal {
                    id: id.to_owned(),
                    cause: CAUSE_LEASE_EXPIRED.to_owned(),
                    detail: format!("request {id} outlived its lease and was reaped"),
                    recovery: RECOVERY_DEADLINE.to_owned(),
                },
            )
            .await;
    }

    /// Audit row for a deadline refusal sent to a waiting caller.
    ///
    /// This is the one supplementary (non-terminal) audit append on the
    /// laned deadline path: the terminal row is the cancellation row of
    /// whichever side tears the request down (see the module docs).
    async fn audit_deadline(&self, id: &str, deadline_ms: u64) {
        let detail = serde_json::json!({ "deadline_ms": deadline_ms }).to_string();
        let _ = self
            .store
            .append_audit(
                id,
                ACTION_DEADLINE_REFUSAL,
                Decision::Timeout,
                Actor::System,
                Some(&detail),
            )
            .await;
    }
}

/// Audit detail for a successful execution.
fn execute_success_detail(capability: &str, outcome: pam_proto::Outcome) -> String {
    serde_json::json!({
        "capability": capability,
        "outcome": outcome_str(outcome),
    })
    .to_string()
}

/// Terminal audit entry for a successful execution.
fn execute_success_entry(detail: &str) -> AuditEntry<'_> {
    AuditEntry {
        action: ACTION_EXECUTE,
        decision: Decision::Allow,
        actor: Actor::System,
        detail: Some(detail),
    }
}

/// Audit detail for a failed execution.
fn execute_failure_detail(capability: &str, detail: &str) -> String {
    serde_json::json!({
        "capability": capability,
        "detail": detail,
    })
    .to_string()
}

/// Terminal audit entry for a failed execution.
fn execute_failure_entry(detail: &str) -> AuditEntry<'_> {
    AuditEntry {
        action: ACTION_EXECUTE,
        decision: Decision::Refuse,
        actor: Actor::System,
        detail: Some(detail),
    }
}

/// Audit detail for an execution the cancel signal stopped.
fn cancelled_detail() -> String {
    serde_json::json!({ "actor": Actor::System.as_str() }).to_string()
}

/// Terminal audit entry for an execution the cancel signal stopped
/// (mirrors the queue's queued-side cancellation row).
fn cancelled_entry(detail: &str) -> AuditEntry<'_> {
    AuditEntry {
        action: crate::queue::ACTION_CANCEL,
        decision: Decision::Deny,
        actor: Actor::System,
        detail: Some(detail),
    }
}

/// Terminal audit entry for a daemon-side bookkeeping failure.
fn internal_failure_entry(detail: &str) -> AuditEntry<'_> {
    AuditEntry {
        action: ACTION_INTERNAL_FAILURE,
        decision: Decision::Refuse,
        actor: Actor::System,
        detail: Some(detail),
    }
}

/// Awaits a router registration under `deadline_ms`. `Err(true)` means
/// the deadline elapsed; `Err(false)` means the router dropped the
/// waiter without answering (internal failure).
async fn await_registration(
    registration: Registration,
    deadline_ms: u64,
) -> Result<Response, bool> {
    match registration {
        Registration::Ready(response) => Ok(*response),
        Registration::Pending(rx) => match timeout(Duration::from_millis(deadline_ms), rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(false),
            Err(_elapsed) => Err(true),
        },
    }
}

/// The refusal an *attached* caller gets when its own deadline elapses
/// (`timed_out`) or the router fails. The attached caller has no request
/// row of its own, so nothing is audited and the in-flight original is
/// left alone — other callers may still be waiting on it.
fn attach_refusal(id: &str, timed_out: bool) -> Response {
    if timed_out {
        Response::Refusal {
            id: id.to_owned(),
            cause: CAUSE_DEADLINE_EXCEEDED.to_owned(),
            detail: "the in-flight request this call attached to did not finish \
                     within the deadline"
                .to_owned(),
            recovery: RECOVERY_DEADLINE.to_owned(),
        }
    } else {
        internal_refusal(id)
    }
}

/// Refusal for a request that arrived while the daemon drains.
fn shutting_down_refusal(id: &str) -> Response {
    Response::Refusal {
        id: id.to_owned(),
        cause: CAUSE_DAEMON_SHUTTING_DOWN.to_owned(),
        detail: "the daemon is draining in-flight work before it exits".to_owned(),
        recovery: RECOVERY_SHUTTING_DOWN.to_owned(),
    }
}

/// Refusal for the version handshake: the client build is newer than
/// this daemon, which restarts itself.
fn outdated_refusal(id: &str, client_version: &str) -> Response {
    Response::Refusal {
        id: id.to_owned(),
        cause: CAUSE_DAEMON_OUTDATED.to_owned(),
        detail: format!(
            "client version {client_version} does not match daemon version \
             {DAEMON_VERSION}; the pam binary was replaced while this daemon ran"
        ),
        recovery: RECOVERY_OUTDATED.to_owned(),
    }
}

/// Refusal for a daemon-side bookkeeping failure.
fn internal_refusal(id: &str) -> Response {
    Response::Refusal {
        id: id.to_owned(),
        cause: CAUSE_INTERNAL_ERROR.to_owned(),
        detail: "the daemon could not record the request".to_owned(),
        recovery: RECOVERY_INTERNAL.to_owned(),
    }
}

/// Refusal for a request that was cancelled.
fn cancelled_refusal(id: &str) -> Response {
    Response::Refusal {
        id: id.to_owned(),
        cause: CAUSE_CANCELLED.to_owned(),
        detail: format!("request {id} was cancelled"),
        recovery: "Re-run the pam command to start a fresh request.".to_owned(),
    }
}

/// Refusal for a capability that ran and failed.
fn failure_refusal(id: &str, detail: String) -> Response {
    Response::Refusal {
        id: id.to_owned(),
        cause: CAUSE_EXECUTION_FAILED.to_owned(),
        detail,
        recovery: RECOVERY_FAILED.to_owned(),
    }
}

/// Refusal for an elapsed deadline.
fn deadline_refusal_response(id: &str, deadline_ms: u64) -> Response {
    Response::Refusal {
        id: id.to_owned(),
        cause: CAUSE_DEADLINE_EXCEEDED.to_owned(),
        detail: format!("request exceeded its {deadline_ms} ms deadline"),
        recovery: RECOVERY_DEADLINE.to_owned(),
    }
}
