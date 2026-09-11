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
//! - the queue's **lease reaper**;
//! - the **retention pruner** ([`crate::retention`]), which prunes on
//!   its first tick — so a boot prunes, right after crash recovery —
//!   and every [`PRUNE_INTERVAL`] after that.
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
//! # Admin surface (GUI-only)
//!
//! Envelopes whose capability starts with the reserved
//! [`crate::admin::ADMIN_PREFIX`] are refused on public IPC regardless
//! of caller labels. Native private administration uses
//! [`crate::admin_transport`] and owns its work through terminal audit. Admin operations
//! are not capabilities: they have no `classify()` entry and can never
//! be granted, approved, or queued. The service records its own request
//! row, enforces the envelope deadline, audits every outcome
//! ([`ACTION_ADMIN`] / [`ACTION_ADMIN_DENIED`] are terminal actions),
//! and answers synchronously — no events, except what an approval
//! resolution already publishes through the approval service. The full
//! security model (why GUI-only is structural for CLI users but
//! advisory at the socket) lives in the [`crate::admin`] module docs.
//!
//! # Caller registry
//!
//! Every **admitted** request (bypass, laned, or attached duplicate)
//! upserts its observed agent+repo pair into the `caller` table — an
//! advisory registry feeding the GUI sidebar and activity filters,
//! never authorization. Admin envelopes are deliberately excluded: the
//! GUI is not an observed workload.
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
//! Admission persists one expiry for the original request. Approval waits,
//! lane waits and execution share it, including ticketed requests. An expired
//! laned request is recorded as `failed` / `lease_expired`, signalled to stop,
//! and exposed as [`CAUSE_DEADLINE_EXCEEDED`]. Explicit cancellation retains
//! its separate cause. Attached observers have independent wait timeouts and
//! never cancel the original request when their own wait expires.
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
//! written *in addition to* the lease-expiry terminal row. The persisted
//! outcome is `lease_expired`; both the original waiter and reaper expose
//! `deadline_exceeded` to callers. Explicit cancellation remains `cancelled`.
//!
//! A store failure on a terminal write cannot be answered to anyone
//! (the caller already has its response or its ticket), so it is logged
//! at error level in the daemon log and the row is left for the next
//! boot's crash recovery. Concurrent statements on the store's single
//! connection used to be the one way such a write failed (turso refuses
//! concurrent use of a connection); the store now serializes them.
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
//! background task, bounded by approval timeout and original admission expiry.
//! The request-state transitions around the wait belong to the pipeline —
//! see the approval module docs for the writer split.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pam_connectors::{CurlTransport, HttpTransport};
use pam_proto::{Envelope, Event, Response};
use pam_store::{Actor, AuditEntry, Decision, RequestState, Store, StoreError};
use thiserror::Error;
use tokio::sync::{Mutex, Notify, Semaphore, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

use crate::admin::{ACTION_ADMIN, ACTION_ADMIN_DENIED, ADMIN_PREFIX, AdminService};
use crate::approval::{ApprovalOutcome, ApprovalService, DEFAULT_APPROVAL_TIMEOUT};
use crate::connector_service::ConnectorService;
use crate::executor::{
    BuiltinCapability, CapabilityFailure, CapabilityOutput, ExecContext, outcome_str,
};
use crate::flow_service::FlowService;
use crate::lifecycle::{
    InstanceLock, LifecycleError, LifecyclePhase, acquire_instance_lock, recover_stuck_rows,
};
use crate::log_service::LogService;
use crate::model_service::ModelService;
use crate::policy::{GateDecision, PolicyError, PolicyGate, classify};
use crate::queue::{AdmitOutcome, CAUSE_CANCELLED, LeasedWork, QueueError, QueueManager};
use crate::retention::{PRUNE_INTERVAL, RetentionService};
use crate::runtime_dir::{RuntimeDir, RuntimeDirError};
use crate::secrets::{SecretBackend, SecretStore};
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

/// `audit.action` for a refusal an executing capability itself decided
/// ([`CapabilityFailure::Refused`]) — the request named something that
/// does not exist, or is not usable as asked.
pub const ACTION_EXECUTION_REFUSAL: &str = "execution_refused";

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
    ACTION_EXECUTION_REFUSAL,
    ACTION_DEADLINE_REFUSAL,
    ACTION_INTERNAL_FAILURE,
    ACTION_ADMIN,
    ACTION_ADMIN_DENIED,
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
    "Inspect retained evidence and retry with a larger request deadline if appropriate.";

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
    /// The private administrative listener could not be secured.
    #[error("private admin transport: {0}")]
    AdminTransport(std::io::Error),
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

    /// Whether anyone is still waiting for `request_id`'s terminal
    /// response. A reaped expiry reads this before choosing the refusal a
    /// waiter receives: a caller that is still parked gets its elapsed
    /// deadline, while an unobserved request records only the reaper's own
    /// teardown. Entries whose receiver the caller dropped do not count —
    /// nobody is listening, and the map entry itself only clears on
    /// [`Self::finish`].
    pub async fn has_waiters(&self, request_id: &str) -> bool {
        self.inner.lock().await.waiting.get(request_id).is_some_and(
            |waiters| waiters.iter().any(|tx| !tx.is_closed()),
        )
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
    models: Arc<ModelService>,
    transport: Transport,
    admin_transport: crate::admin_transport::AdminTransport,
    admin: Arc<AdminService>,
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

    /// Trusted in-process administration for embedding/test hosts. This is not
    /// exposed over public IPC; a socket client cannot obtain this handle.
    #[must_use]
    pub fn admin(&self) -> Arc<AdminService> {
        Arc::clone(&self.admin)
    }

    /// The model layer: registry, runtime, downloads, tier defaults.
    /// The GUI plumbing and the integration tests reach the model
    /// surface through it; agents never do (see [`crate::admin_models`]).
    #[must_use]
    pub fn models(&self) -> Arc<ModelService> {
        Arc::clone(&self.models)
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
        self.admin_transport.shutdown().await;
        self.transport.shutdown().await;
    }
}

/// Configuration for [`run_daemon_with`]. [`run_daemon`] uses the
/// defaults.
#[derive(Clone)]
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
    /// Where connector credentials live; `None` opens the OS-native
    /// credential store (tests inject
    /// [`crate::secrets::FakeSecretBackend`]).
    pub secret_backend: Option<Arc<dyn SecretBackend>>,
    /// How connector calls reach the network; `None` builds a
    /// [`CurlTransport`] over the system `curl` (tests inject
    /// `pam_connectors::testing::FakeTransport`).
    pub http_transport: Option<Arc<dyn HttpTransport>>,
}

impl std::fmt::Debug for DaemonConfig {
    /// Neither injected dependency is `Debug` — and a credential backend
    /// must never render itself — so they are reported as present or
    /// absent.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DaemonConfig")
            .field("base_dir", &self.base_dir)
            .field("approval_timeout", &self.approval_timeout)
            .field("drain_timeout", &self.drain_timeout)
            .field("secret_backend", &self.secret_backend.is_some())
            .field("http_transport", &self.http_transport.is_some())
            .finish()
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            base_dir: None,
            approval_timeout: DEFAULT_APPROVAL_TIMEOUT,
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
            secret_backend: None,
            http_transport: None,
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
#[allow(
    clippy::too_many_lines,
    reason = "ordered service assembly keeps lock, ingress and shutdown ownership visible together"
)]
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
    let base = crate::admin_transport::prepare_base(&base).map_err(DaemonError::AdminTransport)?;
    let dirs = RuntimeDir::at_base(&base)?;
    let lock = acquire_instance_lock(dirs.run_dir())?;
    let store = Arc::new(Store::open(&base.join("state.sqlite3")).await?);
    let recovered = recover_stuck_rows(&store).await?;
    if recovered != 0 {
        tracing::info!(
            count = recovered,
            "crash recovery reconciled in-flight rows from a previous daemon"
        );
    }
    let gate = Arc::new(PolicyGate::new(Arc::clone(&store)).await?);
    let models = ModelService::new(Arc::clone(&store)).await?;
    let logs = LogService::new(Arc::clone(&store), Arc::clone(&models));
    let secrets = open_secret_store(config.secret_backend);
    // macOS only inside: the first keychain touch of a session can be
    // slow, and paying for it right after boot keeps it off the first
    // flow step.
    secrets.warm();
    let connectors = Arc::new(ConnectorService::from_parts(
        Arc::clone(&store),
        Some(Arc::clone(&secrets)),
        open_http_transport(config.http_transport),
    ));
    let queue = Arc::new(QueueManager::new(Arc::clone(&store)));
    queue.rebuild_from_store().await?;

    let (incoming_tx, incoming_rx) = mpsc::channel(INCOMING_CAPACITY);
    let transport = Transport::bind(&dirs, incoming_tx.clone()).await?;

    let approvals = Arc::new(ApprovalService::new(
        Arc::clone(&store),
        transport.event_publisher(),
        config.approval_timeout,
    ));
    let flows = Arc::new(FlowService::new(
        &base,
        Arc::clone(&store),
        Arc::clone(&approvals),
        Arc::clone(&connectors),
        Arc::clone(&logs),
        Arc::clone(&gate),
    ));
    let (phase, _) = watch::channel(LifecyclePhase::Serving);
    // Drain stops the lease-granting side (executor loop, reaper);
    // dispatch keeps answering (with refusals) until the drain is done.
    let (drain_tx, drain_rx) = watch::channel(false);
    let (dispatch_stop_tx, dispatch_stop_rx) = watch::channel(false);
    let admin = Arc::new(AdminService::new(
        Arc::clone(&store),
        Arc::clone(&approvals),
        Arc::clone(&models),
        logs,
        connectors,
        Arc::clone(&flows),
        incoming_tx.clone(),
    ));
    let admin_transport = match crate::admin_transport::AdminTransport::bind(
        &base,
        Arc::clone(&admin),
        phase.clone(),
    ) {
        Ok(listener) => listener,
        Err(error) => {
            transport.shutdown().await;
            return Err(DaemonError::AdminTransport(error));
        }
    };

    let pipeline = Arc::new(Pipeline {
        store: Arc::clone(&store),
        gate,
        queue: Arc::clone(&queue),
        approvals: Arc::clone(&approvals),
        admin: Arc::clone(&admin),
        flows,
        models: Arc::clone(&models),
        secrets,
        events: transport.event_publisher(),
        router: CompletionRouter::new(),
        work: Notify::new(),
        started_at: Instant::now(),
        phase: phase.clone(),
    });

    let tasks = vec![
        Arc::clone(&queue).run_reaper(REAP_INTERVAL, drain_rx.clone()),
        RetentionService::new(Arc::clone(&store)).run_scheduler(PRUNE_INTERVAL, drain_rx.clone()),
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
        models,
        transport,
        admin_transport,
        admin,
        tasks,
        phase,
        _lock: lock,
    })
}

/// The connector credential store for this boot.
///
/// The native store opens lazily, off the async threads, on its first
/// use (see [`SecretStore::native`]) — boot never touches the keychain
/// or the Secret Service bus. A keychain that then will not open is not
/// a boot failure either: the daemon serves, the Connectors screen still
/// draws (saying the store is unavailable), and anything that needs a
/// credential refuses with the store's own cause.
fn open_secret_store(injected: Option<Arc<dyn SecretBackend>>) -> Arc<SecretStore> {
    Arc::new(match injected {
        Some(backend) => SecretStore::new(backend),
        None => SecretStore::native(),
    })
}

/// Builds the transport connector calls run over.
///
/// Like the credential store, a missing `curl` degrades rather than stops:
/// every HTTP connector then refuses with `connector_cli_missing` and the
/// platform's install line, while AWS — which drives its own CLI — keeps
/// working.
fn open_http_transport(injected: Option<Arc<dyn HttpTransport>>) -> Option<Arc<dyn HttpTransport>> {
    if injected.is_some() {
        return injected;
    }
    match CurlTransport::trusted_path() {
        Ok(curl) => Some(Arc::new(CurlTransport::new(curl))),
        Err(error) => {
            tracing::warn!(
                %error,
                recovery = "Use the trusted OS curl on a qualified platform; PATH overrides and inherited proxy configuration are not accepted.",
                "curl was not found; connector calls over HTTP will refuse"
            );
            None
        }
    }
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
    gate: Arc<PolicyGate>,
    queue: Arc<QueueManager>,
    approvals: Arc<ApprovalService>,
    /// GUI-only admin surface; envelopes under the reserved `admin.`
    /// prefix are handed here **before** classify/admit and never touch
    /// the gate, grants, or lanes (see [`crate::admin`]).
    admin: Arc<AdminService>,
    /// The flow engine, carried into every [`ExecContext`] so the three
    /// `flow.*` capabilities can reach it.
    flows: Arc<FlowService>,
    /// The model layer, carried into every [`ExecContext`] so the
    /// `status` capability can report it.
    models: Arc<ModelService>,
    /// The credential store, carried into every [`ExecContext`] so
    /// `status` can say whether the platform keychain answers. Read-only
    /// in that direction: reachability is not a secret, and nothing on
    /// this path can read or write one.
    secrets: Arc<SecretStore>,
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
    let work_slots = Arc::new(Semaphore::new(128));
    let control_slots = Arc::new(Semaphore::new(16));
    let mut tasks = JoinSet::new();
    let mut work_rate = crate::admission_rate::RateWindow::new(256);
    let mut control_rate = crate::admission_rate::RateWindow::new(64);
    loop {
        let request = tokio::select! {
            () = signalled(&mut shutdown) => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => continue,
            request = incoming.recv() => match request { Some(request) => request, None => break },
        };
        let (slots, rate) = if matches!(
            request.envelope.capability.as_str(),
            "status" | "query" | "cancel"
        ) {
            (&control_slots, &mut control_rate)
        } else {
            (&work_slots, &mut work_rate)
        };
        if !rate.admit(std::time::Instant::now()) {
            let _ = request.reply.send(Response::Refusal {
                id: request.envelope.id,
                cause: "request_rate_exhausted".to_owned(),
                detail: "PAM has reached its aggregate request rate limit".to_owned(),
                recovery: "Back off before sending more requests".to_owned(),
            });
            continue;
        }
        let Ok(permit) = Arc::clone(slots).try_acquire_owned() else {
            let _ = request.reply.send(Response::Refusal {
                id: request.envelope.id,
                cause: "request_capacity_exhausted".to_owned(),
                detail: "PAM has reached its active request limit".to_owned(),
                recovery: "Wait for work to finish or cancel an existing request".to_owned(),
            });
            continue;
        };
        let pipeline = Arc::clone(&pipeline);
        tasks.spawn(async move {
            let _permit = permit;
            pipeline.handle(request.envelope, request.reply).await;
        });
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

/// Leases ready work off the lanes and spawns an execution task per
/// lease. Woken by [`Pipeline::work`]; the tick backstops lanes freed by
/// the reaper.
async fn executor_loop(pipeline: Arc<Pipeline>, mut shutdown: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(EXECUTOR_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        for id in pipeline.queue.take_parked_terminals().await {
            pipeline.finish_parked_terminal(&id).await;
        }
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
            () = pipeline.queue.work_available() => {}
            _ = ticker.tick() => {}
        }
    }
}

/// Freeze an existing repository path before admission, dedupe and execution.
/// Missing paths remain usable by global capabilities but cannot confer ownership.
pub(crate) async fn normalize_repository(mut envelope: Envelope) -> Result<Envelope, Response> {
    let started = Instant::now();
    let budget = Duration::from_millis(envelope.deadline_ms).min(crate::queue::MAX_LEASE);
    let repo = envelope.caller.repo.clone();
    let operation =
        crate::blocking_jobs::run(crate::blocking_jobs::Kind::RepositoryIdentity, move || {
            std::fs::canonicalize(repo)
                .ok()
                .and_then(|path| path.into_os_string().into_string().ok())
        });
    let normalized = match tokio::time::timeout(budget, operation).await {
        Ok(Ok(repository)) => repository,
        Ok(Err(error)) => {
            return Err(Response::Refusal {
                id: envelope.id,
                cause: error.cause().to_owned(),
                detail: error.to_string(),
                recovery: error.recovery().to_owned(),
            });
        }
        Err(_) => return Err(repository_deadline_refusal(envelope.id)),
    };
    let remaining = budget.saturating_sub(started.elapsed());
    envelope.deadline_ms = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX);
    if envelope.deadline_ms == 0 {
        return Err(repository_deadline_refusal(envelope.id));
    }
    if let Some(repository) = normalized {
        envelope.caller.repo = repository;
    }
    Ok(envelope)
}

fn repository_deadline_refusal(id: String) -> Response {
    Response::Refusal {
        id,
        cause: "deadline_exceeded".to_owned(),
        detail: "The request deadline expired while resolving its repository.".to_owned(),
        recovery: crate::request_budget::RECOVERY_BUDGET.to_owned(),
    }
}

impl Pipeline {
    /// Runs one request through classify → admit → gate → queue/execute
    /// and answers `reply` with its single [`Response`]. Takes the
    /// pipeline by `Arc` so the approval path can spawn a background
    /// wait for `wait: false` callers.
    async fn handle(self: Arc<Self>, envelope: Envelope, reply: oneshot::Sender<Response>) {
        if envelope.capability.starts_with(ADMIN_PREFIX) {
            let response = self.admin.handle_from_ingress(&envelope, false).await;
            let _ = reply.send(response);
            return;
        }
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

        let envelope = match normalize_repository(envelope).await {
            Ok(envelope) => envelope,
            Err(response) => {
                let _ = reply.send(response);
                return;
            }
        };

        // Unknown capability: no class, no dedupe — record the request,
        // let the gate produce the refusal.
        let Some(class) = classify(&envelope.capability) else {
            let response = self.refuse_unadmitted(&envelope).await;
            let _ = reply.send(response);
            return;
        };

        let admitted = match self.queue.admit(&envelope, class).await {
            Ok(admitted) => admitted,
            Err(error) => {
                let _ = reply.send(Response::Refusal {
                    id,
                    cause: error.cause().to_owned(),
                    detail: error.to_string(),
                    recovery: error.recovery().to_owned(),
                });
                return;
            }
        };
        // Advisory caller registry: every admitted request records its
        // observed agent+repo pair (attribution and GUI filters, never
        // authorization). Failures are non-fatal bookkeeping.
        let _ = self
            .store
            .upsert_caller(&envelope.caller.agent, &envelope.caller.repo)
            .await;

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
            GateDecision::Allow { .. } => self.place_and_wait(envelope).await,
        }
    }

    /// Places an allowed (or approved) request on its lane and, for a
    /// waiting caller, parks only until the persisted admission expiry.
    /// Gate, approval and placement time never renew the request clock.
    async fn place_and_wait(&self, envelope: &Envelope) -> Response {
        let id = &envelope.id;
        let deadline = match self.store.get_request(id).await {
            Ok(Some(row)) => request_deadline(&row),
            _ => return internal_refusal(id),
        };
        let Some(deadline) = deadline else {
            return self.deadline_refusal(envelope).await;
        };
        // Register before placement so the completion cannot slip
        // between the two.
        let registration = self.router.register(id).await;
        let position = match self
            .queue
            .place_in_lane(id, &envelope.caller.repo, envelope.deadline_ms)
            .await
        {
            Ok(position) => position,
            Err(QueueError::Expired) => return self.deadline_refusal(envelope).await,
            Err(error) => {
                let response = self
                    .refuse(
                        id,
                        error.cause().to_owned(),
                        error.to_string(),
                        error.recovery().to_owned(),
                    )
                    .await;
                self.router.finish(id, response.clone()).await;
                return response;
            }
        };
        let _ = self.events.publish(id, Event::Queued).await;
        self.work.notify_one();
        if envelope.wait {
            match await_registration_until(registration, tokio::time::Instant::from_std(deadline))
                .await
            {
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
    /// task bounded by both admission expiry and the approval timeout.
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
            // A ticket changes how the caller observes the request, not its
            // lifetime. The original admission expiry also bounds approval.
            let _ = self.approval_wait_inline(&envelope, &reason).await;
        });
        ticket
    }

    /// Approval pause for both waiting and ticketed requests. The persisted
    /// admission expiry bounds the pause; expiry resolves the approval wait
    /// before recording the durable request timeout.
    async fn approval_wait_inline(&self, envelope: &Envelope, reason: &str) -> Response {
        let id = &envelope.id;
        let deadline = match self.store.get_request(id).await {
            Ok(Some(row)) => request_deadline(&row),
            _ => return internal_refusal(id),
        };
        let Some(deadline) = deadline else {
            return self.deadline_refusal(envelope).await;
        };
        let (cancel_tx, mut cancel) = watch::channel(false);
        let fut = self
            .approvals
            .request_approval(id, &envelope.capability, &mut cancel);
        tokio::pin!(fut);
        tokio::select! {
            outcome = &mut fut => self.conclude_approval(envelope, reason, outcome).await,
            () = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                let _ = cancel_tx.send(true);
                // Resolve any pending approval so the GUI cannot grant stale work.
                let _ = fut.await;
                self.deadline_refusal(envelope).await
            }
        }
    }

    /// Acts on an approval wait's outcome: approved requests move back
    /// to `queued` and continue under the original admission expiry;
    /// everything else becomes a terminal refusal (audited
    /// via [`Self::refuse`], released to attached waiters through the
    /// router).
    async fn conclude_approval(
        &self,
        envelope: &Envelope,
        reason: &str,
        outcome: Result<ApprovalOutcome, StoreError>,
    ) -> Response {
        let id = &envelope.id;
        let capability = &envelope.capability;
        match outcome {
            Ok(ApprovalOutcome::Approved { .. }) => self.place_and_wait(envelope).await,
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
        let Ok(Some(row)) = self.store.get_request(id).await else {
            return internal_refusal(id);
        };
        let Some(deadline) = request_deadline(&row) else {
            return self.deadline_refusal(envelope).await;
        };
        let ctx = self.bypass_context(envelope, cancel, deadline).await;
        let ctx = match ctx {
            Ok(ctx) => ctx,
            Err(error) => {
                return self
                    .fail_bypass(id, &envelope.capability, &format!("{error:?}"))
                    .await;
            }
        };
        match tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
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
            Ok(Err(CapabilityFailure::Cancelled)) => self.cancel_bypass(id).await,
            Ok(Err(CapabilityFailure::Parked { .. })) => {
                self.fail_bypass(id, &envelope.capability, "only a leased flow can park")
                    .await
            }
            Ok(Err(CapabilityFailure::Failed { detail })) => {
                self.fail_bypass(id, &envelope.capability, &detail).await
            }
            Ok(Err(CapabilityFailure::Refused {
                cause,
                detail,
                recovery,
            })) => {
                self.refuse_execution(id, &envelope.capability, cause, detail, recovery)
                    .await
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

    async fn cancel_bypass(&self, id: &str) -> Response {
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

    /// Executes one leased (laned) request and records its terminal
    /// state, audit row, events, and router completion.
    async fn execute_leased(&self, work: LeasedWork) {
        let LeasedWork {
            request_id: id,
            cancel,
            lease_deadline,
        } = work;
        let Ok(Some(row)) = self.store.get_request(&id).await else {
            self.fail_vanished_row(&id).await;
            return;
        };
        if self.store.grant_revocation_revision().await.ok() != row.authorization_revision {
            self.complete_leased(
                &id,
                &row.capability,
                Err(CapabilityFailure::Refused {
                    cause: "authorization_changed".to_owned(),
                    detail: "A grant was revoked after this work was authorized".to_owned(),
                    recovery: "Review current grants and submit a fresh request".to_owned(),
                }),
            )
            .await;
            self.work.notify_one();
            return;
        }
        let continuing_watch = row.capability == "flow.run"
            && self
                .store
                .read_flow_journal(&id)
                .await
                .ok()
                .flatten()
                .is_some_and(|journal| {
                    serde_json::from_str::<serde_json::Value>(&journal.checkpoint_json)
                        .ok()
                        .is_some_and(|cursor| {
                            cursor
                                .get("watch")
                                .is_some_and(serde_json::Value::is_object)
                        })
                });
        if !continuing_watch {
            let _ = self.events.publish(&id, Event::Started).await;
        }

        let result = match BuiltinCapability::from_name(&row.capability) {
            Some(capability) => {
                let args = serde_json::from_str(&row.args_json).unwrap_or(serde_json::Value::Null);
                // The row keeps the caller's agent and repo but not its
                // pid — attribution needs the first two, and nothing a
                // capability does is keyed on the third.
                let caller = pam_proto::Caller {
                    agent: row.caller_agent.clone(),
                    repo: row.repo.clone(),
                    pid: 0,
                };
                let ctx = self
                    .exec_context(
                        id.clone(),
                        row.capability.clone(),
                        caller,
                        args,
                        cancel,
                        lease_deadline.into_std(),
                    )
                    .await;
                match ctx {
                    Ok(ctx) => capability.execute(ctx).await,
                    Err(error) => Err(error),
                }
            }
            // The gate classified it, so this only fires on registry
            // drift between classify() and from_name().
            None => Err(CapabilityFailure::Failed {
                detail: "capability classified but not dispatchable".to_owned(),
            }),
        };

        self.complete_leased(&id, &row.capability, result).await;
        // The lane is free again.
        self.work.notify_one();
    }

    /// A failed/cancelled execution may have left an effect without a receipt.
    /// The store repeats this check atomically for lease reapers and terminal races.
    async fn reconcile_flow_terminal(
        &self,
        id: &str,
        capability: &str,
        result: Result<CapabilityOutput, CapabilityFailure>,
    ) -> Result<CapabilityOutput, CapabilityFailure> {
        if capability != "flow.run" {
            return result;
        }
        let journal =
            self.store
                .read_flow_journal(id)
                .await
                .map_err(|error| CapabilityFailure::Failed {
                    detail: format!("could not reconcile workflow completion: {error}"),
                })?;
        if journal.is_some_and(|row| {
            row.state == pam_store::FlowJournalState::Uncertain
                || (row.state == pam_store::FlowJournalState::Prepared && row.effectful)
        }) {
            return Err(CapabilityFailure::Refused {
                cause: "flow_effect_uncertain".to_owned(),
                detail: "A state-changing step may have executed without a durable completion receipt.".to_owned(),
                recovery: "Inspect retained evidence and reconcile the effect before submitting new work; PAM will not replay it.".to_owned(),
            });
        }
        result
    }

    /// Records one leased execution's terminal state: the row and its
    /// single audit entry through the queue, the event, and the waiters'
    /// response. Each arm is one of the four documented terminal paths
    /// (see the module docs on the audit invariant).
    async fn complete_leased(
        &self,
        id: &str,
        capability: &str,
        result: Result<CapabilityOutput, CapabilityFailure>,
    ) {
        let result = self.reconcile_flow_terminal(id, capability, result).await;
        match result {
            Ok(output) => self.complete_succeeded(id, capability, output).await,
            Err(CapabilityFailure::Parked { resume_at_ms }) => {
                self.complete_parked(id, capability, resume_at_ms).await;
            }
            Err(CapabilityFailure::Cancelled) => {
                let audit_detail = cancelled_detail();
                let terminal = self
                    .queue
                    .complete(
                        id,
                        RequestState::Failed,
                        Some(CAUSE_CANCELLED),
                        cancelled_entry(&audit_detail),
                    )
                    .await;
                log_terminal_failure(id, &terminal);
                if matches!(terminal, Ok(true)) {
                    let _ = self.events.publish(id, Event::Refused).await;
                    self.router.finish(id, cancelled_refusal(id)).await;
                } else if matches!(terminal, Ok(false)) {
                    self.finish_reaped(id).await;
                }
            }
            Err(CapabilityFailure::Failed { detail }) => {
                let audit_detail = execute_failure_detail(capability, &detail);
                let terminal = self
                    .queue
                    .complete(
                        id,
                        RequestState::Failed,
                        Some(CAUSE_EXECUTION_FAILED),
                        execute_failure_entry(&audit_detail),
                    )
                    .await;
                log_terminal_failure(id, &terminal);
                if matches!(terminal, Ok(true)) {
                    let _ = self.events.publish(id, Event::Refused).await;
                    self.router.finish(id, failure_refusal(id, detail)).await;
                } else if matches!(terminal, Ok(false)) {
                    self.finish_reaped(id).await;
                }
            }
            Err(CapabilityFailure::Refused {
                cause,
                detail,
                recovery,
            }) => {
                self.complete_refused_leased(id, capability, cause, detail, recovery)
                    .await;
            }
        }
    }

    async fn complete_refused_leased(
        &self,
        id: &str,
        capability: &str,
        cause: String,
        detail: String,
        recovery: String,
    ) {
        let audit_detail = execution_refusal_detail(capability, &cause, &detail);
        let terminal = self
            .queue
            .complete(
                id,
                RequestState::Refused,
                Some(&cause),
                execution_refusal_entry(&audit_detail),
            )
            .await;
        log_terminal_failure(id, &terminal);
        if matches!(terminal, Ok(true)) {
            let _ = self.events.publish(id, Event::Refused).await;
            self.router
                .finish(
                    id,
                    Response::Refusal {
                        id: id.to_owned(),
                        cause,
                        detail,
                        recovery,
                    },
                )
                .await;
        } else if matches!(terminal, Ok(false)) {
            self.finish_reaped(id).await;
        }
    }

    async fn complete_parked(&self, id: &str, capability: &str, resume_at_ms: i64) {
        if capability == "flow.run" && matches!(self.queue.park(id, resume_at_ms).await, Ok(true)) {
            self.work.notify_one();
            return;
        }
        self.complete_refused_leased(
            id,
            capability,
            "watch_resume_unavailable".to_owned(),
            "The watch could not retain its original authorization, deadline or checkpoint."
                .to_owned(),
            "Inspect the last retained observation and current access before submitting new work."
                .to_owned(),
        )
        .await;
    }

    /// The success arm of [`Self::complete_leased`].
    async fn complete_succeeded(&self, id: &str, capability: &str, output: CapabilityOutput) {
        let audit_detail = execute_success_detail(capability, output.outcome);
        let terminal = self
            .queue
            .complete(
                id,
                RequestState::Done,
                Some(outcome_str(output.outcome)),
                execute_success_entry(&audit_detail),
            )
            .await;
        log_terminal_failure(id, &terminal);
        if matches!(terminal, Ok(true)) {
            let _ = self.events.publish(id, Event::Done).await;
            self.router
                .finish(
                    id,
                    Response::Result {
                        id: id.to_owned(),
                        outcome: output.outcome,
                        body: output.body,
                        evidence: output.evidence,
                    },
                )
                .await;
        } else if matches!(terminal, Ok(false)) {
            // The lease was reaped first: the reaper wrote the terminal
            // row and audit; release any waiters.
            self.finish_reaped(id).await;
        }
    }

    /// A leased request whose row cannot be read is unanswerable: record
    /// the internal failure (logged if even that fails) and free the lane.
    async fn fail_vanished_row(&self, id: &str) {
        let detail = serde_json::json!({ "cause": "request row missing" }).to_string();
        let terminal = self
            .queue
            .complete(
                id,
                RequestState::Failed,
                Some(CAUSE_INTERNAL_ERROR),
                internal_failure_entry(&detail),
            )
            .await;
        log_terminal_failure(id, &terminal);
        if matches!(terminal, Ok(true)) {
            let _ = self.events.publish(id, Event::Refused).await;
            self.router.finish(id, internal_refusal(id)).await;
        } else if matches!(terminal, Ok(false)) {
            self.finish_reaped(id).await;
        }
        self.work.notify_one();
    }

    async fn bypass_context(
        &self,
        envelope: &Envelope,
        cancel: watch::Receiver<bool>,
        deadline: std::time::Instant,
    ) -> Result<ExecContext, CapabilityFailure> {
        self.exec_context(
            envelope.id.clone(),
            envelope.capability.clone(),
            envelope.caller.clone(),
            envelope.args.clone(),
            cancel,
            deadline,
        )
        .await
    }

    /// Builds the execution context for one request.
    async fn exec_context(
        &self,
        request_id: String,
        capability: String,
        caller: pam_proto::Caller,
        args: serde_json::Value,
        cancel: watch::Receiver<bool>,
        deadline: std::time::Instant,
    ) -> Result<ExecContext, CapabilityFailure> {
        let budget = crate::request_budget::RequestBudget::load_persistent(
            Arc::clone(&self.store),
            &request_id,
            deadline,
        )
        .await
        .map_err(|error| CapabilityFailure::Failed {
            detail: error.to_string(),
        })?;
        Ok(ExecContext {
            budget,
            request_id,
            args,
            cancel,
            events: self.events.clone(),
            store: Arc::clone(&self.store),
            queue: Arc::clone(&self.queue),
            models: Arc::clone(&self.models),
            router: self.router.clone(),
            approvals: Arc::clone(&self.approvals),
            flows: Arc::clone(&self.flows),
            secrets: Arc::clone(&self.secrets),
            caller,
            capability,
            started_at: self.started_at,
        })
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

    /// Terminal handling for a capability that refused the request
    /// itself (bypass path): state `refused`, the executor's own
    /// [`ACTION_EXECUTION_REFUSAL`] row, decision `refuse`, actor
    /// `policy` — the capability decided, on policy grounds, that there
    /// was nothing to run.
    async fn refuse_execution(
        &self,
        id: &str,
        capability: &str,
        cause: String,
        detail: String,
        recovery: String,
    ) -> Response {
        let audit_detail = execution_refusal_detail(capability, &cause, &detail);
        let _ = self
            .store
            .finish_request(
                id,
                RequestState::Refused,
                Some(&cause),
                execution_refusal_entry(&audit_detail),
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

    /// Tears a deadline-expired request down: the queue records expiry before
    /// signalling the executor; then audit the refusal, notify subscribers,
    /// and answer the caller.
    async fn deadline_refusal(&self, envelope: &Envelope) -> Response {
        let id = &envelope.id;
        let terminal = self.queue.expire(id).await;
        log_terminal_failure(id, &terminal);
        if terminal.is_err() {
            return internal_refusal(id);
        }
        self.audit_deadline(id, envelope.deadline_ms).await;
        let _ = self.events.publish(id, Event::Refused).await;
        let response = self
            .preserve_terminal_uncertainty(id, deadline_refusal_response(id, envelope.deadline_ms))
            .await;
        self.router.finish(id, response.clone()).await;
        response
    }

    /// Releases waiters of a request whose lease was reaped mid-flight
    /// (the reaper already wrote the terminal row and audit).
    async fn finish_reaped(&self, id: &str) {
        if !matches!(self.store.request_status_meta(id).await, Ok(Some(row)) if row.state.is_terminal())
        {
            return;
        }
        let _ = self.events.publish(id, Event::Refused).await;
        let response = self
            .preserve_terminal_uncertainty(
                id,
                Response::Refusal {
                    id: id.to_owned(),
                    cause: CAUSE_DEADLINE_EXCEEDED.to_owned(),
                    detail: format!("request {id} exceeded its admitted deadline"),
                    recovery: RECOVERY_DEADLINE.to_owned(),
                },
            )
            .await;
        self.router.finish(id, response).await;
    }

    async fn finish_parked_terminal(&self, id: &str) {
        let response = match self.store.get_request(id).await {
            Ok(Some(row)) if row.state.is_terminal() => {
                let outcome = row
                    .outcome
                    .clone()
                    .unwrap_or_else(|| "watch_stopped".to_owned());
                if outcome == crate::queue::CAUSE_LEASE_EXPIRED
                    && self.router.has_waiters(id).await
                {
                    // A queued request the reaper collected expired for its
                    // waiter exactly like one the reaper collects
                    // mid-flight: the caller's fact is its elapsed deadline
                    // (finish_reaped), while the row keeps the reaper's
                    // outcome. Whoever observes the expiry first, the waiter
                    // must not receive the bookkeeping cause, and the
                    // refusal the caller receives is audited like the
                    // waiter-timeout path's.
                    let detail =
                        serde_json::json!({ "expires_at_ms": row.expires_at_ms }).to_string();
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
                    Response::Refusal {
                        id: id.to_owned(),
                        cause: CAUSE_DEADLINE_EXCEEDED.to_owned(),
                        detail: format!("request {id} exceeded its admitted deadline"),
                        recovery: RECOVERY_DEADLINE.to_owned(),
                    }
                } else {
                    Response::Refusal {
                        id: id.to_owned(),
                        cause: outcome,
                        detail: "The request stopped before execution resumed; this does not establish a remote job failure.".to_owned(),
                        recovery: "Read retained evidence and inspect the original deadline and current access.".to_owned(),
                    }
                }
            }
            Ok(_) | Err(_) => internal_refusal(id),
        };
        let _ = self.events.publish(id, Event::Refused).await;
        self.router.finish(id, response).await;
    }

    async fn preserve_terminal_uncertainty(&self, id: &str, fallback: Response) -> Response {
        match self.store.request_status_meta(id).await {
            Ok(Some(row)) if row.outcome.as_deref() == Some("flow_effect_uncertain") => Response::Refusal {
                id: id.to_owned(),
                cause: "flow_effect_uncertain".to_owned(),
                detail: "A state-changing step may have executed without a durable completion receipt.".to_owned(),
                recovery: "Inspect retained evidence and reconcile the effect before submitting new work; PAM will not replay it.".to_owned(),
            },
            Ok(Some(_)) => fallback,
            Ok(None) | Err(_) => internal_refusal(id),
        }
    }

    /// Audit row for a deadline refusal sent to a waiting caller.
    ///
    /// This is the one supplementary (non-terminal) audit append on the
    /// laned deadline path: the terminal row records lease expiry regardless
    /// of whether the original waiter or reaper observed it first.
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
/// Logs a terminal write that failed: nobody can be answered (the caller
/// already holds its ticket or response), so the daemon log is the only
/// place the failure can be seen; crash recovery fails the row on the
/// next boot.
fn log_terminal_failure(id: &str, terminal: &Result<bool, QueueError>) {
    if let Err(err) = terminal {
        tracing::error!(request = %id, %err, "could not record the terminal state");
    }
}

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

/// Audit detail for a refusal the capability itself decided.
fn execution_refusal_detail(capability: &str, cause: &str, detail: &str) -> String {
    serde_json::json!({
        "capability": capability,
        "cause": cause,
        "detail": detail,
    })
    .to_string()
}

/// Terminal audit entry for a refusal the capability itself decided.
fn execution_refusal_entry(detail: &str) -> AuditEntry<'_> {
    AuditEntry {
        action: ACTION_EXECUTION_REFUSAL,
        decision: Decision::Refuse,
        actor: Actor::Policy,
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
    await_registration_until(
        registration,
        tokio::time::Instant::now() + Duration::from_millis(deadline_ms),
    )
    .await
}

/// Shared wait primitive; original requests use persisted expiry, attached
/// observers use their own timeout without cancelling the original request.
pub(crate) async fn await_registration_until(
    registration: Registration,
    deadline: tokio::time::Instant,
) -> Result<Response, bool> {
    match registration {
        Registration::Ready(response) => Ok(*response),
        Registration::Pending(rx) => match tokio::time::timeout_at(deadline, rx).await {
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
pub(crate) fn shutting_down_refusal(id: &str) -> Response {
    Response::Refusal {
        id: id.to_owned(),
        cause: CAUSE_DAEMON_SHUTTING_DOWN.to_owned(),
        detail: "the daemon is draining in-flight work before it exits".to_owned(),
        recovery: RECOVERY_SHUTTING_DOWN.to_owned(),
    }
}

/// Refusal for the version handshake: the client build is newer than
/// this daemon, which restarts itself.
pub(crate) fn outdated_refusal(id: &str, client_version: &str) -> Response {
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

/// Translate the original persisted expiry without granting time spent queued.
fn request_deadline(row: &pam_store::RequestRow) -> Option<std::time::Instant> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis();
    let remaining = i128::from(row.expires_at_ms?) - i128::try_from(now_ms).ok()?;
    let remaining = u64::try_from(remaining).ok().filter(|ms| *ms > 0)?;
    Some(std::time::Instant::now() + Duration::from_millis(remaining.min(3_600_000)))
}
