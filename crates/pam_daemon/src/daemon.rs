//! Pipeline assembly: the request path from `pam.sock` to a response.
//! ```text
//! transport → classify → admit (dedupe + row insert) → policy gate
//!           → lane placement → executor → audit → response
//! ```
//!
//! [`run_daemon`] wires transport, policy gate, queue manager, and store into tokio tasks: a
//! dispatcher spawning one pipeline task per request (`Pipeline::handle`), an executor loop
//! leasing queued work through [`BuiltinCapability`] dispatch, the queue's lease reaper, and the
//! retention pruner ([`crate::retention`]), which prunes on its first tick (so a boot prunes right
//! after crash recovery) and every [`PRUNE_INTERVAL`] after. **Ordering**: dedupe + row insert
//! happen atomically in [`QueueManager::admit`] (audit needs the row to exist), the gate runs next,
//! and only an allowed request reaches [`QueueManager::place_in_lane`]. Admission inserts the row
//! `running`; it becomes `queued` only through the atomic post-gate authorization write inside
//! placement, so a crash between the two leaves a `running` row that crash recovery fails — never
//! executable queued work.
//! - **One admission point, bounded handlers** (ptrack issue 35): `dispatch_loop` is the only
//!   place a request takes a slot. The pool comes from [`crate::policy::admission_pool`] — work,
//!   status (the liveness answer has slots nothing else can take), control (`query`), cancel
//!   (headroom of its own, so the remedy for a saturated daemon cannot be starved by polls) —
//!   plus a pool for requests the private admin plane submits. The slot and the reply channel travel together in a `ReplyGuard`: when the handler
//!   ends for any reason (answer, panic, abort, hard deadline) the caller is answered and the slot
//!   is released, so a permit cannot outlive its handler. Every handler runs under one hard
//!   deadline around all of it — admission, gate, execution, terminal write — of the envelope's
//!   deadline (clamped to the lease ceiling; a control request to [`CONTROL_DEADLINE_CAP`]) plus a
//!   grace. On expiry the caller gets [`CAUSE_DEADLINE_EXCEEDED`] at once, the slot is free, and
//!   the terminal row is still written by a detached task through [`TerminalWriter`].
//! - **`status` is a snapshot read**: answered straight from [`StatusCache`] on a ledger-free
//!   path — no admission row, no audit row, no caller-registry write, no lifecycle events, no
//!   model lane, no keychain. A poll leaves nothing behind. `query` and `cancel` stay audited
//!   requests; none of the control class publishes lifecycle events.
//! - **Admin surface (GUI-only)**: capabilities under [`crate::admin::ADMIN_PREFIX`] are refused on
//!   public IPC regardless of caller labels; only [`crate::admin_transport`] may call them. Admin
//!   ops have no `classify()` entry and are never granted/approved/queued; they record their own
//!   request row, enforce the envelope deadline, and audit every outcome
//!   ([`ACTION_ADMIN`]/[`ACTION_ADMIN_DENIED`], terminal) synchronously, with no events beyond what
//!   an approval resolution already publishes.
//! - **Caller registry**: every admitted request (bypass, laned, attached duplicate) upserts its
//!   agent+repo pair into the `caller` table — advisory only, never authorization; admin envelopes
//!   are excluded.
//! - **Origin on the row**: admission writes where the request entered the daemon — the plane and,
//!   for a connection the framed public listener accepted, the kernel's uid and pid of the peer
//!   and the relay marker ([`crate::ingress::recorded`]) — in the same INSERT as the row. It is
//!   attribution; nothing is authorized by it. A leased execution reads its origin back from the
//!   row. A request whose lifecycle events are published is also registered with the event hub
//!   (capability, repository, agent label, plane) for the administration plane's all-events
//!   stream, and forgotten there when it ends.
//! - **Boot order** ([`run_daemon_with`]): instance lock → store open → crash recovery
//!   ([`crate::lifecycle::recover_stuck_rows`]) → lane rebuild → transport bind (safe to drop stale
//!   sockets, lock already held) → serve.
//! - **Shutdown** is a graceful drain: phase leaves [`LifecyclePhase::Serving`] (new requests
//!   refused, [`CAUSE_DAEMON_SHUTTING_DOWN`]), executor/reaper stop taking leases (`queued` rows
//!   are the restart-safe checkpoint), in-flight leases get [`DaemonConfig::drain_timeout`] then
//!   cooperative cancellation, then the dispatcher stops. No explicit store flush is needed — every
//!   write, audit included, is per-statement durable. A `waiting_approval` request is not drained;
//!   crash recovery fails it on next boot.
//! - **Version handshake and restart policy**: every envelope carries the client build version
//!   (on the framed listener the connection's hello carries it instead, and
//!   [`crate::public_transport`] applies the same rule there before the request is read, so the
//!   pipeline does not look at such an envelope's version again).
//!   The daemon restarts itself for one reason — the binary it was started from was replaced on
//!   disk — and a client's claimed version is only the occasion to look ([`crate::image`]). A
//!   differing version with a replaced image is refused with [`CAUSE_DAEMON_OUTDATED`] and moves
//!   the daemon to [`LifecyclePhase::Restarting`], triggering the drain; `pam daemon` re-spawns
//!   the path recorded at boot ([`DaemonHandle::boot_image_path`]). A differing version with the
//!   image unchanged is refused with [`CAUSE_CLIENT_VERSION_MISMATCH`], naming the daemon's
//!   version and path, and the phase does not move. Neither refusal records a request row. While
//!   the phase is `Restarting` every public request is answered [`CAUSE_DAEMON_OUTDATED`].
//! - **Replies**: `wait: true` parks the pipeline task on the [`CompletionRouter`] until execution
//!   finishes; duplicate callers attached to the same request share the router entry and all get
//!   the terminal [`Response`] (fan-out), with a short post-completion grace period for late
//!   attachers. `wait: false` returns a [`Response::Ticket`] immediately.
//! - **Deadlines**: one expiry (set at admission) covers approval waits, lane waits, and execution,
//!   including ticketed requests; an expired laned request is `failed`/`lease_expired`, exposed as
//!   [`CAUSE_DEADLINE_EXCEEDED`]. Explicit cancellation keeps its own cause. Attached observers'
//!   wait timeouts are independent and never cancel the original request.
//! - **Audit invariant**: every terminal transition (`done`/`refused`/`failed`) goes through the
//!   single choke point [`pam_store::Store::finish_request`], writing state + outcome + terminal
//!   audit row in one transaction (crash-safe; race-safe since an already-terminal row is a
//!   first-wins no-op). [`pam_store::Store::update_request_state`] may never be called with a
//!   terminal state (`debug_assert`-enforced); laned paths reach the choke point via
//!   [`QueueManager::complete`]. Terminal actions ([`TERMINAL_ACTIONS`]): gate or approval refusal
//!   → [`ACTION_GATE_REFUSAL`]; execute success/failure → [`ACTION_EXECUTE`]; cancelled → queue's
//!   cancel action; bypass deadline → [`ACTION_DEADLINE_REFUSAL`]; internal bookkeeping failure →
//!   [`ACTION_INTERNAL_FAILURE`]. A laned deadline writes [`ACTION_DEADLINE_REFUSAL`] in addition
//!   to the lease-expiry row (outcome `lease_expired`, exposed as `deadline_exceeded`). A store
//!   failure on a terminal write is never swallowed: [`TerminalWriter`] retries it, logs it, and
//!   parks the verdict for the maintenance loop; a leased request whose terminal write keeps
//!   failing gives its lane back at once (the result still reaches its waiters) instead of
//!   stranding the lane until the lease deadline; and a row nothing ever finishes is closed by the
//!   queue's reconciler once its deadline has passed ([`QueueManager::reconcile_expired`], every
//!   couple of seconds and once at boot). An early bookkeeping failure writes its terminal row like any
//!   other ending. Every refusal and internal failure of a laned request also releases attached
//!   duplicate callers through the [`CompletionRouter`].
//! - **Audit decisions/actors**: gate refusal → `refuse`/`policy` (unknown or ungranted
//!   capability; denied, timed-out or cancelled approval); execute success → `allow`/`system`,
//!   failure → `refuse`/`system`; cancel → `deny`/`system`; bypass deadline → `timeout`/`system`;
//!   internal failure → `refuse`/`system`. A [`CAUSE_DAEMON_OUTDATED`] refusal carries a retry
//!   hint, and the retry lands on the new daemon.
//! - **Approval pause**: [`GateDecision::RequireApproval`] parks the request in [`crate::approval`]
//!   before lane placement (`waiting_approval`, `approval_pending` on PUB, resolved via
//!   [`DaemonHandle::approvals`]); approval returns it to `queued`. Denial/timeout/cancellation
//!   refuse with [`CAUSE_APPROVAL_DENIED`]/[`CAUSE_APPROVAL_TIMEOUT`]/cancelled. A caller's
//!   `deadline_ms` elapsing mid-approval cancels the wait (resolved `denied`, note `cancelled`);
//!   `wait: false` returns a ticket immediately while the wait runs in the background, bounded by
//!   approval timeout and admission expiry.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pam_connectors::{CurlTransport, HttpTransport};
use pam_proto::{Envelope, Event, Response};
use pam_store::{Actor, AuditEntry, Decision, RequestState, Store, StoreError};
use thiserror::Error;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

use crate::admin::{ACTION_ADMIN, ACTION_ADMIN_DENIED, ADMIN_PREFIX, AdminService};
use crate::approval::{ApprovalOutcome, ApprovalService, DEFAULT_APPROVAL_TIMEOUT};
use crate::connector_service::ConnectorService;
use crate::event_hub::{EventHub, TicketMeta};
use crate::executor::{
    BuiltinCapability, CapabilityFailure, CapabilityOutput, ExecContext, outcome_str,
};
use crate::flow_service::FlowService;
use crate::image::{FsProbe, ImageProbe, ImageWatch, VersionVerdict};
use crate::ingress::{Origin, PublicPeer};
use crate::lifecycle::{
    InstanceLock, LifecycleError, LifecyclePhase, acquire_instance_lock, recover_stuck_rows,
};
use crate::log_service::LogService;
use crate::model_service::ModelService;
use crate::policy::{
    AdmissionPool, CAP_STATUS, CapabilityClass, GateDecision, PolicyError, PolicyGate,
    admission_pool, classify,
};
use crate::queue::{AdmitOutcome, CAUSE_CANCELLED, LeasedWork, QueueError, QueueManager};
use crate::retention::{PRUNE_INTERVAL, RetentionService};
use crate::runtime_dir::{RuntimeDir, RuntimeDirError};
use crate::secrets::{SecretBackend, SecretStore};
use crate::status_cache::StatusCache;
use crate::terminal::{TerminalWriter, Written};
use crate::transport::{EventPublisher, IncomingRequest, Transport, TransportError};

pub use crate::completion_router::{CompletionRouter, Registration};
pub use crate::image::CAUSE_CLIENT_VERSION_MISMATCH;

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
/// daemon's **and** the daemon's binary on disk was replaced: the daemon
/// restarts itself with the new binary. Also the answer to every public
/// request while the daemon is in [`LifecyclePhase::Restarting`].
pub const CAUSE_DAEMON_OUTDATED: &str = "daemon_outdated";

/// Refusal cause when a dispatcher pool has no free slot.
pub const CAUSE_REQUEST_CAPACITY: &str = "request_capacity_exhausted";

/// Refusal cause when a dispatcher pool's rate window is spent.
pub const CAUSE_REQUEST_RATE: &str = "request_rate_exhausted";

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
    crate::queue::ACTION_RECOVERY_REFUSAL,
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

/// Recovery line for [`CAUSE_CLIENT_VERSION_MISMATCH`] refusals.
const RECOVERY_VERSION_MISMATCH: &str = "Use the pam binary this daemon was started from, or stop the daemon from the PAM GUI and start it with the build you intend to use.";

/// Dispatcher slots for ordinary work.
pub const WORK_SLOTS: usize = 128;
/// Dispatcher slots reserved for `status`: a snapshot read holds one for
/// microseconds, so these are never the bottleneck and never shared.
pub const STATUS_SLOTS: usize = 16;
/// Dispatcher slots reserved for `query`.
pub const CONTROL_SLOTS: usize = 16;
/// Dispatcher slots reserved for `cancel` alone; a cancel that finds them
/// taken may still use a control slot.
pub const CANCEL_SLOTS: usize = 8;
/// Dispatcher slots for requests the private admin plane submits, so a
/// public flood cannot refuse a run or a cancel the human asked for. The
/// admin listener serves at most 32 connections, each one request.
pub const ADMIN_SLOTS: usize = 32;
/// Ordinary work admitted per second.
const WORK_RATE: usize = 256;
/// `status` admitted per second.
const STATUS_RATE: usize = 64;
/// `query` admitted per second.
const CONTROL_RATE: usize = 64;
/// `cancel` admitted per second from its own allowance.
const CANCEL_RATE: usize = 16;

/// How long past its deadline a handler may run before it is cut off (see
/// the module docs), unless [`DaemonConfig::handler_grace`] says otherwise.
pub const DEFAULT_HANDLER_GRACE: Duration = Duration::from_secs(30);

/// The grace for a control request: it does bookkeeping, not work.
const CONTROL_GRACE: Duration = Duration::from_secs(2);

/// The longest deadline a control request (`status`, `query`, `cancel`) is
/// given, whatever its envelope asks for: a control slot is held for at
/// most this plus `CONTROL_GRACE`.
pub const CONTROL_DEADLINE_CAP: Duration = Duration::from_secs(10);

/// How much longer than the handler grace a row is left alone before the
/// queue's reconciler closes it (see [`QueueManager::reconcile_expired`]).
const RECONCILE_MARGIN: Duration = Duration::from_secs(15);

/// How often the maintenance loop retries parked terminal writes and
/// prunes the completion router.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(1);

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
    /// The executable image recorded at boot (see [`crate::image`]).
    image: Arc<ImageWatch>,
    /// The dispatcher's pools, for inspection.
    admission: Arc<Admission>,
    #[cfg(test)]
    queue: Arc<QueueManager>,
    #[cfg(test)]
    router: CompletionRouter,
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

    /// The path this daemon was started as, recorded at boot. A respawn
    /// after [`LifecyclePhase::Restarting`] must execute **this** path, not
    /// `std::env::current_exe()` at respawn time: after the usual
    /// rename-into-place install the latter names a deleted file on Linux.
    /// `None` only when the platform could not name the executable at boot.
    #[must_use]
    pub fn boot_image_path(&self) -> Option<PathBuf> {
        self.image.boot_path().map(Path::to_path_buf)
    }

    /// Free dispatcher slots per pool, right now.
    #[must_use]
    pub fn admission_available(&self) -> AdmissionAvailable {
        self.admission.available()
    }

    /// The daemon's event hub: what every lifecycle event is published into
    /// and what followers attach to. For embedding hosts and integration
    /// tests; nothing on public IPC reaches it.
    #[must_use]
    pub fn event_hub(&self) -> Arc<EventHub> {
        Arc::clone(self.transport.event_publisher().hub())
    }

    /// Connection permits the framed public listener has free right now, of
    /// [`crate::framed::MAX_PUBLIC_CONNECTIONS`].
    #[must_use]
    pub fn public_connections_available(&self) -> usize {
        self.transport.public_connections_available()
    }

    /// The queue manager, for in-crate tests that need to stall or inject.
    #[cfg(test)]
    pub(crate) fn queue(&self) -> Arc<QueueManager> {
        Arc::clone(&self.queue)
    }

    /// The completion router, for in-crate tests of its bounds.
    #[cfg(test)]
    pub(crate) fn router(&self) -> CompletionRouter {
        self.router.clone()
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
    /// How the daemon reads its own executable's file facts; `None` uses
    /// the filesystem ([`FsProbe`]). Tests script a replaced binary.
    pub image_probe: Option<Arc<dyn ImageProbe>>,
    /// How long past its deadline a non-control handler may run before it
    /// is cut off (default [`DEFAULT_HANDLER_GRACE`]; tests inject a short
    /// one). The stranded-row reconciler waits this plus a margin.
    pub handler_grace: Duration,
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
            .field("image_probe", &self.image_probe.is_some())
            .field("handler_grace", &self.handler_grace)
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
            image_probe: None,
            handler_grace: DEFAULT_HANDLER_GRACE,
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
    models.set_engine_base(base.clone());
    // A SIGKILLed daemon leaves its engine running; stop it now rather than
    // on the first model op (idempotent, and a no-op with no engine).
    let reaped = models.reap_orphan_engine().await;
    tracing::debug!(?reaped, "checked for an engine left by a previous daemon");
    // Record what this process was started from before anything can ask.
    let image = ImageWatch::capture(
        config
            .image_probe
            .unwrap_or_else(|| Arc::new(FsProbe) as Arc<dyn ImageProbe>),
    );
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
    let queue = Arc::new(
        QueueManager::new(Arc::clone(&store))
            .with_reconcile_grace(config.handler_grace + RECONCILE_MARGIN),
    );
    queue.rebuild_from_store().await?;
    // Boot pass of the stranded-row reconciler: anything still in flight
    // past its deadline (plus the grace) after recovery is closed now.
    loop {
        let closed = queue
            .reconcile_expired(crate::queue::wall_clock_ms())
            .await?;
        if closed < usize::try_from(pam_store::MAX_EXPIRY_BATCH).unwrap_or(usize::MAX) {
            break;
        }
    }
    // After recovery has settled every ticket's state and before any
    // request can run: a landing workspace no live ticket names is gone.
    crate::landing_sweep::sweep_orphaned_workspaces(&store).await;

    let (incoming_tx, incoming_rx) = mpsc::channel(INCOMING_CAPACITY);
    // Built before either transport: both planes publish into and read from
    // the one hub, and both move the one lifecycle phase.
    let hub = EventHub::new();
    let (phase, _) = watch::channel(LifecyclePhase::Serving);
    let transport = Transport::bind_with(
        &dirs,
        incoming_tx.clone(),
        Arc::clone(&store),
        phase.clone(),
        Arc::clone(&hub),
        Arc::clone(&image),
    )
    .await?;

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
        Arc::clone(&image),
        hub,
    ) {
        Ok(listener) => listener,
        Err(error) => {
            transport.shutdown().await;
            return Err(DaemonError::AdminTransport(error));
        }
    };

    let status = StatusCache::new(Arc::clone(&models), Arc::clone(&secrets));
    let admission = Admission::new();
    let router = CompletionRouter::new();
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
        router: router.clone(),
        work: Notify::new(),
        started_at: Instant::now(),
        phase: phase.clone(),
        image: Arc::clone(&image),
        status: Arc::clone(&status),
        // One writer for the whole daemon: the admin surface parks into
        // the same queue the maintenance loop retries.
        terminals: Arc::clone(&admin.terminals),
        handler_grace: config.handler_grace,
    });

    let tasks = vec![
        Arc::clone(&queue).run_reaper(REAP_INTERVAL, drain_rx.clone()),
        RetentionService::new(Arc::clone(&store)).run_scheduler(PRUNE_INTERVAL, drain_rx.clone()),
        status.spawn(drain_rx.clone()),
        // Runs through the drain: a verdict parked while draining is still
        // offered to the store before the daemon exits.
        tokio::spawn(maintenance_loop(
            Arc::clone(&pipeline),
            dispatch_stop_rx.clone(),
        )),
        tokio::spawn(dispatch_loop(
            Arc::clone(&pipeline),
            Arc::clone(&admission),
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
        image,
        admission,
        #[cfg(test)]
        queue,
        #[cfg(test)]
        router,
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
/// every connector then refuses with `connector_cli_missing` and the
/// platform's install line.
fn open_http_transport(injected: Option<Arc<dyn HttpTransport>>) -> Option<Arc<dyn HttpTransport>> {
    if injected.is_some() {
        return injected;
    }
    match CurlTransport::trusted() {
        Ok(transport) => Some(Arc::new(transport)),
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
    /// The boot image and the "was it replaced?" check behind the version
    /// handshake.
    image: Arc<ImageWatch>,
    /// What `status` answers from.
    status: Arc<StatusCache>,
    /// The retrying, parking writer of terminal rows.
    terminals: Arc<TerminalWriter>,
    /// See [`DaemonConfig::handler_grace`].
    handler_grace: Duration,
}

/// The dispatcher's admission pools (see the module docs). The rate
/// windows live in [`dispatch_loop`]; the slots are shared so the daemon
/// handle can report them.
#[derive(Debug)]
pub(crate) struct Admission {
    work: Arc<Semaphore>,
    status: Arc<Semaphore>,
    control: Arc<Semaphore>,
    cancel: Arc<Semaphore>,
    admin: Arc<Semaphore>,
}

/// Free dispatcher slots per pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionAvailable {
    /// Of [`WORK_SLOTS`].
    pub work: usize,
    /// Of [`STATUS_SLOTS`].
    pub status: usize,
    /// Of [`CONTROL_SLOTS`].
    pub control: usize,
    /// Of [`CANCEL_SLOTS`].
    pub cancel: usize,
    /// Of [`ADMIN_SLOTS`].
    pub admin: usize,
}

impl Admission {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            work: Arc::new(Semaphore::new(WORK_SLOTS)),
            status: Arc::new(Semaphore::new(STATUS_SLOTS)),
            control: Arc::new(Semaphore::new(CONTROL_SLOTS)),
            cancel: Arc::new(Semaphore::new(CANCEL_SLOTS)),
            admin: Arc::new(Semaphore::new(ADMIN_SLOTS)),
        })
    }

    fn available(&self) -> AdmissionAvailable {
        AdmissionAvailable {
            work: self.work.available_permits(),
            status: self.status.available_permits(),
            control: self.control.available_permits(),
            cancel: self.cancel.available_permits(),
            admin: self.admin.available_permits(),
        }
    }
}

/// Why the dispatcher could not admit a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exhausted {
    Rate,
    Capacity,
}

/// One pool's admission: the rate window first, then a slot.
fn take_slot(
    slots: &Arc<Semaphore>,
    rate: Option<&mut crate::admission_rate::RateWindow>,
    now: Instant,
) -> Result<OwnedSemaphorePermit, Exhausted> {
    if let Some(rate) = rate
        && !rate.admit(now)
    {
        return Err(Exhausted::Rate);
    }
    Arc::clone(slots)
        .try_acquire_owned()
        .map_err(|_| Exhausted::Capacity)
}

/// A request's reply channel and its dispatcher slot, tied together.
///
/// The handler answers through [`Self::send`]. Whatever else happens to the
/// handler — it returns without answering, panics, is aborted at shutdown,
/// or is cut off by the hard deadline — dropping the guard answers the
/// caller (an internal refusal, or the shutting-down refusal while the
/// daemon drains) and releases the slot. A slot therefore cannot outlive
/// its handler, and a caller is never left without an answer the daemon
/// could still send. When the caller's side of the channel is already gone
/// the answer is simply dropped; the slot is released all the same.
pub(crate) struct ReplyGuard {
    id: String,
    reply: Option<oneshot::Sender<Response>>,
    phase: watch::Receiver<LifecyclePhase>,
    _permit: OwnedSemaphorePermit,
}

impl ReplyGuard {
    pub(crate) fn new(
        id: String,
        reply: oneshot::Sender<Response>,
        phase: watch::Receiver<LifecyclePhase>,
        permit: OwnedSemaphorePermit,
    ) -> Self {
        Self {
            id,
            reply: Some(reply),
            phase,
            _permit: permit,
        }
    }

    /// Answers the caller. Only the first answer is sent.
    pub(crate) fn send(&mut self, response: Response) {
        if let Some(reply) = self.reply.take() {
            // A closed channel means the caller stopped listening.
            let _ = reply.send(response);
        }
    }

    /// Resolves when nobody can receive the answer any more (the task
    /// carrying the reply to the client has gone). Never resolves once the
    /// request has been answered.
    async fn caller_gone(&mut self) {
        match self.reply.as_mut() {
            Some(reply) => reply.closed().await,
            None => std::future::pending().await,
        }
    }
}

impl Drop for ReplyGuard {
    fn drop(&mut self) {
        let Some(reply) = self.reply.take() else {
            return;
        };
        if reply.is_closed() {
            return;
        }
        let response = if *self.phase.borrow() == LifecyclePhase::Serving {
            tracing::error!(
                request = %self.id,
                "a request handler ended without answering; the caller gets an internal refusal"
            );
            internal_refusal(&self.id)
        } else {
            shutting_down_refusal(&self.id)
        };
        let _ = reply.send(response);
    }
}

/// Resolves when the shutdown flag flips to `true` (a dropped sender
/// counts as shutdown).
async fn signalled(shutdown: &mut watch::Receiver<bool>) {
    let _ = shutdown.wait_for(|stop| *stop).await;
}

/// Receives requests from every ingress and spawns one bounded pipeline
/// task each: the single admission point (see the module docs).
async fn dispatch_loop(
    pipeline: Arc<Pipeline>,
    admission: Arc<Admission>,
    mut incoming: mpsc::Receiver<IncomingRequest>,
    mut shutdown: watch::Receiver<bool>,
) {
    use crate::admission_rate::RateWindow;
    let mut tasks = JoinSet::new();
    let mut work_rate = RateWindow::new(WORK_RATE);
    let mut status_rate = RateWindow::new(STATUS_RATE);
    let mut control_rate = RateWindow::new(CONTROL_RATE);
    let mut cancel_rate = RateWindow::new(CANCEL_RATE);
    loop {
        let request = tokio::select! {
            () = signalled(&mut shutdown) => break,
            Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                log_handler_exit(joined);
                continue;
            }
            request = incoming.recv() => match request { Some(request) => request, None => break },
        };
        let now = Instant::now();
        let pool = admission_pool(&request.envelope.capability);
        let admitted = match (request.origin, pool) {
            // The private plane has its own connection cap; no rate here.
            (Origin::Admin, _) => take_slot(&admission.admin, None, now),
            (Origin::Public, AdmissionPool::Work) => {
                take_slot(&admission.work, Some(&mut work_rate), now)
            }
            (Origin::Public, AdmissionPool::Status) => {
                take_slot(&admission.status, Some(&mut status_rate), now)
            }
            (Origin::Public, AdmissionPool::Control) => {
                take_slot(&admission.control, Some(&mut control_rate), now)
            }
            // Its own headroom first; a control slot when that is taken.
            (Origin::Public, AdmissionPool::Cancel) => {
                take_slot(&admission.cancel, Some(&mut cancel_rate), now)
                    .or_else(|_| take_slot(&admission.control, Some(&mut control_rate), now))
            }
        };
        let permit = match admitted {
            Ok(permit) => permit,
            Err(exhausted) => {
                let _ = request
                    .reply
                    .send(exhausted_refusal(request.envelope.id, exhausted));
                continue;
            }
        };
        let pipeline = Arc::clone(&pipeline);
        tasks.spawn(async move {
            let guard = ReplyGuard::new(
                request.envelope.id.clone(),
                request.reply,
                pipeline.phase.subscribe(),
                permit,
            );
            pipeline
                .serve(request.envelope, request.origin, request.peer, guard)
                .await;
        });
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(joined) = tasks.join_next().await {
            log_handler_exit(joined);
        }
    })
    .await;
    // Aborting drops each handler's reply guard: the caller is told the
    // daemon is shutting down and the slot is released.
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

/// A handler that panicked is a daemon bug nobody would otherwise see: its
/// reply guard already answered the caller and released the slot, and the
/// reconciler closes whatever row it left behind.
fn log_handler_exit(joined: Result<(), tokio::task::JoinError>) {
    if let Err(error) = joined
        && error.is_panic()
    {
        tracing::error!(%error, "a request handler panicked");
    }
}

/// The refusal for a request the dispatcher could not admit.
fn exhausted_refusal(id: String, exhausted: Exhausted) -> Response {
    match exhausted {
        Exhausted::Rate => Response::transient_refusal(
            id,
            CAUSE_REQUEST_RATE,
            "PAM has reached its aggregate request rate limit",
            "Back off before sending more requests",
        ),
        Exhausted::Capacity => Response::transient_refusal(
            id,
            CAUSE_REQUEST_CAPACITY,
            "PAM has reached its active request limit",
            "Wait for work to finish or cancel an existing request",
        ),
    }
}

/// Housekeeping that must not depend on traffic: offers parked terminal
/// verdicts to the store again and prunes the completion router.
async fn maintenance_loop(pipeline: Arc<Pipeline>, mut shutdown: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(MAINTENANCE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = signalled(&mut shutdown) => break,
            _ = ticker.tick() => {}
        }
        if pipeline.terminals.parked_count() != 0 {
            pipeline.terminals.retry_parked().await;
        }
        pipeline.router.prune().await;
    }
    // One last offer: a verdict parked during the drain should not wait
    // for the next boot's crash recovery if the store takes it now.
    if pipeline.terminals.parked_count() != 0 {
        pipeline.terminals.retry_parked().await;
    }
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
            match pipeline.queue.take_next(&repo).await {
                Ok(Some(work)) => {
                    let pipeline = Arc::clone(&pipeline);
                    tokio::spawn(async move {
                        // The execution runs in its own task so a panic in
                        // a capability is seen here instead of leaving the
                        // lease to hold its lane until the deadline.
                        let id = work.request_id.clone();
                        let executor = Arc::clone(&pipeline);
                        let execution =
                            tokio::spawn(async move { executor.execute_leased(work).await });
                        if let Err(error) = execution.await
                            && error.is_panic()
                        {
                            tracing::error!(request = %id, %error, "a leased execution panicked");
                            pipeline.fail_panicked_lease(&id).await;
                        }
                    });
                }
                Ok(None) => {}
                // The lane stays as it was and the next tick retries; a
                // store that fails every tick must not fail silently.
                Err(error) => {
                    tracing::error!(%repo, %error, "leasing the next request off its lane failed");
                }
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
                // The blocking pool is busy or a worker died: neither
                // says anything about the request itself.
                retryable: true,
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
        retryable: true,
        id,
        cause: "deadline_exceeded".to_owned(),
        detail: "The request deadline expired while resolving its repository.".to_owned(),
        recovery: crate::request_budget::RECOVERY_BUDGET.to_owned(),
    }
}

/// Who, besides the caller, has to be told how a request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Audience {
    /// A laned request: subscribers follow its events and duplicate
    /// callers may be attached to it through the completion router.
    Laned,
    /// A read-only bypass (or a request refused before it had a class):
    /// a ticket holder may follow its events; nobody attaches.
    Bypass,
    /// A control request: nobody follows a poll, nobody attaches.
    Control,
}

impl Audience {
    fn of(class: Option<CapabilityClass>) -> Self {
        match class {
            Some(CapabilityClass::Control) => Self::Control,
            Some(CapabilityClass::ReadOnly) | None => Self::Bypass,
            Some(
                CapabilityClass::NonDestructive
                | CapabilityClass::Destructive
                | CapabilityClass::External,
            ) => Self::Laned,
        }
    }

    /// Whether lifecycle events are published for the request.
    fn follows_events(self) -> bool {
        self != Self::Control
    }

    /// Whether duplicate callers can be attached to the request.
    fn has_duplicates(self) -> bool {
        self == Self::Laned
    }
}

/// How a parked wait on the completion router ended.
#[derive(Debug, PartialEq)]
pub(crate) enum Waited {
    /// The request finished; here is its terminal response.
    Answer(Response),
    /// The wait's own deadline elapsed first.
    TimedOut,
    /// The router dropped the waiter without answering.
    RouterDropped,
    /// Nobody can receive the answer any more; the wait was abandoned and
    /// the request it was waiting on is left alone.
    CallerGone,
}

/// Parks on `registration` until the answer, `deadline`, or — when the
/// handler's `guard` is given — the caller going away. A handler that is
/// only waiting must not hold its slot for a caller that has left; the
/// laned work continues under its lease either way.
pub(crate) async fn wait_for_terminal(
    registration: Registration,
    deadline: tokio::time::Instant,
    guard: Option<&mut ReplyGuard>,
) -> Waited {
    let rx = match registration {
        Registration::Ready(response) => return Waited::Answer(*response),
        Registration::Pending(rx) => rx,
    };
    let gone = async {
        match guard {
            Some(guard) => guard.caller_gone().await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        answer = rx => match answer {
            Ok(response) => Waited::Answer(response),
            Err(_) => Waited::RouterDropped,
        },
        () = tokio::time::sleep_until(deadline) => Waited::TimedOut,
        () = gone => Waited::CallerGone,
    }
}

impl Pipeline {
    /// Runs one request to its answer under the hard handler deadline (see
    /// the module docs). The deadline wraps everything the handler does;
    /// when it elapses the caller is answered, the slot is released, and
    /// the request's terminal row is written by a detached task.
    async fn serve(
        self: Arc<Self>,
        envelope: Envelope,
        origin: Origin,
        peer: Option<PublicPeer>,
        mut guard: ReplyGuard,
    ) {
        let id = envelope.id.clone();
        let deadline_ms = envelope.deadline_ms;
        let class = classify(&envelope.capability);
        let limit = self.handler_limit(deadline_ms, class);
        let handled = tokio::time::timeout(
            limit,
            Arc::clone(&self).handle(envelope, origin, peer, &mut guard),
        )
        .await;
        if handled.is_ok() {
            // Answered inside; a handler that returned without answering
            // is answered by the guard's drop.
            return;
        }
        tracing::error!(
            request = %id,
            limit_ms = u64::try_from(limit.as_millis()).unwrap_or(u64::MAX),
            "a request handler exceeded its hard deadline; answering the caller and \
             finishing the request in the background"
        );
        guard.send(deadline_refusal_response(&id, deadline_ms));
        // The slot is free from here: persistence must not hold it.
        drop(guard);
        let audience = Audience::of(class);
        tokio::spawn(async move {
            self.finish_overdue(&id, deadline_ms, audience).await;
        });
    }

    /// The hard bound on one handler: the envelope's deadline clamped to
    /// the lease ceiling, plus the grace. A control request is bookkeeping,
    /// so it gets the short cap and the short grace.
    fn handler_limit(&self, deadline_ms: u64, class: Option<CapabilityClass>) -> Duration {
        let asked = Duration::from_millis(deadline_ms).min(crate::queue::MAX_LEASE);
        if class == Some(CapabilityClass::Control) {
            asked.min(CONTROL_DEADLINE_CAP) + CONTROL_GRACE
        } else {
            asked + self.handler_grace
        }
    }

    /// Finishes a request whose handler was cut off: the terminal row
    /// through the store's choke point (first-wins, so a row its handler
    /// did finish is untouched; no row, nothing to write), the `refused`
    /// event, and any attached duplicates.
    async fn finish_overdue(&self, id: &str, deadline_ms: u64, audience: Audience) {
        let detail = serde_json::json!({ "deadline_ms": deadline_ms, "cause": "handler_deadline" })
            .to_string();
        self.terminals
            .finish(
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
        self.announce(
            id,
            audience,
            Event::Refused,
            deadline_refusal_response(id, deadline_ms),
        )
        .await;
        self.events.hub().unregister(id);
    }

    /// Tells the event hub what admission knows about a ticket whose
    /// lifecycle events are about to be published, so the administration
    /// plane's all-events stream can name it. The terminal event removes it
    /// again; an ending that publishes none calls
    /// [`EventHub::unregister`].
    fn register_ticket(&self, envelope: &Envelope, origin: Origin) {
        self.events.hub().register(
            &envelope.id,
            TicketMeta {
                capability: envelope.capability.clone(),
                repo: envelope.caller.repo.clone(),
                agent: envelope.caller.agent.clone(),
                ingress: origin.wire(),
            },
        );
    }

    /// Tells whoever follows `id` how it ended: the lifecycle event for
    /// subscribers, the terminal response for attached duplicates.
    async fn announce(&self, id: &str, audience: Audience, event: Event, response: Response) {
        if audience.follows_events() {
            let _ = self.events.publish(id, event).await;
        }
        if audience.has_duplicates() {
            self.router.finish(id, response).await;
        }
    }

    /// The gates that run before anything is recorded: the drain and the
    /// version handshake. `Some` is the refusal to answer with; neither
    /// gets a request row — the retry lands on the next (or new) daemon
    /// and is recorded there. `greeted` says the request arrived on a
    /// connection whose hello already went through the version rule: the
    /// envelope's own version then decides nothing.
    async fn lifecycle_refusal(&self, envelope: &Envelope, greeted: bool) -> Option<Response> {
        let id = &envelope.id;
        let phase = *self.phase.borrow();
        match phase {
            LifecyclePhase::Serving => {}
            LifecyclePhase::Restarting => {
                return Some(outdated_refusal(
                    id,
                    &envelope.client_version,
                    self.image.boot_path(),
                ));
            }
            LifecyclePhase::Draining => return Some(shutting_down_refusal(id)),
        }
        if greeted {
            return None;
        }
        match self
            .image
            .verdict(&envelope.client_version, DAEMON_VERSION)
            .await
        {
            VersionVerdict::Match => None,
            VersionVerdict::Restart => {
                // The binary this daemon was started from is no longer
                // the one on disk. Answer this request, then hand over.
                tracing::info!(
                    client_version = %envelope.client_version,
                    daemon_version = DAEMON_VERSION,
                    "the daemon's binary was replaced on disk; restarting with it"
                );
                request_restart(&self.phase);
                Some(outdated_refusal(
                    id,
                    &envelope.client_version,
                    self.image.boot_path(),
                ))
            }
            VersionVerdict::Mismatch => {
                // A claimed version restarts nothing: the caller is a
                // different build and is told so.
                tracing::debug!(
                    client_version = %envelope.client_version,
                    daemon_version = DAEMON_VERSION,
                    "refused a client of a different build; the binary on disk is unchanged"
                );
                Some(version_mismatch_refusal(
                    id,
                    &envelope.client_version,
                    self.image.boot_path(),
                ))
            }
        }
    }

    /// Runs one request through classify → admit → gate → queue/execute
    /// and answers through `guard` with its single [`Response`]. Takes the
    /// pipeline by `Arc` so the approval path can spawn a background
    /// wait for `wait: false` callers.
    async fn handle(
        self: Arc<Self>,
        mut envelope: Envelope,
        origin: Origin,
        peer: Option<PublicPeer>,
        guard: &mut ReplyGuard,
    ) {
        if envelope.capability.starts_with(ADMIN_PREFIX) {
            let response = self.admin.handle_from_ingress(&envelope, false).await;
            guard.send(response);
            return;
        }
        let id = envelope.id.clone();

        if let Some(refusal) = self.lifecycle_refusal(&envelope, peer.is_some()).await {
            guard.send(refusal);
            return;
        }

        let class = classify(&envelope.capability);
        if envelope.capability == CAP_STATUS {
            // A snapshot read: no row, no audit, no events, nothing slow
            // (see the module docs). Answered the same whether or not the
            // caller asked to wait — there is nothing to hold a ticket for.
            guard.send(Response::Result {
                id,
                outcome: pam_proto::Outcome::Verified,
                body: self.status.body(&self.store, self.started_at).await,
                evidence: Vec::new(),
            });
            return;
        }
        if class == Some(CapabilityClass::Control) {
            // A control slot is held for bookkeeping, never for an hour:
            // the row's own expiry carries the cap, so the bypass deadline
            // and the reconciler both honour it.
            let cap = u64::try_from(CONTROL_DEADLINE_CAP.as_millis()).unwrap_or(u64::MAX);
            envelope.deadline_ms = envelope.deadline_ms.min(cap);
        }

        let envelope = match normalize_repository(envelope).await {
            Ok(envelope) => envelope,
            Err(response) => {
                guard.send(response);
                return;
            }
        };

        // Unknown capability: no class, no dedupe — record the request,
        // let the gate produce the refusal.
        let recorded = crate::ingress::recorded(origin, peer);
        let Some(class) = class else {
            let response = self.refuse_unadmitted(&envelope, origin, &recorded).await;
            guard.send(response);
            return;
        };

        let admitted = match self.queue.admit_from(&envelope, class, &recorded).await {
            Ok(admitted) => admitted,
            Err(error) => {
                guard.send(queue_refusal(id, &error));
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
                self.answer_attached(&envelope, &existing_request_id, guard)
                    .await;
            }
            AdmitOutcome::Bypass => {
                let audience = Audience::of(Some(class));
                if audience.follows_events() {
                    self.register_ticket(&envelope, origin);
                }
                if envelope.wait {
                    let response = self.execute_bypass(&envelope, origin, audience).await;
                    guard.send(response);
                } else {
                    guard.send(Response::Ticket {
                        id: id.clone(),
                        ticket: id,
                        position: 0,
                    });
                    // Result reaches the store and event stream only.
                    let _ = self.execute_bypass(&envelope, origin, audience).await;
                }
                // A bypass ends in this handler. Its terminal event already
                // removed it from the hub; an ending that published none
                // (a verdict parked for retry) is forgotten here.
                self.events.hub().unregister(&envelope.id);
            }
            AdmitOutcome::Admitted => {
                self.register_ticket(&envelope, origin);
                let response = Arc::clone(&self)
                    .gate_and_place(&envelope, Some(&mut *guard))
                    .await;
                guard.send(response);
            }
        }
    }

    /// Answers a duplicate caller attached to an in-flight request: a
    /// ticket for `wait: false`, otherwise the original's terminal response
    /// when it arrives within this caller's own deadline.
    async fn answer_attached(&self, envelope: &Envelope, existing: &str, guard: &mut ReplyGuard) {
        let id = &envelope.id;
        let ticket = || Response::Ticket {
            id: id.clone(),
            ticket: existing.to_owned(),
            position: 0,
        };
        if !envelope.wait {
            guard.send(ticket());
            return;
        }
        let registration = self.router.register(existing).await;
        // The original may have finished between the dedupe read and this
        // registration with its answer no longer retained (the router's
        // retention is bounded). Its terminal state is durable: hand the
        // caller the ticket to read it with rather than park it on an
        // answer that already left.
        if matches!(registration, Registration::Pending(_))
            && matches!(
                self.store.request_status_meta(existing).await,
                Ok(Some(row)) if row.state.is_terminal()
            )
        {
            guard.send(ticket());
            return;
        }
        let deadline = tokio::time::Instant::now() + Duration::from_millis(envelope.deadline_ms);
        match wait_for_terminal(registration, deadline, Some(&mut *guard)).await {
            Waited::Answer(response) => guard.send(response),
            Waited::TimedOut => guard.send(attach_refusal(id, true)),
            Waited::RouterDropped => guard.send(attach_refusal(id, false)),
            // Nobody to answer; the original is left alone.
            Waited::CallerGone => {}
        }
    }

    /// The laned path after admission: gate, then place (pausing for an
    /// approval when the gate requires one) and, for waiting callers,
    /// park on the completion router under the deadline. Every refusal
    /// and internal failure here also releases attached duplicates.
    async fn gate_and_place(
        self: Arc<Self>,
        envelope: &Envelope,
        guard: Option<&mut ReplyGuard>,
    ) -> Response {
        let id = &envelope.id;
        let Ok(decision) = self.gate.evaluate(id, &envelope.capability).await else {
            // Keep the not-yet-placed row out of the lanes forever.
            return self.fail_internal(id, Audience::Laned).await;
        };
        match decision {
            GateDecision::Refuse {
                cause,
                detail,
                recovery,
            } => {
                self.refuse(id, Audience::Laned, cause, detail, recovery)
                    .await
            }
            GateDecision::RequireApproval { reason } => {
                self.approval_pause(envelope, reason, guard).await
            }
            GateDecision::Allow { .. } => self.place_and_wait(envelope, guard).await,
        }
    }

    /// Places an allowed (or approved) request on its lane and, for a
    /// waiting caller, parks only until the persisted admission expiry.
    /// Gate, approval and placement time never renew the request clock.
    async fn place_and_wait(
        &self,
        envelope: &Envelope,
        guard: Option<&mut ReplyGuard>,
    ) -> Response {
        let id = &envelope.id;
        let deadline = match self.store.get_request(id).await {
            Ok(Some(row)) => request_deadline(&row),
            // The row cannot be read: it still gets its terminal state.
            _ => return self.fail_internal(id, Audience::Laned).await,
        };
        let Some(deadline) = deadline else {
            return self.deadline_refusal(envelope, Audience::Laned).await;
        };
        // Register before placement so the completion cannot slip
        // between the two.
        let registration = self.router.register(id).await;
        let position = match self.queue.place_in_lane(id, &envelope.caller.repo).await {
            Ok(position) => position,
            Err(QueueError::Expired) => {
                return self.deadline_refusal(envelope, Audience::Laned).await;
            }
            Err(error) => {
                return self
                    .refuse(
                        id,
                        Audience::Laned,
                        error.cause().to_owned(),
                        error.to_string(),
                        error.recovery().to_owned(),
                    )
                    .await;
            }
        };
        let _ = self.events.publish(id, Event::Queued).await;
        self.work.notify_one();
        if envelope.wait {
            match wait_for_terminal(
                registration,
                tokio::time::Instant::from_std(deadline),
                guard,
            )
            .await
            {
                Waited::Answer(response) => response,
                Waited::TimedOut => self.deadline_refusal(envelope, Audience::Laned).await,
                // Never delivered (nobody is listening); the laned work
                // continues under its lease and its result stays durable.
                Waited::RouterDropped | Waited::CallerGone => internal_refusal(id),
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
    async fn approval_pause(
        self: Arc<Self>,
        envelope: &Envelope,
        reason: String,
        guard: Option<&mut ReplyGuard>,
    ) -> Response {
        if envelope.wait {
            return self.approval_wait_inline(envelope, &reason, guard).await;
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
            let _ = self.approval_wait_inline(&envelope, &reason, None).await;
        });
        ticket
    }

    /// Approval pause for both waiting and ticketed requests. The persisted
    /// admission expiry bounds the pause; expiry resolves the approval wait
    /// before recording the durable request timeout.
    async fn approval_wait_inline(
        &self,
        envelope: &Envelope,
        reason: &str,
        guard: Option<&mut ReplyGuard>,
    ) -> Response {
        let id = &envelope.id;
        let deadline = match self.store.get_request(id).await {
            Ok(Some(row)) => request_deadline(&row),
            _ => return self.fail_internal(id, Audience::Laned).await,
        };
        let Some(deadline) = deadline else {
            return self.deadline_refusal(envelope, Audience::Laned).await;
        };
        let (cancel_tx, mut cancel) = watch::channel(false);
        let fut = self
            .approvals
            .request_approval(id, &envelope.capability, &mut cancel);
        tokio::pin!(fut);
        tokio::select! {
            outcome = &mut fut => self.conclude_approval(envelope, reason, outcome, guard).await,
            () = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                let _ = cancel_tx.send(true);
                // Resolve any pending approval so the GUI cannot grant stale work.
                let _ = fut.await;
                self.deadline_refusal(envelope, Audience::Laned).await
            }
        }
    }

    /// Acts on an approval wait's outcome: approved requests move back
    /// to `queued` and continue under the original admission expiry;
    /// everything else becomes a terminal refusal (audited and released
    /// to attached waiters through [`Self::refuse`] — they may have
    /// attached during the long `waiting_approval` window).
    async fn conclude_approval(
        &self,
        envelope: &Envelope,
        reason: &str,
        outcome: Result<ApprovalOutcome, StoreError>,
        guard: Option<&mut ReplyGuard>,
    ) -> Response {
        let id = &envelope.id;
        let capability = &envelope.capability;
        let (cause, detail, recovery) = match outcome {
            Ok(ApprovalOutcome::Approved { .. }) => {
                return self.place_and_wait(envelope, guard).await;
            }
            Ok(ApprovalOutcome::Denied) => (
                CAUSE_APPROVAL_DENIED,
                format!("approval for capability {capability:?} was denied ({reason})"),
                RECOVERY_APPROVAL_DENIED,
            ),
            Ok(ApprovalOutcome::TimedOut) => (
                CAUSE_APPROVAL_TIMEOUT,
                format!("approval for capability {capability:?} expired unanswered ({reason})"),
                RECOVERY_APPROVAL_TIMEOUT,
            ),
            Ok(ApprovalOutcome::Cancelled) => (
                CAUSE_CANCELLED,
                format!(
                    "request was cancelled while waiting for approval \
                     of capability {capability:?}"
                ),
                RECOVERY_APPROVAL_CANCELLED,
            ),
            Err(_) => return self.fail_internal(id, Audience::Laned).await,
        };
        self.refuse(
            id,
            Audience::Laned,
            cause.to_owned(),
            detail,
            recovery.to_owned(),
        )
        .await
    }

    /// Executes a bypass request inline, under the envelope's deadline,
    /// and records its terminal state. A control request publishes no
    /// lifecycle events (see [`Audience`]).
    async fn execute_bypass(
        &self,
        envelope: &Envelope,
        origin: Origin,
        audience: Audience,
    ) -> Response {
        let id = &envelope.id;
        if audience.follows_events() {
            let _ = self.events.publish(id, Event::Started).await;
        }
        // No lease exists for a bypass; the sender is held so the cancel
        // signal simply never fires. The deadline timeout below dropping
        // the future is the cancellation mechanism on this path.
        let (_cancel_tx, cancel) = watch::channel(false);
        let Some(capability) = BuiltinCapability::from_name(&envelope.capability) else {
            return self
                .fail_bypass(
                    id,
                    audience,
                    &envelope.capability,
                    "capability classified but not dispatchable",
                )
                .await;
        };
        let Ok(Some(row)) = self.store.get_request(id).await else {
            // The row cannot be read back: it still gets a terminal state
            // (retried, then left to the reconciler), never a bare return.
            return self.fail_internal(id, audience).await;
        };
        let Some(deadline) = request_deadline(&row) else {
            return self.deadline_refusal(envelope, audience).await;
        };
        let ctx = self
            .exec_context(
                envelope.id.clone(),
                envelope.capability.clone(),
                envelope.caller.clone(),
                envelope.args.clone(),
                cancel,
                deadline,
                origin,
                row.origin,
            )
            .await;
        let ctx = match ctx {
            Ok(ctx) => ctx,
            Err(error) => {
                return self
                    .fail_bypass(id, audience, &envelope.capability, &format!("{error:?}"))
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
                self.finish_bypass_done(id, audience, &envelope.capability, output)
                    .await
            }
            Ok(Err(CapabilityFailure::Cancelled)) => self.cancel_bypass(id, audience).await,
            Ok(Err(CapabilityFailure::Parked { .. })) => {
                self.fail_bypass(
                    id,
                    audience,
                    &envelope.capability,
                    "only a leased flow can park",
                )
                .await
            }
            Ok(Err(CapabilityFailure::Failed { detail })) => {
                self.fail_bypass(id, audience, &envelope.capability, &detail)
                    .await
            }
            Ok(Err(CapabilityFailure::Refused {
                cause,
                detail,
                recovery,
            })) => {
                self.refuse_execution(id, audience, &envelope.capability, cause, detail, recovery)
                    .await
            }
            Err(_elapsed) => {
                self.finish_bypass_deadline(id, audience, envelope.deadline_ms)
                    .await
            }
        }
    }

    /// The success arm of [`Self::execute_bypass`].
    async fn finish_bypass_done(
        &self,
        id: &str,
        audience: Audience,
        capability: &str,
        output: CapabilityOutput,
    ) -> Response {
        let detail = execute_success_detail(capability, output.outcome);
        let written = self
            .terminals
            .finish(
                id,
                RequestState::Done,
                Some(outcome_str(output.outcome)),
                execute_success_entry(&detail),
            )
            .await;
        if written == Written::Parked {
            // The audit invariant: nothing is reported as done whose
            // terminal row is not durable. The verdict is parked and will
            // be recorded; the caller retries.
            return unrecorded_refusal(id);
        }
        if audience.follows_events() {
            let _ = self.events.publish(id, Event::Done).await;
        }
        Response::Result {
            id: id.to_owned(),
            outcome: output.outcome,
            body: output.body,
            evidence: output.evidence,
        }
    }

    /// The elapsed-deadline arm of [`Self::execute_bypass`].
    async fn finish_bypass_deadline(
        &self,
        id: &str,
        audience: Audience,
        deadline_ms: u64,
    ) -> Response {
        let detail = serde_json::json!({ "deadline_ms": deadline_ms }).to_string();
        self.terminals
            .finish(
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
        if audience.follows_events() {
            let _ = self.events.publish(id, Event::Refused).await;
        }
        deadline_refusal_response(id, deadline_ms)
    }

    async fn cancel_bypass(&self, id: &str, audience: Audience) -> Response {
        // Unreachable without a lease, but handled legibly.
        let detail = cancelled_detail();
        self.terminals
            .finish(
                id,
                RequestState::Failed,
                Some(CAUSE_CANCELLED),
                cancelled_entry(&detail),
            )
            .await;
        if audience.follows_events() {
            let _ = self.events.publish(id, Event::Refused).await;
        }
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
        // Scoped: only a revocation of a grant this request depends on voids
        // it. A store that cannot answer is not permission to run.
        if !matches!(
            self.store.request_authorization_current(&id).await,
            Ok(true)
        ) {
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
                    serde_json::from_str::<serde_json::Value>(&journal.checkpoint_json).is_ok_and(
                        |cursor| {
                            cursor
                                .get("watch")
                                .is_some_and(serde_json::Value::is_object)
                        },
                    )
                });
        if !continuing_watch {
            let _ = self.events.publish(&id, Event::Started).await;
        }

        let result = match BuiltinCapability::from_name(&row.capability) {
            // Unreadable persisted args fail the lease rather than running
            // the capability with empty args it never asked for.
            Some(_) if serde_json::from_str::<serde_json::Value>(&row.args_json).is_err() => {
                Err(CapabilityFailure::Failed {
                    detail: "the request's persisted arguments are not readable JSON".to_owned(),
                })
            }
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
                        // Recorded at admission: a request the private
                        // plane submitted is still that plane's when its
                        // lane reaches it.
                        Origin::of_row(&row.origin),
                        row.origin,
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
                self.finish_leased(
                    id,
                    RequestState::Failed,
                    CAUSE_CANCELLED,
                    cancelled_entry(&audit_detail),
                    Event::Refused,
                    cancelled_refusal(id),
                )
                .await;
            }
            Err(CapabilityFailure::Failed { detail }) => {
                let audit_detail = execute_failure_detail(capability, &detail);
                self.finish_leased(
                    id,
                    RequestState::Failed,
                    CAUSE_EXECUTION_FAILED,
                    execute_failure_entry(&audit_detail),
                    Event::Refused,
                    failure_refusal(id, detail),
                )
                .await;
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

    /// The one way a leased request ends: the row and its single audit
    /// entry through the queue (which frees the lane), then the event and
    /// the waiters' response.
    ///
    /// A terminal write the store refuses is retried briefly. If it still
    /// fails, the lane is given back at once rather than held until the
    /// lease deadline, the verdict is parked for the maintenance loop to
    /// record, and the waiters still get the real result — the work
    /// happened, and telling them `deadline_exceeded` an hour later would
    /// be false.
    async fn finish_leased(
        &self,
        id: &str,
        state: RequestState,
        outcome: &str,
        audit: AuditEntry<'_>,
        event: Event,
        response: Response,
    ) {
        let mut terminal = self.queue.complete(id, state, Some(outcome), audit).await;
        for pause in crate::terminal::RETRY_BACKOFF {
            if terminal.is_ok() {
                break;
            }
            tokio::time::sleep(pause).await;
            terminal = self.queue.complete(id, state, Some(outcome), audit).await;
        }
        match terminal {
            Ok(true) => {
                let _ = self.events.publish(id, event).await;
                self.router.finish(id, response).await;
            }
            // The lease was reaped first: the reaper wrote the terminal
            // row and audit; release any waiters.
            Ok(false) => self.finish_reaped(id).await,
            Err(error) => {
                tracing::error!(
                    request = %id,
                    %error,
                    "could not record a leased request's terminal state; releasing its lane \
                     and parking the verdict for retry"
                );
                self.terminals.park(id, state, Some(outcome), audit);
                self.queue.abandon_lease(id).await;
                let _ = self.events.publish(id, event).await;
                self.router.finish(id, response).await;
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
        self.finish_leased(
            id,
            RequestState::Refused,
            &cause,
            execution_refusal_entry(&audit_detail),
            Event::Refused,
            Response::Refusal {
                id: id.to_owned(),
                retryable: is_transient_cause(&cause),
                cause: cause.clone(),
                detail,
                recovery,
            },
        )
        .await;
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
        self.finish_leased(
            id,
            RequestState::Done,
            outcome_str(output.outcome),
            execute_success_entry(&audit_detail),
            Event::Done,
            Response::Result {
                id: id.to_owned(),
                outcome: output.outcome,
                body: output.body,
                evidence: output.evidence,
            },
        )
        .await;
    }

    /// A leased request whose row cannot be read is unanswerable: record
    /// the internal failure (logged if even that fails) and free the lane.
    async fn fail_vanished_row(&self, id: &str) {
        let detail = serde_json::json!({ "cause": "request row missing" }).to_string();
        self.finish_leased(
            id,
            RequestState::Failed,
            CAUSE_INTERNAL_ERROR,
            internal_failure_entry(&detail),
            Event::Refused,
            internal_refusal(id),
        )
        .await;
        self.work.notify_one();
    }

    /// A capability that panicked mid-lease: the request fails with the
    /// internal cause and its lane is freed now, not at the lease deadline.
    async fn fail_panicked_lease(&self, id: &str) {
        let detail = serde_json::json!({ "cause": "capability panicked" }).to_string();
        self.finish_leased(
            id,
            RequestState::Failed,
            CAUSE_INTERNAL_ERROR,
            internal_failure_entry(&detail),
            Event::Refused,
            internal_refusal(id),
        )
        .await;
        self.work.notify_one();
    }

    /// Builds the execution context for one request.
    // One argument per fact the context is born with.
    #[allow(clippy::too_many_arguments)]
    async fn exec_context(
        &self,
        request_id: String,
        capability: String,
        caller: pam_proto::Caller,
        args: serde_json::Value,
        cancel: watch::Receiver<bool>,
        deadline: std::time::Instant,
        origin: Origin,
        peer: pam_store::RequestOrigin,
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
            origin,
            peer,
            status: Arc::clone(&self.status),
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
    async fn refuse_unadmitted(
        &self,
        envelope: &Envelope,
        origin: Origin,
        recorded: &pam_store::RequestOrigin,
    ) -> Response {
        let inserted = self
            .store
            .insert_request_from(
                &envelope.id,
                &envelope.capability,
                &envelope.caller.repo,
                &envelope.caller.agent,
                &envelope.args.to_string(),
                envelope.idempotency_key.as_deref(),
                recorded,
            )
            .await;
        if inserted.is_err() {
            return internal_refusal(&envelope.id);
        }
        self.register_ticket(envelope, origin);
        match self.gate.evaluate(&envelope.id, &envelope.capability).await {
            Ok(GateDecision::Refuse {
                cause,
                detail,
                recovery,
            }) => {
                self.refuse(&envelope.id, Audience::Bypass, cause, detail, recovery)
                    .await
            }
            // classify() said None, so the gate must refuse; anything
            // else is an internal inconsistency — and the row just
            // inserted still gets its terminal state.
            _ => self.fail_internal(&envelope.id, Audience::Bypass).await,
        }
    }

    /// Marks a request refused — terminal state and gate-refusal audit
    /// row in one transaction — publishes the `refused` event, releases
    /// any attached duplicates with the same refusal, and builds the
    /// refusal response.
    async fn refuse(
        &self,
        id: &str,
        audience: Audience,
        cause: String,
        detail: String,
        recovery: String,
    ) -> Response {
        let audit_detail = serde_json::json!({
            "cause": cause,
            "detail": detail,
            "profile": self.gate.profile().as_str(),
        })
        .to_string();
        self.terminals
            .finish(
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
        let response = Response::Refusal {
            id: id.to_owned(),
            cause,
            detail,
            recovery,
            retryable: false,
        };
        self.announce(id, audience, Event::Refused, response.clone())
            .await;
        response
    }

    /// Terminal handling for a daemon-side bookkeeping failure: fail the
    /// request with its [`ACTION_INTERNAL_FAILURE`] audit row, tell
    /// whoever follows it, and answer with the internal refusal.
    async fn fail_internal(&self, id: &str, audience: Audience) -> Response {
        let detail = serde_json::json!({ "cause": CAUSE_INTERNAL_ERROR }).to_string();
        self.terminals
            .finish(
                id,
                RequestState::Failed,
                Some(CAUSE_INTERNAL_ERROR),
                internal_failure_entry(&detail),
            )
            .await;
        let response = internal_refusal(id);
        self.announce(id, audience, Event::Refused, response.clone())
            .await;
        response
    }

    /// Terminal handling for a bypass execution failure.
    async fn fail_bypass(
        &self,
        id: &str,
        audience: Audience,
        capability: &str,
        detail: &str,
    ) -> Response {
        let audit_detail = execute_failure_detail(capability, detail);
        self.terminals
            .finish(
                id,
                RequestState::Failed,
                Some(CAUSE_EXECUTION_FAILED),
                execute_failure_entry(&audit_detail),
            )
            .await;
        if audience.follows_events() {
            let _ = self.events.publish(id, Event::Refused).await;
        }
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
        audience: Audience,
        capability: &str,
        cause: String,
        detail: String,
        recovery: String,
    ) -> Response {
        let audit_detail = execution_refusal_detail(capability, &cause, &detail);
        self.terminals
            .finish(
                id,
                RequestState::Refused,
                Some(&cause),
                execution_refusal_entry(&audit_detail),
            )
            .await;
        if audience.follows_events() {
            let _ = self.events.publish(id, Event::Refused).await;
        }
        Response::Refusal {
            id: id.to_owned(),
            retryable: is_transient_cause(&cause),
            cause,
            detail,
            recovery,
        }
    }

    /// Tears a deadline-expired request down: the queue records expiry before
    /// signalling the executor; then audit the refusal, notify subscribers,
    /// and answer the caller.
    async fn deadline_refusal(&self, envelope: &Envelope, audience: Audience) -> Response {
        let id = &envelope.id;
        let terminal = self.queue.expire(id).await;
        log_terminal_failure(id, &terminal);
        if terminal.is_err() {
            // Ownership stays with the queue: the reaper or the
            // reconciler finishes the row and releases its waiters.
            return internal_refusal(id);
        }
        self.audit_deadline(id, envelope.deadline_ms).await;
        let response = self
            .preserve_terminal_uncertainty(id, deadline_refusal_response(id, envelope.deadline_ms))
            .await;
        self.announce(id, audience, Event::Refused, response.clone())
            .await;
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
                    retryable: true,
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
                if outcome == crate::queue::CAUSE_LEASE_EXPIRED && self.router.has_waiters(id).await
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
                        retryable: true,
                        id: id.to_owned(),
                        cause: CAUSE_DEADLINE_EXCEEDED.to_owned(),
                        detail: format!("request {id} exceeded its admitted deadline"),
                        recovery: RECOVERY_DEADLINE.to_owned(),
                    }
                } else {
                    Response::Refusal {
                        retryable: false,
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
                retryable: false,
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

/// The refusal an *attached* caller gets when its own deadline elapses
/// (`timed_out`) or the router fails. The attached caller has no request
/// row of its own, so nothing is audited and the in-flight original is
/// left alone — other callers may still be waiting on it.
fn attach_refusal(id: &str, timed_out: bool) -> Response {
    if timed_out {
        Response::transient_refusal(
            id,
            CAUSE_DEADLINE_EXCEEDED,
            "the in-flight request this call attached to did not finish within the deadline",
            RECOVERY_DEADLINE,
        )
    } else {
        internal_refusal(id)
    }
}

/// Refusal for a request that arrived while the daemon drains.
pub(crate) fn shutting_down_refusal(id: &str) -> Response {
    Response::transient_refusal(
        id,
        CAUSE_DAEMON_SHUTTING_DOWN,
        "the daemon is draining in-flight work before it exits",
        RECOVERY_SHUTTING_DOWN,
    )
}

/// Moves a serving daemon to [`LifecyclePhase::Restarting`]; a daemon that
/// is already draining keeps its phase.
pub(crate) fn request_restart(phase: &watch::Sender<LifecyclePhase>) {
    let _ = phase.send_if_modified(|current| {
        if *current == LifecyclePhase::Serving {
            *current = LifecyclePhase::Restarting;
            true
        } else {
            false
        }
    });
}

/// What a refusal says about where the daemon runs from.
fn image_label(boot_path: Option<&Path>) -> String {
    boot_path.map_or_else(
        || "an unknown path".to_owned(),
        |path| path.display().to_string(),
    )
}

/// Refusal for the version handshake when the daemon's binary on disk was
/// replaced: the daemon restarts itself, and the retry lands on the new one.
pub(crate) fn outdated_refusal(
    id: &str,
    client_version: &str,
    boot_path: Option<&Path>,
) -> Response {
    Response::transient_refusal(
        id,
        CAUSE_DAEMON_OUTDATED,
        format!(
            "client version {client_version} does not match daemon version \
             {DAEMON_VERSION}; the pam binary at {} was replaced while this daemon ran",
            image_label(boot_path)
        ),
        RECOVERY_OUTDATED,
    )
}

/// Refusal for a client of a different build when the daemon's binary on
/// disk is unchanged: nothing restarts, and sending the same request again
/// would only repeat (so it is not `retryable`).
pub(crate) fn version_mismatch_refusal(
    id: &str,
    client_version: &str,
    boot_path: Option<&Path>,
) -> Response {
    Response::refusal(
        id,
        CAUSE_CLIENT_VERSION_MISMATCH,
        format!(
            "client version {client_version} does not match daemon version {DAEMON_VERSION} \
             running from {}; that binary has not changed on disk, so the daemon keeps running",
            image_label(boot_path)
        ),
        RECOVERY_VERSION_MISMATCH,
    )
}

/// Refusal for a daemon-side bookkeeping failure.
pub(crate) fn internal_refusal(id: &str) -> Response {
    Response::transient_refusal(
        id,
        CAUSE_INTERNAL_ERROR,
        "the daemon could not record the request",
        RECOVERY_INTERNAL,
    )
}

/// Refusal for a bypass request that ran but whose terminal row the store
/// would not take: the verdict is parked for retry, and reporting success
/// without a durable audit row would break the audit invariant.
fn unrecorded_refusal(id: &str) -> Response {
    Response::transient_refusal(
        id,
        CAUSE_INTERNAL_ERROR,
        "the request ran but the daemon could not record its outcome yet; \
         the outcome is queued to be recorded",
        RECOVERY_INTERNAL,
    )
}

/// The refusal for an admission the queue turned down. Capacity, an
/// elapsed deadline and a store failure are all transient.
fn queue_refusal(id: String, error: &QueueError) -> Response {
    let retryable = matches!(
        error,
        QueueError::Capacity { .. } | QueueError::Expired | QueueError::Store(_)
    );
    Response::Refusal {
        id,
        cause: error.cause().to_owned(),
        detail: error.to_string(),
        recovery: error.recovery().to_owned(),
        retryable,
    }
}

/// Whether a cause a capability refused with is transient: the request's
/// own deadline ran out, or the daemon's blocking pool was full. Everything
/// else a capability refuses with would only repeat.
fn is_transient_cause(cause: &str) -> bool {
    matches!(
        cause,
        CAUSE_DEADLINE_EXCEEDED | "blocking_capacity_exhausted"
    )
}

/// Refusal for a request that was cancelled.
fn cancelled_refusal(id: &str) -> Response {
    Response::refusal(
        id,
        CAUSE_CANCELLED,
        format!("request {id} was cancelled"),
        "Re-run the pam command to start a fresh request.",
    )
}

/// Refusal for a capability that ran and failed.
fn failure_refusal(id: &str, detail: String) -> Response {
    Response::refusal(id, CAUSE_EXECUTION_FAILED, detail, RECOVERY_FAILED)
}

/// Refusal for an elapsed deadline.
pub(crate) fn deadline_refusal_response(id: &str, deadline_ms: u64) -> Response {
    Response::transient_refusal(
        id,
        CAUSE_DEADLINE_EXCEEDED,
        format!("request exceeded its {deadline_ms} ms deadline"),
        RECOVERY_DEADLINE,
    )
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
