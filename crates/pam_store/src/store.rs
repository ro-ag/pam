//! The [`Store`] handle: open, migrate, and a thin typed helper surface.
//!
//! Services (queue, policy, audit) own their richer queries and add them
//! alongside their own tasks; only helpers the spine needs today live
//! here.

#[path = "evidence_views.rs"]
pub(crate) mod evidence_views;
#[path = "request_budget.rs"]
mod request_budget;
pub use request_budget::*;
#[path = "flow_journal.rs"]
mod flow_journal;
#[path = "landing_session.rs"]
mod landing_session;
pub use landing_session::LandingSession;
#[path = "watch_schedule.rs"]
mod watch_schedule;
pub use evidence_views::*;
pub use flow_journal::*;
#[path = "correlation.rs"]
mod correlation;
pub use correlation::*;
#[path = "correlation_membership.rs"]
mod correlation_membership;
#[path = "flow_results.rs"]
mod flow_results;
pub use flow_results::*;
#[path = "watch_progress.rs"]
mod watch_progress;

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use turso::{Builder, Connection, Database, params};

use crate::conn_gate::{ConnGate, ConnGuard};
use crate::error::StoreError;
use crate::migrations;

/// Runs a future's statements on a held [`ConnGuard`] as one transaction:
/// `BEGIN`, the future, then `COMMIT` on `Ok` or `ROLLBACK` on `Err`.
///
/// A macro rather than a function taking a closure on purpose. The terminal
/// write runs at the bottom of the daemon's deepest call chains, and a debug
/// build's engine frames already take most of a 2 MiB test-thread stack; the
/// future is polled directly from the calling method, with no helper future
/// wrapped around it. Cancel-safety does not depend on this macro:
/// whatever cuts the sequence short, the next [`Store::lock`] finds the open
/// transaction and rolls it back.
macro_rules! transact {
    ($conn:expr, $body:expr) => {{
        $conn.begin().await?;
        let result: Result<_, StoreError> = $body.await;
        $conn.end(result).await
    }};
}

/// Default `limit` for [`Store::list_requests_filtered`] when the caller
/// passes `None`.
pub const DEFAULT_REQUEST_LIST_LIMIT: u64 = 100;

/// Hard upper bound on the `limit` of [`Store::list_requests_filtered`]
/// and [`Store::list_model_jobs`]; a larger request is clamped, keeping
/// every list query bounded.
pub const MAX_LIST_LIMIT: u64 = 500;

/// The `request.outcome` the daemon's admin tripwire records for a refused
/// `admin.*` attempt (a forged or public-socket caller). Activity never hides
/// those rows, whatever `hide_probes` says.
pub const OUTCOME_ADMIN_DENIED: &str = "admin_denied";

/// Largest database file [`Store::open`] checks for structural damage at
/// boot. The check reads every page, so past this size it would hold up
/// daemon start; [`Store::check_integrity`] runs it on demand instead.
const BOOT_CHECK_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// Longest batch [`Store::fail_expired_requests`] finishes in one transaction.
pub const MAX_EXPIRY_BATCH: u32 = 64;

/// SQL predicate over a `request` row: its admission still stands.
///
/// A request snapshots the number of revocations that existed when it was
/// admitted (`authorization_revision`), and every revocation is numbered in
/// order (`grant.revoked_seq`). The admission is void once a grant the request
/// depends on was revoked after that snapshot — its own capability, or, for a
/// `flow.run` ticket, any `flow.step:` capability, since the steps a run
/// reaches are gated under those names. Re-granting does not restore it. A
/// revocation of anything else leaves the request alone: it never depended on
/// that grant. A revoked row without a sequence number counts as later than
/// every admission, so a gap can only invalidate, never authorize.
const ADMISSION_STANDS: &str = "request.authorization_revision IS NOT NULL AND NOT EXISTS (     SELECT 1 FROM \"grant\" g WHERE g.revoked_ts IS NOT NULL      AND (g.revoked_seq IS NULL OR g.revoked_seq > request.authorization_revision)      AND (g.capability = request.capability           OR (request.capability = 'flow.run' AND g.capability LIKE 'flow.step:%')))";

/// Fixed startup subsets; never interpolate caller-supplied SQL predicates.
#[derive(Clone, Copy)]
enum RecoveryRows {
    Queued,
    Stuck,
}

impl RecoveryRows {
    fn predicate(self) -> &'static str {
        match self {
            Self::Queued => "state = 'queued'",
            Self::Stuck => "state IN ('running','waiting_approval')",
        }
    }
}

/// Lifecycle state of a capability request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestState {
    /// Accepted, waiting for a worker.
    Queued,
    /// Currently executing.
    Running,
    /// Parked until a human approves or denies.
    WaitingApproval,
    /// Finished successfully.
    Done,
    /// Rejected by policy before running.
    Refused,
    /// Started but did not finish successfully.
    Failed,
}

impl RequestState {
    /// The value stored in the `request.state` column.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::WaitingApproval => "waiting_approval",
            Self::Done => "done",
            Self::Refused => "refused",
            Self::Failed => "failed",
        }
    }

    /// True for the states a request never leaves (`done`, `refused`,
    /// `failed`).
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Refused | Self::Failed)
    }

    /// Parses a `request.state` column value back into the enum.
    pub fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "waiting_approval" => Ok(Self::WaitingApproval),
            "done" => Ok(Self::Done),
            "refused" => Ok(Self::Refused),
            "failed" => Ok(Self::Failed),
            other => Err(StoreError::UnexpectedValue {
                column: "request.state",
                value: other.to_owned(),
            }),
        }
    }
}

/// The plane a request entered the daemon on, as recorded in
/// `request.ingress`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestIngress {
    /// The public listener: an agent, the CLI, anything that can reach the
    /// public socket. Also what a row written before the column existed
    /// reads as.
    Public,
    /// Submitted by the private administration plane on a human's behalf.
    Admin,
}

impl RequestIngress {
    /// The value stored in the `request.ingress` column.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Admin => "admin",
        }
    }

    /// Parses a `request.ingress` column value back into the enum.
    pub fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "public" => Ok(Self::Public),
            "admin" => Ok(Self::Admin),
            other => Err(StoreError::UnexpectedValue {
                column: "request.ingress",
                value: other.to_owned(),
            }),
        }
    }
}

/// Where a request entered the daemon and what the operating system said
/// about the connection it arrived on. Written once, by the INSERT that
/// creates the row. Attribution only: nothing is authorized by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestOrigin {
    /// The plane the request arrived on.
    pub ingress: RequestIngress,
    /// The peer's user id as the kernel reported it at accept; `None` where
    /// the platform or the listener has none to report.
    pub peer_uid: Option<u32>,
    /// The peer's process id as the kernel reported it at accept. It names
    /// a short-lived process and can be reused.
    pub peer_pid: Option<u32>,
    /// The client said it came through a session relay, in which case the
    /// peer is the relay process. Self-reported.
    pub relayed: bool,
}

impl RequestOrigin {
    /// A public request with no recorded peer: the legacy listener, and what
    /// a row written before the columns existed reads as.
    pub const PUBLIC: Self = Self {
        ingress: RequestIngress::Public,
        peer_uid: None,
        peer_pid: None,
        relayed: false,
    };

    /// A request the private administration plane submitted.
    pub const ADMIN: Self = Self {
        ingress: RequestIngress::Admin,
        peer_uid: None,
        peer_pid: None,
        relayed: false,
    };
}

/// Outcome recorded on an audit row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Policy let the request through.
    Allow,
    /// Policy rejected the request.
    Refuse,
    /// A human approved the request.
    Approve,
    /// A human denied the request.
    Deny,
    /// An approval expired unanswered.
    Timeout,
}

impl Decision {
    /// The value stored in the `audit.decision` column.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Refuse => "refuse",
            Self::Approve => "approve",
            Self::Deny => "deny",
            Self::Timeout => "timeout",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "allow" => Ok(Self::Allow),
            "refuse" => Ok(Self::Refuse),
            "approve" => Ok(Self::Approve),
            "deny" => Ok(Self::Deny),
            "timeout" => Ok(Self::Timeout),
            other => Err(StoreError::UnexpectedValue {
                column: "audit.decision",
                value: other.to_owned(),
            }),
        }
    }
}

/// Who made an audited decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor {
    /// The policy engine.
    Policy,
    /// A human operator.
    Human,
    /// The daemon itself (timeouts, restarts).
    System,
}

impl Actor {
    /// The value stored in the `audit.actor` column.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Human => "human",
            Self::System => "system",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "policy" => Ok(Self::Policy),
            "human" => Ok(Self::Human),
            "system" => Ok(Self::System),
            other => Err(StoreError::UnexpectedValue {
                column: "audit.actor",
                value: other.to_owned(),
            }),
        }
    }
}

/// One row of the `request` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestRow {
    /// Request id.
    pub id: String,
    /// Capability being requested.
    pub capability: String,
    /// Repository the caller acts on.
    pub repo: String,
    /// Agent that issued the request.
    pub caller_agent: String,
    /// Capability arguments as a JSON document.
    pub args_json: String,
    /// Caller-chosen key for in-flight deduplication, when one was sent.
    pub idempotency_key: Option<String>,
    /// Current lifecycle state.
    pub state: RequestState,
    /// Final outcome, once there is one.
    pub outcome: Option<String>,
    /// Unix seconds when the row was created.
    pub created_ts: i64,
    /// Unix seconds of the last state change.
    pub updated_ts: i64,
    /// Absolute admission deadline in Unix milliseconds; legacy/admin rows have none.
    pub expires_at_ms: Option<i64>,
    /// Whether the policy gate allowed queue placement.
    pub queue_authorized: bool,
    /// Monotonic retained grant-revocation count captured at authorization.
    pub authorization_revision: Option<i64>,
    /// Earliest next watch poll in Unix milliseconds; never extends admission expiry.
    pub resume_at_ms: Option<i64>,
    /// Where the request entered the daemon, and the peer it arrived from.
    pub origin: RequestOrigin,
}

/// How a pending approval was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalResolution {
    /// A human approved the operation.
    Approved,
    /// A human denied the operation.
    Denied,
    /// The approval expired unanswered.
    Timeout,
}

impl ApprovalResolution {
    /// The value stored in the `approval.resolution` column.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Timeout => "timeout",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "approved" => Ok(Self::Approved),
            "denied" => Ok(Self::Denied),
            "timeout" => Ok(Self::Timeout),
            other => Err(StoreError::UnexpectedValue {
                column: "approval.resolution",
                value: other.to_owned(),
            }),
        }
    }
}

/// One row of the `approval` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRow {
    /// Approval row id.
    pub id: i64,
    /// Request this approval gates.
    pub request_id: String,
    /// Capability awaiting approval.
    pub capability: String,
    /// Unix seconds when the approval was requested.
    pub requested_ts: i64,
    /// Unix seconds when it was resolved, once it was.
    pub resolved_ts: Option<i64>,
    /// How it was resolved, once it was.
    pub resolution: Option<ApprovalResolution>,
    /// Free-form context recorded at resolution.
    pub note: Option<String>,
}

/// One unresolved approval, joined with its request for the GUI's
/// pending list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingApproval {
    /// Request waiting on this approval.
    pub request_id: String,
    /// Capability awaiting approval.
    pub capability: String,
    /// Repository the request acts on.
    pub repo: String,
    /// Agent that issued the request.
    pub caller_agent: String,
    /// Unix seconds when the approval was requested.
    pub requested_ts: i64,
    /// The request's own capability (`flow.run` for a gated flow step).
    pub request_capability: String,
    /// The arguments the agent submitted, as the JSON document stored on
    /// the request row.
    pub args_json: String,
}

/// One row of the `grant` table — history included: a revoked grant
/// keeps its row with `revoked_ts` set, and a re-grant is a new row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRow {
    /// Grant row id.
    pub id: i64,
    /// Capability the grant covers.
    pub capability: String,
    /// Grant scope; only `global` exists today.
    pub scope: String,
    /// Unix seconds when the grant was recorded.
    pub granted_ts: i64,
    /// Unix seconds when the grant was revoked, once it was.
    pub revoked_ts: Option<i64>,
}

/// One row of the `caller` table — an observed agent+repo pair. An
/// advisory registry (attribution and GUI filters), never authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerRow {
    /// Agent name the caller self-reported.
    pub agent: String,
    /// Repository path the caller worked in.
    pub repo: String,
    /// Unix seconds when this pair was first observed.
    pub first_seen: i64,
    /// Unix seconds when this pair was last observed.
    pub last_seen: i64,
}

/// The audit row [`Store::finish_request`] appends alongside a terminal
/// state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditEntry<'a> {
    /// What was decided about (e.g. `execute`, `cancel`).
    pub action: &'a str,
    /// Outcome recorded on the row.
    pub decision: Decision,
    /// Who made the decision.
    pub actor: Actor,
    /// Free-form context (JSON by convention).
    pub detail: Option<&'a str>,
}

/// One change to the `grant` table, for the audited single-transaction
/// methods ([`Store::apply_grant_change_audited`],
/// [`Store::finish_request_with_grant_change`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantChange<'a> {
    /// Record a new active global grant for this capability.
    Add(&'a str),
    /// Revoke this capability's active grant; the row stays as history.
    Revoke(&'a str),
}

/// What an audited grant change did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantChangeOutcome {
    /// The grant table changed and its audit row committed with it.
    Applied,
    /// Nothing was written: an `Add` found an active grant already, or a
    /// `Revoke` found none.
    Unchanged,
}

/// One row of the `audit` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    /// Audit row id.
    pub id: i64,
    /// Request this row belongs to.
    pub request_id: String,
    /// What was decided about (e.g. `enqueue`, `auto_grant`).
    pub action: String,
    /// Outcome recorded on the row.
    pub decision: Decision,
    /// Who made the decision.
    pub actor: Actor,
    /// Free-form context (JSON by convention).
    pub detail: Option<String>,
    /// Unix seconds when the row was written.
    pub ts: i64,
}

/// One row of the `model_job` table: a download or a verification, with
/// where it got to.
///
/// `kind` is `download` or `verify`; `state` is `running`, `done`,
/// `failed` or `cancelled` — both are CHECK-constrained in the schema and
/// kept as strings here because the model layer, not the store, owns their
/// vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelJobRow {
    /// Job id, `job_<ulid>`.
    pub id: String,
    /// `download` or `verify`.
    pub kind: String,
    /// Registry id the job is about (`<vendor>/<file stem>`).
    pub model_id: String,
    /// Source URL, for a download.
    pub source: Option<String>,
    /// `running`, `done`, `failed` or `cancelled`.
    pub state: String,
    /// Bytes moved (a download) or hashed (a verification) so far.
    pub bytes_done: i64,
    /// Expected total, when it is known.
    pub bytes_total: Option<i64>,
    /// Verdict detail as JSON: the digest on success, cause and detail on
    /// failure.
    pub detail: Option<String>,
    /// Unix seconds when the job started.
    pub created_ts: i64,
    /// Unix seconds of the last progress or the verdict.
    pub updated_ts: i64,
}

/// Evidence kind whose `meta_json` carries the compression figures the
/// tokens-avoided odometer aggregates.
pub const EVIDENCE_KIND_LOG_COMPACT: &str = "log.compact";

/// One row of the `evidence` table, blob included.
///
/// `path` stays NULL for now: every row the daemon writes is blob-backed,
/// and path-backed evidence arrives with the retention plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRow {
    /// Evidence id, `ev_<ulid>`, minted by the daemon.
    pub id: String,
    /// Request the evidence belongs to.
    pub request_id: String,
    /// What the row is (`log.source`, `log.compact`, `log.summary`, ...);
    /// the vocabulary belongs to the services that write it.
    pub kind: String,
    /// The stored bytes, exactly as they were handed in.
    pub content: Vec<u8>,
    /// Lowercase hex sha256 of `content`.
    pub content_hash: String,
    /// Small kind-specific metadata as JSON text, when the writer left any.
    pub meta_json: Option<String>,
    /// Unix seconds when the row was written.
    pub ts: i64,
}

/// One `evidence` row without its blob: what the GUI lists.
///
/// `bytes` is the blob's length read with SQL `LENGTH`, so a listing
/// never pulls a 64 MiB log through the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceMeta {
    /// Evidence id, `ev_<ulid>`.
    pub id: String,
    /// Request the evidence belongs to.
    pub request_id: String,
    /// What the row is (`log.source`, `log.compact`, `log.summary`, ...).
    pub kind: String,
    /// Length of the stored blob in bytes.
    pub bytes: u64,
    /// Lowercase hex sha256 of the content.
    pub content_hash: String,
    /// Small kind-specific metadata as JSON text, when the writer left any.
    pub meta_json: Option<String>,
    /// Unix seconds when the row was written.
    pub ts: i64,
}

/// Aggregate over the `log.compact` evidence rows in a time window: what
/// the tokens-avoided odometer shows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CompressionStats {
    /// How many compactions happened in the window.
    pub compressions: u64,
    /// Total bytes of the sources that were compacted.
    pub source_bytes: u64,
    /// Total bytes the compact forms take.
    pub compact_bytes: u64,
    /// Estimated input tokens the compaction avoided.
    pub tokens_avoided_est: u64,
}

/// What one evidence prune pass removed: the retention window's report
/// for the evidence half.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EvidencePrune {
    /// Evidence rows deleted.
    pub rows: u64,
    /// Total length of the blobs those rows held.
    pub bytes: u64,
}

/// What one request prune pass removed, table by table.
///
/// An audit window prunes whole records, so the figures come from four
/// tables at once; the panel adds the evidence halves together and shows
/// one line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RequestPrune {
    /// `request` rows deleted.
    pub requests: u64,
    /// `audit` rows deleted with them.
    pub audit_rows: u64,
    /// `approval` rows deleted with them.
    pub approvals: u64,
    /// `evidence` rows deleted with them, the kept kind included — the
    /// verdict outlives the evidence window but not its own record.
    pub evidence_rows: u64,
    /// Total length of the blobs those evidence rows held.
    pub evidence_bytes: u64,
}

/// What a retention pass would remove, counted without removing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RetentionCensus {
    /// Rows the pass would remove at these cutoffs (evidence rows, then
    /// request records; an evidence row that goes with its request is
    /// counted once).
    pub eligible_rows: u64,
    /// Rows the windows could ever remove: all evidence rows plus all
    /// terminal requests.
    pub total_rows: u64,
}

/// One row of the `connector` table: a connector's configuration and its
/// last self-test verdict.
///
/// Secrets never live here: `base_url` and `username` are plain
/// configuration; the credential itself belongs to the OS keychain via
/// `pam_daemon`'s `SecretStore`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorRow {
    /// Connector id (`github`, `jenkins`, ...).
    pub id: String,
    /// Whether the connector is enabled.
    pub enabled: bool,
    /// Base URL, for connectors that need one (e.g. a self-hosted Jenkins).
    pub base_url: Option<String>,
    /// Username, for connectors whose auth needs one alongside a token.
    pub username: Option<String>,
    /// Outcome of the last self-test: `"passed"` or `"failed"`, once one
    /// ran.
    pub last_test_status: Option<String>,
    /// Free-form detail from the last self-test.
    pub last_test_detail: Option<String>,
    /// Unix seconds when the last self-test ran.
    pub last_test_ts: Option<i64>,
    /// Unix seconds of the last change to this row.
    pub updated_ts: i64,
}

/// A partial update to a [`ConnectorRow`]: a field left as `None` is left
/// untouched by [`Store::upsert_connector`].
///
/// `base_url` and `username` are `Option<Option<&str>>` so a patch can
/// distinguish "leave it" (`None`) from "clear it" (`Some(None)`) from
/// "set it" (`Some(Some(value))`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnectorPatch<'a> {
    /// Invalidate a verdict around a credential mutation outside this database.
    pub invalidate_test: bool,
    /// New `enabled` value, when given.
    pub enabled: Option<bool>,
    /// New `base_url`, when given; `Some(None)` clears it.
    pub base_url: Option<Option<&'a str>>,
    /// New `username`, when given; `Some(None)` clears it.
    pub username: Option<Option<&'a str>>,
}

/// Handle to the durable state database.
///
/// Async by design (the Turso engine drives its own I/O); the daemon
/// owns threading and task placement.
pub struct Store {
    /// Keeps the database itself alive alongside the connection.
    _db: Database,
    /// The one connection, behind the only lock that reaches it. turso
    /// refuses concurrent use of one connection outright
    /// (`Misuse("concurrent use forbidden")`), and the daemon drives this
    /// store from many tasks at once — executor, dispatcher, reaper, admin.
    /// Each method takes [`Self::lock`] for its statements; the transactional
    /// methods run their whole `BEGIN`..`COMMIT` window through
    /// [`ConnGuard::begin`]..[`ConnGuard::end`], and a call dropped inside one is rolled
    /// back before the next caller is handed the connection.
    gate: ConnGate,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

impl Store {
    /// Opens (creating if needed) the database at `path`.
    ///
    /// Creates the parent directory if missing, enables foreign keys,
    /// sets a busy timeout, and applies any pending migrations. WAL is
    /// the engine's native journal mode; nothing needs to switch it on.
    pub async fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|source| StoreError::CreateDir {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        // The boot check reads every page, so it is only run while that is
        // cheap; a larger file is checked on demand ([`Self::check_integrity`]).
        let check = std::fs::metadata(path).map_or(0, |meta| meta.len()) <= BOOT_CHECK_MAX_BYTES;
        let path = path.to_str().ok_or_else(|| StoreError::NonUtf8Path {
            path: path.to_path_buf(),
        })?;
        Self::init(Builder::new_local(path).build().await?, check).await
    }

    /// Opens a fresh in-memory database, for tests.
    pub async fn open_in_memory() -> Result<Self, StoreError> {
        Self::init(Builder::new_local(":memory:").build().await?, false).await
    }

    async fn init(db: Database, check: bool) -> Result<Self, StoreError> {
        let conn = db.connect()?;
        conn.execute("PRAGMA foreign_keys = ON", ()).await?;
        conn.execute("PRAGMA busy_timeout = 5000", ()).await?;
        if check {
            // Before migrating: a damaged file must be refused as it is,
            // not rewritten further.
            integrity_check(&conn).await?;
        } else {
            tracing::debug!("skipping the boot integrity check for this database");
        }
        migrations::run(&conn).await?;
        Ok(Self {
            _db: db,
            gate: ConnGate::new(conn),
        })
    }

    /// Exclusive use of the connection, guaranteed outside a transaction.
    /// Every statement in this crate goes through the guard it returns.
    pub(crate) async fn lock(&self) -> Result<ConnGuard<'_>, StoreError> {
        self.gate.lock().await
    }

    /// Runs the engine's structural check over the whole file and answers
    /// [`StoreError::Corrupt`] with what it found. [`Self::open`] runs the
    /// same check at boot for files up to 256 MiB; this is the on-demand
    /// form for larger ones (it reads every page under the connection lock,
    /// so it belongs behind a deliberate operator action, not on a timer).
    pub async fn check_integrity(&self) -> Result<(), StoreError> {
        let conn = self.lock().await?;
        integrity_check(&conn).await
    }

    /// The schema version currently recorded in the database.
    pub async fn schema_version(&self) -> Result<i64, StoreError> {
        let conn = self.lock().await?;
        migrations::current_version(&conn).await
    }

    /// Inserts a new request in the `queued` state.
    ///
    /// `idempotency_key` is the caller-chosen dedupe key from the request
    /// envelope, when one was sent.
    pub async fn insert_request(
        &self,
        id: &str,
        capability: &str,
        repo: &str,
        caller_agent: &str,
        args_json: &str,
        idempotency_key: Option<&str>,
    ) -> Result<(), StoreError> {
        self.insert_request_from(
            id,
            capability,
            repo,
            caller_agent,
            args_json,
            idempotency_key,
            &RequestOrigin::PUBLIC,
        )
        .await
    }

    /// [`Self::insert_request`] recording where the request entered the
    /// daemon, in the same INSERT.
    // One request row = one INSERT: every column the row needs at birth is an argument.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_request_from(
        &self,
        id: &str,
        capability: &str,
        repo: &str,
        caller_agent: &str,
        args_json: &str,
        idempotency_key: Option<&str>,
        origin: &RequestOrigin,
    ) -> Result<(), StoreError> {
        self.insert_request_in_state(
            id,
            capability,
            repo,
            caller_agent,
            args_json,
            idempotency_key,
            RequestState::Queued,
            None,
            origin,
        )
        .await
    }

    /// Inserts a request already executing outside the queue, such as an admin op.
    ///
    /// The initial `running` state is written by the same INSERT as the identity
    /// and arguments. A crash cannot expose an intermediate queued request to
    /// queue recovery. Duplicate IDs fail exactly as in [`Self::insert_request`].
    pub async fn insert_running_request(
        &self,
        id: &str,
        capability: &str,
        repo: &str,
        caller_agent: &str,
        args_json: &str,
        idempotency_key: Option<&str>,
    ) -> Result<(), StoreError> {
        self.insert_running_request_from(
            id,
            capability,
            repo,
            caller_agent,
            args_json,
            idempotency_key,
            &RequestOrigin::PUBLIC,
        )
        .await
    }

    /// [`Self::insert_running_request`] recording where the request entered
    /// the daemon, in the same INSERT.
    // One request row = one INSERT: every column the row needs at birth is an argument.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_running_request_from(
        &self,
        id: &str,
        capability: &str,
        repo: &str,
        caller_agent: &str,
        args_json: &str,
        idempotency_key: Option<&str>,
        origin: &RequestOrigin,
    ) -> Result<(), StoreError> {
        self.insert_request_in_state(
            id,
            capability,
            repo,
            caller_agent,
            args_json,
            idempotency_key,
            RequestState::Running,
            None,
            origin,
        )
        .await
    }

    /// Records pre-gate admission as running, with a durable absolute deadline
    /// and the grant-revocation revision captured atomically with insertion.
    // One request row = one INSERT: every column the row needs at birth is an argument.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_admitted_request(
        &self,
        id: &str,
        capability: &str,
        repo: &str,
        caller_agent: &str,
        args_json: &str,
        idempotency_key: Option<&str>,
        expires_at_ms: i64,
    ) -> Result<(), StoreError> {
        self.insert_admitted_request_from(
            id,
            capability,
            repo,
            caller_agent,
            args_json,
            idempotency_key,
            expires_at_ms,
            &RequestOrigin::PUBLIC,
        )
        .await
    }

    /// [`Self::insert_admitted_request`] recording where the request entered
    /// the daemon — the plane and the kernel's view of the peer — in the same
    /// INSERT, so no admitted row exists without it.
    // One request row = one INSERT: every column the row needs at birth is an argument.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_admitted_request_from(
        &self,
        id: &str,
        capability: &str,
        repo: &str,
        caller_agent: &str,
        args_json: &str,
        idempotency_key: Option<&str>,
        expires_at_ms: i64,
        origin: &RequestOrigin,
    ) -> Result<(), StoreError> {
        self.insert_request_in_state(
            id,
            capability,
            repo,
            caller_agent,
            args_json,
            idempotency_key,
            RequestState::Running,
            Some(expires_at_ms),
            origin,
        )
        .await
    }

    /// Atomically records post-gate authorization without extending the deadline
    /// or refreshing the admission revision. Revocation during gating/approval
    /// invalidates this admission even when the capability was later re-granted.
    pub async fn authorize_queued_request(
        &self,
        id: &str,
        repo: &str,
        now_ms: i64,
    ) -> Result<bool, StoreError> {
        let conn = self.lock().await?;
        let changed = conn
            .execute(
                &format!(
                    "UPDATE request SET state = 'queued', queue_authorized = 1, updated_ts = ?1
             WHERE id = ?2 AND repo = ?3 AND queue_authorized = 0
             AND state IN ('running','waiting_approval') AND expires_at_ms > ?4
             AND {ADMISSION_STANDS}"
                ),
                params![now_ts(), id, repo, now_ms],
            )
            .await?;
        Ok(changed == 1)
    }

    /// Restores only a safe journaled flow under its original admission and expiry.
    /// The startup lock must be held; runtime authorization is checked again on dispatch.
    pub async fn requeue_journaled_flow(&self, id: &str, now_ms: i64) -> Result<bool, StoreError> {
        let conn = self.lock().await?;
        let changed = conn.execute(
            &format!(
                "UPDATE request SET state = 'queued', updated_ts = ?1 WHERE id = ?2
             AND capability = 'flow.run' AND state IN ('running','waiting_approval')
             AND queue_authorized = 1 AND expires_at_ms > ?3
             AND {ADMISSION_STANDS}
             AND EXISTS (SELECT 1 FROM flow_journal WHERE request_id = ?2 AND state IN ('ready','completed'))"
            ),
            params![now_ts(), id, now_ms],
        ).await?;
        Ok(changed == 1)
    }

    /// Starts only a still-queued authorized request before its original expiry.
    /// A cancellation or terminal transition cannot be resurrected by a stale lane.
    pub async fn start_queued_request(&self, id: &str, now_ms: i64) -> Result<bool, StoreError> {
        let conn = self.lock().await?;
        let changed = conn
            .execute(
                &format!(
                    "UPDATE request SET state = 'running', resume_at_ms = NULL, updated_ts = ?1 WHERE id = ?2
             AND resume_at_ms IS NULL AND state = 'queued' AND queue_authorized = 1 AND expires_at_ms > ?3
             AND {ADMISSION_STANDS}"
                ),
                params![now_ts(), id, now_ms],
            )
            .await?;
        Ok(changed == 1)
    }

    /// Monotonic revision while revoked grant rows are retained: how many
    /// revocations exist, of any capability. A request snapshots this at
    /// admission. Comparing the snapshot to this figure by equality voids
    /// every older request on any revocation; prefer
    /// [`Self::request_authorization_current`], which voids only the requests
    /// that depended on the revoked grant.
    pub async fn grant_revocation_revision(&self) -> Result<i64, StoreError> {
        let conn = self.lock().await?;
        let mut rows = conn
            .query(
                "SELECT COUNT(*) FROM \"grant\" WHERE revoked_ts IS NOT NULL",
                (),
            )
            .await?;
        let row = rows.next().await?.ok_or_else(|| StoreError::NotFound {
            table: "grant",
            id: "revocation revision".into(),
        })?;
        Ok(row.get(0)?)
    }

    /// True while `request_id`'s admission still stands: it captured a
    /// revision, and no grant it depends on has been revoked since (its own
    /// capability; for a `flow.run` ticket also any `flow.step:` capability).
    /// False for a missing request, a row admitted without a revision, or
    /// once a relevant revocation landed — re-granting never restores it.
    ///
    /// This is the scoped replacement for comparing
    /// `authorization_revision` with [`Self::grant_revocation_revision`].
    pub async fn request_authorization_current(
        &self,
        request_id: &str,
    ) -> Result<bool, StoreError> {
        let conn = self.lock().await?;
        let mut rows = conn
            .query(
                &format!("SELECT 1 FROM request WHERE id = ?1 AND {ADMISSION_STANDS}"),
                params![request_id],
            )
            .await?;
        Ok(rows.next().await?.is_some())
    }

    /// How many revocations a request for `capability` depends on: the same
    /// relevance rule as [`Self::request_authorization_current`], as a
    /// monotonic counter. A long-running watcher stamps it once and compares
    /// later; the figure moves only when a grant that capability depends on
    /// is revoked.
    pub async fn grant_revocation_revision_for(&self, capability: &str) -> Result<i64, StoreError> {
        let conn = self.lock().await?;
        let mut rows = conn
            .query(
                "SELECT COUNT(*) FROM \"grant\" g WHERE g.revoked_ts IS NOT NULL
                 AND (g.capability = ?1 OR (?1 = 'flow.run' AND g.capability LIKE 'flow.step:%'))",
                params![capability],
            )
            .await?;
        let row = rows.next().await?.ok_or_else(|| StoreError::NotFound {
            table: "grant",
            id: "scoped revocation revision".into(),
        })?;
        Ok(row.get(0)?)
    }

    /// Count and UTF-8 bytes of retained identity/argument fields for active admissions.
    ///
    /// Every in-flight row with a deadline counts, expired or not. A row
    /// stranded past its deadline therefore holds its slot until something
    /// finishes it; [`Self::admission_usage_at`] counts only live admissions.
    pub async fn admission_usage(&self) -> Result<(u64, u64), StoreError> {
        self.admission_usage_where("").await
    }

    /// [`Self::admission_usage`] over the admissions whose deadline is still
    /// ahead of `now_ms`. A request past its deadline can no longer be
    /// authorized, started, or woken, so it must not count against the
    /// admission cap; [`Self::fail_expired_requests`] gives such rows their
    /// terminal state.
    pub async fn admission_usage_at(&self, now_ms: i64) -> Result<(u64, u64), StoreError> {
        // An integer of ours, not caller text: safe to place in the SQL.
        self.admission_usage_where(&format!(" AND expires_at_ms > {now_ms}"))
            .await
    }

    async fn admission_usage_where(&self, extra: &str) -> Result<(u64, u64), StoreError> {
        let conn = self.lock().await?;
        // One SUM per field, added here: a single `SUM(a + b + ...)` nests
        // deeply enough to cost the engine about a megabyte of stack in a
        // debug build, and admission runs this under the daemon's handlers.
        let mut rows = conn
            .query(
                &format!(
                    "SELECT COUNT(*), COALESCE(SUM(LENGTH(CAST(id AS BLOB))), 0),
             COALESCE(SUM(LENGTH(CAST(capability AS BLOB))), 0),
             COALESCE(SUM(LENGTH(CAST(repo AS BLOB))), 0),
             COALESCE(SUM(LENGTH(CAST(caller_agent AS BLOB))), 0),
             COALESCE(SUM(LENGTH(CAST(args_json AS BLOB))), 0),
             COALESCE(SUM(LENGTH(CAST(idempotency_key AS BLOB))), 0)
             FROM request WHERE expires_at_ms IS NOT NULL
             AND state IN ('queued','running','waiting_approval'){extra}"
                ),
                (),
            )
            .await?;
        let row = rows.next().await?.ok_or_else(|| StoreError::NotFound {
            table: "request",
            id: "admission usage".into(),
        })?;
        let mut bytes = 0_u64;
        for column in 1..=6 {
            bytes =
                bytes.saturating_add(u64::try_from(row.get::<i64>(column)?).unwrap_or(u64::MAX));
        }
        Ok((u64::try_from(row.get::<i64>(0)?).unwrap_or(u64::MAX), bytes))
    }

    /// Finishes in-flight requests whose admission deadline passed at or
    /// before `now_ms`: state `failed`, `outcome`, and one `audit` row each,
    /// oldest deadline first, at most `limit` (clamped into
    /// `1..=`[`MAX_EXPIRY_BATCH`]) in one transaction. Returns the ids this
    /// call finished; call again while it returns `limit` ids.
    ///
    /// Every row goes through the same statements as
    /// [`Self::finish_request`], so a flow with an unresolved effect is still
    /// sealed as `flow_effect_uncertain` rather than hidden behind `outcome`,
    /// and a row another finisher reached first is left alone. The caller
    /// decides when a row is stranded: pass a `now_ms` far enough behind the
    /// clock that a handler still running past its deadline has had time to
    /// write its own verdict.
    pub async fn fail_expired_requests(
        &self,
        now_ms: i64,
        limit: u32,
        outcome: &str,
        audit: AuditEntry<'_>,
    ) -> Result<Vec<String>, StoreError> {
        let limit = limit.clamp(1, MAX_EXPIRY_BATCH);
        let conn = self.lock().await?;
        transact!(conn, async {
            let mut rows = conn
                .query(
                    &format!(
                        "SELECT id FROM request
                         WHERE state IN ('queued','running','waiting_approval')
                           AND expires_at_ms IS NOT NULL AND expires_at_ms <= ?1
                           AND LENGTH(CAST(id AS BLOB)) <= 128
                         ORDER BY expires_at_ms, id LIMIT {limit}"
                    ),
                    params![now_ms],
                )
                .await?;
            let mut ids: Vec<String> = Vec::new();
            while let Some(row) = rows.next().await? {
                ids.push(row.get(0)?);
            }
            drop(rows);
            let mut finished = Vec::with_capacity(ids.len());
            for id in ids {
                if Self::finish_request_in_txn(
                    &conn,
                    &id,
                    RequestState::Failed,
                    Some(outcome),
                    audit,
                )
                .await?
                {
                    finished.push(id);
                }
            }
            Ok(finished)
        })
    }

    /// Scope a dedupe key to the entire authorized operation shape, including expiry.
    pub async fn find_admitted_by_shape(
        &self,
        capability: &str,
        repo: &str,
        args_json: &str,
        key: Option<&str>,
        now_ms: i64,
    ) -> Result<Option<RequestRow>, StoreError> {
        let conn = self.lock().await?;
        let mut rows = conn
            .query(
                &format!(
                    "SELECT {} FROM request WHERE capability = ?1 AND repo = ?2 AND args_json = ?3
             AND (?4 IS NULL OR idempotency_key = ?4) AND expires_at_ms > ?5
             AND state IN ('queued','running','waiting_approval') ORDER BY created_ts, id LIMIT 1",
                    Self::REQUEST_COLUMNS
                ),
                params![capability, repo, args_json, key, now_ms],
            )
            .await?;
        rows.next()
            .await?
            .map(|row| Self::parse_request_row(&row))
            .transpose()
    }

    // Keep the six public insertion fields intact; only the initial state differs.
    // One request row = one INSERT: the arity is the row's column count, not a design choice.
    #[allow(clippy::too_many_arguments)]
    async fn insert_request_in_state(
        &self,
        id: &str,
        capability: &str,
        repo: &str,
        caller_agent: &str,
        args_json: &str,
        idempotency_key: Option<&str>,
        state: RequestState,
        expires_at_ms: Option<i64>,
        origin: &RequestOrigin,
    ) -> Result<(), StoreError> {
        let conn = self.lock().await?;
        let now = now_ts();
        conn.execute(
            "INSERT INTO request
                     (id, capability, repo, caller_agent, args_json,
                      idempotency_key, state, outcome, created_ts, updated_ts, expires_at_ms,
                      authorization_revision, ingress, peer_uid, peer_pid, relayed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, ?8, ?9,
                      CASE WHEN ?9 IS NOT NULL THEN
                        (SELECT COUNT(*) FROM \"grant\" WHERE revoked_ts IS NOT NULL)
                      ELSE NULL END,
                      ?10, ?11, ?12, ?13)",
            params![
                id,
                capability,
                repo,
                caller_agent,
                args_json,
                idempotency_key,
                state.as_str(),
                now,
                expires_at_ms,
                origin.ingress.as_str(),
                origin.peer_uid.map(i64::from),
                origin.peer_pid.map(i64::from),
                i64::from(origin.relayed)
            ],
        )
        .await?;
        Ok(())
    }

    /// The `request` column list every row query selects, in the order
    /// [`Self::parse_request_row`] expects.
    const REQUEST_COLUMNS: &'static str = "id, capability, repo, caller_agent, args_json,
         idempotency_key, state, outcome, created_ts, updated_ts, expires_at_ms, queue_authorized, authorization_revision, resume_at_ms,
         ingress, peer_uid, peer_pid, relayed";

    /// Builds a [`RequestRow`] from a row selected with
    /// [`Self::REQUEST_COLUMNS`].
    fn parse_request_row(row: &turso::Row) -> Result<RequestRow, StoreError> {
        let state: String = row.get(6)?;
        Ok(RequestRow {
            id: row.get(0)?,
            capability: row.get(1)?,
            repo: row.get(2)?,
            caller_agent: row.get(3)?,
            args_json: row.get(4)?,
            idempotency_key: row.get(5)?,
            state: RequestState::parse(&state)?,
            outcome: row.get(7)?,
            created_ts: row.get(8)?,
            updated_ts: row.get(9)?,
            expires_at_ms: row.get(10)?,
            queue_authorized: row.get::<i64>(11)? == 1,
            authorization_revision: row.get(12)?,
            resume_at_ms: row.get(13)?,
            origin: Self::parse_request_origin(row, 14)?,
        })
    }

    /// The four origin columns starting at `first`, in
    /// [`Self::REQUEST_COLUMNS`] order. A stored id outside `u32` (nothing
    /// this code writes) reads as unrecorded rather than as another id.
    fn parse_request_origin(row: &turso::Row, first: usize) -> Result<RequestOrigin, StoreError> {
        let ingress: String = row.get(first)?;
        let narrow = |value: Option<i64>| value.and_then(|value| u32::try_from(value).ok());
        Ok(RequestOrigin {
            ingress: RequestIngress::parse(&ingress)?,
            peer_uid: narrow(row.get(first + 1)?),
            peer_pid: narrow(row.get(first + 2)?),
            relayed: row.get::<i64>(first + 3)? == 1,
        })
    }

    /// Reads one request by id, or `None` if it does not exist.
    pub async fn get_request(&self, id: &str) -> Result<Option<RequestRow>, StoreError> {
        let conn = self.lock().await?;
        let mut rows = conn
            .query(
                &format!(
                    "SELECT {} FROM request WHERE id = ?1",
                    Self::REQUEST_COLUMNS
                ),
                params![id],
            )
            .await?;
        match rows.next().await? {
            Some(row) => Ok(Some(Self::parse_request_row(&row)?)),
            None => Ok(None),
        }
    }

    /// Reads every `queued` request. Intended for bounded test fixtures;
    /// startup recovery must use [`Self::queued_recovery_page`] instead.
    pub async fn list_queued_ordered(&self) -> Result<Vec<RequestRow>, StoreError> {
        let conn = self.lock().await?;
        let mut rows = conn
            .query(
                &format!(
                    "SELECT {} FROM request
                     WHERE state = 'queued' ORDER BY created_ts, id",
                    Self::REQUEST_COLUMNS
                ),
                (),
            )
            .await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            out.push(Self::parse_request_row(&row)?);
        }
        Ok(out)
    }

    /// Reads the next recovery page in `(created_ts, id)` order, strictly after
    /// `after`. A page contains at most 16 rows and `maximum_bytes` selected text
    /// bytes, clamped to the queue's absolute 8 MiB ceiling.
    ///
    /// SQL checks byte lengths before returning even an identifier to Rust.
    /// `None` means an oversized legacy row was encountered; no payload from that
    /// page is read. `Some([])` means recovery is complete. The caller must stop
    /// startup on `None`, leaving backup/repair of the legacy database to its
    /// operator. Silently skipping such a row would conceal retained work.
    pub async fn queued_recovery_page(
        &self,
        after: Option<(i64, &str)>,
        maximum_bytes: u64,
    ) -> Result<Option<Vec<RequestRow>>, StoreError> {
        self.recovery_page(RecoveryRows::Queued, after, maximum_bytes)
            .await
    }

    /// Reads a bounded page of `running` / `waiting_approval` rows using the
    /// same ordering and byte guards as [`Self::queued_recovery_page`].
    /// `None` requires an explicit startup failure and operator backup/repair.
    pub async fn stuck_recovery_page(
        &self,
        after: Option<(i64, &str)>,
        maximum_bytes: u64,
    ) -> Result<Option<Vec<RequestRow>>, StoreError> {
        self.recovery_page(RecoveryRows::Stuck, after, maximum_bytes)
            .await
    }

    async fn recovery_page(
        &self,
        subset: RecoveryRows,
        after: Option<(i64, &str)>,
        maximum_bytes: u64,
    ) -> Result<Option<Vec<RequestRow>>, StoreError> {
        let conn = self.lock().await?;
        let maximum = i64::try_from(maximum_bytes.min(8 * 1024 * 1024)).unwrap_or(0);
        let Some(ids) = Self::recovery_ids(&conn, subset, after, maximum).await? else {
            return Ok(None);
        };
        let mut page = Vec::with_capacity(ids.len());
        for id in ids {
            // Keep the SQL bound at the payload query too. The same connection
            // mutex covers both reads; no local writer can enlarge a row between
            // the metadata pass and materialization. Each text column is
            // withheld by SQL when it alone exceeds the bound, and the row's
            // total is checked before any of it is parsed.
            let mut rows = conn
                .query(
                    &format!(
                        "SELECT {}, {} FROM request WHERE id = ?1 AND ({})",
                        Self::RECOVERY_GUARDED_COLUMNS,
                        Self::RECOVERY_LENGTH_COLUMNS,
                        subset.predicate(),
                    ),
                    params![id, maximum],
                )
                .await?;
            let Some(row) = rows.next().await? else {
                return Ok(None);
            };
            match Self::recovery_row_bytes(&row, Self::RECOVERY_GUARDED_COUNT)? {
                Some(size) if size <= maximum => {}
                _ => return Ok(None),
            }
            page.push(Self::parse_request_row(&row)?);
        }
        Ok(Some(page))
    }

    /// The byte length of every text field a recovery row carries, one
    /// column each. Nullable legacy outcome/key included; `CAST AS BLOB`
    /// counts UTF-8 bytes, not characters or a prefix before NUL.
    ///
    /// Separate columns, added up in Rust by [`Self::recovery_row_bytes`],
    /// rather than one `a + b + ...` in SQL: the engine translates an
    /// expression recursively with one very large frame per level in a debug
    /// build, and an eight-term sum inside a comparison was deep enough to
    /// take the daemon's boot recovery to within a few kilobytes of a 2 MiB
    /// thread stack.
    const RECOVERY_LENGTH_COLUMNS: &'static str = "LENGTH(CAST(id AS BLOB)), \
         LENGTH(CAST(capability AS BLOB)), LENGTH(CAST(repo AS BLOB)), \
         LENGTH(CAST(caller_agent AS BLOB)), LENGTH(CAST(args_json AS BLOB)), \
         LENGTH(CAST(state AS BLOB)), COALESCE(LENGTH(CAST(idempotency_key AS BLOB)), 0), \
         COALESCE(LENGTH(CAST(outcome AS BLOB)), 0)";

    /// How many length columns [`Self::RECOVERY_LENGTH_COLUMNS`] selects.
    const RECOVERY_LENGTH_COUNT: usize = 8;

    /// [`Self::REQUEST_COLUMNS`] in the same order, with every text column
    /// replaced by NULL when it alone is longer than `?2`, so an oversized
    /// legacy value is never handed to Rust.
    const RECOVERY_GUARDED_COLUMNS: &'static str = "\
         CASE WHEN LENGTH(CAST(id AS BLOB)) <= ?2 THEN id END, \
         CASE WHEN LENGTH(CAST(capability AS BLOB)) <= ?2 THEN capability END, \
         CASE WHEN LENGTH(CAST(repo AS BLOB)) <= ?2 THEN repo END, \
         CASE WHEN LENGTH(CAST(caller_agent AS BLOB)) <= ?2 THEN caller_agent END, \
         CASE WHEN LENGTH(CAST(args_json AS BLOB)) <= ?2 THEN args_json END, \
         CASE WHEN LENGTH(CAST(idempotency_key AS BLOB)) <= ?2 THEN idempotency_key END, \
         CASE WHEN LENGTH(CAST(state AS BLOB)) <= ?2 THEN state END, \
         CASE WHEN LENGTH(CAST(outcome AS BLOB)) <= ?2 THEN outcome END, \
         created_ts, updated_ts, expires_at_ms, queue_authorized, authorization_revision, \
         resume_at_ms, ingress, peer_uid, peer_pid, relayed";

    /// How many columns [`Self::RECOVERY_GUARDED_COLUMNS`] selects: the
    /// index of the first length column that follows them.
    const RECOVERY_GUARDED_COUNT: usize = 18;

    /// Adds up the length columns starting at `first`. `None` when a length
    /// is negative: the row is refused, never guessed at.
    fn recovery_row_bytes(row: &turso::Row, first: usize) -> Result<Option<i64>, StoreError> {
        let mut size = 0_i64;
        for column in first..first + Self::RECOVERY_LENGTH_COUNT {
            let length = row.get::<i64>(column)?;
            if length < 0 {
                return Ok(None);
            }
            size = size.saturating_add(length);
        }
        Ok(Some(size))
    }

    /// Metadata-only page; `conn` is the page reader's locked connection.
    /// The identifier is withheld by SQL when it alone exceeds the bound,
    /// and a row whose total exceeds it stops the page before the
    /// identifier is read.
    async fn recovery_ids(
        conn: &Connection,
        subset: RecoveryRows,
        after: Option<(i64, &str)>,
        maximum: i64,
    ) -> Result<Option<Vec<String>>, StoreError> {
        let mut rows = conn
            .query(
                &format!(
                    "SELECT CASE WHEN LENGTH(CAST(id AS BLOB)) <= ?3 THEN id END, {lengths}
                 FROM request WHERE ({predicate})
                 AND (?1 IS NULL OR created_ts > ?1 OR (created_ts = ?1 AND id > ?2))
                 ORDER BY created_ts, id LIMIT 16",
                    lengths = Self::RECOVERY_LENGTH_COLUMNS,
                    predicate = subset.predicate(),
                ),
                params![after.map(|(ts, _)| ts), after.map(|(_, id)| id), maximum],
            )
            .await?;
        let mut ids = Vec::new();
        let mut bytes = 0_i64;
        while let Some(row) = rows.next().await? {
            let Some(size) = Self::recovery_row_bytes(&row, 1)? else {
                return Ok(None);
            };
            if size > maximum {
                return Ok(None);
            }
            if bytes.saturating_add(size) > maximum {
                break;
            }
            let Some(id) = row.get::<Option<String>>(0)? else {
                return Ok(None);
            };
            bytes += size;
            ids.push(id);
        }
        Ok(Some(ids))
    }

    /// Moves a request to a **non-terminal** `state`, recording `outcome`
    /// and bumping `updated_ts`. Errors if the request does not exist.
    ///
    /// # Invariant: terminal transitions go through `finish_request`
    ///
    /// Every transition into a terminal state (`done`, `refused`,
    /// `failed`) must go through [`Self::finish_request`], which writes
    /// the state and its audit row in one transaction — every terminal
    /// state gets its own audit row, with no crash window in between and
    /// no silent paths. A terminal `state` here is refused with
    /// [`StoreError::TerminalTransition`] before any write, in every
    /// build.
    ///
    /// # Invariant: terminal states are absorbing
    ///
    /// The `UPDATE` itself only matches an in-flight row. A request that
    /// already finished — cancelled, reaped, or timed out while its caller
    /// was parked — keeps its verdict and its cause: the call fails with
    /// [`StoreError::AlreadyTerminal`] and writes nothing, so a late
    /// approval or wake-up can never bring a finished request back to life.
    pub async fn update_request_state(
        &self,
        id: &str,
        state: RequestState,
        outcome: Option<&str>,
    ) -> Result<(), StoreError> {
        if state.is_terminal() {
            return Err(StoreError::TerminalTransition {
                state: state.as_str(),
            });
        }
        let conn = self.lock().await?;
        let changed = conn
            .execute(
                "UPDATE request SET state = ?2, outcome = ?3, updated_ts = ?4
                 WHERE id = ?1 AND state IN ('queued','running','waiting_approval')",
                params![id, state.as_str(), outcome, now_ts()],
            )
            .await?;
        if changed == 0 {
            return Err(Self::missing_or_terminal(&conn, id).await?);
        }
        Ok(())
    }

    /// Why an in-flight-only write matched nothing: the request finished
    /// already, or was never there.
    async fn missing_or_terminal(conn: &Connection, id: &str) -> Result<StoreError, StoreError> {
        let mut rows = conn
            .query("SELECT 1 FROM request WHERE id = ?1", params![id])
            .await?;
        Ok(match rows.next().await? {
            Some(_) => StoreError::AlreadyTerminal { id: id.to_owned() },
            None => StoreError::NotFound {
                table: "request",
                id: id.to_owned(),
            },
        })
    }

    /// Moves a request into terminal `state`, recording `outcome` and
    /// appending its `audit` row — both in **one transaction**, so no
    /// crash or interleaving can leave a terminal request without an
    /// audit row. This is the single choke point for terminal
    /// transitions (see [`Self::update_request_state`]).
    ///
    /// Returns `true` when this call performed the transition. A request
    /// that is **already terminal** is left untouched and returns
    /// `false` — the idempotent guard against double-finish races
    /// (reaper vs executor): the first finisher wins, the second no-ops
    /// and writes no duplicate audit row. A missing request errors with
    /// [`StoreError::NotFound`]; a non-terminal `state` errors with
    /// [`StoreError::NotTerminal`].
    pub async fn finish_request(
        &self,
        id: &str,
        state: RequestState,
        outcome: Option<&str>,
        audit: AuditEntry<'_>,
    ) -> Result<bool, StoreError> {
        if !state.is_terminal() {
            return Err(StoreError::NotTerminal {
                state: state.as_str(),
            });
        }
        let conn = self.lock().await?;
        // COMMIT on both `Ok` outcomes: the no-op path wrote nothing of
        // its own, so committing it is free and keeps one exit path.
        transact!(
            conn,
            Self::finish_request_in_txn(&conn, id, state, outcome, audit)
        )
    }

    /// The statements inside [`Self::finish_request`]'s transaction.
    async fn finish_request_in_txn(
        conn: &Connection,
        id: &str,
        state: RequestState,
        outcome: Option<&str>,
        audit: AuditEntry<'_>,
    ) -> Result<bool, StoreError> {
        let uncertain = Self::terminal_flow_uncertainty_locked(conn, id).await?;
        let uncertainty_detail = uncertain.then(|| {
            serde_json::json!({
                "cause": "flow_effect_uncertain",
                "requested_state": state.as_str(),
                "requested_cause": outcome,
                "requested_decision": audit.decision.as_str(),
                "requested_detail": audit.detail,
                "reconciliation_required": true,
            })
            .to_string()
        });
        let (state, outcome, audit) = if uncertain {
            (
                RequestState::Failed,
                Some("flow_effect_uncertain"),
                AuditEntry {
                    decision: Decision::Refuse,
                    detail: uncertainty_detail.as_deref(),
                    ..audit
                },
            )
        } else {
            (state, outcome, audit)
        };
        let changed = conn
            .execute(
                "UPDATE request SET state = ?2, outcome = ?3, updated_ts = ?4
                 WHERE id = ?1 AND state IN ('queued','running','waiting_approval')",
                params![id, state.as_str(), outcome, now_ts()],
            )
            .await?;
        if changed == 0 {
            // Nothing matched: either the row is already terminal (the
            // idempotent no-op) or it does not exist at all.
            let mut rows = conn
                .query("SELECT 1 FROM request WHERE id = ?1", params![id])
                .await?;
            return match rows.next().await? {
                Some(_) => Ok(false),
                None => Err(StoreError::NotFound {
                    table: "request",
                    id: id.to_owned(),
                }),
            };
        }
        conn.execute(
            "INSERT INTO audit (request_id, action, decision, actor, detail, ts)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                id,
                audit.action,
                audit.decision.as_str(),
                audit.actor.as_str(),
                audit.detail,
                now_ts()
            ],
        )
        .await?;
        Ok(true)
    }

    /// `conn` is the caller's locked connection, inside its terminal transaction. Seal an
    /// unresolved effect before any terminal writer can hide it behind success,
    /// cancellation, or a deadline. A terminal row remains an idempotent no-op.
    async fn terminal_flow_uncertainty_locked(
        conn: &Connection,
        id: &str,
    ) -> Result<bool, StoreError> {
        let landing_intent = Self::landing_prepared_intent_locked(conn, id).await?;
        conn
            .execute(
                "UPDATE flow_journal SET state='uncertain',revision=revision+1
                 WHERE request_id=?1 AND (state='prepared' OR (state='ready' AND ?2=1)) AND effectful=1
                   AND EXISTS(SELECT 1 FROM request WHERE id=?1
                     AND state IN ('queued','running','waiting_approval'))",
                params![id, i64::from(landing_intent)],
            )
            .await?;
        let mut rows = conn
            .query(
                "SELECT 1 FROM flow_journal j JOIN request r ON r.id=j.request_id
                 WHERE j.request_id=?1 AND j.state='uncertain'
                   AND r.state IN ('queued','running','waiting_approval')",
                params![id],
            )
            .await?;
        Ok(rows.next().await?.is_some())
    }

    /// Ids of terminal requests with **no** audit row whose action is in
    /// `terminal_actions` — the every-terminal-state-is-audited
    /// invariant's violation query, oldest first. Empty means the
    /// invariant holds; exposed for the invariant tests and the GUI's
    /// health view. The daemon supplies its terminal action names
    /// (`pam_daemon`'s `TERMINAL_ACTIONS`).
    pub async fn terminal_requests_missing_audit(
        &self,
        terminal_actions: &[&str],
    ) -> Result<Vec<String>, StoreError> {
        let conn = self.lock().await?;
        let sql = if terminal_actions.is_empty() {
            // No action can match, so every terminal request is missing.
            "SELECT id FROM request
             WHERE state IN ('done','refused','failed')
             ORDER BY created_ts, id"
                .to_owned()
        } else {
            let placeholders: Vec<String> = (1..=terminal_actions.len())
                .map(|i| format!("?{i}"))
                .collect();
            format!(
                "SELECT r.id FROM request r
                 WHERE r.state IN ('done','refused','failed')
                   AND NOT EXISTS (
                       SELECT 1 FROM audit a
                       WHERE a.request_id = r.id AND a.action IN ({}))
                 ORDER BY r.created_ts, r.id",
                placeholders.join(", ")
            )
        };
        let actions: Vec<String> = terminal_actions.iter().map(|a| (*a).to_owned()).collect();
        let mut rows = conn.query(&sql, actions).await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            out.push(row.get(0)?);
        }
        Ok(out)
    }

    /// Counts the in-flight requests (state `queued`, `running`, or
    /// `waiting_approval`). Feeds the `status` capability's
    /// `active_requests` figure.
    pub async fn count_inflight(&self) -> Result<i64, StoreError> {
        let conn = self.lock().await?;
        let mut rows = conn
            .query(
                "SELECT COUNT(*) FROM request
                 WHERE state IN ('queued','running','waiting_approval')",
                (),
            )
            .await?;
        match rows.next().await? {
            Some(row) => Ok(row.get(0)?),
            None => Ok(0),
        }
    }

    /// Appends one audit row. Audit rows are never updated or deleted by
    /// normal operations.
    pub async fn append_audit(
        &self,
        request_id: &str,
        action: &str,
        decision: Decision,
        actor: Actor,
        detail: Option<&str>,
    ) -> Result<(), StoreError> {
        let conn = self.lock().await?;
        conn.execute(
            "INSERT INTO audit (request_id, action, decision, actor, detail, ts)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                request_id,
                action,
                decision.as_str(),
                actor.as_str(),
                detail,
                now_ts()
            ],
        )
        .await?;
        Ok(())
    }

    /// Reads every audit row for one request, oldest first.
    pub async fn audit_for_request(&self, request_id: &str) -> Result<Vec<AuditRow>, StoreError> {
        let conn = self.lock().await?;
        let mut rows = conn
            .query(
                "SELECT id, request_id, action, decision, actor, detail, ts
                 FROM audit WHERE request_id = ?1 ORDER BY id",
                params![request_id],
            )
            .await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            let decision: String = row.get(3)?;
            let actor: String = row.get(4)?;
            out.push(AuditRow {
                id: row.get(0)?,
                request_id: row.get(1)?,
                action: row.get(2)?,
                decision: Decision::parse(&decision)?,
                actor: Actor::parse(&actor)?,
                detail: row.get(5)?,
                ts: row.get(6)?,
            });
        }
        Ok(out)
    }

    /// True when `capability` currently has an active global grant
    /// (a `grant` row whose `revoked_ts` is NULL).
    pub async fn active_grant(&self, capability: &str) -> Result<bool, StoreError> {
        let conn = self.lock().await?;
        let mut rows = conn
            .query(
                "SELECT 1 FROM \"grant\"
                 WHERE capability = ?1 AND revoked_ts IS NULL LIMIT 1",
                params![capability],
            )
            .await?;
        Ok(rows.next().await?.is_some())
    }

    /// Records a new machine-wide grant for `capability` (scope `global`,
    /// granted now).
    ///
    /// History is preserved by design: revocation sets `revoked_ts` on the
    /// old row ([`Self::revoke_grant`]) and a re-grant is a new row.
    /// Granting and revoking are GUI-only administration (the daemon's
    /// admin surface); the policy gate only ever *adds* grants, on the
    /// relaxed profile's auto-grant path.
    ///
    /// This write carries no audit row. A caller that owes one uses
    /// [`Self::apply_grant_change_audited`] or
    /// [`Self::finish_request_with_grant_change`], which commit the grant and
    /// its audit row together.
    pub async fn insert_grant(&self, capability: &str) -> Result<(), StoreError> {
        let conn = self.lock().await?;
        Self::insert_grant_row(&conn, capability).await
    }

    async fn insert_grant_row(conn: &Connection, capability: &str) -> Result<(), StoreError> {
        conn.execute(
            "INSERT INTO \"grant\" (capability, scope, granted_ts)
             VALUES (?1, 'global', ?2)",
            params![capability, now_ts()],
        )
        .await?;
        Ok(())
    }

    /// Revokes `capability`'s active grant by setting `revoked_ts` — the
    /// row stays, as history. Errors with [`StoreError::NotFound`] when
    /// no active grant exists (never granted, or already revoked).
    ///
    /// Like [`Self::insert_grant`] this carries no audit row; see the
    /// audited variants.
    pub async fn revoke_grant(&self, capability: &str) -> Result<(), StoreError> {
        let conn = self.lock().await?;
        let revoked = transact!(conn, Self::revoke_grant_rows(&conn, capability))?;
        if revoked {
            Ok(())
        } else {
            Err(StoreError::NotFound {
                table: "grant",
                id: capability.to_owned(),
            })
        }
    }

    /// Revokes inside the caller's transaction, numbering the revocation one
    /// past every earlier one so [`ADMISSION_STANDS`] can tell which requests
    /// were admitted before it. False when no active grant exists.
    async fn revoke_grant_rows(conn: &Connection, capability: &str) -> Result<bool, StoreError> {
        let mut rows = conn
            .query(
                "SELECT COUNT(*) FROM \"grant\" WHERE revoked_ts IS NOT NULL",
                (),
            )
            .await?;
        let revoked_before: i64 = match rows.next().await? {
            Some(row) => row.get(0)?,
            None => 0,
        };
        drop(rows);
        let changed = conn
            .execute(
                "UPDATE \"grant\" SET revoked_ts = ?2, revoked_seq = ?3
                 WHERE capability = ?1 AND revoked_ts IS NULL",
                params![capability, now_ts(), revoked_before.saturating_add(1)],
            )
            .await?;
        Ok(changed > 0)
    }

    /// Applies one grant change inside the caller's transaction.
    async fn apply_grant_change(
        conn: &Connection,
        change: GrantChange<'_>,
    ) -> Result<GrantChangeOutcome, StoreError> {
        let applied = match change {
            GrantChange::Add(capability) => {
                let mut rows = conn
                    .query(
                        "SELECT 1 FROM \"grant\"
                         WHERE capability = ?1 AND revoked_ts IS NULL LIMIT 1",
                        params![capability],
                    )
                    .await?;
                let active = rows.next().await?.is_some();
                drop(rows);
                if !active {
                    Self::insert_grant_row(conn, capability).await?;
                }
                !active
            }
            GrantChange::Revoke(capability) => Self::revoke_grant_rows(conn, capability).await?,
        };
        Ok(if applied {
            GrantChangeOutcome::Applied
        } else {
            GrantChangeOutcome::Unchanged
        })
    }

    async fn insert_audit_row(
        conn: &Connection,
        request_id: &str,
        audit: AuditEntry<'_>,
    ) -> Result<(), StoreError> {
        conn.execute(
            "INSERT INTO audit (request_id, action, decision, actor, detail, ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                request_id,
                audit.action,
                audit.decision.as_str(),
                audit.actor.as_str(),
                audit.detail,
                now_ts()
            ],
        )
        .await?;
        Ok(())
    }

    /// Applies `change` and appends `audit` to `request_id` in **one
    /// transaction**: the grant table never changes without the row that
    /// says who changed it, and no audit row claims a change that did not
    /// commit.
    ///
    /// The request stays in whatever state it was; this is for a grant made
    /// in the middle of a request (the relaxed profile's auto-grant).
    /// [`GrantChangeOutcome::Unchanged`] — an `Add` over an active grant, a
    /// `Revoke` with none — writes nothing at all, audit row included. A
    /// missing request fails the audit row's foreign key and rolls the grant
    /// change back.
    pub async fn apply_grant_change_audited(
        &self,
        request_id: &str,
        change: GrantChange<'_>,
        audit: AuditEntry<'_>,
    ) -> Result<GrantChangeOutcome, StoreError> {
        let conn = self.lock().await?;
        transact!(conn, async {
            let outcome = Self::apply_grant_change(&conn, change).await?;
            if outcome == GrantChangeOutcome::Applied {
                Self::insert_audit_row(&conn, request_id, audit).await?;
            }
            Ok(outcome)
        })
    }

    /// Applies `change`, moves request `id` to `done` with `outcome`, and
    /// appends `audit` — all in **one transaction**. This is the admin
    /// path's grant and revoke: the mutation, the terminal state and the
    /// audit row commit together or not at all.
    ///
    /// - [`GrantChangeOutcome::Applied`]: all three are durable.
    /// - [`GrantChangeOutcome::Unchanged`]: the change did not apply (an
    ///   active grant already exists, or none to revoke). Nothing was
    ///   written and the request is still in flight, so the caller finishes
    ///   it as a refusal through [`Self::finish_request`].
    /// - [`StoreError::AlreadyTerminal`]: the request finished first (its
    ///   deadline, say). The grant table was **not** changed: an operation
    ///   that was recorded as failed must not have taken effect.
    /// - [`StoreError::NotFound`]: no such request; nothing written.
    pub async fn finish_request_with_grant_change(
        &self,
        id: &str,
        change: GrantChange<'_>,
        outcome: Option<&str>,
        audit: AuditEntry<'_>,
    ) -> Result<GrantChangeOutcome, StoreError> {
        let conn = self.lock().await?;
        transact!(conn, async {
            let mut rows = conn
                .query(
                    "SELECT 1 FROM request
                     WHERE id = ?1 AND state IN ('queued','running','waiting_approval')",
                    params![id],
                )
                .await?;
            let in_flight = rows.next().await?.is_some();
            drop(rows);
            if !in_flight {
                return Err(Self::missing_or_terminal(&conn, id).await?);
            }
            if Self::apply_grant_change(&conn, change).await? == GrantChangeOutcome::Unchanged {
                return Ok(GrantChangeOutcome::Unchanged);
            }
            if !Self::finish_request_in_txn(&conn, id, RequestState::Done, outcome, audit).await? {
                // Unreachable while this transaction holds the connection;
                // an error here rolls the grant change back with it.
                return Err(StoreError::AlreadyTerminal { id: id.to_owned() });
            }
            Ok(GrantChangeOutcome::Applied)
        })
    }

    /// Every grant row, revoked history included, newest first — the
    /// GUI's capability view.
    pub async fn list_grants(&self) -> Result<Vec<GrantRow>, StoreError> {
        let conn = self.lock().await?;
        let mut rows = conn
            .query(
                "SELECT id, capability, scope, granted_ts, revoked_ts
                 FROM \"grant\" ORDER BY granted_ts DESC, id DESC",
                (),
            )
            .await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            out.push(GrantRow {
                id: row.get(0)?,
                capability: row.get(1)?,
                scope: row.get(2)?,
                granted_ts: row.get(3)?,
                revoked_ts: row.get(4)?,
            });
        }
        Ok(out)
    }

    /// Recent request rows, newest first, optionally filtered by exact
    /// `repo`, `caller_agent`, and/or `state` — the GUI's activity feed.
    ///
    /// `limit` defaults to [`DEFAULT_REQUEST_LIST_LIMIT`] and is clamped
    /// into `1..=`[`MAX_LIST_LIMIT`], so the query stays bounded
    /// no matter what the caller asks for.
    ///
    /// `hide_probes` drops the observatory's own traffic — every
    /// `admin.*` op and the `status` health probe — so the GUI polling
    /// itself every few seconds cannot crowd real agent work out of the
    /// newest-N window. `admin.log.compress` is exempt: a human asked for
    /// that compression, so its row is activity, not a probe. So is every
    /// `admin.*` attempt the tripwire refused ([`OUTCOME_ADMIN_DENIED`]):
    /// that row is somebody other than the GUI trying to administer PAM, and
    /// hiding it with the GUI's own polls would hide the one thing the
    /// tripwire exists to show. Auditors pass `false` and see everything.
    pub async fn list_requests_filtered(
        &self,
        limit: Option<u64>,
        repo: Option<&str>,
        agent: Option<&str>,
        state: Option<RequestState>,
        capability: Option<&str>,
        hide_probes: bool,
    ) -> Result<Vec<RequestRow>, StoreError> {
        let conn = self.lock().await?;
        let limit = limit
            .unwrap_or(DEFAULT_REQUEST_LIST_LIMIT)
            .clamp(1, MAX_LIST_LIMIT);
        let mut clauses: Vec<String> = Vec::new();
        let mut args: Vec<String> = Vec::new();
        // A terminal state matches most of the table: the unary plus keeps
        // `request_state_idx` out of the plan, so the engine walks
        // `request_created_idx` newest first and stops at the limit instead
        // of collecting and sorting every finished request. An in-flight
        // state is rare, and there the state index is the short way in.
        let state_column = if state.is_some_and(RequestState::is_terminal) {
            "+state"
        } else {
            "state"
        };
        for (column, value) in [
            ("repo", repo),
            ("caller_agent", agent),
            (state_column, state.map(RequestState::as_str)),
            ("capability", capability),
        ] {
            if let Some(value) = value {
                args.push(value.to_owned());
                clauses.push(format!("{column} = ?{}", args.len()));
            }
        }
        if hide_probes {
            // Literals, not bound args: the patterns are ours, never the
            // caller's.
            clauses.push(format!(
                "(capability NOT LIKE 'admin.%' OR capability = 'admin.log.compress' \
                 OR (state = 'refused' AND outcome = '{OUTCOME_ADMIN_DENIED}')) \
                 AND capability <> 'status'"
            ));
        }
        let where_sql = if clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {} ", clauses.join(" AND "))
        };
        let sql = format!(
            "SELECT {} FROM request {where_sql}\
             ORDER BY created_ts DESC, id DESC LIMIT {limit}",
            Self::REQUEST_COLUMNS
        );
        let mut rows = conn.query(&sql, args).await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            out.push(Self::parse_request_row(&row)?);
        }
        Ok(out)
    }

    /// Records that the agent+repo pair was observed now: inserts the
    /// `caller` row on first sight, bumps `last_seen` afterwards. The
    /// registry is advisory (see [`CallerRow`]); the pipeline calls this
    /// on every admitted request.
    pub async fn upsert_caller(&self, agent: &str, repo: &str) -> Result<(), StoreError> {
        let conn = self.lock().await?;
        conn.execute(
            "INSERT INTO caller (agent, repo, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT (agent, repo) DO UPDATE SET last_seen = excluded.last_seen",
            params![agent, repo, now_ts()],
        )
        .await?;
        Ok(())
    }

    /// Every observed agent+repo pair, most recently seen first — feeds
    /// the GUI sidebar and activity filters.
    pub async fn list_callers(&self) -> Result<Vec<CallerRow>, StoreError> {
        let conn = self.lock().await?;
        let mut rows = conn
            .query(
                "SELECT agent, repo, first_seen, last_seen
                 FROM caller ORDER BY last_seen DESC, agent, repo",
                (),
            )
            .await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            out.push(CallerRow {
                agent: row.get(0)?,
                repo: row.get(1)?,
                first_seen: row.get(2)?,
                last_seen: row.get(3)?,
            });
        }
        Ok(out)
    }

    /// Inserts an unresolved approval row for `request_id`, requested
    /// now. The approval service writes exactly one per gated request.
    pub async fn insert_approval(
        &self,
        request_id: &str,
        capability: &str,
    ) -> Result<(), StoreError> {
        let conn = self.lock().await?;
        conn.execute(
            "INSERT INTO approval (request_id, capability, requested_ts)
                 VALUES (?1, ?2, ?3)",
            params![request_id, capability, now_ts()],
        )
        .await?;
        Ok(())
    }

    /// Parks `request_id` on a new approval: inserts the unresolved
    /// `approval` row and moves the request to `waiting_approval` in **one
    /// transaction**, so a crash can leave neither a pending approval on a
    /// request that still reads `running` nor a waiting request with nothing
    /// to approve.
    ///
    /// A request that already finished is refused with
    /// [`StoreError::AlreadyTerminal`] and gets no approval row; a missing
    /// one with [`StoreError::NotFound`].
    pub async fn insert_approval_waiting(
        &self,
        request_id: &str,
        capability: &str,
    ) -> Result<(), StoreError> {
        let conn = self.lock().await?;
        transact!(conn, async {
            let now = now_ts();
            let changed = conn
                .execute(
                    "UPDATE request SET state = 'waiting_approval', outcome = NULL, updated_ts = ?2
                     WHERE id = ?1 AND state IN ('queued','running','waiting_approval')",
                    params![request_id, now],
                )
                .await?;
            if changed == 0 {
                return Err(Self::missing_or_terminal(&conn, request_id).await?);
            }
            conn.execute(
                "INSERT INTO approval (request_id, capability, requested_ts)
                 VALUES (?1, ?2, ?3)",
                params![request_id, capability, now],
            )
            .await?;
            Ok(())
        })
    }

    /// Resolves `request_id`'s pending approval and appends `audit` — and,
    /// when `remember` names a capability, records the grant that approval
    /// creates together with its own audit row — all in **one
    /// transaction**. A persisted authorization therefore always has the
    /// audit rows that explain it, and a resolved approval is never missing
    /// its decision in the trail.
    ///
    /// Returns `true` when a new grant row was written. With `remember` set
    /// and a grant already active, no second active row is added and the
    /// grant's audit row is not written (nothing was granted); the
    /// resolution and its audit row still commit. Errors with
    /// [`StoreError::NotFound`], writing nothing, when the request has no
    /// unresolved approval — the same race guard as
    /// [`Self::resolve_approval`].
    pub async fn resolve_approval_audited(
        &self,
        request_id: &str,
        resolution: ApprovalResolution,
        note: Option<&str>,
        audit: AuditEntry<'_>,
        remember: Option<(&str, AuditEntry<'_>)>,
    ) -> Result<bool, StoreError> {
        let conn = self.lock().await?;
        transact!(conn, async {
            let changed = conn
                .execute(
                    "UPDATE approval SET resolved_ts = ?2, resolution = ?3, note = ?4
                     WHERE request_id = ?1 AND resolved_ts IS NULL",
                    params![request_id, now_ts(), resolution.as_str(), note],
                )
                .await?;
            if changed == 0 {
                return Err(StoreError::NotFound {
                    table: "approval",
                    id: request_id.to_owned(),
                });
            }
            Self::insert_audit_row(&conn, request_id, audit).await?;
            let Some((capability, grant_audit)) = remember else {
                return Ok(false);
            };
            let granted = Self::apply_grant_change(&conn, GrantChange::Add(capability)).await?
                == GrantChangeOutcome::Applied;
            if granted {
                Self::insert_audit_row(&conn, request_id, grant_audit).await?;
            }
            Ok(granted)
        })
    }

    /// Resolves `request_id`'s pending approval: sets `resolved_ts`,
    /// `resolution`, and `note`.
    ///
    /// Race guard: only a row whose `resolved_ts` is still NULL is
    /// updated; a request without one (never requested, or already
    /// resolved) errors with [`StoreError::NotFound`], so two concurrent
    /// resolutions cannot both claim the approval.
    pub async fn resolve_approval(
        &self,
        request_id: &str,
        resolution: ApprovalResolution,
        note: Option<&str>,
    ) -> Result<(), StoreError> {
        let conn = self.lock().await?;
        let changed = conn
            .execute(
                "UPDATE approval SET resolved_ts = ?2, resolution = ?3, note = ?4
                 WHERE request_id = ?1 AND resolved_ts IS NULL",
                params![request_id, now_ts(), resolution.as_str(), note],
            )
            .await?;
        if changed == 0 {
            return Err(StoreError::NotFound {
                table: "approval",
                id: request_id.to_owned(),
            });
        }
        Ok(())
    }

    /// Reads `request_id`'s newest approval row, or `None` if it never
    /// needed one.
    pub async fn approval_for_request(
        &self,
        request_id: &str,
    ) -> Result<Option<ApprovalRow>, StoreError> {
        let conn = self.lock().await?;
        let mut rows = conn
            .query(
                "SELECT id, request_id, capability, requested_ts, resolved_ts,
                        resolution, note
                 FROM approval WHERE request_id = ?1 ORDER BY id DESC LIMIT 1",
                params![request_id],
            )
            .await?;
        match rows.next().await? {
            Some(row) => {
                let resolution: Option<String> = row.get(5)?;
                Ok(Some(ApprovalRow {
                    id: row.get(0)?,
                    request_id: row.get(1)?,
                    capability: row.get(2)?,
                    requested_ts: row.get(3)?,
                    resolved_ts: row.get(4)?,
                    resolution: resolution
                        .as_deref()
                        .map(ApprovalResolution::parse)
                        .transpose()?,
                    note: row.get(6)?,
                }))
            }
            None => Ok(None),
        }
    }

    /// Every unresolved approval whose request is still in flight, joined
    /// with that request, oldest first — the GUI's pending list.
    ///
    /// A request that already finished can no longer be approved: nothing is
    /// waiting on the answer. A crash between a terminal write and the
    /// approval's own resolution leaves such a row behind, and listing it
    /// would advertise an approval nobody can grant.
    pub async fn list_pending_approvals(&self) -> Result<Vec<PendingApproval>, StoreError> {
        let conn = self.lock().await?;
        let mut rows = conn
            .query(
                "SELECT a.request_id, a.capability, r.repo, r.caller_agent,
                        a.requested_ts, r.capability, r.args_json
                 FROM approval a JOIN request r ON r.id = a.request_id
                 WHERE a.resolved_ts IS NULL
                   AND r.state IN ('queued','running','waiting_approval')
                 ORDER BY a.requested_ts, a.id",
                (),
            )
            .await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            out.push(PendingApproval {
                request_id: row.get(0)?,
                capability: row.get(1)?,
                repo: row.get(2)?,
                caller_agent: row.get(3)?,
                requested_ts: row.get(4)?,
                request_capability: row.get(5)?,
                args_json: row.get(6)?,
            });
        }
        Ok(out)
    }

    /// Reads a setting value (JSON text), or `None` if unset.
    pub async fn get_setting(&self, key: &str) -> Result<Option<String>, StoreError> {
        let conn = self.lock().await?;
        let mut rows = conn
            .query("SELECT value FROM setting WHERE key = ?1", params![key])
            .await?;
        match rows.next().await? {
            Some(row) => Ok(Some(row.get(0)?)),
            None => Ok(None),
        }
    }

    /// Reads a setting with its byte bound applied before allocation.
    pub async fn get_setting_bounded(
        &self,
        key: &str,
        maximum: usize,
    ) -> Result<Option<String>, StoreError> {
        let maximum = i64::try_from(maximum).unwrap_or(i64::MAX).min(32_768);
        let conn = self.lock().await?;
        let mut rows = conn.query("SELECT CASE WHEN LENGTH(CAST(value AS BLOB))<=?2 THEN value ELSE NULL END FROM setting WHERE key=?1", params![key,maximum]).await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        row.get::<Option<String>>(0)?
            .map(Some)
            .ok_or_else(|| StoreError::UnexpectedValue {
                column: "setting",
                value: "value exceeds bounded read".to_owned(),
            })
    }

    /// Compare exact prior bytes and update under the single connection lock.
    /// Returns false on conflict; no implicit retry or overwrite.
    pub async fn compare_exchange_setting(
        &self,
        key: &str,
        expected: Option<&str>,
        value: &str,
    ) -> Result<bool, StoreError> {
        if value.len() > 32_768 || expected.is_some_and(|prior| prior.len() > 32_768) {
            return Err(StoreError::UnexpectedValue {
                column: "setting",
                value: "CAS value exceeds 32 KiB".to_owned(),
            });
        }
        let conn = self.lock().await?;
        let mut rows = conn.query("SELECT CASE WHEN LENGTH(CAST(value AS BLOB))<=32768 THEN value ELSE NULL END FROM setting WHERE key=?1", params![key]).await?;
        let prior =
            match rows.next().await? {
                Some(row) => Some(row.get::<Option<String>>(0)?.ok_or_else(|| {
                    StoreError::UnexpectedValue {
                        column: "setting",
                        value: "stored CAS value exceeds 32 KiB".to_owned(),
                    }
                })?),
                None => None,
            };
        drop(rows);
        if prior.as_deref() != expected {
            return Ok(false);
        }
        conn.execute("INSERT INTO setting(key,value) VALUES (?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![key,value]).await?;
        Ok(true)
    }

    /// Writes a setting value (JSON text), replacing any previous value.
    pub async fn set_setting(&self, key: &str, value: &str) -> Result<(), StoreError> {
        let conn = self.lock().await?;
        conn.execute(
            "INSERT INTO setting (key, value) VALUES (?1, ?2)
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )
        .await?;
        Ok(())
    }

    /// Writes several settings in **one transaction**: every pair lands or
    /// none does. A group of settings that is only valid together (the two
    /// retention windows) is saved through this, so neither a crash nor a
    /// concurrent save can persist half of one decision.
    pub async fn set_settings(&self, pairs: &[(&str, &str)]) -> Result<(), StoreError> {
        let conn = self.lock().await?;
        transact!(conn, async {
            for (key, value) in pairs {
                conn.execute(
                    "INSERT INTO setting (key, value) VALUES (?1, ?2)
                     ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                    params![*key, *value],
                )
                .await?;
            }
            Ok(())
        })
    }

    /// Records a new `running` model job.
    pub async fn insert_model_job(
        &self,
        id: &str,
        kind: &str,
        model_id: &str,
        source: Option<&str>,
        bytes_total: Option<i64>,
    ) -> Result<(), StoreError> {
        let conn = self.lock().await?;
        conn.execute(
            "INSERT INTO model_job
                     (id, kind, model_id, source, state, bytes_done, bytes_total,
                      created_ts, updated_ts)
                 VALUES (?1, ?2, ?3, ?4, 'running', 0, ?5, ?6, ?6)",
            params![id, kind, model_id, source, bytes_total, now_ts()],
        )
        .await?;
        Ok(())
    }

    /// Moves a running job's progress figures forward.
    ///
    /// Silently does nothing for a job that already reached its verdict —
    /// a poll that races the terminal write must not resurrect the row.
    pub async fn update_model_job_progress(
        &self,
        id: &str,
        bytes_done: i64,
        bytes_total: Option<i64>,
    ) -> Result<(), StoreError> {
        let conn = self.lock().await?;
        conn.execute(
            "UPDATE model_job
                    SET bytes_done = ?2, bytes_total = ?3, updated_ts = ?4
                  WHERE id = ?1 AND state = 'running'",
            params![id, bytes_done, bytes_total, now_ts()],
        )
        .await?;
        Ok(())
    }

    /// Writes a job's verdict: `done`, `failed` or `cancelled`, with the
    /// detail JSON the GUI shows.
    ///
    /// Only a `running` row is finished, so the first verdict wins.
    pub async fn finish_model_job(
        &self,
        id: &str,
        state: &str,
        detail: Option<&str>,
    ) -> Result<(), StoreError> {
        let conn = self.lock().await?;
        conn.execute(
            "UPDATE model_job
                    SET state = ?2, detail = ?3, updated_ts = ?4
                  WHERE id = ?1 AND state = 'running'",
            params![id, state, detail, now_ts()],
        )
        .await?;
        Ok(())
    }

    /// The most recent model jobs, newest first, bounded by `limit`
    /// (clamped into `1..=`[`MAX_LIST_LIMIT`]).
    pub async fn list_model_jobs(&self, limit: u64) -> Result<Vec<ModelJobRow>, StoreError> {
        let conn = self.lock().await?;
        let limit = limit.clamp(1, MAX_LIST_LIMIT);
        let mut rows = conn
            .query(
                &format!(
                    "SELECT id, kind, model_id, source, state, bytes_done, bytes_total,
                            detail, created_ts, updated_ts
                       FROM model_job
                      ORDER BY created_ts DESC, id DESC LIMIT {limit}"
                ),
                (),
            )
            .await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            out.push(ModelJobRow {
                id: row.get(0)?,
                kind: row.get(1)?,
                model_id: row.get(2)?,
                source: row.get(3)?,
                state: row.get(4)?,
                bytes_done: row.get(5)?,
                bytes_total: row.get(6)?,
                detail: row.get(7)?,
                created_ts: row.get(8)?,
                updated_ts: row.get(9)?,
            });
        }
        Ok(out)
    }

    /// Fails every `running` job, returning how many were closed — boot
    /// recovery for the jobs a dead daemon left behind.
    ///
    /// Terminal rows are untouched: a job that already succeeded or was
    /// cancelled keeps its verdict across the restart.
    pub async fn fail_running_model_jobs(&self, detail: &str) -> Result<u64, StoreError> {
        let conn = self.lock().await?;
        let changed = conn
            .execute(
                "UPDATE model_job
                    SET state = 'failed', detail = ?1, updated_ts = ?2
                  WHERE state = 'running'",
                params![detail, now_ts()],
            )
            .await?;
        Ok(changed)
    }

    /// Writes one evidence row: the bytes, their sha256, and optional
    /// kind-specific metadata.
    ///
    /// `content_hash` is computed here so every row is addressable by
    /// digest whatever wrote it, and `path` stays NULL — evidence is
    /// blob-backed today.
    pub async fn insert_evidence(
        &self,
        id: &str,
        request_id: &str,
        kind: &str,
        content: &[u8],
        meta_json: Option<&str>,
    ) -> Result<(), StoreError> {
        // Hash and copy before taking the connection: a 64 MiB blob is
        // tens of milliseconds of CPU nobody else should wait behind.
        let content_hash = hex::encode(Sha256::digest(content));
        let content = content.to_vec();
        let conn = self.lock().await?;
        conn.execute(
            "INSERT INTO evidence
                     (id, request_id, kind, content, path, content_hash, meta_json, ts)
                 VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7)",
            params![
                id,
                request_id,
                kind,
                content,
                content_hash,
                meta_json,
                now_ts()
            ],
        )
        .await?;
        Ok(())
    }

    /// Reads one evidence row by id, blob included, or `None` if it does
    /// not exist.
    pub async fn get_evidence(&self, id: &str) -> Result<Option<EvidenceRow>, StoreError> {
        let conn = self.lock().await?;
        let mut rows = conn
            .query(
                "SELECT id, request_id, kind, content, content_hash, meta_json, ts
                 FROM evidence WHERE id = ?1",
                params![id],
            )
            .await?;
        match rows.next().await? {
            Some(row) => Ok(Some(EvidenceRow {
                id: row.get(0)?,
                request_id: row.get(1)?,
                kind: row.get(2)?,
                content: blob_column(&row, 3)?,
                content_hash: row.get(4)?,
                meta_json: row.get(5)?,
                ts: row.get(6)?,
            })),
            None => Ok(None),
        }
    }

    /// Every evidence row for one request, oldest first, without the
    /// blobs — the GUI's evidence strip.
    pub async fn list_evidence(&self, request_id: &str) -> Result<Vec<EvidenceMeta>, StoreError> {
        let conn = self.lock().await?;
        let mut rows = conn
            .query(
                "SELECT id, request_id, kind, LENGTH(content), content_hash, meta_json, ts
                 FROM evidence WHERE request_id = ?1 ORDER BY ts ASC, id ASC",
                params![request_id],
            )
            .await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            out.push(EvidenceMeta {
                id: row.get(0)?,
                request_id: row.get(1)?,
                kind: row.get(2)?,
                bytes: length_column(&row, 3)?,
                content_hash: row.get(4)?,
                meta_json: row.get(5)?,
                ts: row.get(6)?,
            });
        }
        Ok(out)
    }

    /// Sums the compression figures over the [`EVIDENCE_KIND_LOG_COMPACT`]
    /// rows written at or after `since_ts`.
    ///
    /// The figures are read out of `meta_json` in Rust rather than with
    /// SQL JSON functions, so the aggregate does not depend on the
    /// engine's JSON support. A row whose metadata cannot be read still
    /// counts as a compression — it happened — but contributes no
    /// figures, and says so in the log.
    pub async fn compression_stats(&self, since_ts: i64) -> Result<CompressionStats, StoreError> {
        let conn = self.lock().await?;
        let mut rows = conn
            .query(
                "SELECT id, meta_json FROM evidence WHERE kind = ?1 AND ts >= ?2",
                params![EVIDENCE_KIND_LOG_COMPACT, since_ts],
            )
            .await?;
        let mut stats = CompressionStats::default();
        while let Some(row) = rows.next().await? {
            stats.compressions = stats.compressions.saturating_add(1);
            let id: String = row.get(0)?;
            let meta: Option<String> = row.get(1)?;
            let Some(meta) = meta.as_deref() else {
                tracing::warn!(evidence_id = %id, "compression meta is missing");
                continue;
            };
            match serde_json::from_str::<serde_json::Value>(meta) {
                Ok(value) => {
                    stats.source_bytes = stats
                        .source_bytes
                        .saturating_add(meta_u64(&value, "source_bytes"));
                    stats.compact_bytes = stats
                        .compact_bytes
                        .saturating_add(meta_u64(&value, "compact_bytes"));
                    stats.tokens_avoided_est = stats
                        .tokens_avoided_est
                        .saturating_add(meta_u64(&value, "tokens_avoided_est"));
                }
                Err(error) => {
                    tracing::warn!(evidence_id = %id, %error, "unreadable compression meta");
                }
            }
        }
        Ok(stats)
    }

    /// Evidence rows one prune transaction removes: the oldest
    /// [`Self::EVIDENCE_PRUNE_BATCH`] older than `?1`, not kind `?2`, and
    /// hanging off a request that has already finished.
    ///
    /// A running request keeps its evidence whatever its age — the
    /// executor is still writing it, and a half-pruned working set is
    /// worse than an old one. Written as an ordered range over `ts` with a
    /// per-row request lookup so the engine walks `evidence_ts_idx` and
    /// stops at the batch size, instead of collecting every terminal
    /// request first and sorting what hangs off them.
    pub(crate) fn evidence_prune_batch_sql() -> String {
        format!(
            "SELECT e.id FROM evidence e WHERE e.ts < ?1 AND e.kind <> ?2 AND EXISTS \
             (SELECT 1 FROM request r WHERE r.id = e.request_id \
              AND r.state IN ('done','refused','failed')) \
             ORDER BY e.ts, e.id LIMIT {}",
            Self::EVIDENCE_PRUNE_BATCH
        )
    }

    /// Request records one prune transaction removes: the oldest
    /// [`Self::REQUEST_PRUNE_BATCH`] terminal rows untouched since `?1`.
    ///
    /// "Terminal" is spelled as "not in flight" on purpose: the schema's
    /// CHECK admits exactly six states, so the two say the same thing, but
    /// this form leaves `request_state_idx` out of the plan and lets the
    /// engine walk `request_updated_idx` in order and stop at the batch
    /// size.
    pub(crate) fn request_prune_batch_sql() -> String {
        format!(
            "SELECT id FROM request \
             WHERE state NOT IN ('queued','running','waiting_approval') AND updated_ts < ?1 \
             ORDER BY updated_ts, id LIMIT {}",
            Self::REQUEST_PRUNE_BATCH
        )
    }

    /// Evidence rows one prune transaction removes. Blobs run to 64 MiB
    /// each, so the batch stays small: the connection lock is released
    /// between batches and a terminal write never waits behind a whole
    /// backlog.
    const EVIDENCE_PRUNE_BATCH: u64 = 64;

    /// Request records one prune transaction removes, children included.
    const REQUEST_PRUNE_BATCH: u64 = 256;

    /// Deletes evidence rows older than `cutoff_ts` whose kind is not
    /// `keep_kind` and whose request is already terminal.
    ///
    /// This is the evidence half of retention: the bulky blobs go first
    /// and the verdict (`keep_kind`) stays, so activity history keeps
    /// reading straight after a pass. The work runs oldest first in
    /// bounded batches, one transaction each, and the connection lock is
    /// released between them, so a first pass over months of data cannot
    /// hold every other store call behind it. The figures are counted
    /// before each delete, so the report is exact whatever the engine
    /// reports for a multi-row statement. Dropping the call keeps the
    /// batches already committed; the next pass finishes the rest.
    pub async fn prune_evidence_before(
        &self,
        cutoff_ts: i64,
        keep_kind: &str,
    ) -> Result<EvidencePrune, StoreError> {
        let mut total = EvidencePrune::default();
        loop {
            let batch = {
                let conn = self.lock().await?;
                transact!(
                    conn,
                    Self::prune_evidence_batch(&conn, cutoff_ts, keep_kind)
                )?
            };
            total.rows = total.rows.saturating_add(batch.rows);
            total.bytes = total.bytes.saturating_add(batch.bytes);
            if batch.rows < Self::EVIDENCE_PRUNE_BATCH {
                return Ok(total);
            }
        }
    }

    /// One batch of [`Self::prune_evidence_before`], inside its transaction.
    async fn prune_evidence_batch(
        conn: &Connection,
        cutoff_ts: i64,
        keep_kind: &str,
    ) -> Result<EvidencePrune, StoreError> {
        // The same oldest-first id set three times; nothing between the
        // statements changes which evidence rows the filter selects.
        let batch = Self::evidence_prune_batch_sql();
        let (rows, bytes) = Self::measure(
            conn,
            &format!(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(content)), 0) \
                 FROM evidence WHERE id IN ({batch})"
            ),
            params![cutoff_ts, keep_kind],
        )
        .await?;
        if rows > 0 {
            conn.execute(
                &format!(
                    "UPDATE evidence_view SET view_blob = NULL, expired_at = ?3 \
                     WHERE evidence_id IN ({batch})"
                ),
                params![cutoff_ts, keep_kind, now_ts()],
            )
            .await?;
            conn.execute(
                &format!("DELETE FROM evidence WHERE id IN ({batch})"),
                params![cutoff_ts, keep_kind],
            )
            .await?;
        }
        Ok(EvidencePrune { rows, bytes })
    }

    /// Deletes terminal requests older than `cutoff_ts` together with
    /// their audit, approval, and evidence rows — children first.
    ///
    /// This is the audit half of retention, and the destructive one: a
    /// record leaves whole, verdict included, so nothing dangles and the
    /// foreign keys stay satisfied. In-flight requests are never touched,
    /// however old they look. Like the evidence half it works oldest first
    /// in bounded batches: each batch is one transaction, so a record is
    /// never half-removed, and the connection lock is released between
    /// batches.
    pub async fn prune_requests_before(&self, cutoff_ts: i64) -> Result<RequestPrune, StoreError> {
        let mut total = RequestPrune::default();
        loop {
            let batch = {
                let conn = self.lock().await?;
                transact!(conn, Self::prune_requests_batch(&conn, cutoff_ts))?
            };
            total.requests = total.requests.saturating_add(batch.requests);
            total.audit_rows = total.audit_rows.saturating_add(batch.audit_rows);
            total.approvals = total.approvals.saturating_add(batch.approvals);
            total.evidence_rows = total.evidence_rows.saturating_add(batch.evidence_rows);
            total.evidence_bytes = total.evidence_bytes.saturating_add(batch.evidence_bytes);
            if batch.requests < Self::REQUEST_PRUNE_BATCH {
                return Ok(total);
            }
        }
    }

    /// One batch of [`Self::prune_requests_before`], inside its transaction.
    async fn prune_requests_batch(
        conn: &Connection,
        cutoff_ts: i64,
    ) -> Result<RequestPrune, StoreError> {
        // The same oldest-first id set for every table. The `request` rows
        // themselves go last, so each child statement still sees them.
        let batch = Self::request_prune_batch_sql();
        let children = format!("request_id IN ({batch})");
        let (evidence_rows, evidence_bytes) = Self::measure(
            conn,
            &format!(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(content)), 0) \
                 FROM evidence WHERE {children}"
            ),
            params![cutoff_ts],
        )
        .await?;
        let (audit_rows, _) = Self::measure(
            conn,
            &format!("SELECT COUNT(*), 0 FROM audit WHERE {children}"),
            params![cutoff_ts],
        )
        .await?;
        let (approvals, _) = Self::measure(
            conn,
            &format!("SELECT COUNT(*), 0 FROM approval WHERE {children}"),
            params![cutoff_ts],
        )
        .await?;
        let (requests, _) = Self::measure(
            conn,
            &format!("SELECT COUNT(*), 0 FROM request WHERE id IN ({batch})"),
            params![cutoff_ts],
        )
        .await?;
        if requests > 0 {
            // Children first: the foreign keys point at `request`.
            for sql in [
                format!("DELETE FROM request_budget WHERE {children}"),
                format!("DELETE FROM flow_journal WHERE {children}"),
                format!("DELETE FROM landing_session WHERE {children}"),
                format!("DELETE FROM correlation_membership WHERE {children}"),
                format!("DELETE FROM correlation_step WHERE {children}"),
                format!("DELETE FROM correlation_target WHERE {children}"),
                format!("DELETE FROM evidence_view WHERE {children}"),
                format!("DELETE FROM evidence_read_allowance WHERE {children}"),
                format!("DELETE FROM evidence WHERE {children}"),
                format!("DELETE FROM approval WHERE {children}"),
                format!("DELETE FROM audit WHERE {children}"),
                format!("DELETE FROM request WHERE id IN ({batch})"),
            ] {
                conn.execute(&sql, params![cutoff_ts]).await?;
            }
        }
        Ok(RequestPrune {
            requests,
            audit_rows,
            approvals,
            evidence_rows,
            evidence_bytes,
        })
    }

    /// Counts what [`Self::prune_evidence_before`] followed by
    /// [`Self::prune_requests_before`] would remove at these cutoffs,
    /// without removing anything. A `None` cutoff means that window is
    /// forever and contributes nothing.
    ///
    /// The filters are the prune statements' own, without their batch
    /// order and limit, so the count is what a pass run right now would
    /// delete: evidence older than `evidence_cutoff` that is not
    /// `keep_kind` and hangs off a finished request, every evidence row of
    /// a terminal request untouched since `request_cutoff` (counted once
    /// when both apply), and those request records themselves. All of it
    /// is read under one hold of the connection, so the figures describe
    /// one moment. Read-only.
    pub async fn retention_census(
        &self,
        evidence_cutoff: Option<i64>,
        keep_kind: &str,
        request_cutoff: Option<i64>,
    ) -> Result<RetentionCensus, StoreError> {
        // "Terminal", spelled as the request prune spells it.
        const LEAVING: &str = "SELECT id FROM request \
             WHERE state NOT IN ('queued','running','waiting_approval') AND updated_ts < ";
        // The evidence prune's own filter over `?1` (cutoff) and `?2` (kept kind).
        const AGED: &str = "e.ts < ?1 AND e.kind <> ?2 AND EXISTS \
             (SELECT 1 FROM request r WHERE r.id = e.request_id \
              AND r.state IN ('done','refused','failed'))";
        let conn = self.lock().await?;
        let (evidence, _) = Self::measure(&conn, "SELECT COUNT(*), 0 FROM evidence", ()).await?;
        let (terminal, _) = Self::measure(
            &conn,
            "SELECT COUNT(*), 0 FROM request \
             WHERE state NOT IN ('queued','running','waiting_approval')",
            (),
        )
        .await?;
        let mut eligible = 0u64;
        if let Some(cutoff) = evidence_cutoff {
            let (aged, _) = Self::measure(
                &conn,
                &format!("SELECT COUNT(*), 0 FROM evidence e WHERE {AGED}"),
                params![cutoff, keep_kind],
            )
            .await?;
            eligible = eligible.saturating_add(aged);
        }
        if let Some(cutoff) = request_cutoff {
            let (requests, _) = Self::measure(
                &conn,
                &format!("SELECT COUNT(*), 0 FROM request WHERE id IN ({LEAVING}?1)"),
                params![cutoff],
            )
            .await?;
            let (with_request, _) = Self::measure(
                &conn,
                &format!("SELECT COUNT(*), 0 FROM evidence WHERE request_id IN ({LEAVING}?1)"),
                params![cutoff],
            )
            .await?;
            eligible = eligible
                .saturating_add(requests)
                .saturating_add(with_request);
            if let Some(evidence_cutoff) = evidence_cutoff {
                // Counted by both windows above: once is enough.
                let (both, _) = Self::measure(
                    &conn,
                    &format!(
                        "SELECT COUNT(*), 0 FROM evidence e \
                         WHERE {AGED} AND e.request_id IN ({LEAVING}?3)"
                    ),
                    params![evidence_cutoff, keep_kind, cutoff],
                )
                .await?;
                eligible = eligible.saturating_sub(both);
            }
        }
        Ok(RetentionCensus {
            eligible_rows: eligible,
            total_rows: evidence.saturating_add(terminal),
        })
    }

    /// Reads one `SELECT count, bytes` row as a `(u64, u64)` pair. A
    /// missing row or a negative figure reads as zero: a prune report
    /// never invents work it did not do.
    async fn measure<P: turso::IntoParams>(
        conn: &Connection,
        sql: &str,
        params: P,
    ) -> Result<(u64, u64), StoreError> {
        let mut rows = conn.query(sql, params).await?;
        let Some(row) = rows.next().await? else {
            return Ok((0, 0));
        };
        let count: i64 = row.get(0)?;
        let bytes: i64 = row.get(1)?;
        Ok((
            u64::try_from(count).unwrap_or(0),
            u64::try_from(bytes).unwrap_or(0),
        ))
    }

    /// The `connector` column list every row query selects, in the order
    /// [`Self::parse_connector_row`] expects.
    const CONNECTOR_COLUMNS: &'static str = "id, enabled, base_url, username, \
         last_test_status, last_test_detail, last_test_ts, updated_ts";

    /// Builds a [`ConnectorRow`] from a row selected with
    /// [`Self::CONNECTOR_COLUMNS`].
    fn parse_connector_row(row: &turso::Row) -> Result<ConnectorRow, StoreError> {
        let enabled: i64 = row.get(1)?;
        Ok(ConnectorRow {
            id: row.get(0)?,
            enabled: enabled != 0,
            base_url: row.get(2)?,
            username: row.get(3)?,
            last_test_status: row.get(4)?,
            last_test_detail: row.get(5)?,
            last_test_ts: row.get(6)?,
            updated_ts: row.get(7)?,
        })
    }

    /// Every connector row, ordered by id.
    pub async fn list_connectors(&self) -> Result<Vec<ConnectorRow>, StoreError> {
        let conn = self.lock().await?;
        let mut rows = conn
            .query(
                &format!(
                    "SELECT {} FROM connector ORDER BY id",
                    Self::CONNECTOR_COLUMNS
                ),
                (),
            )
            .await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            out.push(Self::parse_connector_row(&row)?);
        }
        Ok(out)
    }

    /// Reads one connector row by id, or `None` if it has never been
    /// configured or tested.
    pub async fn get_connector(&self, id: &str) -> Result<Option<ConnectorRow>, StoreError> {
        let conn = self.lock().await?;
        let mut rows = conn
            .query(
                &format!(
                    "SELECT {} FROM connector WHERE id = ?1",
                    Self::CONNECTOR_COLUMNS
                ),
                params![id],
            )
            .await?;
        match rows.next().await? {
            Some(row) => Ok(Some(Self::parse_connector_row(&row)?)),
            None => Ok(None),
        }
    }

    /// Creates or patches a connector row: `INSERT ... ON CONFLICT DO
    /// UPDATE`, touching only the fields `patch` sets. `updated_ts` is
    /// always bumped to now, whether the row was created or patched.
    ///
    /// A field of `patch` left as `None` keeps its current value across a
    /// patch (or lands on its column default on first insert); a
    /// `base_url`/`username` field given as `Some(None)` clears it.
    pub async fn upsert_connector(
        &self,
        id: &str,
        patch: ConnectorPatch<'_>,
    ) -> Result<ConnectorRow, StoreError> {
        let conn = self.lock().await?;
        let enabled = patch.enabled.unwrap_or(false);
        let base_url = patch.base_url.flatten();
        let username = patch.username.flatten();

        // Only the fields the caller actually set are reassigned on
        // conflict; the rest keep the existing row's value instead of
        // being overwritten by the INSERT's (possibly default) values.
        let mut set_clauses = vec!["updated_ts = excluded.updated_ts".to_owned()];
        if patch.enabled.is_some() {
            set_clauses.push("enabled = excluded.enabled".to_owned());
        }
        if patch.base_url.is_some() {
            set_clauses.push("base_url = excluded.base_url".to_owned());
        }
        if patch.username.is_some() {
            set_clauses.push("username = excluded.username".to_owned());
        }
        let mut changed = vec![if patch.invalidate_test { "1" } else { "0" }];
        if patch.base_url.is_some() {
            changed.push("base_url IS NOT excluded.base_url");
        }
        if patch.username.is_some() {
            changed.push("username IS NOT excluded.username");
        }
        let changed = changed.join(" OR ");
        for column in ["last_test_status", "last_test_detail", "last_test_ts"] {
            set_clauses.push(format!(
                "{column} = CASE WHEN {changed} THEN NULL ELSE {column} END"
            ));
        }
        let sql = format!(
            "INSERT INTO connector (id, enabled, base_url, username, updated_ts)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (id) DO UPDATE SET {}",
            set_clauses.join(", ")
        );
        conn.execute(
            &sql,
            params![id, i64::from(enabled), base_url, username, now_ts()],
        )
        .await?;

        let mut rows = conn
            .query(
                &format!(
                    "SELECT {} FROM connector WHERE id = ?1",
                    Self::CONNECTOR_COLUMNS
                ),
                params![id],
            )
            .await?;
        match rows.next().await? {
            Some(row) => Self::parse_connector_row(&row),
            None => Err(StoreError::NotFound {
                table: "connector",
                id: id.to_owned(),
            }),
        }
    }

    /// Records the result of a connector self-test, creating the row when
    /// it does not exist yet. Only the self-test fields (and
    /// `updated_ts`) are written; `enabled`, `base_url` and `username`
    /// are left untouched on an existing row, and land on their column
    /// defaults when the row is created here.
    pub async fn record_connector_test(
        &self,
        id: &str,
        passed: bool,
        detail: &str,
    ) -> Result<(), StoreError> {
        let conn = self.lock().await?;
        let status = if passed { "passed" } else { "failed" };
        let now = now_ts();
        conn.execute(
            "INSERT INTO connector
                     (id, enabled, last_test_status, last_test_detail, last_test_ts, updated_ts)
                 VALUES (?1, 0, ?2, ?3, ?4, ?4)
                 ON CONFLICT (id) DO UPDATE SET
                     last_test_status = excluded.last_test_status,
                     last_test_detail = excluded.last_test_detail,
                     last_test_ts = excluded.last_test_ts,
                     updated_ts = excluded.updated_ts",
            params![id, status, detail, now],
        )
        .await?;
        Ok(())
    }
}

/// Asks the engine whether the file is structurally sound before anything
/// reads or migrates it. `quick_check` skips the index cross-checks, so it
/// stays cheap; a database that fails it is refused with a legible
/// [`StoreError::Corrupt`] instead of surfacing later as a random engine
/// error half-way through a request. A file the engine cannot read at all
/// reaches the same variant through [`StoreError`]'s conversion.
async fn integrity_check(conn: &Connection) -> Result<(), StoreError> {
    let mut rows = conn.query("PRAGMA quick_check", ()).await?;
    let mut problems: Vec<String> = Vec::new();
    while let Some(row) = rows.next().await? {
        let line = match row.get_value(0)? {
            turso::Value::Text(text) => text,
            other => format!("{other:?}"),
        };
        if line != "ok" && problems.len() < 4 {
            problems.push(line.chars().take(200).collect());
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(StoreError::Corrupt {
            detail: problems.join("; "),
        })
    }
}

/// Reads a BLOB column as bytes; a NULL blob is an empty vector.
fn blob_column(row: &turso::Row, idx: usize) -> Result<Vec<u8>, StoreError> {
    match row.get_value(idx)? {
        turso::Value::Blob(bytes) => Ok(bytes),
        turso::Value::Null => Ok(Vec::new()),
        turso::Value::Text(text) => Ok(text.into_bytes()),
        other => Err(StoreError::UnexpectedValue {
            column: "evidence.content",
            value: format!("{other:?}"),
        }),
    }
}

/// Reads a `LENGTH(...)` column as a byte count. `LENGTH` of a NULL blob
/// is NULL, which means no content at all: zero bytes.
fn length_column(row: &turso::Row, idx: usize) -> Result<u64, StoreError> {
    match row.get_value(idx)? {
        turso::Value::Integer(length) => Ok(u64::try_from(length).unwrap_or(0)),
        turso::Value::Null => Ok(0),
        other => Err(StoreError::UnexpectedValue {
            column: "evidence.content length",
            value: format!("{other:?}"),
        }),
    }
}

/// Reads one non-negative integer field out of an evidence `meta_json`
/// object. A missing, negative, or non-numeric field contributes nothing.
fn meta_u64(value: &serde_json::Value, field: &str) -> u64 {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

/// Current time as unix seconds.
fn now_ts() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    i64::try_from(secs).unwrap_or(i64::MAX)
}
