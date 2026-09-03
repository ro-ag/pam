//! The [`Store`] handle: open, migrate, and a thin typed helper surface.
//!
//! Services (queue, policy, audit) own their richer queries and add them
//! alongside their own tasks; only helpers the spine needs today live
//! here.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use turso::{Builder, Connection, Database, params};

use crate::error::StoreError;
use crate::migrations;

/// Default `limit` for [`Store::list_requests_filtered`] when the caller
/// passes `None`.
pub const DEFAULT_REQUEST_LIST_LIMIT: u64 = 100;

/// Hard upper bound on [`Store::list_requests_filtered`]'s `limit`; a
/// larger request is clamped, keeping the activity query bounded.
pub const MAX_REQUEST_LIST_LIMIT: u64 = 500;

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
    pub(crate) conn: Connection,
    /// Serializes [`Store::finish_request`] transactions: the connection
    /// is shared across tasks, and a statement issued between another
    /// task's `BEGIN` and `COMMIT` would join that transaction. Only
    /// `finish_request` opens transactions at runtime, so only it takes
    /// this lock.
    /// Serializes every statement on `conn`. turso refuses concurrent use
    /// of one connection outright (`Misuse("concurrent use forbidden")`),
    /// and the daemon drives this store from many tasks at once —
    /// executor, dispatcher, reaper, admin. Each method holds the lock for
    /// its statements; [`Self::finish_request`] holds it across its whole
    /// `BEGIN`..`COMMIT` window so no other statement can join or break
    /// the transaction.
    conn_lock: tokio::sync::Mutex<()>,
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
        let path = path.to_str().ok_or_else(|| StoreError::NonUtf8Path {
            path: path.to_path_buf(),
        })?;
        Self::init(Builder::new_local(path).build().await?).await
    }

    /// Opens a fresh in-memory database, for tests.
    pub async fn open_in_memory() -> Result<Self, StoreError> {
        Self::init(Builder::new_local(":memory:").build().await?).await
    }

    async fn init(db: Database) -> Result<Self, StoreError> {
        let conn = db.connect()?;
        conn.execute("PRAGMA foreign_keys = ON", ()).await?;
        conn.execute("PRAGMA busy_timeout = 5000", ()).await?;
        migrations::run(&conn).await?;
        Ok(Self {
            _db: db,
            conn,
            conn_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// The schema version currently recorded in the database.
    pub async fn schema_version(&self) -> Result<i64, StoreError> {
        let _guard = self.conn_lock.lock().await;
        migrations::current_version(&self.conn).await
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
        let _guard = self.conn_lock.lock().await;
        let now = now_ts();
        self.conn
            .execute(
                "INSERT INTO request
                     (id, capability, repo, caller_agent, args_json,
                      idempotency_key, state, outcome, created_ts, updated_ts)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, ?8)",
                params![
                    id,
                    capability,
                    repo,
                    caller_agent,
                    args_json,
                    idempotency_key,
                    RequestState::Queued.as_str(),
                    now
                ],
            )
            .await?;
        Ok(())
    }

    /// The `request` column list every row query selects, in the order
    /// [`Self::parse_request_row`] expects.
    const REQUEST_COLUMNS: &'static str = "id, capability, repo, caller_agent, args_json,
         idempotency_key, state, outcome, created_ts, updated_ts";

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
        })
    }

    /// Reads one request by id, or `None` if it does not exist.
    pub async fn get_request(&self, id: &str) -> Result<Option<RequestRow>, StoreError> {
        let _guard = self.conn_lock.lock().await;
        let mut rows = self
            .conn
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

    /// Finds the oldest in-flight request carrying `idempotency_key`.
    ///
    /// In-flight means state `queued`, `running`, or `waiting_approval`;
    /// terminal requests never match, so a retried key after completion
    /// starts a fresh execution. Used by the queue manager's dedupe check.
    pub async fn find_inflight_by_key(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<RequestRow>, StoreError> {
        let _guard = self.conn_lock.lock().await;
        let mut rows = self
            .conn
            .query(
                &format!(
                    "SELECT {} FROM request
                     WHERE idempotency_key = ?1
                       AND state IN ('queued','running','waiting_approval')
                     ORDER BY created_ts, id LIMIT 1",
                    Self::REQUEST_COLUMNS
                ),
                params![idempotency_key],
            )
            .await?;
        match rows.next().await? {
            Some(row) => Ok(Some(Self::parse_request_row(&row)?)),
            None => Ok(None),
        }
    }

    /// Finds the oldest in-flight request with the same shape: equal
    /// `capability`, `repo`, and `args_json` (byte equality of the JSON
    /// text). Fallback dedupe for envelopes without an idempotency key;
    /// matches regardless of whether the in-flight request carries one.
    pub async fn find_inflight_by_shape(
        &self,
        capability: &str,
        repo: &str,
        args_json: &str,
    ) -> Result<Option<RequestRow>, StoreError> {
        let _guard = self.conn_lock.lock().await;
        let mut rows = self
            .conn
            .query(
                &format!(
                    "SELECT {} FROM request
                     WHERE capability = ?1 AND repo = ?2 AND args_json = ?3
                       AND state IN ('queued','running','waiting_approval')
                     ORDER BY created_ts, id LIMIT 1",
                    Self::REQUEST_COLUMNS
                ),
                params![capability, repo, args_json],
            )
            .await?;
        match rows.next().await? {
            Some(row) => Ok(Some(Self::parse_request_row(&row)?)),
            None => Ok(None),
        }
    }

    /// Reads every `queued` request, oldest first (ties broken by id, and
    /// request ids are ULID-ordered). The queue manager rebuilds its lanes
    /// from this on boot.
    pub async fn list_queued_ordered(&self) -> Result<Vec<RequestRow>, StoreError> {
        let _guard = self.conn_lock.lock().await;
        let mut rows = self
            .conn
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

    /// Reads every `running` or `waiting_approval` row, oldest first —
    /// the rows a dead daemon left mid-flight. Crash recovery on boot
    /// fails each of them (cause `daemon_restart`) through
    /// [`Self::finish_request`] before the lanes are rebuilt; a live
    /// daemon never calls this.
    pub async fn list_stuck_ordered(&self) -> Result<Vec<RequestRow>, StoreError> {
        let _guard = self.conn_lock.lock().await;
        let mut rows = self
            .conn
            .query(
                &format!(
                    "SELECT {} FROM request
                     WHERE state IN ('running','waiting_approval')
                     ORDER BY created_ts, id",
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

    /// Moves a request to a **non-terminal** `state`, recording `outcome`
    /// and bumping `updated_ts`. Errors if the request does not exist.
    ///
    /// # Invariant: terminal transitions go through `finish_request`
    ///
    /// Every transition into a terminal state (`done`, `refused`,
    /// `failed`) must go through [`Self::finish_request`], which writes
    /// the state and its audit row in one transaction — every terminal
    /// state gets its own audit row, with no crash window in between and
    /// no silent paths. No code path may call this helper with a terminal
    /// state; a `debug_assert` enforces it as far as the type system
    /// cannot.
    pub async fn update_request_state(
        &self,
        id: &str,
        state: RequestState,
        outcome: Option<&str>,
    ) -> Result<(), StoreError> {
        let _guard = self.conn_lock.lock().await;
        debug_assert!(
            !state.is_terminal(),
            "terminal transitions must go through finish_request"
        );
        let changed = self
            .conn
            .execute(
                "UPDATE request SET state = ?2, outcome = ?3, updated_ts = ?4 WHERE id = ?1",
                params![id, state.as_str(), outcome, now_ts()],
            )
            .await?;
        if changed == 0 {
            return Err(StoreError::NotFound {
                table: "request",
                id: id.to_owned(),
            });
        }
        Ok(())
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
        let _guard = self.conn_lock.lock().await;
        self.conn.execute("BEGIN", ()).await?;
        let finished = self.finish_request_in_txn(id, state, outcome, audit).await;
        match finished {
            // COMMIT on both outcomes: the no-op path wrote nothing of
            // its own, and a concurrent statement that joined the
            // transaction window must not be rolled back with it.
            Ok(finished) => {
                self.conn.execute("COMMIT", ()).await?;
                Ok(finished)
            }
            Err(err) => {
                // Best effort: the returned error is the one that matters.
                let _ = self.conn.execute("ROLLBACK", ()).await;
                Err(err)
            }
        }
    }

    /// The statements inside [`Self::finish_request`]'s transaction.
    async fn finish_request_in_txn(
        &self,
        id: &str,
        state: RequestState,
        outcome: Option<&str>,
        audit: AuditEntry<'_>,
    ) -> Result<bool, StoreError> {
        let changed = self
            .conn
            .execute(
                "UPDATE request SET state = ?2, outcome = ?3, updated_ts = ?4
                 WHERE id = ?1 AND state IN ('queued','running','waiting_approval')",
                params![id, state.as_str(), outcome, now_ts()],
            )
            .await?;
        if changed == 0 {
            // Nothing matched: either the row is already terminal (the
            // idempotent no-op) or it does not exist at all.
            let mut rows = self
                .conn
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
        self.conn
            .execute(
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
        let _guard = self.conn_lock.lock().await;
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
        let mut rows = self.conn.query(&sql, actions).await?;
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
        let _guard = self.conn_lock.lock().await;
        let mut rows = self
            .conn
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
        let _guard = self.conn_lock.lock().await;
        self.conn
            .execute(
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
        let _guard = self.conn_lock.lock().await;
        let mut rows = self
            .conn
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
        let _guard = self.conn_lock.lock().await;
        let mut rows = self
            .conn
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
    pub async fn insert_grant(&self, capability: &str) -> Result<(), StoreError> {
        let _guard = self.conn_lock.lock().await;
        self.conn
            .execute(
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
    pub async fn revoke_grant(&self, capability: &str) -> Result<(), StoreError> {
        let _guard = self.conn_lock.lock().await;
        let changed = self
            .conn
            .execute(
                "UPDATE \"grant\" SET revoked_ts = ?2
                 WHERE capability = ?1 AND revoked_ts IS NULL",
                params![capability, now_ts()],
            )
            .await?;
        if changed == 0 {
            return Err(StoreError::NotFound {
                table: "grant",
                id: capability.to_owned(),
            });
        }
        Ok(())
    }

    /// Every grant row, revoked history included, newest first — the
    /// GUI's capability view.
    pub async fn list_grants(&self) -> Result<Vec<GrantRow>, StoreError> {
        let _guard = self.conn_lock.lock().await;
        let mut rows = self
            .conn
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
    /// into `1..=`[`MAX_REQUEST_LIST_LIMIT`], so the query stays bounded
    /// no matter what the caller asks for.
    pub async fn list_requests_filtered(
        &self,
        limit: Option<u64>,
        repo: Option<&str>,
        agent: Option<&str>,
        state: Option<RequestState>,
        capability: Option<&str>,
    ) -> Result<Vec<RequestRow>, StoreError> {
        let _guard = self.conn_lock.lock().await;
        let limit = limit
            .unwrap_or(DEFAULT_REQUEST_LIST_LIMIT)
            .clamp(1, MAX_REQUEST_LIST_LIMIT);
        let mut clauses: Vec<String> = Vec::new();
        let mut args: Vec<String> = Vec::new();
        for (column, value) in [
            ("repo", repo),
            ("caller_agent", agent),
            ("state", state.map(RequestState::as_str)),
            ("capability", capability),
        ] {
            if let Some(value) = value {
                args.push(value.to_owned());
                clauses.push(format!("{column} = ?{}", args.len()));
            }
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
        let mut rows = self.conn.query(&sql, args).await?;
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
        let _guard = self.conn_lock.lock().await;
        self.conn
            .execute(
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
        let _guard = self.conn_lock.lock().await;
        let mut rows = self
            .conn
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
        let _guard = self.conn_lock.lock().await;
        self.conn
            .execute(
                "INSERT INTO approval (request_id, capability, requested_ts)
                 VALUES (?1, ?2, ?3)",
                params![request_id, capability, now_ts()],
            )
            .await?;
        Ok(())
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
        let _guard = self.conn_lock.lock().await;
        let changed = self
            .conn
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
        let _guard = self.conn_lock.lock().await;
        let mut rows = self
            .conn
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

    /// Every unresolved approval joined with its request, oldest first —
    /// the GUI's pending list.
    pub async fn list_pending_approvals(&self) -> Result<Vec<PendingApproval>, StoreError> {
        let _guard = self.conn_lock.lock().await;
        let mut rows = self
            .conn
            .query(
                "SELECT a.request_id, a.capability, r.repo, r.caller_agent,
                        a.requested_ts
                 FROM approval a JOIN request r ON r.id = a.request_id
                 WHERE a.resolved_ts IS NULL
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
            });
        }
        Ok(out)
    }

    /// Reads a setting value (JSON text), or `None` if unset.
    pub async fn get_setting(&self, key: &str) -> Result<Option<String>, StoreError> {
        let _guard = self.conn_lock.lock().await;
        let mut rows = self
            .conn
            .query("SELECT value FROM setting WHERE key = ?1", params![key])
            .await?;
        match rows.next().await? {
            Some(row) => Ok(Some(row.get(0)?)),
            None => Ok(None),
        }
    }

    /// Writes a setting value (JSON text), replacing any previous value.
    pub async fn set_setting(&self, key: &str, value: &str) -> Result<(), StoreError> {
        let _guard = self.conn_lock.lock().await;
        self.conn
            .execute(
                "INSERT INTO setting (key, value) VALUES (?1, ?2)
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .await?;
        Ok(())
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
        let _guard = self.conn_lock.lock().await;
        self.conn
            .execute(
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
        let _guard = self.conn_lock.lock().await;
        self.conn
            .execute(
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
        let _guard = self.conn_lock.lock().await;
        self.conn
            .execute(
                "UPDATE model_job
                    SET state = ?2, detail = ?3, updated_ts = ?4
                  WHERE id = ?1 AND state = 'running'",
                params![id, state, detail, now_ts()],
            )
            .await?;
        Ok(())
    }

    /// The most recent model jobs, newest first, bounded by `limit`
    /// (clamped into `1..=`[`MAX_REQUEST_LIST_LIMIT`]).
    pub async fn list_model_jobs(&self, limit: u64) -> Result<Vec<ModelJobRow>, StoreError> {
        let _guard = self.conn_lock.lock().await;
        let limit = limit.clamp(1, MAX_REQUEST_LIST_LIMIT);
        let mut rows = self
            .conn
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
        let _guard = self.conn_lock.lock().await;
        let changed = self
            .conn
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
        let _guard = self.conn_lock.lock().await;
        let content_hash = hex::encode(Sha256::digest(content));
        self.conn
            .execute(
                "INSERT INTO evidence
                     (id, request_id, kind, content, path, content_hash, meta_json, ts)
                 VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7)",
                params![
                    id,
                    request_id,
                    kind,
                    content.to_vec(),
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
        let _guard = self.conn_lock.lock().await;
        let mut rows = self
            .conn
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
        let _guard = self.conn_lock.lock().await;
        let mut rows = self
            .conn
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
        let _guard = self.conn_lock.lock().await;
        let mut rows = self
            .conn
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

    /// The `evidence` rows an evidence-window pass removes: older than
    /// `cutoff_ts`, not `keep_kind`, and hanging off a request that has
    /// already finished.
    ///
    /// A running request keeps its evidence whatever its age — the
    /// executor is still writing it, and a half-pruned working set is
    /// worse than an old one.
    const EVIDENCE_PRUNE_FILTER: &'static str = "ts < ?1 AND kind <> ?2 AND request_id IN \
         (SELECT id FROM request WHERE state IN ('done','refused','failed'))";

    /// The `request` rows an audit-window pass removes: terminal, and
    /// untouched since `cutoff_ts`.
    const REQUEST_PRUNE_FILTER: &'static str =
        "state IN ('done','refused','failed') AND updated_ts < ?1";

    /// The same rows as a subquery, for the child tables.
    const REQUEST_PRUNE_CHILDREN: &'static str = "request_id IN (SELECT id FROM request WHERE \
         state IN ('done','refused','failed') AND updated_ts < ?1)";

    /// Deletes evidence rows older than `cutoff_ts` whose kind is not
    /// `keep_kind` and whose request is already terminal.
    ///
    /// This is the evidence half of retention: the bulky blobs go first
    /// and the verdict (`keep_kind`) stays, so activity history keeps
    /// reading straight after a pass. One transaction under the
    /// connection lock; the figures are counted before the delete, so the
    /// report is exact whatever the engine reports for a multi-row
    /// statement.
    pub async fn prune_evidence_before(
        &self,
        cutoff_ts: i64,
        keep_kind: &str,
    ) -> Result<EvidencePrune, StoreError> {
        let _guard = self.conn_lock.lock().await;
        self.conn.execute("BEGIN", ()).await?;
        let pruned = self.prune_evidence_in_txn(cutoff_ts, keep_kind).await;
        self.end_txn(pruned).await
    }

    /// The statements inside [`Self::prune_evidence_before`]'s transaction.
    async fn prune_evidence_in_txn(
        &self,
        cutoff_ts: i64,
        keep_kind: &str,
    ) -> Result<EvidencePrune, StoreError> {
        let filter = Self::EVIDENCE_PRUNE_FILTER;
        let (rows, bytes) = self
            .measure(
                &format!(
                    "SELECT COUNT(*), COALESCE(SUM(LENGTH(content)), 0) \
                     FROM evidence WHERE {filter}"
                ),
                params![cutoff_ts, keep_kind],
            )
            .await?;
        if rows > 0 {
            self.conn
                .execute(
                    &format!("DELETE FROM evidence WHERE {filter}"),
                    params![cutoff_ts, keep_kind],
                )
                .await?;
        }
        Ok(EvidencePrune { rows, bytes })
    }

    /// Deletes terminal requests older than `cutoff_ts` together with
    /// their audit, approval, and evidence rows — children first, one
    /// transaction under the connection lock.
    ///
    /// This is the audit half of retention, and the destructive one: a
    /// record leaves whole, verdict included, so nothing dangles and the
    /// foreign keys stay satisfied. In-flight requests are never touched,
    /// however old they look.
    pub async fn prune_requests_before(&self, cutoff_ts: i64) -> Result<RequestPrune, StoreError> {
        let _guard = self.conn_lock.lock().await;
        self.conn.execute("BEGIN", ()).await?;
        let pruned = self.prune_requests_in_txn(cutoff_ts).await;
        self.end_txn(pruned).await
    }

    /// The statements inside [`Self::prune_requests_before`]'s transaction.
    async fn prune_requests_in_txn(&self, cutoff_ts: i64) -> Result<RequestPrune, StoreError> {
        let children = Self::REQUEST_PRUNE_CHILDREN;
        let requests_filter = Self::REQUEST_PRUNE_FILTER;
        let (evidence_rows, evidence_bytes) = self
            .measure(
                &format!(
                    "SELECT COUNT(*), COALESCE(SUM(LENGTH(content)), 0) \
                     FROM evidence WHERE {children}"
                ),
                params![cutoff_ts],
            )
            .await?;
        let (audit_rows, _) = self
            .measure(
                &format!("SELECT COUNT(*), 0 FROM audit WHERE {children}"),
                params![cutoff_ts],
            )
            .await?;
        let (approvals, _) = self
            .measure(
                &format!("SELECT COUNT(*), 0 FROM approval WHERE {children}"),
                params![cutoff_ts],
            )
            .await?;
        let (requests, _) = self
            .measure(
                &format!("SELECT COUNT(*), 0 FROM request WHERE {requests_filter}"),
                params![cutoff_ts],
            )
            .await?;
        if requests > 0 {
            // Children first: the foreign keys point at `request`.
            for sql in [
                format!("DELETE FROM evidence WHERE {children}"),
                format!("DELETE FROM approval WHERE {children}"),
                format!("DELETE FROM audit WHERE {children}"),
                format!("DELETE FROM request WHERE {requests_filter}"),
            ] {
                self.conn.execute(&sql, params![cutoff_ts]).await?;
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

    /// Reads one `SELECT count, bytes` row as a `(u64, u64)` pair. A
    /// missing row or a negative figure reads as zero: a prune report
    /// never invents work it did not do.
    async fn measure<P: turso::IntoParams>(
        &self,
        sql: &str,
        params: P,
    ) -> Result<(u64, u64), StoreError> {
        let mut rows = self.conn.query(sql, params).await?;
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

    /// Closes an open transaction around `result`: `COMMIT` when the
    /// statements succeeded, best-effort `ROLLBACK` when they did not —
    /// the original error is the one worth returning.
    async fn end_txn<T>(&self, result: Result<T, StoreError>) -> Result<T, StoreError> {
        match result {
            Ok(value) => {
                self.conn.execute("COMMIT", ()).await?;
                Ok(value)
            }
            Err(err) => {
                let _ = self.conn.execute("ROLLBACK", ()).await;
                Err(err)
            }
        }
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
        let _guard = self.conn_lock.lock().await;
        let mut rows = self
            .conn
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
        let _guard = self.conn_lock.lock().await;
        let mut rows = self
            .conn
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
        let _guard = self.conn_lock.lock().await;
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
        let sql = format!(
            "INSERT INTO connector (id, enabled, base_url, username, updated_ts)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (id) DO UPDATE SET {}",
            set_clauses.join(", ")
        );
        self.conn
            .execute(
                &sql,
                params![id, i64::from(enabled), base_url, username, now_ts()],
            )
            .await?;

        let mut rows = self
            .conn
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
        let _guard = self.conn_lock.lock().await;
        let status = if passed { "passed" } else { "failed" };
        let now = now_ts();
        self.conn
            .execute(
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
