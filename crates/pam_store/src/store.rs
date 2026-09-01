//! The [`Store`] handle: open, migrate, and a thin typed helper surface.
//!
//! Services (queue, policy, audit) own their richer queries and add them
//! alongside their own tasks; only helpers the spine needs today live
//! here.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

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
    txn_lock: tokio::sync::Mutex<()>,
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
            txn_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// The schema version currently recorded in the database.
    pub async fn schema_version(&self) -> Result<i64, StoreError> {
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
        let _guard = self.txn_lock.lock().await;
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
    ) -> Result<Vec<RequestRow>, StoreError> {
        let limit = limit
            .unwrap_or(DEFAULT_REQUEST_LIST_LIMIT)
            .clamp(1, MAX_REQUEST_LIST_LIMIT);
        let mut clauses: Vec<String> = Vec::new();
        let mut args: Vec<String> = Vec::new();
        for (column, value) in [
            ("repo", repo),
            ("caller_agent", agent),
            ("state", state.map(RequestState::as_str)),
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
        self.conn
            .execute(
                "INSERT INTO setting (key, value) VALUES (?1, ?2)
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .await?;
        Ok(())
    }
}

/// Current time as unix seconds.
fn now_ts() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    i64::try_from(secs).unwrap_or(i64::MAX)
}
