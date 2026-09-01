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

    fn parse(value: &str) -> Result<Self, StoreError> {
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
    /// Current lifecycle state.
    pub state: RequestState,
    /// Final outcome, once there is one.
    pub outcome: Option<String>,
    /// Unix seconds when the row was created.
    pub created_ts: i64,
    /// Unix seconds of the last state change.
    pub updated_ts: i64,
}

/// Handle to the durable state database.
///
/// Async by design (the Turso engine drives its own I/O); the daemon
/// owns threading and task placement.
pub struct Store {
    /// Keeps the database itself alive alongside the connection.
    _db: Database,
    pub(crate) conn: Connection,
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
        Ok(Self { _db: db, conn })
    }

    /// The schema version currently recorded in the database.
    pub async fn schema_version(&self) -> Result<i64, StoreError> {
        migrations::current_version(&self.conn).await
    }

    /// Inserts a new request in the `queued` state.
    pub async fn insert_request(
        &self,
        id: &str,
        capability: &str,
        repo: &str,
        caller_agent: &str,
        args_json: &str,
    ) -> Result<(), StoreError> {
        let now = now_ts();
        self.conn
            .execute(
                "INSERT INTO request
                     (id, capability, repo, caller_agent, args_json, state,
                      outcome, created_ts, updated_ts)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?7)",
                params![
                    id,
                    capability,
                    repo,
                    caller_agent,
                    args_json,
                    RequestState::Queued.as_str(),
                    now
                ],
            )
            .await?;
        Ok(())
    }

    /// Reads one request by id, or `None` if it does not exist.
    pub async fn get_request(&self, id: &str) -> Result<Option<RequestRow>, StoreError> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, capability, repo, caller_agent, args_json,
                        state, outcome, created_ts, updated_ts
                 FROM request WHERE id = ?1",
                params![id],
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        let state: String = row.get(5)?;
        Ok(Some(RequestRow {
            id: row.get(0)?,
            capability: row.get(1)?,
            repo: row.get(2)?,
            caller_agent: row.get(3)?,
            args_json: row.get(4)?,
            state: RequestState::parse(&state)?,
            outcome: row.get(6)?,
            created_ts: row.get(7)?,
            updated_ts: row.get(8)?,
        }))
    }

    /// Moves a request to `state`, recording `outcome` and bumping
    /// `updated_ts`. Errors if the request does not exist.
    pub async fn update_request_state(
        &self,
        id: &str,
        state: RequestState,
        outcome: Option<&str>,
    ) -> Result<(), StoreError> {
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
