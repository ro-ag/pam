//! Embedded, ordered schema migrations tracked via `PRAGMA user_version`.
//!
//! Each migration moves the database to exactly one version; the runner
//! applies every migration newer than the file's recorded version inside
//! its own transaction. A database stamped with a version newer than the
//! binary knows is refused rather than guessed at.

use turso::Connection;

use crate::error::StoreError;

/// One schema migration: the version it produces and the SQL that gets there.
pub(crate) struct Migration {
    pub(crate) version: i64,
    pub(crate) sql: &'static str,
}

/// Every migration this binary knows, ordered by ascending version.
pub(crate) const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        sql: SCHEMA_V1,
    },
    Migration {
        version: 2,
        sql: SCHEMA_V2,
    },
    Migration {
        version: 3,
        sql: SCHEMA_V3,
    },
    Migration {
        version: 4,
        sql: SCHEMA_V4,
    },
    Migration {
        version: 5,
        sql: SCHEMA_V5,
    },
];

/// Highest schema version this binary can produce.
pub(crate) fn latest_version() -> i64 {
    MIGRATIONS.last().map_or(0, |m| m.version)
}

/// Reads the schema version currently recorded in the database.
pub(crate) async fn current_version(conn: &Connection) -> Result<i64, StoreError> {
    let mut rows = conn.query("PRAGMA user_version", ()).await?;
    // The pragma always yields one row; treat a missing row as a fresh db.
    match rows.next().await? {
        Some(row) => Ok(row.get(0)?),
        None => Ok(0),
    }
}

/// Applies every migration newer than the database's recorded version.
///
/// Idempotent on reopen: an up-to-date database is left untouched. A
/// database whose version is newer than this binary knows is refused
/// with [`StoreError::VersionTooNew`].
pub(crate) async fn run(conn: &Connection) -> Result<(), StoreError> {
    let current = current_version(conn).await?;
    let latest = latest_version();
    if current > latest {
        return Err(StoreError::VersionTooNew {
            found: current,
            supported: latest,
        });
    }
    for migration in MIGRATIONS.iter().filter(|m| m.version > current) {
        apply(conn, migration).await?;
    }
    Ok(())
}

/// Applies one migration inside its own transaction, rolling back on
/// failure so a botched migration never leaves a half-stamped database.
async fn apply(conn: &Connection, migration: &Migration) -> Result<(), StoreError> {
    conn.execute("BEGIN", ()).await?;
    let version = migration.version;
    let applied = async {
        conn.execute_batch(migration.sql).await?;
        conn.execute(&format!("PRAGMA user_version = {version}"), ())
            .await?;
        Ok::<(), StoreError>(())
    }
    .await;
    match applied {
        Ok(()) => {
            conn.execute("COMMIT", ()).await?;
            Ok(())
        }
        Err(err) => {
            // Best effort: the returned error is the one that matters.
            let _ = conn.execute("ROLLBACK", ()).await;
            Err(err)
        }
    }
}

/// Migration 1: the full spine schema.
///
/// `grant` is an SQL keyword, so the table name is quoted everywhere.
const SCHEMA_V1: &str = r#"
CREATE TABLE request (
    id           TEXT PRIMARY KEY,
    capability   TEXT NOT NULL,
    repo         TEXT NOT NULL,
    caller_agent TEXT NOT NULL,
    args_json    TEXT NOT NULL,
    state        TEXT NOT NULL CHECK (state IN
        ('queued','running','waiting_approval','done','refused','failed')),
    outcome      TEXT,
    created_ts   INTEGER NOT NULL,
    updated_ts   INTEGER NOT NULL
);
CREATE INDEX request_state_idx ON request (state);

CREATE TABLE audit (
    id         INTEGER PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES request (id),
    action     TEXT NOT NULL,
    decision   TEXT NOT NULL CHECK (decision IN
        ('allow','refuse','approve','deny','timeout')),
    actor      TEXT NOT NULL CHECK (actor IN ('policy','human','system')),
    detail     TEXT,
    ts         INTEGER NOT NULL
);
CREATE INDEX audit_request_idx ON audit (request_id);

CREATE TABLE evidence (
    id           TEXT PRIMARY KEY,
    request_id   TEXT NOT NULL REFERENCES request (id),
    kind         TEXT NOT NULL,
    content      BLOB,
    path         TEXT,
    content_hash TEXT NOT NULL,
    ts           INTEGER NOT NULL
);
CREATE INDEX evidence_request_idx ON evidence (request_id);

CREATE TABLE "grant" (
    id         INTEGER PRIMARY KEY,
    capability TEXT NOT NULL,
    scope      TEXT NOT NULL DEFAULT 'global',
    granted_ts INTEGER NOT NULL,
    revoked_ts INTEGER
);

CREATE TABLE approval (
    id           INTEGER PRIMARY KEY,
    request_id   TEXT NOT NULL REFERENCES request (id),
    capability   TEXT NOT NULL,
    requested_ts INTEGER NOT NULL,
    resolved_ts  INTEGER,
    resolution   TEXT CHECK (resolution IN ('approved','denied','timeout')),
    note         TEXT
);

CREATE TABLE caller (
    agent      TEXT NOT NULL,
    repo       TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    PRIMARY KEY (agent, repo)
);

CREATE TABLE setting (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

/// Migration 2: caller-chosen idempotency key on `request`, for in-flight
/// request deduplication by the queue manager. Nullable — most requests
/// never set one — and indexed for the dedupe lookup on enqueue.
const SCHEMA_V2: &str = r"
ALTER TABLE request ADD COLUMN idempotency_key TEXT;
CREATE INDEX request_idempotency_idx ON request (idempotency_key);
";

/// Migration 3: `model_job`, the history of the model layer's long-running
/// work.
///
/// A download or a verification is not a request — admin ops answer
/// synchronously and the transfer outlives them — so its progress and its
/// verdict live here instead of on a `request` row. The GUI reads the
/// table; a `running` row found at boot belonged to a daemon that is gone
/// and is failed with cause `daemon_restart` (the part file still
/// resumes).
const SCHEMA_V3: &str = r"
CREATE TABLE model_job (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN ('download','verify')),
    model_id    TEXT NOT NULL,
    source      TEXT,
    state       TEXT NOT NULL CHECK (state IN ('running','done','failed','cancelled')),
    bytes_done  INTEGER NOT NULL DEFAULT 0,
    bytes_total INTEGER,
    detail      TEXT,
    created_ts  INTEGER NOT NULL,
    updated_ts  INTEGER NOT NULL
);
CREATE INDEX model_job_state_idx ON model_job (state);
";

/// Migration 4: `evidence.meta_json` — small kind-specific metadata
/// alongside the blob.
///
/// A compact carries its compression figures, a summary the model
/// figures it was produced with. The GUI lists a request's evidence, and
/// the tokens-avoided odometer aggregates over the compacts, without
/// reading a single blob.
const SCHEMA_V4: &str = "ALTER TABLE evidence ADD COLUMN meta_json TEXT;";

/// Migration 5: `connector` — one row per connector (`github`, `jenkins`,
/// ...) holding its configuration and last self-test verdict.
///
/// Secrets never live here: only `base_url` and `username` are plain
/// configuration; the credential itself belongs to the OS keychain via
/// `pam_daemon`'s `SecretStore`.
const SCHEMA_V5: &str = "
CREATE TABLE connector (
  id TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  base_url TEXT,
  username TEXT,
  last_test_status TEXT CHECK (last_test_status IN ('passed', 'failed')),
  last_test_detail TEXT,
  last_test_ts INTEGER,
  updated_ts INTEGER NOT NULL
);
";
