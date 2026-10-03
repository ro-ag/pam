//! Embedded, ordered schema migrations tracked via `PRAGMA user_version`.
//!
//! Each migration moves the database to exactly one version; the runner
//! applies every migration newer than the file's recorded version inside
//! its own transaction. A database stamped with a version newer than the
//! binary knows is refused rather than guessed at.

use rusqlite::{Connection, TransactionBehavior};

use crate::error::{StoreError, engine};

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
    Migration {
        version: 6,
        sql: SCHEMA_V6,
    },
    Migration {
        version: 7,
        sql: SCHEMA_V7,
    },
    Migration {
        version: 8,
        sql: SCHEMA_V8,
    },
    Migration {
        version: 9,
        sql: SCHEMA_V9,
    },
    Migration {
        version: 10,
        sql: SCHEMA_V10,
    },
    Migration {
        version: 11,
        sql: SCHEMA_V11,
    },
    Migration {
        version: 12,
        sql: SCHEMA_V12,
    },
    Migration {
        version: 13,
        sql: SCHEMA_V13,
    },
    Migration {
        version: ENGINE_BOUNDARY,
        sql: SCHEMA_V14,
    },
];

/// The schema version at which the store's engine changed. Every database
/// written by the previous engine, and by every pam release up to 0.4.3, is
/// below it; a database at or above it has been opened, checked and stamped
/// by this engine. See [`SCHEMA_V14`].
pub(crate) const ENGINE_BOUNDARY: i64 = 14;

/// `PAM1`, the application id migration 14 stamps into the database header.
pub(crate) const APPLICATION_ID: i64 = 0x5041_4D31;

/// Migration 14: the engine boundary. No table changes.
///
/// It exists for two reasons. First, the version stamp: a pam built on the
/// previous engine knows schema versions up to 13 at most (11 in release
/// 0.4.3) and refuses anything newer before it reads a row, so a database
/// this engine has taken over is never opened by a binary that predates the
/// take-over; the way back is the `pre-sqlite` backup (see `backup`).
/// Second, the mark: the one-time work of the first open by this engine (a
/// copy of the files as found, the full integrity and foreign-key checks) is
/// done exactly when the version is below this one, so stamping it is what
/// keeps that work from repeating.
///
/// The application id names the file as pam's in its header, where `file(1)`
/// and the open path can read it without the engine. It is written in the
/// same transaction as the version.
const SCHEMA_V14: &str = "PRAGMA application_id = 1346456881;";

/// Migration 13: where a request entered the daemon, on its row.
///
/// - `ingress` is the plane the request arrived on: `public` (the public
///   listener) or `admin` (submitted by the private administration plane on a
///   human's behalf). Rows written before this migration, and rows of a
///   writer that does not say, are `public`: `admin` is only ever recorded
///   for a request that provably entered on the private plane.
/// - `peer_uid` and `peer_pid` are the kernel's view of the connection the
///   request arrived on, where the platform reports one; NULL otherwise (the
///   legacy listener, Windows, an administration submission).
/// - `relayed` is the client's own statement that it came through a session
///   relay, in which case the peer is the relay process.
///
/// All of it is attribution. Nothing is authorized by these columns.
const SCHEMA_V13: &str = "
ALTER TABLE request ADD COLUMN ingress TEXT NOT NULL DEFAULT 'public' CHECK (ingress IN ('public', 'admin'));
ALTER TABLE request ADD COLUMN peer_uid INTEGER;
ALTER TABLE request ADD COLUMN peer_pid INTEGER;
ALTER TABLE request ADD COLUMN relayed INTEGER NOT NULL DEFAULT 0 CHECK (relayed IN (0, 1));
";

/// Migration 12: indexes for the hot scans, scoped revocation, immutability.
///
/// - The Activity list (`ORDER BY created_ts DESC, id DESC LIMIT n`), both
///   prune passes (`updated_ts`, evidence `ts`) and the compression odometer
///   (`kind`, `ts`) used to scan and sort their whole table under the
///   connection lock; each gets the index its ordering needs.
/// - `grant.revoked_seq` numbers revocations in the order they happened, so a
///   request is invalidated only by a revocation that is both later than its
///   admission and about a capability it depends on. Rows revoked before this
///   migration are ranked by `revoked_ts`; revocations inside one second share
///   the highest rank of that second, which can only invalidate more, never
///   less.
/// - Audit rows are append-only and an evidence view's bytes and identity are
///   immutable: the triggers refuse any `UPDATE` of `audit`, and any `UPDATE`
///   of `evidence_view` other than retention's tombstone (blob to NULL with
///   every identity column unchanged). Retention still deletes whole records.
const SCHEMA_V12: &str = r#"
CREATE INDEX request_created_idx ON request (created_ts DESC, id DESC);
CREATE INDEX request_updated_idx ON request (updated_ts, id);
CREATE INDEX evidence_ts_idx ON evidence (ts, id);
CREATE INDEX evidence_kind_ts_idx ON evidence (kind, ts);
ALTER TABLE "grant" ADD COLUMN revoked_seq INTEGER;
UPDATE "grant" SET revoked_seq = (
    SELECT COUNT(*) FROM "grant" earlier
    WHERE earlier.revoked_ts IS NOT NULL AND earlier.revoked_ts <= "grant".revoked_ts
) WHERE revoked_ts IS NOT NULL;
CREATE INDEX grant_capability_idx ON "grant" (capability);
CREATE TRIGGER audit_append_only BEFORE UPDATE ON audit
BEGIN
    SELECT RAISE(ABORT, 'audit rows are append-only');
END;
CREATE TRIGGER evidence_view_immutable BEFORE UPDATE ON evidence_view
WHEN NEW.view_blob IS NOT NULL
  OR NEW.evidence_id IS NOT OLD.evidence_id
  OR NEW.request_id IS NOT OLD.request_id
  OR NEW.repository IS NOT OLD.repository
  OR NEW.origin_json IS NOT OLD.origin_json
  OR NEW.identity_json IS NOT OLD.identity_json
  OR NEW.map_json IS NOT OLD.map_json
  OR NEW.view_id IS NOT OLD.view_id
  OR NEW.view_sha256 IS NOT OLD.view_sha256
  OR NEW.view_bytes IS NOT OLD.view_bytes
BEGIN
    SELECT RAISE(ABORT, 'evidence views are immutable');
END;
"#;

const SCHEMA_V11: &str = "CREATE TABLE landing_session(request_id TEXT PRIMARY KEY REFERENCES request(id) ON DELETE CASCADE, revision INTEGER NOT NULL CHECK(revision>=0), document TEXT NOT NULL CHECK(length(CAST(document AS BLOB))<=131072));";

/// Highest schema version this binary can produce.
#[cfg(test)]
pub(crate) fn latest_version() -> i64 {
    MIGRATIONS.last().map_or(0, |m| m.version)
}

/// Reads the schema version currently recorded in the database.
pub(crate) fn current_version(conn: &Connection) -> Result<i64, StoreError> {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(engine)
}

/// Applies every migration of `migrations` newer than the database's
/// recorded version.
///
/// Idempotent on reopen: an up-to-date database is left untouched. A
/// database whose version is newer than the last of `migrations` is refused
/// with [`StoreError::VersionTooNew`]: a binary never guesses at a schema it
/// does not know. That refusal is the whole downgrade story, and it holds
/// for binaries built on the previous engine too, which run this same check
/// against the version this engine stamps (see [`SCHEMA_V14`]).
///
/// The list is [`MIGRATIONS`] everywhere but in tests that stand an older or
/// a later binary next to a file.
pub(crate) fn run_with(conn: &mut Connection, migrations: &[Migration]) -> Result<(), StoreError> {
    let current = current_version(conn)?;
    let latest = migrations.last().map_or(0, |m| m.version);
    if current > latest {
        return Err(StoreError::VersionTooNew {
            found: current,
            supported: latest,
        });
    }
    for migration in migrations.iter().filter(|m| m.version > current) {
        apply(conn, migration)?;
    }
    Ok(())
}

/// The application id currently recorded in the database.
pub(crate) fn application_id(conn: &Connection) -> Result<i64, StoreError> {
    conn.pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(engine)
}

/// Applies one migration inside its own transaction, so a botched migration
/// never leaves a half-stamped database: the schema change and the version
/// stamp commit together, and an error (or a failed `COMMIT`) rolls both
/// back when the transaction is dropped.
fn apply(conn: &mut Connection, migration: &Migration) -> Result<(), StoreError> {
    let txn = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(engine)?;
    txn.execute_batch(migration.sql).map_err(engine)?;
    // An integer of ours, not caller text: the pragma takes no bound value.
    txn.execute_batch(&format!("PRAGMA user_version = {}", migration.version))
        .map_err(engine)?;
    txn.commit().map_err(engine)
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

/// Durable expiry and post-gate queue authorization. Legacy rows default closed.
const SCHEMA_V6: &str = "
ALTER TABLE request ADD COLUMN expires_at_ms INTEGER;
ALTER TABLE request ADD COLUMN authorization_revision INTEGER;
ALTER TABLE request ADD COLUMN queue_authorized INTEGER NOT NULL DEFAULT 0 CHECK (queue_authorized IN (0, 1));
";

/// Immutable public views survive source retention as metadata-only tombstones.
const SCHEMA_V7: &str = "
CREATE TABLE evidence_view (
 evidence_id TEXT PRIMARY KEY,
 request_id TEXT NOT NULL REFERENCES request(id),
 repository TEXT NOT NULL,
 origin_json TEXT NOT NULL,
 identity_json TEXT NOT NULL,
 map_json TEXT NOT NULL,
 view_id TEXT NOT NULL UNIQUE,
 view_sha256 TEXT NOT NULL,
 view_bytes INTEGER NOT NULL,
 view_blob BLOB,
 expired_at INTEGER
);
CREATE INDEX evidence_view_request_idx ON evidence_view(request_id);
CREATE TABLE evidence_read_allowance (
 request_id TEXT NOT NULL REFERENCES request(id),
 repository TEXT NOT NULL,
 started_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 remaining_bytes INTEGER NOT NULL,
 remaining_pages INTEGER NOT NULL,
 PRIMARY KEY(request_id, repository)
);
";

/// Immutable workflow identities, retained exactly as long as their request.
const SCHEMA_V8: &str = "
CREATE TABLE correlation_target (
 request_id TEXT PRIMARY KEY REFERENCES request(id),
 canonical_json TEXT NOT NULL CHECK(LENGTH(CAST(canonical_json AS BLOB))<=16384)
);
CREATE TABLE correlation_step (
 request_id TEXT NOT NULL REFERENCES correlation_target(request_id),
 step_id TEXT NOT NULL CHECK(LENGTH(CAST(step_id AS BLOB)) BETWEEN 1 AND 256),
 canonical_json TEXT NOT NULL CHECK(LENGTH(CAST(canonical_json AS BLOB))<=8192),
 PRIMARY KEY(request_id,step_id)
);
";

const SCHEMA_V9: &str = r"
CREATE TABLE request_budget (
 request_id TEXT PRIMARY KEY REFERENCES request(id) ON DELETE CASCADE,
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 256),
 http_calls INTEGER NOT NULL DEFAULT 0 CHECK(http_calls BETWEEN 0 AND 128),
 http_bytes INTEGER NOT NULL DEFAULT 0 CHECK(http_bytes BETWEEN 0 AND 134217728),
 command_bytes INTEGER NOT NULL DEFAULT 0 CHECK(command_bytes BETWEEN 0 AND 134217728)
);
CREATE TABLE flow_journal (
 request_id TEXT PRIMARY KEY REFERENCES request(id) ON DELETE CASCADE,
 schema_version INTEGER NOT NULL CHECK(schema_version=1),
 flow_digest TEXT NOT NULL CHECK(length(CAST(flow_digest AS BLOB))=64),
 repository TEXT NOT NULL CHECK(length(CAST(repository AS BLOB)) BETWEEN 1 AND 4096),
 input_fingerprint TEXT NOT NULL CHECK(length(CAST(input_fingerprint AS BLOB))=64),
 revision INTEGER NOT NULL CHECK(revision>=0),
 state TEXT NOT NULL CHECK(state IN ('ready','prepared','completed','uncertain')),
 step_id TEXT CHECK(step_id IS NULL OR length(CAST(step_id AS BLOB)) BETWEEN 1 AND 256),
 attempt INTEGER NOT NULL CHECK(attempt BETWEEN 0 AND 256),
 effectful INTEGER NOT NULL CHECK(effectful IN (0,1)),
 checkpoint_json TEXT NOT NULL CHECK(length(CAST(checkpoint_json AS BLOB))<=131072),
 evidence_refs_json TEXT NOT NULL CHECK(length(CAST(evidence_refs_json AS BLOB))<=16384)
);
";

const SCHEMA_V10: &str = "
ALTER TABLE request ADD COLUMN resume_at_ms INTEGER;
CREATE TABLE correlation_membership (
 request_id TEXT NOT NULL,
 step_id TEXT NOT NULL,
 members_json TEXT NOT NULL CHECK(length(CAST(members_json AS BLOB))<=16384),
 PRIMARY KEY(request_id,step_id),
 FOREIGN KEY(request_id,step_id) REFERENCES correlation_step(request_id,step_id) ON DELETE CASCADE
);
";
