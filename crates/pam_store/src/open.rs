//! Opening and closing the database.
//!
//! Nothing here depends on how the engine library was compiled. Every
//! setting is applied to the connection at run time and, where the engine can
//! be asked, read back; a setting that did not take refuses the open.
//!
//! # The open path for a file
//!
//! 1. **Look, without the engine** (`header`). No file: a new database. An
//!    empty file with no log is a new database only in a directory pam has
//!    never used; where a backup, a log, the daemon's lock, flows or model
//!    records say pam has run before, it is refused, because an empty file is
//!    not a database pam wrote. A file that cannot be a database is refused
//!    as it is. Otherwise the header's schema version says whether an upgrade
//!    is pending.
//! 2. **Back up before anything can change** (`backup`). When the header's
//!    version is below the newest this binary knows, every database file is
//!    copied as found. Below [`migrations::ENGINE_BOUNDARY`] that copy is the
//!    one-time `pre-sqlite` backup; at or above it, a `pre-v<N>` migration
//!    backup. A copy that cannot be written refuses the open
//!    ([`StoreError::UpgradeBackup`]); nothing has been touched.
//! 3. **Open and harden.** The engine replays the write-ahead log into its
//!    view of the database; that rewrites the log's index and nothing else.
//!    The connection is told not to fold the log into the main file when it
//!    closes, and keeps that setting for life: only [`shut`] folds it.
//! 4. **Read the real version**, through the log. If the header had only
//!    lagged (the upgrade was committed but never checkpointed), the backup
//!    made in step 2 is not of a pre-upgrade database and is removed or
//!    relabelled.
//! 5. **Check before any write.** A database below the engine boundary gets
//!    the full `integrity_check` and `foreign_key_check`, whatever its size:
//!    this is the one moment another engine's pages meet this engine's
//!    checker. Every other open runs `quick_check` on files up to 256 MiB.
//!    A failure refuses the open ([`StoreError::Corrupt`], naming the backup
//!    and what to do); the files are as they were found.
//! 6. **Journal and durability settings**, then, for a database below the
//!    boundary, a checkpoint that folds the previous engine's log into the
//!    main file before this engine appends to it.
//! 7. **Migrate.** Each migration is one transaction that also stamps its
//!    version; migration 14 is the boundary stamp.
//! 8. **Checkpoint**, when anything was migrated or the header lagged, so
//!    the main file's header carries the version the next open decides on.
//! 9. **Retention** of migration backups, and the read-only second
//!    connection.

use std::path::Path;
use std::time::Duration;

use rusqlite::config::DbConfig;
use rusqlite::limits::Limit;
use rusqlite::{Connection, OpenFlags};

use crate::backup::{self, Backup, Kind};
use crate::error::{EngineError, StoreError, engine};
use crate::header::{self, OnDisk};
use crate::migrations::{self, Migration};

/// How long a statement waits for another connection's lock (an operator's
/// shell, a backup tool) before it answers busy.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the closing checkpoint waits for another connection's lock. The
/// fold at close is best effort (a log it cannot fold stays for the next
/// open, nothing is lost), so it must not hold a daemon's shutdown for the
/// whole [`BUSY_TIMEOUT`]: on Windows a lock still held by another
/// connection made every such close wait the full five seconds.
const CLOSE_BUSY_TIMEOUT: Duration = Duration::from_millis(250);

/// Largest string or blob the connection accepts. Evidence blobs and views
/// run to 64 MiB; nothing the store writes comes near twice that.
const MAX_VALUE_BYTES: i32 = 128 * 1024 * 1024;

/// The write-ahead log is truncated back to this size after a checkpoint,
/// so one large write does not leave a large file behind for good.
const WAL_SIZE_LIMIT_BYTES: i64 = 16 * 1024 * 1024;

/// Statements kept prepared. The store has about 130 fixed statements; the
/// hot paths use far fewer, and the cache evicts the least recently used.
const STATEMENT_CACHE: usize = 128;

/// Findings of a structural check kept in the refusal.
const MAX_FINDINGS: usize = 4;

/// Where the database lives.
pub(crate) enum Target {
    /// A file, created if missing. `check` runs the structural check before
    /// anything else reads or writes it.
    File { path: String, check: bool },
    /// A private in-memory database, for tests.
    Memory,
}

/// An opened database.
pub(crate) struct Opened {
    /// The one connection that writes.
    pub(crate) writer: Connection,
    /// A second, read-only connection to the same file. `None` for an
    /// in-memory database, which has nothing a second connection could
    /// open.
    pub(crate) reader: Option<Connection>,
}

/// Opens, configures, checks and migrates. Blocks; call it from a blocking
/// thread.
pub(crate) fn open(target: &Target) -> Result<Opened, StoreError> {
    open_with(target, migrations::MIGRATIONS)
}

/// [`open`] for a binary that knows `known` as its migrations. The list is
/// [`migrations::MIGRATIONS`] everywhere but in the tests that stand in for a
/// later binary, one with a migration this one does not have yet.
pub(crate) fn open_with(target: &Target, known: &[Migration]) -> Result<Opened, StoreError> {
    match target {
        Target::Memory => {
            let mut writer =
                Connection::open_in_memory_with_flags(writer_flags()).map_err(engine)?;
            harden(&writer)?;
            keep_deleted_content_out(&writer)?;
            migrations::run_with(&mut writer, known)?;
            Ok(Opened {
                writer,
                reader: None,
            })
        }
        Target::File { path, check } => open_file(path, *check, known),
    }
}

// Not `URI`: the path is a path. `NO_MUTEX`: the gate already gives the
// connection to one thread at a time.
fn writer_flags() -> OpenFlags {
    OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
}

/// The open path for a file; see the module documentation for the steps.
fn open_file(path: &str, quick_check: bool, known: &[Migration]) -> Result<Opened, StoreError> {
    let state = Path::new(path);
    let latest = known.last().map_or(0, |migration| migration.version);
    let on_disk = header::inspect(state)?;
    let header_version = match on_disk {
        OnDisk::Database(header) => Some(header.user_version),
        OnDisk::Absent | OnDisk::Empty => None,
    };
    let mut backup = match on_disk {
        OnDisk::Database(header) if header.user_version < latest => {
            tracing::info!(
                schema = header.user_version,
                previous_engine = header.previous_engine,
                "the state database needs an upgrade; copying its files first"
            );
            Some(backup::take(
                state,
                pending_kind(header.user_version, latest),
            )?)
        }
        _ => None,
    };

    let mut writer =
        Connection::open_with_flags(literal_path(path), writer_flags()).map_err(engine)?;
    // For the connection's whole life: closing it must never fold the log
    // into the main file on its own. A database that is refused is left
    // exactly as it was found, a store that is dropped does no I/O in its
    // destructor, and only `shut` writes the log back.
    set(&writer, DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    harden(&writer)?;
    keep_deleted_content_out(&writer)?;

    let found = migrations::current_version(&writer)
        .map_err(|error| name_the_copy(error, backup.as_ref(), state))?;
    if found > latest {
        // Not a pre-upgrade database after all: the header had lagged.
        if let Some(unneeded) = backup.take() {
            backup::discard(&unneeded);
        }
        return Err(StoreError::VersionTooNew {
            found,
            supported: latest,
        });
    }
    if found >= migrations::ENGINE_BOUNDARY {
        // A version from pam's range without pam's mark is somebody else's
        // database. Refused here, before the first statement that writes.
        let application_id = migrations::application_id(&writer)?;
        if application_id != migrations::APPLICATION_ID {
            if let Some(unneeded) = backup.take() {
                backup::discard(&unneeded);
            }
            return Err(StoreError::NotPamDatabase {
                found: application_id,
                expected: migrations::APPLICATION_ID,
            });
        }
    }
    let existing = header_version.is_some();
    backup = settle_backup(backup, existing && found < latest, found, latest);
    // Below the boundary the file has never been checked by this engine.
    let first_open_by_this_engine = existing && found < migrations::ENGINE_BOUNDARY;
    if first_open_by_this_engine {
        full_check(&writer).map_err(|error| name_the_copy(error, backup.as_ref(), state))?;
    } else if quick_check {
        integrity_check(&writer).map_err(|error| name_the_copy(error, backup.as_ref(), state))?;
    } else {
        tracing::debug!("skipping the boot integrity check for this database");
    }
    durable_journal(&writer)?;
    if first_open_by_this_engine {
        // The previous engine's log goes into the main file, under this
        // engine's hands, before this engine appends to it.
        checkpoint(&writer, "before the first migration by this engine");
    }
    if let Err(error) = migrations::run_with(&mut writer, known) {
        if let Some(kept) = &backup {
            tracing::error!(
                backup = %kept.dir.display(),
                "the upgrade failed; the database files as they were before it are in the backup"
            );
        }
        return Err(error);
    }
    if header_version != Some(latest) {
        // New, migrated, or stamped only in the log: put the version where
        // the next open reads it.
        checkpoint(&writer, "after opening");
    }
    if let Some(made) = &backup {
        tracing::info!(
            from = found,
            to = latest,
            backup = %made.dir.display(),
            "the state database was upgraded; its files as they were before are in the backup"
        );
        if matches!(made.kind, Kind::PreSchema(_)) {
            backup::prune_migration_backups(&backup::root_for(state));
        }
    }
    let reader = open_reader(path)?;
    Ok(Opened {
        writer,
        reader: Some(reader),
    })
}

/// The kind of backup a database at `version` gets before it is upgraded.
fn pending_kind(version: i64, latest: i64) -> Kind {
    if version < migrations::ENGINE_BOUNDARY {
        Kind::PreSqlite
    } else {
        Kind::PreSchema(latest)
    }
}

/// Reconciles the backup made from the header's version with the version the
/// engine read through the log.
fn settle_backup(
    backup: Option<Backup>,
    upgrade_pending: bool,
    found: i64,
    latest: i64,
) -> Option<Backup> {
    let backup = backup?;
    if !upgrade_pending {
        // The upgrade had already been committed; this is a copy of an
        // upgraded database under a pre-upgrade name.
        backup::discard(&backup);
        return None;
    }
    Some(backup::relabel(backup, pending_kind(found, latest)))
}

/// Tells a corruption refusal where a copy of the database is. Other errors
/// pass through.
///
/// With a backup made by this open (an upgrade was pending), that copy is
/// the database exactly as it was found, and the refusal spells out the
/// three ways on. Without one (an ordinary open), it points at the newest
/// backup an earlier upgrade left, when there is one, and says how old that
/// is.
fn name_the_copy(error: StoreError, backup: Option<&Backup>, state: &Path) -> StoreError {
    let StoreError::Corrupt { detail } = error else {
        return error;
    };
    let detail = if let Some(backup) = backup {
        format!(
            "{detail}. This was the first open of this database by this version of \
             pam; it changed nothing, and a copy of the database files exactly as \
             they were found is in {dir}. To recover, stop the daemon, then either \
             (a) go back: install the pam release that wrote the database, copy the \
             files in that directory over the state file and its -wal next to the \
             backup directory, and start it; or (b) salvage: run `sqlite3 <a copy \
             of the state file> .recover` and inspect the result; or (c) start \
             empty: move the state file and its -wal and -shm files out of the pam \
             directory and start pam (grants, approvals and the audit history \
             start over)",
            dir = backup.dir.display()
        )
    } else if let Some(dir) = backup::newest(&backup::root_for(state)) {
        format!(
            "{detail}. Nothing was changed. The newest copy pam made before an \
             upgrade is in {}; it is as old as that upgrade",
            dir.display()
        )
    } else {
        detail
    };
    StoreError::Corrupt { detail }
}

/// The engine build this crate links treats a name that starts with `file:`
/// as a URI whatever the open flags say. A relative path that happens to
/// start that way is anchored so it stays a path.
pub(crate) fn literal_path(path: &str) -> String {
    if path.starts_with("file:") {
        format!("./{path}")
    } else {
        path.to_owned()
    }
}

/// Settings that hold for every connection: file or memory, writer or
/// reader. None of them writes to the database.
fn harden(conn: &Connection) -> Result<(), StoreError> {
    conn.busy_timeout(BUSY_TIMEOUT).map_err(engine)?;
    // The schema is not allowed to rewrite itself or the file's internals
    // from SQL, and functions that reach outside the database are refused
    // inside triggers, CHECKs and views.
    set(conn, DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    set(conn, DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    // A double-quoted token is an identifier or an error, never silently a
    // string: a misspelt column name must not become a constant.
    set(conn, DbConfig::SQLITE_DBCONFIG_DQS_DML, false)?;
    set(conn, DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)?;
    // The schema depends on foreign keys: cascades, and a missing request
    // failing the audit row that names it.
    set(conn, DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY, true)?;
    if pragma_i64(conn, "foreign_keys")? != 1 {
        return Err(refused("foreign key enforcement did not switch on"));
    }
    // No second database can be attached to this connection.
    conn.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)
        .map_err(engine)?;
    conn.set_limit(Limit::SQLITE_LIMIT_LENGTH, MAX_VALUE_BYTES)
        .map_err(engine)?;
    conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE);
    Ok(())
}

/// Deleted content is overwritten in the file, so retention's deletions are
/// real inside it. The pragma answers with the value now in force. For the
/// connection that writes.
fn keep_deleted_content_out(conn: &Connection) -> Result<(), StoreError> {
    if update_and_read(conn, "secure_delete", "ON")? != 1 {
        return Err(refused("secure_delete did not switch on"));
    }
    Ok(())
}

/// Write-ahead logging with a full sync on every commit: a terminal write and
/// its audit row survive the process, and the operating system, dying the
/// moment after the call has returned. Switching a rollback-journal file to
/// WAL is a write, so this runs after the check.
///
/// What "synced" means is the platform's. On Windows it is
/// `FlushFileBuffers`, which asks the drive to empty its cache. On macOS it
/// is `fsync`, which hands the data to the drive and does not: see
/// [`apple_sync`].
fn durable_journal(conn: &Connection) -> Result<(), StoreError> {
    let mode: String = conn
        .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
        .map_err(engine)?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(refused(&format!(
            "the database stayed in journal mode {mode:?} instead of WAL"
        )));
    }
    conn.pragma_update(None, "synchronous", "FULL")
        .map_err(engine)?;
    if pragma_i64(conn, "synchronous")? != 2 {
        return Err(refused("synchronous = FULL did not take"));
    }
    conn.pragma_update_and_check(None, "journal_size_limit", WAL_SIZE_LIMIT_BYTES, |row| {
        row.get::<_, i64>(0)
    })
    .map_err(engine)?;
    apple_sync(conn)
}

/// macOS only: which syncs go all the way to the drive.
///
/// `fsync` on macOS returns once the drive has the data, not once the drive
/// has written it; only `F_FULLFSYNC` waits for that.
///
/// - **Checkpoints use `F_FULLFSYNC`** (`checkpoint_fullfsync = ON`). A
///   checkpoint is where the main file is rewritten and the log recycled, a
///   few times an hour; if the main file's pages were still in the drive's
///   cache when the log is reset, a power cut could leave neither holding
///   them. This keeps the database's *integrity* independent of the drive's
///   cache.
/// - **Commits use `fsync`** (`fullfsync` stays off). Measured on the
///   development host (Apple Silicon, internal SSD, 2026-10-02, 2,000
///   commits, three rounds; `sync_cost_test`): 0.18 to 0.20 ms per commit
///   with `fsync`, 4.9 to 5.2 ms with `F_FULLFSYNC`. The bar for turning it
///   on was 2 ms. What this leaves exposed is narrow and stated: after a
///   *power cut or kernel panic*, the last commits the drive had accepted
///   and not yet written can be missing. They disappear whole (the log is
///   checksummed and replay stops at the first frame that did not make it),
///   newest first, and the database stays consistent; a request
///   acknowledged in that last moment is back in its earlier state and the
///   boot recovery closes it. A process crash or `kill -9` loses nothing:
///   the data is already with the operating system.
#[cfg(target_os = "macos")]
fn apple_sync(conn: &Connection) -> Result<(), StoreError> {
    conn.pragma_update(None, "checkpoint_fullfsync", "ON")
        .map_err(engine)?;
    if pragma_i64(conn, "checkpoint_fullfsync")? != 1 {
        return Err(refused("checkpoint_fullfsync did not switch on"));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
#[allow(clippy::unnecessary_wraps, reason = "same signature as the macOS form")]
fn apple_sync(_conn: &Connection) -> Result<(), StoreError> {
    Ok(())
}

/// The read-only second connection: write-ahead logging lets it read while
/// the writer writes. Same hardening as the writer; it cannot write even if
/// asked to (opened read-only, and `query_only` on top).
fn open_reader(path: &str) -> Result<Connection, StoreError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let reader = Connection::open_with_flags(literal_path(path), flags).map_err(engine)?;
    harden(&reader)?;
    reader
        .pragma_update(None, "query_only", "ON")
        .map_err(engine)?;
    if pragma_i64(&reader, "query_only")? != 1 {
        return Err(refused("query_only did not switch on"));
    }
    // Reads the schema now, so a database this connection cannot read
    // refuses the open rather than the first list query.
    migrations::current_version(&reader)?;
    Ok(reader)
}

/// Ends a connection.
///
/// With `fold_log` (the writer, on an orderly close) the write-ahead log is
/// first folded into the main file and truncated, and the connection is then
/// allowed to remove the log files as it closes: after this a copy of the
/// main file alone is a complete backup. Without it (the reader) the
/// connection is just closed.
///
/// A connection that is dropped instead never folds the log: what it leaves
/// is what a killed process leaves, a main file plus a log the next open
/// replays. Nothing committed is lost either way.
pub(crate) fn shut(conn: Connection, fold_log: bool) -> Result<(), StoreError> {
    // The fold is best effort: wait briefly for a lock, never the statement
    // timeout (see CLOSE_BUSY_TIMEOUT).
    if fold_log && let Err(error) = conn.busy_timeout(CLOSE_BUSY_TIMEOUT) {
        tracing::warn!(%error, "the closing checkpoint keeps the statement busy timeout");
    }
    // With the log empty, let the close delete it and its index.
    if fold_log
        && checkpoint(&conn, "at close")
        && let Err(error) = set(&conn, DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, false)
    {
        tracing::warn!(%error, "the log files could not be released for removal at close");
    }
    conn.close().map_err(|(_, error)| engine(error))
}

/// Folds the write-ahead log into the main file and truncates it. True when
/// the whole log was folded. A database that is not in WAL mode has no log
/// and answers true.
///
/// Never fatal: when another connection is in the middle of a read or a
/// write the checkpoint cannot finish, the log simply stays, and the next
/// checkpoint or the next open deals with it.
fn checkpoint(conn: &Connection, when: &str) -> bool {
    let outcome = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", (), |row| {
        row.get::<_, i64>(0)
    });
    match outcome {
        Ok(0) => true,
        Ok(_) => {
            tracing::warn!(
                when,
                "the write-ahead log could not be folded into the main file: another \
                 connection is using the database. Nothing is lost; the log stays until \
                 the next checkpoint"
            );
            false
        }
        Err(error) => {
            tracing::warn!(when, %error, "the write-ahead log checkpoint failed; the log stays");
            false
        }
    }
}

fn set(conn: &Connection, config: DbConfig, on: bool) -> Result<(), StoreError> {
    if conn.set_db_config(config, on).map_err(engine)? == on {
        Ok(())
    } else {
        Err(refused(&format!(
            "connection setting {config:?} did not take"
        )))
    }
}

fn pragma_i64(conn: &Connection, name: &str) -> Result<i64, StoreError> {
    conn.pragma_query_value(None, name, |row| row.get(0))
        .map_err(engine)
}

fn update_and_read(conn: &Connection, name: &str, value: &str) -> Result<i64, StoreError> {
    conn.pragma_update_and_check(None, name, value, |row| row.get(0))
        .map_err(engine)
}

/// An open refused because the connection could not be given a setting the
/// store's guarantees rest on.
fn refused(what: &str) -> StoreError {
    StoreError::Database(EngineError::new(
        0,
        &format!(
            "{what}; the store refuses to run without it. This is a defect in the \
             build, not in the database file: reinstall pam"
        ),
    ))
}

/// Asks the engine whether the file is structurally sound before anything
/// reads or migrates it. `quick_check` skips the index cross-checks, so it
/// stays cheap; a database that fails it is refused with a legible
/// [`StoreError::Corrupt`] instead of surfacing later as a random engine
/// error half-way through a request. A file the engine cannot read at all
/// reaches the same variant through the engine-error conversion.
pub(crate) fn integrity_check(conn: &Connection) -> Result<(), StoreError> {
    findings_to_refusal(&structural_findings(conn, "PRAGMA quick_check")?)
}

/// The check a database gets once, on its first open by this engine: every
/// page, every index against its table, and every foreign key.
fn full_check(conn: &Connection) -> Result<(), StoreError> {
    let mut findings = structural_findings(conn, "PRAGMA integrity_check")?;
    if findings.is_empty() {
        findings = foreign_key_findings(conn)?;
    }
    findings_to_refusal(&findings)
}

fn findings_to_refusal(findings: &[String]) -> Result<(), StoreError> {
    if findings.is_empty() {
        Ok(())
    } else {
        Err(StoreError::Corrupt {
            detail: findings.join("; "),
        })
    }
}

/// The lines of a structural check other than `ok`, bounded.
fn structural_findings(conn: &Connection, pragma: &str) -> Result<Vec<String>, StoreError> {
    let mut stmt = conn.prepare(pragma).map_err(engine)?;
    let mut rows = stmt.query(()).map_err(engine)?;
    let mut problems: Vec<String> = Vec::new();
    while let Some(row) = rows.next().map_err(engine)? {
        let line = match row.get_ref(0).map_err(engine)? {
            rusqlite::types::ValueRef::Text(text) => String::from_utf8_lossy(text).into_owned(),
            other => format!("{other:?}"),
        };
        if line != "ok" && problems.len() < MAX_FINDINGS {
            problems.push(line.chars().take(200).collect());
        }
    }
    Ok(problems)
}

/// Rows whose foreign key names a parent that does not exist, bounded.
fn foreign_key_findings(conn: &Connection) -> Result<Vec<String>, StoreError> {
    let mut stmt = conn.prepare("PRAGMA foreign_key_check").map_err(engine)?;
    let mut rows = stmt.query(()).map_err(engine)?;
    let mut problems: Vec<String> = Vec::new();
    while let Some(row) = rows.next().map_err(engine)? {
        if problems.len() >= MAX_FINDINGS {
            continue;
        }
        let table: String = row.get(0).map_err(engine)?;
        let rowid: Option<i64> = row.get(1).map_err(engine)?;
        let parent: String = row.get(2).map_err(engine)?;
        let which = rowid.map_or_else(|| "a row".to_owned(), |rowid| format!("row {rowid}"));
        let line = format!("{which} of {table} refers to a {parent} row that does not exist");
        problems.push(line.chars().take(200).collect());
    }
    Ok(problems)
}
