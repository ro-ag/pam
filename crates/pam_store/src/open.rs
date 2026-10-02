//! Opening the database: the connection's settings, the boot check, and the
//! migrations, in that order.
//!
//! Nothing here depends on how the engine library was compiled. Every
//! setting is applied to the connection at run time and, where the engine can
//! be asked, read back; a setting that did not take refuses the open.

use std::time::Duration;

use rusqlite::config::DbConfig;
use rusqlite::limits::Limit;
use rusqlite::{Connection, OpenFlags};

use crate::error::{EngineError, StoreError, engine};
use crate::migrations;

/// How long a statement waits for another connection's lock (an operator's
/// shell, a backup tool) before it answers busy.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest string or blob the connection accepts. Evidence blobs and views
/// run to 64 MiB; nothing the store writes comes near twice that.
const MAX_VALUE_BYTES: i32 = 128 * 1024 * 1024;

/// The write-ahead log is truncated back to this size after a checkpoint,
/// so one large write does not leave a large file behind for good.
const WAL_SIZE_LIMIT_BYTES: i64 = 16 * 1024 * 1024;

/// Statements kept prepared. The store has about 130 fixed statements; the
/// hot paths use far fewer, and the cache evicts the least recently used.
const STATEMENT_CACHE: usize = 128;

/// Where the database lives.
pub(crate) enum Target {
    /// A file, created if missing. `check` runs the structural check before
    /// anything else reads or writes it.
    File { path: String, check: bool },
    /// A private in-memory database, for tests.
    Memory,
}

/// Opens, configures, checks and migrates. Blocks; call it from a blocking
/// thread.
pub(crate) fn open(target: &Target) -> Result<Connection, StoreError> {
    // Not `URI`: the path is a path. `NO_MUTEX`: the gate already gives the
    // connection to one thread at a time.
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let mut conn = match target {
        Target::File { path, .. } => Connection::open_with_flags(literal_path(path), flags),
        Target::Memory => Connection::open_in_memory_with_flags(flags),
    }
    .map_err(engine)?;
    // Until the file has passed its check and migrated, closing the
    // connection must not fold the log into the main file: a database that is
    // refused is left exactly as it was found.
    set(&conn, DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    harden(&conn)?;
    match target {
        Target::File { check: true, .. } => integrity_check(&conn)?,
        Target::File { check: false, .. } => {
            tracing::debug!("skipping the boot integrity check for this database");
        }
        Target::Memory => {}
    }
    if matches!(target, Target::File { .. }) {
        durable_journal(&conn)?;
    }
    migrations::run(&mut conn)?;
    set(&conn, DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, false)?;
    Ok(conn)
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

/// Settings that hold for every connection, file or memory. None of them
/// writes to the database.
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
    // Deleted content is overwritten in the file, so retention's deletions
    // are real inside it. The pragma answers with the value now in force.
    if update_and_read(conn, "secure_delete", "ON")? != 1 {
        return Err(refused("secure_delete did not switch on"));
    }
    conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE);
    Ok(())
}

/// Write-ahead logging with a full sync on every commit: a terminal write and
/// its audit row survive power loss once the call has returned. Switching a
/// rollback-journal file to WAL is a write, so this runs after the check.
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
    Ok(())
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
    let mut stmt = conn.prepare("PRAGMA quick_check").map_err(engine)?;
    let mut rows = stmt.query(()).map_err(engine)?;
    let mut problems: Vec<String> = Vec::new();
    while let Some(row) = rows.next().map_err(engine)? {
        let line = match row.get_ref(0).map_err(engine)? {
            rusqlite::types::ValueRef::Text(text) => String::from_utf8_lossy(text).into_owned(),
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
