//! The synchronous client the store's statements are written against.
//!
//! A thin layer over the engine's own client with one purpose: every call
//! answers [`StoreError`], so a statement, a row read and the store's own
//! refusals share one `?` and the engine's error type never reaches a public
//! signature. Statements are prepared through the connection's statement
//! cache; the SQL text is the cache key.
//!
//! Everything here blocks. It is only ever called from inside a job handed to
//! [`crate::conn_gate::ConnGate::run`], which runs on a blocking thread with
//! exclusive use of the connection.

use rusqlite::types::{FromSql, ValueRef};
use rusqlite::{CachedStatement, Connection, Params, TransactionBehavior};

use crate::error::{StoreError, engine};

/// The held connection, for the length of one job. A copyable handle: it is
/// passed by value.
#[derive(Clone, Copy)]
pub(crate) struct Db<'c> {
    conn: &'c Connection,
}

/// A prepared statement, returned to the cache when dropped.
pub(crate) struct Stmt<'c> {
    stmt: CachedStatement<'c>,
}

/// The rows of one execution of a [`Stmt`]. Dropping it resets the
/// statement, which ends the read it holds open.
pub(crate) struct Rows<'s> {
    rows: rusqlite::Rows<'s>,
}

/// One result row, valid until the next [`Rows::next`].
pub(crate) struct Row<'r> {
    row: &'r rusqlite::Row<'r>,
}

impl<'c> Db<'c> {
    pub(crate) fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Runs one statement that returns no rows and answers how many rows it
    /// changed. Exactly as many values as the statement has parameters must
    /// be bound; the engine's client refuses anything else.
    pub(crate) fn execute<P: Params>(self, sql: &str, params: P) -> Result<u64, StoreError> {
        let mut stmt = self.conn.prepare_cached(sql).map_err(engine)?;
        let changed = stmt.execute(params).map_err(engine)?;
        Ok(u64::try_from(changed).unwrap_or(u64::MAX))
    }

    /// Prepares a statement to read rows from with [`Stmt::query`].
    pub(crate) fn prepare(self, sql: &str) -> Result<Stmt<'c>, StoreError> {
        Ok(Stmt {
            stmt: self.conn.prepare_cached(sql).map_err(engine)?,
        })
    }

    /// True when the statement yields at least one row. The read is over
    /// when this returns.
    pub(crate) fn exists<P: Params>(self, sql: &str, params: P) -> Result<bool, StoreError> {
        let mut stmt = self.prepare(sql)?;
        let mut rows = stmt.query(params)?;
        Ok(rows.next()?.is_some())
    }
}

impl Stmt<'_> {
    /// Binds `params` and starts reading. Exactly as many values as the
    /// statement has parameters must be bound.
    pub(crate) fn query<P: Params>(&mut self, params: P) -> Result<Rows<'_>, StoreError> {
        Ok(Rows {
            rows: self.stmt.query(params).map_err(engine)?,
        })
    }
}

impl Rows<'_> {
    /// Steps to the next row; `None` once the statement is exhausted.
    pub(crate) fn next(&mut self) -> Result<Option<Row<'_>>, StoreError> {
        Ok(self.rows.next().map_err(engine)?.map(|row| Row { row }))
    }
}

impl Row<'_> {
    /// Reads column `idx` as `T`. Strict: an integer column is not read as
    /// text, and NULL is only read into an `Option`.
    pub(crate) fn get<T: FromSql>(&self, idx: usize) -> Result<T, StoreError> {
        self.row.get(idx).map_err(engine)
    }

    /// Borrows column `idx` as the engine holds it, whatever its type.
    pub(crate) fn value(&self, idx: usize) -> Result<ValueRef<'_>, StoreError> {
        self.row.get_ref(idx).map_err(engine)
    }
}

/// Runs `body` as one transaction: commit when it answers `Ok`, roll back
/// when it answers `Err` or unwinds. A failed `COMMIT` is rolled back too.
/// The statements' own error is the one returned.
///
/// The transaction takes the write lock when it begins, so a second
/// connection to the same file (an operator's shell) waits or is refused at
/// `BEGIN`, not half-way through the statements.
pub(crate) fn in_txn<T>(
    conn: &mut Connection,
    body: impl FnOnce(Db<'_>) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    let txn = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(engine)?;
    // Dropping `txn` on the error path, or while unwinding, rolls back.
    let value = body(Db::new(&txn))?;
    txn.commit().map_err(engine)?;
    Ok(value)
}

/// Runs `body` as one read transaction: every statement in it reads the same
/// snapshot of the database, taken at its first read. Nothing is written, so
/// ending it commits nothing; it only releases the snapshot.
pub(crate) fn in_read_txn<T>(
    conn: &mut Connection,
    body: impl FnOnce(Db<'_>) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    let txn = conn
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(engine)?;
    let value = body(Db::new(&txn))?;
    txn.commit().map_err(engine)?;
    Ok(value)
}
