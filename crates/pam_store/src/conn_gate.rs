//! The one database connection, reachable only through its lock.
//!
//! turso refuses concurrent use of a connection outright
//! (`Misuse("concurrent use forbidden")`) and refuses a `BEGIN` inside an open
//! transaction (`cannot start a transaction within a transaction`). Both rules
//! used to be kept by convention: a detached `Mutex<()>` next to a
//! crate-visible connection, and a hand-written `BEGIN`..`COMMIT` per method.
//! A store call whose future was dropped between the two (a caller deadline,
//! an aborted task, a panic) released the lock with the transaction still
//! open, and every later statement silently joined it: visible in-process,
//! never committed, lost on restart.
//!
//! Here the mutex owns the connection, so a statement without the lock does
//! not compile, and two things make a transaction cancel-safe:
//!
//! - [`ConnGuard::begin`] and [`ConnGuard::end`] bracket every transaction
//!   (the store's `transact!` macro pairs them), and `end` closes every path
//!   that reaches it with `COMMIT` or `ROLLBACK`;
//! - [`ConnGate::lock`] asks the engine whether it is still inside a
//!   transaction before handing the connection out, and rolls back whatever a
//!   dropped holder left behind. `Drop` cannot await, so the rollback runs at
//!   the next acquisition instead: nothing can run on the connection in
//!   between, because the connection is only reachable through this lock.

use std::ops::Deref;

use tokio::sync::{Mutex, MutexGuard};
use turso::Connection;

use crate::error::StoreError;

/// Owner of the connection. Nothing else holds a handle to it.
pub(crate) struct ConnGate {
    conn: Mutex<Connection>,
}

/// Exclusive use of the connection, outside any transaction on acquisition.
pub(crate) struct ConnGuard<'a> {
    conn: MutexGuard<'a, Connection>,
}

impl ConnGate {
    pub(crate) fn new(conn: Connection) -> Self {
        Self {
            conn: Mutex::new(conn),
        }
    }

    /// Waits for exclusive use of the connection and guarantees it is in
    /// autocommit mode.
    ///
    /// A transaction found open here was abandoned: its holder is gone and
    /// can no longer commit it. It is rolled back before the caller sees the
    /// connection. A rollback that fails, or leaves the transaction open,
    /// refuses the call with [`StoreError::AbandonedTransaction`] rather than
    /// letting the caller write into somebody else's transaction.
    pub(crate) async fn lock(&self) -> Result<ConnGuard<'_>, StoreError> {
        let conn = self.conn.lock().await;
        if !conn.is_autocommit()? {
            // Boxed: this path is cold, and inlining its statement future
            // would grow the future of every store call that takes the lock.
            Box::pin(Self::roll_back_abandoned(&conn)).await?;
        }
        Ok(ConnGuard { conn })
    }

    async fn roll_back_abandoned(conn: &Connection) -> Result<(), StoreError> {
        tracing::warn!(
            "a store call was dropped inside a transaction; rolling it back before reuse"
        );
        if let Err(error) = conn.execute("ROLLBACK", ()).await {
            tracing::error!(%error, "the abandoned transaction could not be rolled back");
            return Err(StoreError::AbandonedTransaction);
        }
        if conn.is_autocommit()? {
            Ok(())
        } else {
            Err(StoreError::AbandonedTransaction)
        }
    }
}

impl Deref for ConnGuard<'_> {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        &self.conn
    }
}

impl ConnGuard<'_> {
    /// Opens a transaction on the held connection. Every `begin` is paired
    /// with [`Self::end`]; a pair that is cut short — the future dropped, a
    /// `?` between the two — leaves the transaction open only until the
    /// next [`ConnGate::lock`], which rolls it back.
    pub(crate) async fn begin(&self) -> Result<(), StoreError> {
        self.conn.execute("BEGIN", ()).await?;
        Ok(())
    }

    /// Closes the transaction around `result`: `COMMIT` when the statements
    /// succeeded, `ROLLBACK` when they failed or the commit itself failed.
    /// The statements' own error is the one returned.
    pub(crate) async fn end<T>(&self, result: Result<T, StoreError>) -> Result<T, StoreError> {
        match result {
            Ok(value) => match self.conn.execute("COMMIT", ()).await {
                Ok(_) => Ok(value),
                Err(error) => {
                    // A failed COMMIT leaves the transaction open; close it
                    // here rather than at the next acquisition.
                    let _ = self.conn.execute("ROLLBACK", ()).await;
                    Err(error.into())
                }
            },
            Err(error) => {
                // Best effort: the statements' error is the one worth
                // returning, and the next acquisition rolls back if this
                // did not.
                let _ = self.conn.execute("ROLLBACK", ()).await;
                Err(error)
            }
        }
    }
}
