//! The one database connection, reachable only through its gate.
//!
//! The engine's client is synchronous and a connection may be used by one
//! thread at a time, so every store call has the same shape: wait for the
//! gate, then run one closure (a *job*) on a blocking thread with exclusive
//! use of the connection, to completion.
//!
//! - **Waiting is asynchronous.** Callers queue on a fair async mutex, as
//!   suspended futures, first come first served. One blocking thread is in
//!   use at a time.
//! - **A started job cannot be abandoned.** The job owns the lock guard and
//!   runs off the async threads; dropping the caller's future (a deadline, an
//!   aborted task) does not stop it. A transaction is therefore never left
//!   open by a dropped caller: the job commits or rolls back on its own. A
//!   caller dropped *before* its job started cancels the job; either way a
//!   job runs whole or not at all.
//! - **A panic is contained.** The job runs under `catch_unwind`; unwinding
//!   rolls back any open transaction, the caller is answered
//!   [`StoreError::Unavailable`], and the next call proceeds.
//! - **The connection is checked before reuse.** After every job the gate
//!   asks the engine whether a transaction is still open, and rolls it back.
//!   If that fails the gate is poisoned and every later call is refused with
//!   [`StoreError::AbandonedTransaction`] rather than run inside somebody
//!   else's transaction. The store's own jobs cannot reach this path (their
//!   transactions are scoped values that end with the job); it is the net
//!   under them.
//!
//! - **Waiting is bounded.** At most [`MAX_QUEUED_CALLS`] calls wait for, or
//!   run on, one connection. The next one is refused with
//!   [`StoreError::Overloaded`] before it queues, so a disk that has stalled
//!   under callers that keep arriving shows up as a refusal with a cause
//!   instead of as memory that grows until the process is killed.
//! - **Closing is explicit.** [`ConnGate::close`] waits for the running job,
//!   closes the connection and leaves the gate empty; every later call is
//!   answered [`StoreError::Closed`]. A gate that is dropped without being
//!   closed just drops its connection: nothing waits and nothing is written
//!   (see `open::shut` for what each way of ending leaves on disk).
//!
//! The blocking thread comes from the runtime's blocking pool
//! (`spawn_blocking`) rather than a thread of the store's own because tokio's
//! paused test clock treats an outstanding blocking task as work in progress
//! and does not auto-advance past it; a private thread would let the clock
//! jump a deadline while the store was still answering.

use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use rusqlite::Connection;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::error::StoreError;

/// Most calls that may wait for, or run on, one connection at a time.
///
/// The daemon admits at most 200 requests at once across its pools (128
/// work, 16 status, 16 query, 8 cancel, 32 admin-submitted) and runs about a
/// dozen service loops; each of those waits on one store call at a time, and
/// a caller that gives up (its deadline passed) leaves the queue. So about
/// two hundred waiters is the most a healthy daemon can produce, and five
/// times that is reached only when something spawns store calls without
/// bound while the disk is not answering. A waiter costs its closure and the
/// arguments it owns, usually a few hundred bytes.
pub(crate) const MAX_QUEUED_CALLS: usize = 1024;

/// Owner of the connection. Nothing else holds a handle to it.
pub(crate) struct ConnGate {
    /// `None` once the gate has been closed.
    conn: Arc<Mutex<Option<Connection>>>,
    /// Set when a transaction a job left open could not be rolled back.
    poisoned: Arc<AtomicBool>,
    /// Calls waiting for the connection or running on it.
    queued: Arc<AtomicUsize>,
}

/// One call's place in the queue, given back when the call ends or its
/// future is dropped.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Cancels a blocking task that has not started when the caller goes away.
/// A task that has started is unaffected: tokio cannot abort it, which is
/// the property the gate relies on.
struct AbortUnstarted<T>(JoinHandle<T>);

impl<T> Drop for AbortUnstarted<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl ConnGate {
    pub(crate) fn new(conn: Connection) -> Self {
        Self {
            conn: Arc::new(Mutex::new(Some(conn))),
            poisoned: Arc::new(AtomicBool::new(false)),
            queued: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Takes a place in the queue, or refuses when it is full.
    fn enter(&self) -> Result<Slot, StoreError> {
        let ahead = self.queued.fetch_add(1, Ordering::AcqRel);
        // Built first so the count is given back on the refusal path too.
        let slot = Slot(Arc::clone(&self.queued));
        if ahead >= MAX_QUEUED_CALLS {
            return Err(StoreError::Overloaded { waiting: ahead });
        }
        Ok(slot)
    }

    /// Calls waiting for the connection or running on it, right now.
    #[cfg(test)]
    pub(crate) fn queued(&self) -> usize {
        self.queued.load(Ordering::Acquire)
    }

    /// Runs `job` on the connection, off the async threads, to completion.
    ///
    /// The connection is outside any transaction when `job` starts and is
    /// put back outside any transaction when it ends. Must be called from
    /// within a tokio runtime.
    pub(crate) async fn run<T, F>(&self, job: F) -> Result<T, StoreError>
    where
        F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static,
    {
        let _slot = self.enter()?;
        let mut held = Arc::clone(&self.conn).lock_owned().await;
        if held.is_none() {
            return Err(StoreError::Closed);
        }
        if self.poisoned.load(Ordering::Acquire) {
            return Err(StoreError::AbandonedTransaction);
        }
        let poisoned = Arc::clone(&self.poisoned);
        // The guard moves into the task: the connection stays locked until
        // the job has finished and the connection has been checked, whatever
        // happens to this future meanwhile.
        let mut task = AbortUnstarted(tokio::task::spawn_blocking(move || {
            let Some(conn) = held.as_mut() else {
                // Checked above under this same guard; kept as an answer
                // rather than an assumption.
                return Ok(Err(StoreError::Closed));
            };
            let outcome = catch_unwind(AssertUnwindSafe(|| job(conn)));
            if outcome.is_err() {
                // A statement the panic interrupted must not be handed out
                // again half-stepped.
                conn.flush_prepared_statement_cache();
            }
            if !leave_no_transaction(conn) {
                poisoned.store(true, Ordering::Release);
            }
            outcome
        }));
        match (&mut task.0).await {
            Ok(Ok(result)) => result,
            Ok(Err(panic)) => {
                let detail = panic_detail(panic.as_ref());
                tracing::error!(%detail, "a store call panicked; its transaction was rolled back");
                Err(StoreError::Unavailable {
                    detail: format!("the call panicked ({detail})"),
                })
            }
            Err(error) => Err(StoreError::Unavailable {
                detail: if error.is_cancelled() {
                    "the runtime is shutting down".to_owned()
                } else {
                    "the blocking task failed".to_owned()
                },
            }),
        }
    }
}

impl ConnGate {
    /// Waits for the running job, hands the connection to `shut`, and leaves
    /// the gate closed. Idempotent: a second close finds nothing and does
    /// nothing.
    ///
    /// It takes no place in the queue, so a full queue cannot refuse it; it
    /// waits its turn behind the calls already queued, and the calls behind
    /// it are answered [`StoreError::Closed`]. Once it has the connection the
    /// shutting runs to its end on a blocking thread whether or not the
    /// caller is still waiting.
    pub(crate) async fn close<F>(&self, shut: F) -> Result<(), StoreError>
    where
        F: FnOnce(Connection) -> Result<(), StoreError> + Send + 'static,
    {
        let mut held = Arc::clone(&self.conn).lock_owned().await;
        let closed = tokio::task::spawn_blocking(move || match held.take() {
            Some(conn) => shut(conn),
            None => Ok(()),
        })
        .await;
        closed.unwrap_or_else(|error| {
            Err(StoreError::Unavailable {
                detail: if error.is_panic() {
                    "closing the database panicked".to_owned()
                } else {
                    "the runtime is shutting down".to_owned()
                },
            })
        })
    }
}

/// Puts the connection back in autocommit mode after a job. False when a
/// transaction is still open and could not be rolled back.
fn leave_no_transaction(conn: &Connection) -> bool {
    if conn.is_autocommit() {
        return true;
    }
    tracing::error!("a store call ended inside an open transaction; rolling it back before reuse");
    if let Err(error) = conn.execute_batch("ROLLBACK") {
        tracing::error!(%error, "the open transaction could not be rolled back");
    }
    conn.is_autocommit()
}

/// The message of a panic payload, bounded.
fn panic_detail(panic: &(dyn Any + Send)) -> String {
    let text = panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("no message");
    text.chars().take(200).collect()
}
