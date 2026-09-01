//! Daemon lifecycle: single-instance lock, crash recovery of stuck
//! request rows, the lifecycle phase the pipeline consults, and the
//! daemon's own log file.
//!
//! # Single instance
//!
//! Exactly one daemon per base directory, arbitrated by an advisory file
//! lock on `<base>/run/daemon.lock` ([`acquire_instance_lock`], the
//! stable `std::fs::File` locking API — `flock` on unix, `LockFileEx` on
//! Windows). The holder writes its pid into the file so a losing
//! contender can name who beat it. The lock is held for the daemon's
//! whole lifetime — [`InstanceLock`] keeps the file handle open and the
//! OS releases the lock when the handle drops (daemon exit included, so
//! a crashed daemon never wedges the next one).
//!
//! # Lock-first ordering
//!
//! The lock is acquired **before** anything else touches the runtime
//! directory. Only the lock holder may remove and rebind the socket
//! files (`pam.sock`, `events.sock`), so a stale socket with no lock
//! holder is removed safely and a live daemon's sockets are never
//! yanked from under it. [`crate::transport::Transport::bind`] performs
//! the removal; [`crate::daemon::run_daemon_with`] guarantees the
//! ordering.
//!
//! # Crash recovery
//!
//! On boot — after the lock, before the lanes are rebuilt —
//! [`recover_stuck_rows`] fails every `running` / `waiting_approval`
//! row a dead daemon left mid-flight: terminal `failed`, outcome
//! [`CAUSE_DAEMON_RESTART`], audited through the
//! [`pam_store::Store::finish_request`] choke point (action
//! [`ACTION_DAEMON_RESTART`], decision `timeout`, actor `system`, with
//! a retry note in the detail). A ticket holder polling such a request
//! finds a legible failure instead of a row stuck in-flight forever.
//! `queued` rows are untouched — they are restart-safe by design and
//! [`crate::queue::QueueManager::rebuild_from_store`] restores them.
//!
//! # Self-logging
//!
//! [`init_daemon_logging`] writes the daemon's own tracing output to
//! `<base>/log/daemon.log`, rotated daily. This log is for debugging
//! PAM itself and is never mixed with product evidence (which lives in
//! the store's `evidence` table).

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use pam_store::{Actor, ApprovalResolution, AuditEntry, Decision, RequestState, Store, StoreError};
use thiserror::Error;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};

/// Name of the single-instance lock file inside the run directory.
pub const LOCK_FILE: &str = "daemon.lock";

/// Subdirectory of the base directory holding the daemon's own log.
pub const LOG_DIR: &str = "log";

/// File name prefix of the daemon's own log (daily rotation appends the
/// date, e.g. `daemon.log.2026-09-01`).
pub const LOG_FILE: &str = "daemon.log";

/// `request.outcome` (the machine cause) recorded when crash recovery
/// fails a row the previous daemon left mid-flight.
pub const CAUSE_DAEMON_RESTART: &str = "daemon_restart";

/// `audit.action` for a crash-recovery failure; part of
/// [`crate::daemon::TERMINAL_ACTIONS`].
pub const ACTION_DAEMON_RESTART: &str = "daemon_restart";

/// Where the daemon is in its life. Exposed through
/// [`crate::daemon::DaemonHandle::lifecycle`] so the process shell (and
/// tests) can observe a drain or a self-restart request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecyclePhase {
    /// Accepting and executing requests.
    Serving,
    /// Shutting down: new requests are refused
    /// (`daemon_shutting_down`), in-flight work drains under a bound.
    Draining,
    /// Draining like [`Self::Draining`], but because a newer client
    /// revealed a newer binary on disk — the process shell should
    /// re-spawn `pam daemon` after the drain completes.
    Restarting,
}

/// Why a lifecycle operation failed.
#[derive(Debug, Error)]
pub enum LifecycleError {
    /// Another daemon already holds the instance lock.
    #[error(
        "another pam daemon already holds {} ({})",
        path.display(),
        pid.map_or_else(|| "pid unknown".to_owned(), |pid| format!("pid {pid}"))
    )]
    AlreadyRunning {
        /// The lock file that is held.
        path: PathBuf,
        /// The holder's pid, when the lock file was readable.
        pid: Option<u32>,
    },
    /// A filesystem operation on a lifecycle path failed.
    #[error("cannot prepare {}: {source}", path.display())]
    Io {
        /// The path the operation acted on.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
}

/// The held single-instance lock. Keep it alive for the daemon's whole
/// lifetime; dropping it releases the lock (as does process exit, even
/// a crash — the OS ties the lock to the open handle, not the file's
/// existence).
#[derive(Debug)]
pub struct InstanceLock {
    /// The open, locked handle. Held only for the lock it carries.
    _file: File,
    path: PathBuf,
}

impl InstanceLock {
    /// Path of the held lock file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Takes the single-instance lock in `run_dir`, writing this process's
/// pid into the lock file.
///
/// Fails with [`LifecycleError::AlreadyRunning`] (naming the holder's
/// pid when readable) if another process holds it. The file is opened
/// without truncation — a live holder's pid must not be erased by a
/// losing contender — and truncated only after the lock is won.
pub fn acquire_instance_lock(run_dir: &Path) -> Result<InstanceLock, LifecycleError> {
    let path = run_dir.join(LOCK_FILE);
    let io_err = |source| LifecycleError::Io {
        path: path.clone(),
        source,
    };
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(io_err)?;
    match file.try_lock() {
        Ok(()) => {
            file.set_len(0).map_err(io_err)?;
            file.seek(SeekFrom::Start(0)).map_err(io_err)?;
            write!(file, "{}", std::process::id()).map_err(io_err)?;
            file.flush().map_err(io_err)?;
            Ok(InstanceLock { _file: file, path })
        }
        Err(TryLockError::WouldBlock) => {
            let pid = std::fs::read_to_string(&path)
                .ok()
                .and_then(|contents| contents.trim().parse().ok());
            Err(LifecycleError::AlreadyRunning { path, pid })
        }
        Err(TryLockError::Error(source)) => Err(io_err(source)),
    }
}

/// Fails every `running` / `waiting_approval` row a dead daemon left
/// mid-flight (see the module docs), returning the ids it recovered.
///
/// Every failure goes through [`Store::finish_request`] — terminal
/// state and audit row in one transaction, first-wins on an already
/// terminal row. A recovered `waiting_approval` row's dangling approval
/// is resolved as a timeout (note [`CAUSE_DAEMON_RESTART`]) so the
/// GUI's pending list does not advertise an approval nobody can grant.
pub async fn recover_stuck_rows(store: &Store) -> Result<Vec<String>, StoreError> {
    let stuck = store.list_stuck_ordered().await?;
    let mut recovered = Vec::with_capacity(stuck.len());
    for row in stuck {
        let was_waiting = row.state == RequestState::WaitingApproval;
        let detail = serde_json::json!({
            "cause": CAUSE_DAEMON_RESTART,
            "note": "the daemon restarted while this request was in flight; \
                     re-run the pam command to retry",
        })
        .to_string();
        let finished = store
            .finish_request(
                &row.id,
                RequestState::Failed,
                Some(CAUSE_DAEMON_RESTART),
                AuditEntry {
                    action: ACTION_DAEMON_RESTART,
                    decision: Decision::Timeout,
                    actor: Actor::System,
                    detail: Some(&detail),
                },
            )
            .await?;
        if was_waiting {
            match store
                .resolve_approval(
                    &row.id,
                    ApprovalResolution::Timeout,
                    Some(CAUSE_DAEMON_RESTART),
                )
                .await
            {
                // NotFound: no unresolved approval row (e.g. the daemon
                // died between the state write and the approval insert).
                Ok(()) | Err(StoreError::NotFound { .. }) => {}
                Err(err) => return Err(err),
            }
        }
        if finished {
            recovered.push(row.id);
        }
    }
    Ok(recovered)
}

/// Builds the non-blocking writer for the daemon's own log:
/// `<base>/log/daemon.log`, rotated daily. Keep the [`WorkerGuard`]
/// alive until exit — dropping it flushes the background writer.
pub fn daemon_log_writer(base: &Path) -> Result<(NonBlocking, WorkerGuard), LifecycleError> {
    let dir = base.join(LOG_DIR);
    std::fs::create_dir_all(&dir).map_err(|source| LifecycleError::Io {
        path: dir.clone(),
        source,
    })?;
    Ok(tracing_appender::non_blocking(
        tracing_appender::rolling::daily(&dir, LOG_FILE),
    ))
}

/// Installs the daemon's global tracing subscriber writing to
/// `<base>/log/daemon.log` (see [`daemon_log_writer`]): daily rotation,
/// no ANSI, level `info` unless the `PAM_LOG` environment variable
/// names a filter. Debugging PAM itself — never product evidence.
///
/// Keep the returned guard alive until process exit. A subscriber that
/// is already installed (tests) is left in place.
pub fn init_daemon_logging(base: &Path) -> Result<WorkerGuard, LifecycleError> {
    let (writer, guard) = daemon_log_writer(base)?;
    let filter = tracing_subscriber::EnvFilter::try_from_env("PAM_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_ansi(false)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
    Ok(guard)
}
