//! Client-side daemon lifecycle: lazy auto-start.
//!
//! Any `pam` command may find no daemon behind `pam.sock` — a fresh
//! machine, a crashed daemon, or one that just drained itself away for
//! a self-restart. [`ensure_daemon`] makes the daemon exist before the
//! command talks to it: probe, spawn `pam daemon` detached if nobody is
//! there, and wait (bounded, ~3 s, one respawn retry) for readiness.
//!
//! # Probe
//!
//! "A daemon is running" is read from the same facts the daemon
//! maintains: the `daemon.lock` file is **held** (the probe tries the
//! advisory lock itself — winning it proves nobody else holds it, and
//! the probe releases it immediately) and the `pam.sock` file exists.
//! A stale socket with no lock holder therefore reads as *no daemon*,
//! and the spawned daemon removes and rebinds it under the lock. The
//! lock probe is authoritative in a way pinging the socket is not: it
//! cannot be fooled by a leftover socket file, needs no timeout, and
//! costs one syscall.
//!
//! # What this module does not do
//!
//! Sending the actual request (and retrying it once after an
//! auto-start or a `daemon_outdated` refusal) is the full CLI request
//! flow, built on top of this in the client work (task #13).

use std::fs::{OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use pam_daemon::lifecycle::LOCK_FILE;
use pam_daemon::runtime_dir::{RuntimeDir, RuntimeDirError};
use thiserror::Error;

/// How long [`ensure_daemon`] waits for a spawned daemon to become
/// ready, per spawn attempt.
pub const READINESS_WAIT: Duration = Duration::from_secs(3);

/// How often the readiness wait re-probes.
const READINESS_POLL: Duration = Duration::from_millis(50);

/// How many times [`ensure_daemon`] spawns before giving up: the spec's
/// "retry once".
const SPAWN_ATTEMPTS: u32 = 2;

/// Why the daemon could not be ensured.
#[derive(Debug, Error)]
pub enum ClientError {
    /// The runtime directory is unusable (home unresolvable, socket
    /// path too long, or the directory could not be created).
    #[error(transparent)]
    RuntimeDir(#[from] RuntimeDirError),
    /// The lock-file probe failed at the filesystem level.
    #[error("cannot probe daemon lock {}: {source}", path.display())]
    Probe {
        /// The lock file being probed.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// Spawning `pam daemon` failed.
    #[error("cannot spawn the pam daemon: {source}")]
    Spawn {
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The daemon did not become ready within the bounded wait.
    #[error(
        "the pam daemon did not become ready within {waited:?} \
         (after {SPAWN_ATTEMPTS} spawn attempts)"
    )]
    NotReady {
        /// Total time spent waiting across all attempts.
        waited: Duration,
    },
}

/// What [`ensure_daemon`] found or did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsureOutcome {
    /// A daemon already held the lock and served the socket.
    AlreadyRunning,
    /// No daemon was there; one was spawned and became ready.
    Started,
}

/// Makes sure a daemon serves `base_dir` (default `~/.pam` in the real
/// CLI): probes for a live one, otherwise spawns `pam daemon` detached
/// and waits — up to [`READINESS_WAIT`] per attempt, one retry — for it
/// to hold the lock and bind the socket.
pub fn ensure_daemon(base_dir: &Path) -> Result<EnsureOutcome, ClientError> {
    ensure_daemon_with(
        base_dir,
        &mut spawn_detached_daemon,
        READINESS_WAIT,
        READINESS_POLL,
    )
}

/// [`ensure_daemon`] with the spawner and timing injected — the
/// decision logic, unit-testable with a fake spawner (a test binary
/// cannot spawn the real `pam`; the real spawner is the thin
/// [`spawn_detached_daemon`] wrapper).
pub(crate) fn ensure_daemon_with(
    base_dir: &Path,
    spawn: &mut dyn FnMut() -> io::Result<()>,
    wait: Duration,
    poll: Duration,
) -> Result<EnsureOutcome, ClientError> {
    let dirs = RuntimeDir::at_base(base_dir)?;
    if daemon_ready(&dirs)? {
        return Ok(EnsureOutcome::AlreadyRunning);
    }
    for _attempt in 0..SPAWN_ATTEMPTS {
        spawn().map_err(|source| ClientError::Spawn { source })?;
        let deadline = Instant::now() + wait;
        loop {
            if daemon_ready(&dirs)? {
                return Ok(EnsureOutcome::Started);
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(poll);
        }
    }
    Err(ClientError::NotReady {
        waited: wait * SPAWN_ATTEMPTS,
    })
}

/// True when a daemon holds the instance lock **and** the request
/// socket file exists (see the module docs on the probe).
fn daemon_ready(dirs: &RuntimeDir) -> Result<bool, ClientError> {
    if !dirs.router_socket().exists() {
        return Ok(false);
    }
    lock_is_held(&dirs.run_dir().join(LOCK_FILE))
}

/// Probes the advisory lock on `path`: `true` when someone else holds
/// it. Winning the lock proves nobody does; it is released immediately
/// (the handle drops at return).
fn lock_is_held(path: &Path) -> Result<bool, ClientError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        // Never truncate: a live daemon's pid lives in this file.
        .truncate(false)
        .open(path)
        .map_err(|source| ClientError::Probe {
            path: path.to_path_buf(),
            source,
        })?;
    match file.try_lock() {
        Ok(()) => Ok(false),
        Err(TryLockError::WouldBlock) => Ok(true),
        Err(TryLockError::Error(source)) => Err(ClientError::Probe {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// The real spawner: `current_exe() daemon`, detached (no inherited
/// stdio, never waited on — the daemon self-logs to `~/.pam/log/`).
fn spawn_detached_daemon() -> io::Result<()> {
    let exe = std::env::current_exe()?;
    Command::new(exe)
        .arg("daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_child| ())
}
