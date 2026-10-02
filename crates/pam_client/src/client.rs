//! Client-side daemon lifecycle and the public request flow.
//!
//! **Lazy start.** [`ensure_daemon`] looks for a daemon behind the public endpoint, spawns
//! `pam daemon` detached if there is none, and waits (bounded, ~3 s, one respawn retry) for
//! readiness. Readiness is a **successful hello**: `daemon.lock` has an exclusive holder (a
//! shared-lock probe conflicts with it) **and** the daemon acknowledged this build's hello
//! ([`crate::transport::probe`]), so a stale socket file left behind by a crash never reads as
//! ready. A lock holder whose endpoint is not up yet is a daemon still booting (crash recovery,
//! warm-up): the client waits for it instead of spawning another process. The spawned daemon is
//! isolated from the caller: its own process group, a fixed working directory, and an explicit
//! environment allowlist ([`daemon_env`]) instead of the caller's environment. Client path
//! resolution never creates or chmods the runtime directory; only daemon startup prepares it.
//!
//! **What the hello can find instead.** A daemon whose binary was replaced on disk answers
//! `daemon_outdated` and restarts itself: the client waits for the replacement. A daemon of
//! another build whose binary is unchanged answers `client_version_mismatch`: it is running and
//! it is left alone — the request that follows gets that refusal, with the daemon's version, its
//! executable and what to do, and the client never stops a daemon over it. A peer that greets in
//! ZMTP is a pre-migration daemon: an unsandboxed client stops it the way `pam daemon stop` does
//! (the pid in the instance lock, `SIGTERM`, a bounded wait for the lock), then starts its own
//! build; a client that may not signal it, or that dials through `PAM_SOCKET_DIR`, fails with the
//! instruction for the human ([`ClientError::LegacyDaemon`], [`ClientError::LegacyBehindRelay`]).
//! That is the only case in which a client stops a daemon on its own.
//!
//! **Requests.** [`send_request`] ensures the daemon, builds the envelope, and exchanges it over
//! one framed connection (hello, `request`, `reply`; the connect is bounded at 5 s and retries a
//! restarting daemon's endpoint inside that window, the reply at `deadline_ms` plus a margin),
//! refusing the reserved GUI-only `admin.*` namespace before touching the socket ([`send_admin`]
//! is the GUI's path instead). A hello the daemon refuses with an `error` frame comes back as the
//! refusal it is, naming the request: cause, detail and recovery are the daemon's. After a
//! [`CAUSE_DAEMON_OUTDATED`] refusal the old daemon drains and a new one takes over: the client
//! waits for that replacement to be ready, then retries exactly once. [`send_request_with_id`]
//! takes the request id from the caller, so the id is known before anything is sent.
//!
//! **Follows.** [`follow_ticket`] follows one ticket on one framed connection (`pam wait`
//! quietly, `pam subscribe` printing each event): hello, `follow`, then the ticket's events and
//! an `end` frame that carries the durable result, so nothing is queried afterwards
//! ([`follow_ticket_to_end`] returns it). A follow that attaches late receives what the daemon
//! still holds of the earlier events, and one that attaches after the ticket finished ends at
//! once. The daemon's momentary condition is not a verdict: transient refusals (capacity, rate,
//! shutting down, restarting) and a dropped connection are retried with bounded backoff until the
//! caller's timeout, resuming after the last sequence number seen; a changed daemon epoch is a
//! restarted daemon and starts the position over. An event kind or frame type this build does
//! not know is skipped.

use std::ffi::OsString;
use std::fs::{File, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use pam_daemon::admin::{ADMIN_CALLER_AGENT, ADMIN_PREFIX, ADMIN_REPO};
use pam_daemon::daemon::CAUSE_DAEMON_OUTDATED;
use pam_daemon::lifecycle::LOCK_FILE;
use pam_daemon::runtime_dir::{RuntimeDir, RuntimeDirError};
use pam_proto::wire::{End, ErrorFrame, Via, cause};
use pam_proto::{Caller, Envelope, Event, PROTOCOL_VERSION, Response};
use thiserror::Error;

use crate::request::{build_envelope, build_envelope_with_id, new_request_id};
use crate::transport::{self, Dial, Probe, Resume, TransportError};

/// How long [`ensure_daemon`] waits for a spawned daemon to become
/// ready, per spawn attempt.
pub const READINESS_WAIT: Duration = Duration::from_secs(3);

/// The session socket override: when `$PAM_SOCKET_DIR` names a directory,
/// public dials use the public socket directly inside it instead of
/// `<base>/run`'s — the layout [`crate::relay`] (`pam listen`) binds — and
/// lazy daemon auto-start is off. The relay is the transport, so a missing
/// relay is an error naming `pam listen`, never a spawned daemon, and a
/// pre-migration daemon behind it is an error for the human, never a signal.
pub const SOCKET_DIR_ENV: &str = "PAM_SOCKET_DIR";

/// [`SOCKET_DIR_ENV`] as the client sees it: set and non-empty.
fn session_socket_dir() -> Option<PathBuf> {
    let dir = std::env::var_os(SOCKET_DIR_ENV)?;
    (!dir.is_empty()).then_some(PathBuf::from(dir))
}

/// The runtime directories one public dial uses: the session override's
/// flat layout when set, `<base>/run` otherwise — the resolution rule with
/// the override injected, unit-testable without mutating process
/// environment (which the workspace's `unsafe` denial forbids in edition
/// 2024).
pub(crate) fn dial_dirs_with(
    session_dir: Option<&Path>,
    base_dir: &Path,
) -> Result<RuntimeDir, RuntimeDirError> {
    match session_dir {
        Some(dir) => RuntimeDir::paths_at_dir(dir),
        None => RuntimeDir::paths_at_base(base_dir),
    }
}

/// The daemon-half of a public dial: probe for (or lazily spawn) a daemon,
/// unless the session override is active — the relay is then the
/// transport, and probing a base whose lock nobody holds would only
/// trigger a pointless spawn.
async fn ensure_daemon_for_dial(base_dir: &Path) -> Result<(), RequestError> {
    ensure_for_dial_off_thread(
        session_socket_dir().as_deref(),
        base_dir,
        real_spawner(base_dir),
        READINESS_WAIT,
        READINESS_POLL,
    )
    .await
    .map_err(RequestError::from)
}

/// The production spawner for `base_dir`: [`spawn_daemon_process`] on this
/// binary.
fn real_spawner(base_dir: &Path) -> impl FnMut() -> io::Result<()> + Send + 'static {
    let base = base_dir.to_path_buf();
    move || spawn_daemon_process(&daemon_exe()?, &base)
}

/// The binary a daemon is spawned from: this process's executable. On
/// Linux a binary replaced on disk after this process started reads back as
/// `…/pam (deleted)`; the replacement at the original path is what a newer
/// daemon must run, so that suffix is stripped when the path exists.
///
/// # Errors
///
/// Whatever [`std::env::current_exe`] produced.
pub fn daemon_exe() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    if cfg!(target_os = "linux")
        && let Some(stripped) = exe
            .to_str()
            .and_then(|text| text.strip_suffix(" (deleted)"))
    {
        let replaced = PathBuf::from(stripped);
        if replaced.exists() {
            return Ok(replaced);
        }
    }
    Ok(exe)
}

/// [`ensure_daemon_for_dial`] with the override and spawner injected, so
/// the never-spawn guarantee is unit-testable without process environment
/// (which the workspace's `unsafe` denial forbids in edition 2024).
pub(crate) async fn ensure_for_dial_off_thread(
    session_dir: Option<&Path>,
    base_dir: &Path,
    spawn: impl FnMut() -> io::Result<()> + Send + 'static,
    wait: Duration,
    poll: Duration,
) -> Result<(), ClientError> {
    if session_dir.is_some() {
        return Ok(());
    }
    ensure_daemon_off_thread(base_dir, spawn, wait, poll)
        .await
        .map(|_| ())
}

/// How often the readiness wait re-probes.
const READINESS_POLL: Duration = Duration::from_millis(50);

/// How many times [`ensure_daemon`] spawns before giving up: the spec's
/// "retry once".
const SPAWN_ATTEMPTS: u32 = 2;

/// How long one readiness hello may take. A listener that has not answered
/// by then is a live daemon too busy to greet, so a timeout counts as ready
/// and the request's own exchange reports what it meets.
const HELLO_PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// How long a daemon that is stopping or restarting may take to release the
/// instance lock: the drain is up to ten seconds (`DEFAULT_DRAIN_TIMEOUT`),
/// and a successor then has to boot.
pub(crate) const HANDOVER_WAIT: Duration = Duration::from_secs(20);

/// File name of the socket a pre-migration daemon listens on. On Windows it
/// is an `AF_UNIX` socket this build cannot open, so its presence beside a
/// held lock and no public control file is how such a daemon is recognised.
const LEGACY_SOCKET_FILE: &str = "pam.sock";

/// What the human does about a pre-migration daemon this process may not stop.
///
/// Two commands on unix, because stopping is half of it: a client that may
/// not signal the old daemon is confined, and a confined client usually may
/// not start a daemon either (it cannot write the base, or it dials through
/// a relay and never spawns). `pam status` run outside starts the current
/// daemon; with only `pam daemon stop` the retry fails with "did not become
/// ready" or a transport failure (upgrade rehearsal, 2026-10-02).
const LEGACY_RECOVERY: &str = if cfg!(windows) {
    "end that pam daemon process, then retry"
} else {
    "run `pam daemon stop` and then `pam status` outside the sandbox, then retry"
};

/// Why no daemon this build can talk to could be ensured.
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
    /// The blocking readiness probe ([`ensure_daemon`] on a worker
    /// thread) could not be joined: it panicked or the runtime is
    /// shutting down.
    #[error("the daemon readiness probe did not complete: {source}")]
    ProbeTask {
        /// The underlying join error.
        #[source]
        source: tokio::task::JoinError,
    },
    /// A pre-migration daemon holds the instance lock and this process could
    /// not stop it: the lock names no pid, or signalling is not permitted
    /// (as under a sandbox that denies signals).
    #[error(
        "a pre-migration pam daemon ({}) is running and this process may not stop it ({detail}); \
         {LEGACY_RECOVERY}",
        .pid.map_or_else(|| "pid unknown".to_owned(), |holder| format!("pid {holder}"))
    )]
    LegacyDaemon {
        /// The pid in the instance lock, when it names one.
        pid: Option<u32>,
        /// Why it could not be stopped.
        detail: String,
    },
    /// A pre-migration daemon was told to stop and has not released the
    /// instance lock yet. Transient: it exits when its drain completes.
    #[error(
        "a pre-migration pam daemon (pid {pid}) was told to stop and is still draining after \
         {waited:?}; it exits when the drain completes, then retry"
    )]
    LegacyDraining {
        /// The draining daemon's pid.
        pid: u32,
        /// How long the client waited for the lock.
        waited: Duration,
    },
    /// The session relay (`PAM_SOCKET_DIR`) leads to a pre-migration daemon.
    /// A client that dials through a relay never signals anything.
    #[error(
        "the pam daemon behind the session relay in {} ($PAM_SOCKET_DIR) predates this pam's \
         wire protocol; run `pam daemon stop` and then `pam status` outside the sandbox and try \
         again",
        dir.display()
    )]
    LegacyBehindRelay {
        /// The override directory that was dialled.
        dir: PathBuf,
    },
}

/// What [`ensure_daemon`] found or did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsureOutcome {
    /// A daemon already held the lock and answered the hello.
    AlreadyRunning,
    /// No daemon was there (or only a pre-migration one, which was stopped);
    /// one was spawned and became ready.
    Started,
}

/// Makes sure a daemon of this build serves `base_dir` (default `~/.pam` in
/// the real CLI): greets a live one, otherwise spawns `pam daemon` detached
/// and waits — up to [`READINESS_WAIT`] per attempt, one retry — for it to
/// hold the lock and acknowledge a hello. A pre-migration daemon found
/// there is stopped first (module docs).
pub fn ensure_daemon(base_dir: &Path) -> Result<EnsureOutcome, ClientError> {
    ensure_daemon_with(
        base_dir,
        &mut real_spawner(base_dir),
        READINESS_WAIT,
        READINESS_POLL,
    )
}

/// [`ensure_daemon`] for async callers: the probe sleeps and polls
/// synchronously (up to [`READINESS_WAIT`] per spawn attempt), so it runs
/// on a blocking thread instead of parking a tokio or Tauri worker.
async fn ensure_daemon_async(base_dir: &Path) -> Result<EnsureOutcome, ClientError> {
    ensure_daemon_off_thread(
        base_dir,
        real_spawner(base_dir),
        READINESS_WAIT,
        READINESS_POLL,
    )
    .await
}

/// [`ensure_daemon_async`] with the spawner and timing injected: runs
/// [`ensure_daemon_with`] on a blocking thread and joins it.
pub(crate) async fn ensure_daemon_off_thread(
    base_dir: &Path,
    mut spawn: impl FnMut() -> io::Result<()> + Send + 'static,
    wait: Duration,
    poll: Duration,
) -> Result<EnsureOutcome, ClientError> {
    let base = base_dir.to_path_buf();
    tokio::task::spawn_blocking(move || ensure_daemon_with(&base, &mut spawn, wait, poll))
        .await
        .map_err(|source| ClientError::ProbeTask { source })?
}

/// [`ensure_daemon`] with the spawner and timing injected — the
/// decision logic, unit-testable with a fake spawner (a test binary
/// cannot spawn the real `pam`; the real spawner is the thin
/// [`spawn_daemon_process`] wrapper). The signal is the real one
/// (`signal_terminate`); [`Ensure`] takes that too.
pub(crate) fn ensure_daemon_with(
    base_dir: &Path,
    spawn: &mut dyn FnMut() -> io::Result<()>,
    wait: Duration,
    poll: Duration,
) -> Result<EnsureOutcome, ClientError> {
    Ensure {
        spawn,
        signal: &mut signal_terminate,
        client_version: env!("CARGO_PKG_VERSION"),
        wait,
        poll,
        handover: HANDOVER_WAIT,
        probe: HELLO_PROBE_TIMEOUT,
    }
    .run(base_dir)
}

/// One run of the ensure logic with everything it touches outside the
/// runtime directory injected: how a daemon is spawned, how one is
/// signalled, the version the hello states, and every wait.
pub(crate) struct Ensure<'a> {
    /// Starts `pam daemon` for the base.
    pub(crate) spawn: &'a mut dyn FnMut() -> io::Result<()>,
    /// Sends the stop signal to a pid (`SIGTERM` in production).
    pub(crate) signal: &'a mut dyn FnMut(u32) -> Result<(), StopError>,
    /// The version the readiness hello states.
    pub(crate) client_version: &'a str,
    /// Readiness wait per spawn attempt.
    pub(crate) wait: Duration,
    /// Pause between two looks at the daemon.
    pub(crate) poll: Duration,
    /// How long a stopping or restarting daemon may hold the lock.
    pub(crate) handover: Duration,
    /// How long one readiness hello may take.
    pub(crate) probe: Duration,
}

impl Ensure<'_> {
    /// The decision logic of [`ensure_daemon`].
    ///
    /// A daemon that is already on its way — **booting** (it holds the
    /// instance lock but does not answer yet) or **restarting** (its binary
    /// was replaced on disk and it is draining) — is waited for, never raced
    /// with a second spawn: the extra process would only lose the lock and
    /// exit. A **pre-migration** daemon is superseded once. A daemon of
    /// another build counts as running and is left alone: the request that
    /// follows gets its refusal.
    pub(crate) fn run(&mut self, base_dir: &Path) -> Result<EnsureOutcome, ClientError> {
        let dirs = RuntimeDir::paths_at_base(base_dir)?;
        let mut state = self.settled(base_dir, &dirs)?;
        if state == DaemonState::Legacy {
            state = self.supersede(base_dir, &dirs)?;
        }
        match state {
            DaemonState::Ready => return Ok(EnsureOutcome::AlreadyRunning),
            // Greeting in the old protocol again after it was stopped: a
            // service manager or an older client keeps starting it.
            DaemonState::Legacy => {
                return Err(ClientError::LegacyDaemon {
                    pid: lock_holder(base_dir),
                    detail: "it was stopped and a pre-migration daemon took the instance lock \
                             again"
                        .to_owned(),
                });
            }
            DaemonState::Absent => {}
            // `settled` returns neither; refuse rather than spawn over a
            // lock holder.
            DaemonState::Booting | DaemonState::Restarting => {
                return Err(ClientError::NotReady {
                    waited: self.wait * SPAWN_ATTEMPTS,
                });
            }
        }
        for _attempt in 0..SPAWN_ATTEMPTS {
            (self.spawn)().map_err(|source| ClientError::Spawn { source })?;
            let deadline = Instant::now() + self.wait;
            loop {
                if self.state(&dirs)? == DaemonState::Ready {
                    return Ok(EnsureOutcome::Started);
                }
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(self.poll);
            }
        }
        Err(ClientError::NotReady {
            waited: self.wait * SPAWN_ATTEMPTS,
        })
    }

    /// Where the daemon stands once it is no longer on its way: waits out
    /// a booting daemon (for as long as a spawn would be given) and a
    /// restarting one (for the handover), and returns the first state that
    /// is neither.
    fn settled(&self, base_dir: &Path, dirs: &RuntimeDir) -> Result<DaemonState, ClientError> {
        let started = Instant::now();
        loop {
            let state = self.state(dirs)?;
            let budget = match state {
                DaemonState::Booting => self.wait * SPAWN_ATTEMPTS,
                DaemonState::Restarting => self.handover,
                _ => return Ok(state),
            };
            if started.elapsed() >= budget {
                return Err(never_ready(base_dir, dirs, budget));
            }
            std::thread::sleep(self.poll);
        }
    }

    /// Stops a pre-migration daemon by the mechanism `pam daemon stop` uses
    /// and reports where the base stands afterwards.
    ///
    /// The pid is read from the instance lock first and the daemon is
    /// greeted once more after that: if it no longer answers in the old
    /// protocol, another client already superseded it and nothing is
    /// signalled; if it still does, the pid read before is its own.
    fn supersede(
        &mut self,
        base_dir: &Path,
        dirs: &RuntimeDir,
    ) -> Result<DaemonState, ClientError> {
        let pid = match probe_daemon(base_dir)? {
            DaemonStatus::NotRunning => return self.settled(base_dir, dirs),
            DaemonStatus::Running { pid } => pid,
        };
        let again = self.settled(base_dir, dirs)?;
        if again != DaemonState::Legacy {
            return Ok(again);
        }
        let Some(pid) = pid else {
            return Err(ClientError::LegacyDaemon {
                pid: None,
                detail: "its lock file names no pid".to_owned(),
            });
        };
        (self.signal)(pid).map_err(|error| ClientError::LegacyDaemon {
            pid: Some(pid),
            detail: match error {
                StopError::Signal { detail, .. } => detail,
                other => other.to_string(),
            },
        })?;
        if !wait_for_daemon_exit(base_dir, self.handover)? {
            return Err(ClientError::LegacyDraining {
                pid,
                waited: self.handover,
            });
        }
        self.settled(base_dir, dirs)
    }

    /// Where a daemon stands behind one runtime directory right now: the
    /// instance lock, then one hello.
    fn state(&self, dirs: &RuntimeDir) -> Result<DaemonState, ClientError> {
        if !lock_is_held(&dirs.run_dir().join(LOCK_FILE))? {
            return Ok(DaemonState::Absent);
        }
        let hello = pam_proto::wire::Hello {
            proto: pam_proto::wire::WIRE_PROTOCOL,
            version: self.client_version.to_owned(),
            via: Via::Direct,
        };
        Ok(match transport::probe(dirs, &hello, self.probe) {
            Probe::Unreachable(_) => DaemonState::Booting,
            Probe::Legacy => DaemonState::Legacy,
            Probe::Refused(frame) if frame.cause == cause::DAEMON_OUTDATED => {
                DaemonState::Restarting
            }
            // Acknowledged, or listening and too busy to greet, or answering
            // with another refusal (a full listener, a slow handshake, a
            // client of another build): a daemon of this protocol is there
            // and stays, and the request's own exchange reports what it meets.
            Probe::Ready(_) | Probe::Silent | Probe::Refused(_) => DaemonState::Ready,
        })
    }
}

/// The error for a lock holder that never answered a hello within `waited`.
///
/// On Windows a pre-migration daemon cannot be greeted at all: it listens on
/// an `AF_UNIX` socket this build cannot open. A held lock, no public
/// control file after the wait and the old socket file in the run directory
/// is such a daemon, reported with the instruction to end it; there is no
/// automatic stop on that platform.
fn never_ready(base_dir: &Path, dirs: &RuntimeDir, waited: Duration) -> ClientError {
    if cfg!(windows)
        && dirs.run_dir().join(LEGACY_SOCKET_FILE).exists()
        && !dirs.public_control().exists()
    {
        return ClientError::LegacyDaemon {
            pid: lock_holder(base_dir),
            detail: "it publishes no public endpoint this pam can dial".to_owned(),
        };
    }
    ClientError::NotReady { waited }
}

/// Where a daemon stands behind one runtime directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonState {
    /// The lock is held and a daemon of this protocol answers: it
    /// acknowledged the hello, is too busy to greet, or refuses this
    /// particular client (another build), which is the request's answer to
    /// get, not a reason to start or stop anything.
    Ready,
    /// The lock is held but nothing answers yet: a daemon in crash recovery
    /// or warm-up (it binds after taking the lock).
    Booting,
    /// The lock is held by a daemon whose binary was replaced on disk: it
    /// answered `daemon_outdated` and is draining to hand over.
    Restarting,
    /// The lock is held by a daemon that greets in ZMTP: a pre-migration
    /// build.
    Legacy,
    /// Nobody holds the lock; any socket file is a stale leftover.
    Absent,
}

/// Probe the daemon's exclusive instance lock through a read-only handle.
/// A shared probe conflicts with that exclusive lock on both Unix and Windows,
/// but concurrent probes do not mistake each other for a running daemon.
/// Missing files mean no holder; access/locking errors never imply readiness.
fn lock_is_held(path: &Path) -> Result<bool, ClientError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(ClientError::Probe {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    match file.try_lock_shared() {
        Ok(()) => {
            // Explicitly release before promising no holder: a concurrent fork
            // can retain a duplicate handle after this local File drops.
            file.unlock().map_err(|source| ClientError::Probe {
                path: path.to_path_buf(),
                source,
            })?;
            Ok(false)
        }
        Err(TryLockError::WouldBlock) => Ok(true),
        Err(TryLockError::Error(source)) => Err(ClientError::Probe {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Environment variables a spawned daemon keeps from its caller: the
/// user's identity and locale, temp locations, and the few platform
/// variables the OS credential stores and process APIs need. Everything
/// else — in particular anything an agent harness exported — is dropped,
/// because the daemon outlives the command that started it and serves
/// every later caller.
const DAEMON_ENV_ALLOWLIST: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LANGUAGE",
    // The daemon's own documented debug filter (`init_daemon_logging`).
    "PAM_LOG",
    // Secret Service / keyring access on Linux.
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
    // Windows process, profile and credential-store basics.
    "SystemRoot",
    "SystemDrive",
    "windir",
    "ComSpec",
    "PATHEXT",
    "USERNAME",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "ProgramData",
];

/// `PATH` for a daemon whose caller's value has no usable entry.
#[cfg(unix)]
const DEFAULT_DAEMON_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// The environment a spawned daemon gets from `vars` (the caller's): the
/// `DAEMON_ENV_ALLOWLIST` plus `LC_*`, with `PATH` reduced to its
/// absolute entries (an empty or relative entry would resolve against
/// whatever directory the daemon runs in). The base directory is not
/// copied from the environment; `daemon_command` sets it explicitly.
#[must_use]
pub fn daemon_env(vars: impl Iterator<Item = (OsString, OsString)>) -> Vec<(OsString, OsString)> {
    let mut kept = Vec::new();
    let mut path = None;
    for (name, value) in vars {
        let Some(text) = name.to_str() else {
            continue;
        };
        if text.eq_ignore_ascii_case("PATH") {
            path = Some(value);
        } else if text.starts_with("LC_")
            || DAEMON_ENV_ALLOWLIST
                .iter()
                .any(|allowed| text.eq_ignore_ascii_case(allowed))
        {
            kept.push((name, value));
        }
    }
    let absolute: Vec<PathBuf> = path
        .iter()
        .flat_map(std::env::split_paths)
        .filter(|entry| entry.is_absolute())
        .collect();
    if let Ok(joined) = std::env::join_paths(&absolute)
        && !absolute.is_empty()
    {
        kept.push((OsString::from("PATH"), joined));
    } else {
        #[cfg(unix)]
        kept.push((OsString::from("PATH"), OsString::from(DEFAULT_DAEMON_PATH)));
    }
    kept
}

/// The fixed working directory of a spawned daemon: never the caller's
/// (an agent's repository), which flows must not see as the daemon's home.
fn daemon_cwd() -> PathBuf {
    if cfg!(unix) {
        PathBuf::from("/")
    } else {
        std::env::temp_dir()
    }
}

/// The command that starts `exe daemon` isolated from its caller: own
/// process group (a harness that kills the caller's group does not kill the
/// shared daemon), fixed working directory, null stdio, and the
/// [`daemon_env`] allowlist over `vars` plus an explicit absolute
/// `PAM_BASE_DIR`, so a relative override still names the same directory
/// from the new working directory.
pub(crate) fn daemon_command(
    exe: &Path,
    base_dir: &Path,
    vars: impl Iterator<Item = (OsString, OsString)>,
) -> Command {
    let base = std::path::absolute(base_dir).unwrap_or_else(|_| base_dir.to_path_buf());
    let mut command = Command::new(exe);
    command
        .arg("daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_clear()
        .envs(daemon_env(vars))
        .env("PAM_BASE_DIR", base)
        .current_dir(daemon_cwd());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        // CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW.
        command.creation_flags(0x0000_0200 | 0x0800_0000);
    }
    command
}

/// Starts `exe daemon` for `base_dir` as an isolated background process
/// (`daemon_command`) and reaps it from a helper thread when it exits, so
/// a long-lived caller (the GUI) accumulates no zombies. The daemon
/// self-logs to `<base>/log/`.
///
/// # Errors
///
/// Whatever spawning the process produced.
pub fn spawn_daemon_process(exe: &Path, base_dir: &Path) -> io::Result<()> {
    let mut child = daemon_command(exe, base_dir, std::env::vars_os()).spawn()?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

/// Default bound on `pam wait` / `pam subscribe`, in milliseconds
/// (10 minutes) — the CLI's `--timeout-ms` default.
pub const DEFAULT_FOLLOW_TIMEOUT_MS: u64 = 600_000;

/// [`DEFAULT_FOLLOW_TIMEOUT_MS`] as a [`Duration`].
pub const DEFAULT_FOLLOW_TIMEOUT: Duration = Duration::from_millis(DEFAULT_FOLLOW_TIMEOUT_MS);

/// Extra client-side budget on top of the envelope's `deadline_ms`
/// before [`send_request`] gives up on a reply: the daemon enforces the
/// deadline itself (it refuses, not hangs), so the margin only covers
/// transport latency around that refusal.
const REPLY_MARGIN: Duration = Duration::from_secs(5);

/// Pause before the single retry after a `daemon_outdated` refusal —
/// long enough for the old daemon to finish its drain and the new
/// binary to take the lock in the common case.
const OUTDATED_RETRY_PAUSE: Duration = Duration::from_millis(750);

/// Why the request flow failed client-side (a daemon-side "no" is a
/// [`Response::Refusal`], not an error).
#[derive(Debug, Error)]
pub enum RequestError {
    /// No daemon this build can talk to could be ensured: none became
    /// ready, or the one that runs is a pre-migration daemon this process
    /// may not stop (see [`ClientError`]).
    #[error(transparent)]
    Ensure(#[from] ClientError),
    /// The runtime directory is unusable.
    #[error(transparent)]
    RuntimeDir(#[from] RuntimeDirError),
    /// Connecting the daemon's public endpoint failed.
    #[error("cannot connect to {endpoint}: {source}")]
    Connect {
        /// The endpoint that failed: the socket path, or the control file on
        /// Windows.
        endpoint: String,
        /// The underlying connect error.
        #[source]
        source: io::Error,
    },
    /// The session relay (`PAM_SOCKET_DIR`) is not answering. The client
    /// never spawns a daemon while the override is set — the relay is the
    /// transport — so this names the way to start it instead.
    #[error(
        "no session relay answered in {dir} ($PAM_SOCKET_DIR); start one \
         outside the sandbox with `pam listen {dir}`"
    )]
    SessionUnreachable {
        /// The override directory whose socket did not answer.
        dir: PathBuf,
        /// The underlying connect error.
        #[source]
        source: io::Error,
    },
    /// The connection failed after it was made.
    #[error("transport failure talking to the daemon: {source}")]
    Transport {
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The daemon's bytes were not a frame this protocol allows there.
    #[error("cannot parse the daemon's reply: {detail}")]
    Parse {
        /// What was wrong with it.
        detail: String,
    },
    /// No reply within the client-side budget.
    #[error("no reply from the daemon within {waited:?} (deadline plus margin)")]
    ReplyTimeout {
        /// How long the client waited.
        waited: Duration,
    },
    /// No terminal event within the follow bound.
    #[error("request {ticket} did not reach a terminal event within {waited:?}")]
    FollowTimeout {
        /// The ticket being followed.
        ticket: String,
        /// How long the client waited.
        waited: Duration,
    },
    /// Scoped ticket lookup refused access; following stops without retrying.
    #[error("cannot follow request {ticket}: {cause}: {detail}; {recovery}")]
    FollowRefused {
        /// The original ticket, retained for later authorized recovery.
        ticket: String,
        /// Stable daemon refusal cause.
        cause: String,
        /// Safe refusal explanation.
        detail: String,
        /// Authorized next step.
        recovery: String,
    },
    /// [`send_request`] was handed a GUI-only `admin.*` capability —
    /// the structural guard keeping every CLI code path out of the
    /// admin surface (see [`send_admin`]).
    #[error(
        "capability {capability:?} is a GUI-only admin operation; the pam CLI \
         has no security commands — use the PAM GUI"
    )]
    AdminOnly {
        /// The refused `admin.*` capability.
        capability: String,
    },
    /// [`send_admin`] was handed a capability outside the `admin.*`
    /// namespace; ordinary capabilities go through [`send_request`].
    #[error("send_admin only sends admin.* operations, got {capability:?}")]
    NotAdmin {
        /// The refused capability.
        capability: String,
    },
    /// The private administration channel failed. The request is never replayed:
    /// a lost reply does not establish whether its effects were applied.
    #[error("private administration channel failed: {source}; operation was not retried")]
    AdminTransport {
        /// Native transport, peer-verification, or unsupported-platform error.
        #[source]
        source: io::Error,
    },
}

/// True when `response` is the version-handshake refusal after which
/// the spec tells the client to retry once: the daemon found the binary
/// on disk newer than itself and is restarting.
#[must_use]
pub fn should_retry(response: &Response) -> bool {
    matches!(response, Response::Refusal { cause, .. } if cause == CAUSE_DAEMON_OUTDATED)
}

/// Sends one request through the full client flow (module docs): ensure the daemon, build the
/// envelope, exchange it over one framed connection, retry exactly once after a `daemon_outdated`
/// refusal. The daemon's answer (result, refusal, or ticket) is returned as-is; rendering and exit
/// codes are the caller's job (the `pam` binary's `render` module).
///
/// A capability under the reserved `admin.` prefix errors with [`RequestError::AdminOnly`] **before
/// anything touches the socket** — every CLI subcommand funnels through here, so no subcommand,
/// present or future, can reach the daemon's GUI-only admin surface. The GUI uses [`send_admin`]
/// instead.
pub async fn send_request(
    base_dir: &Path,
    capability: &str,
    args: serde_json::Value,
    wait: bool,
    deadline_ms: u64,
    idempotency_key: Option<String>,
) -> Result<Response, RequestError> {
    send_request_with_id(
        base_dir,
        new_request_id(),
        capability,
        args,
        wait,
        deadline_ms,
        idempotency_key,
    )
    .await
}

/// [`send_request`] with the request id chosen by the caller (see
/// [`crate::request::build_envelope_with_id`]): the id is known before
/// anything is sent, so a caller can name the request when its reply never
/// arrives, or mark its own control traffic.
pub async fn send_request_with_id(
    base_dir: &Path,
    id: String,
    capability: &str,
    args: serde_json::Value,
    wait: bool,
    deadline_ms: u64,
    idempotency_key: Option<String>,
) -> Result<Response, RequestError> {
    if capability.starts_with(ADMIN_PREFIX) {
        return Err(RequestError::AdminOnly {
            capability: capability.to_owned(),
        });
    }
    let envelope = build_envelope_with_id(id, capability, args, wait, deadline_ms, idempotency_key);
    send_envelope(base_dir, &envelope).await
}

/// [`send_request`] that keeps asking through the daemon's momentary
/// conditions: a refusal the daemon marked `retryable` (or, from a daemon
/// that does not mark them, one of the [`TRANSIENT_CAUSES`]) or a transient
/// transport failure ([`RequestError::is_transient`]) is retried with bounded
/// backoff for up to `patience`, then returned as it came. Meant for reads of
/// a request that is already known good (a terminal ticket), where a busy
/// daemon must not read as a policy refusal. Each attempt is a fresh
/// request id.
pub async fn send_request_patient(
    base_dir: &Path,
    capability: &str,
    args: serde_json::Value,
    wait: bool,
    deadline_ms: u64,
    patience: Duration,
) -> Result<Response, RequestError> {
    let deadline = Instant::now() + patience;
    let mut pause = TRANSIENT_MIN;
    loop {
        let sent = send_request(base_dir, capability, args.clone(), wait, deadline_ms, None).await;
        let retry = match &sent {
            Ok(Response::Refusal {
                cause, retryable, ..
            }) => *retryable || is_transient_cause(cause),
            Err(error) => error.is_transient(),
            Ok(_) => false,
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if !retry || remaining.is_zero() {
            return sent;
        }
        tokio::time::sleep(pause.min(remaining)).await;
        pause = (pause * 2).min(TRANSIENT_MAX);
    }
}

/// Sends one **GUI-only** admin operation (`admin.*`) to the daemon — the path `pam gui`
/// administers the daemon through (grants, approvals, profile, activity), deliberately separate
/// from [`send_request`], which refuses `admin.*` outright. The native administration channel
/// authenticates peers independently of the envelope's caller fields, never falls back to the
/// public socket, and is unavailable where that channel is unsupported.
///
/// The daemon is ensured first through the public hello (so a pre-migration daemon is superseded
/// before its admin listener is spoken to in frames it does not know). The exchange then runs
/// once: a transport error or version refusal is returned without replaying the operation,
/// because a missing reply can follow an applied change — inspect the resulting state before
/// manually retrying. A capability outside `admin.*` errors with [`RequestError::NotAdmin`].
/// Admin ops always wait (synchronous request/reply).
pub async fn send_admin(
    base_dir: &Path,
    op: &str,
    args: serde_json::Value,
    deadline_ms: u64,
) -> Result<Response, RequestError> {
    if !op.starts_with(ADMIN_PREFIX) {
        return Err(RequestError::NotAdmin {
            capability: op.to_owned(),
        });
    }
    let envelope = Envelope {
        v: PROTOCOL_VERSION,
        id: new_request_id(),
        capability: op.to_owned(),
        client_version: env!("CARGO_PKG_VERSION").to_owned(),
        caller: Caller {
            agent: ADMIN_CALLER_AGENT.to_owned(),
            repo: ADMIN_REPO.to_owned(),
            pid: std::process::id(),
        },
        args,
        idempotency_key: None,
        deadline_ms,
        wait: true,
    };
    exchange_admin(base_dir, &envelope).await
}

/// The two steps of [`send_admin`] for an envelope already built: ensure the
/// daemon through the public hello, then one exchange on the private
/// channel. A hello the admin plane refuses (`client_version_mismatch`,
/// `daemon_outdated`, …) is that plane's answer: a refusal naming the
/// operation, never replayed.
pub(crate) async fn exchange_admin(
    base_dir: &Path,
    envelope: &Envelope,
) -> Result<Response, RequestError> {
    ensure_daemon_async(base_dir).await?;
    pam_daemon::admin_transport::exchange(base_dir, envelope)
        .await
        .map_err(|source| RequestError::AdminTransport { source })
}

/// How one public exchange or follow reaches the daemon, and how patient
/// it is: everything the request flow reads from the environment or from a
/// constant, in one injectable place.
#[derive(Debug, Clone)]
pub(crate) struct DialOptions {
    /// `$PAM_SOCKET_DIR`, when the session relay is the transport.
    pub(crate) session_dir: Option<PathBuf>,
    /// The version the hello states.
    pub(crate) client_version: String,
    /// Bound on one connect, retries of a restarting endpoint included.
    pub(crate) connect_timeout: Duration,
    /// Pause before waiting on the replacement of an outdated daemon.
    pub(crate) pause: Duration,
    /// Longest wait for an outdated daemon's drain to hand over.
    pub(crate) replacement_wait: Duration,
    /// First pause after a transient failure of a follow.
    pub(crate) backoff_min: Duration,
    /// Cap on that pause.
    pub(crate) backoff_max: Duration,
}

impl DialOptions {
    /// The production values, with the session override as given.
    pub(crate) fn new(session_dir: Option<PathBuf>) -> Self {
        Self {
            session_dir,
            client_version: env!("CARGO_PKG_VERSION").to_owned(),
            connect_timeout: CONNECT_TIMEOUT,
            pause: OUTDATED_RETRY_PAUSE,
            replacement_wait: HANDOVER_WAIT,
            backoff_min: TRANSIENT_MIN,
            backoff_max: TRANSIENT_MAX,
        }
    }

    /// The production values for this process's environment.
    fn from_env() -> Self {
        Self::new(session_socket_dir())
    }

    /// The runtime directories this dial uses.
    fn dirs(&self, base_dir: &Path) -> Result<RuntimeDir, RuntimeDirError> {
        dial_dirs_with(self.session_dir.as_deref(), base_dir)
    }

    /// The dial of `dirs`: the hello says `relay` when the session override
    /// is in effect. Self-reported; attribution only.
    fn dial<'a>(&self, dirs: &'a RuntimeDir) -> Dial<'a> {
        let via = if self.session_dir.is_some() {
            Via::Relay
        } else {
            Via::Direct
        };
        let mut dial = Dial::new(dirs, via, self.connect_timeout);
        dial.hello.version.clone_from(&self.client_version);
        dial
    }

    /// Maps a connect failure to its error: under the session override the
    /// relay directory is the transport, so the error names `pam listen`
    /// rather than an endpoint the sandboxed caller could not reach anyway.
    fn connect_error(&self, dirs: &RuntimeDir, source: io::Error) -> RequestError {
        match &self.session_dir {
            Some(dir) => RequestError::SessionUnreachable {
                dir: dir.clone(),
                source,
            },
            None => RequestError::Connect {
                endpoint: transport::endpoint_label(dirs),
                source,
            },
        }
    }

    /// The error for a peer that greeted in ZMTP where no takeover is (or
    /// is any longer) this client's to perform.
    fn legacy_error(&self, base_dir: &Path) -> ClientError {
        match &self.session_dir {
            Some(dir) => ClientError::LegacyBehindRelay { dir: dir.clone() },
            None => ClientError::LegacyDaemon {
                pid: lock_holder(base_dir),
                detail: "it still answers in the old protocol after this client tried to \
                         supersede it"
                    .to_owned(),
            },
        }
    }

    /// What a transport failure is to the caller of a request, apart from
    /// the two cases the callers act on themselves (a ZMTP greeting, an
    /// `error` frame).
    fn request_error(&self, dirs: &RuntimeDir, error: TransportError) -> RequestError {
        match error {
            TransportError::Connect(source) => self.connect_error(dirs, source),
            TransportError::Io(source) => RequestError::Transport { source },
            TransportError::Timeout { waited } => RequestError::ReplyTimeout { waited },
            TransportError::Protocol(detail) => RequestError::Parse { detail },
            // Both callers turn an `error` frame into the refusal it is before
            // they come here; kept total rather than assumed.
            TransportError::Refused(frame) => RequestError::Parse {
                detail: format!("{}: {}", frame.cause, frame.detail),
            },
            TransportError::LegacyDaemon => RequestError::Ensure(ClientError::LegacyDaemon {
                pid: None,
                detail: "it answers in the old protocol".to_owned(),
            }),
        }
    }
}

/// The public exchange loop behind [`send_request`]:
/// ensure the daemon, exchange over the public endpoint, and after a
/// `daemon_outdated` refusal wait for the replacement daemon to be ready
/// and retry exactly once. With the session override active
/// the daemon probe is skipped and the endpoint comes from the relay
/// directory instead of `<base>/run`.
pub(crate) async fn send_envelope(
    base_dir: &Path,
    envelope: &Envelope,
) -> Result<Response, RequestError> {
    send_envelope_with(base_dir, envelope, &DialOptions::from_env(), || {
        ensure_daemon_for_dial(base_dir)
    })
    .await
}

/// [`send_envelope`] with the dial options and the daemon-ensure step
/// injected, so the wait-for-the-replacement and the supersede behaviour are
/// testable without spawning a real `pam` (a test binary cannot).
///
/// Two things are retried, each at most once per call. A `daemon_outdated`
/// answer — a refusal in a reply, or an `error` frame at the hello, which is
/// surfaced as the same refusal — waits for the replacement and sends the
/// envelope again. A ZMTP greeting from a pre-migration daemon goes back to
/// the ensure step, which supersedes it (never under the session override:
/// that is an error for the human). Every other `error` frame is returned
/// as the refusal it is, sent once: `client_version_mismatch` among them,
/// whose detail names the running daemon's version and executable — the
/// client never stops a daemon over it.
pub(crate) async fn send_envelope_with<E, F>(
    base_dir: &Path,
    envelope: &Envelope,
    options: &DialOptions,
    ensure: E,
) -> Result<Response, RequestError>
where
    E: Fn() -> F,
    F: std::future::Future<Output = Result<(), RequestError>>,
{
    let mut retried = false;
    let mut superseded = false;
    loop {
        ensure().await?;
        let dirs = options.dirs(base_dir)?;
        let holder = lock_holder(base_dir);
        let budget = Duration::from_millis(envelope.deadline_ms) + REPLY_MARGIN;
        let response = match transport::call(&options.dial(&dirs), envelope, budget).await {
            Ok(response) => response,
            Err(TransportError::LegacyDaemon) => {
                if superseded || options.session_dir.is_some() {
                    return Err(options.legacy_error(base_dir).into());
                }
                // The loop head's ensure meets the same greeting and stops
                // that daemon, or says why it may not.
                superseded = true;
                continue;
            }
            Err(TransportError::Refused(frame)) => refusal_of(&envelope.id, frame),
            Err(error) => return Err(options.request_error(&dirs, error)),
        };
        if should_retry(&response) && !retried {
            retried = true;
            tokio::time::sleep(options.pause).await;
            if options.session_dir.is_none() {
                await_replacement(base_dir, holder, options.replacement_wait).await;
            }
            // The loop head re-ensures: a daemon that did not respawn itself
            // is started, and readiness is a real hello, not a stale file.
            continue;
        }
        return Ok(response);
    }
}

/// An `error` frame as the refusal of request `id`: the daemon said no
/// before there was a request to answer, with the same three fields a
/// refusal carries. `retryable` follows the cause.
fn refusal_of(id: &str, frame: ErrorFrame) -> Response {
    Response::Refusal {
        retryable: is_transient_cause(&frame.cause),
        id: id.to_owned(),
        cause: frame.cause,
        detail: frame.detail,
        recovery: frame.recovery,
    }
}

/// The pid in the instance lock file while a daemon holds the lock.
fn lock_holder(base_dir: &Path) -> Option<u32> {
    match probe_daemon(base_dir) {
        Ok(DaemonStatus::Running { pid }) => pid,
        _ => None,
    }
}

/// Waits (bounded) until the daemon that refused as outdated has been
/// replaced: its lock is free or held by a different pid. A retry sent
/// while the old daemon still drains only meets `daemon_shutting_down`.
async fn await_replacement(base_dir: &Path, old_pid: Option<u32>, wait: Duration) {
    let deadline = Instant::now() + wait;
    loop {
        match probe_daemon(base_dir) {
            Ok(DaemonStatus::Running { pid }) => {
                if pid.is_some() && pid != old_pid {
                    return;
                }
            }
            Ok(DaemonStatus::NotRunning) | Err(_) => return,
        }
        if Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(READINESS_POLL).await;
    }
}

/// How long one connect may take before it fails. A daemon that is merely
/// restarting is back well inside this; a socket nobody binds must not park
/// every command for longer.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Deadline of the `query` that authorises a follow. Small in the common
/// case — the answer is a single indexed row read — but bounded generously:
/// on a loaded runner the daemon can serialize the read behind an active
/// flow's store work, and a too-tight deadline turned a healthy follow into
/// a `deadline_exceeded` refusal (Windows CI, 2026-09-17). The follow's own
/// timeout still bounds the whole wait.
const QUERY_DEADLINE_MS: u64 = 15_000;

/// First pause after a transient failure of a follow or of a patient
/// request; doubles up to [`TRANSIENT_MAX`].
const TRANSIENT_MIN: Duration = Duration::from_millis(500);

/// Cap on the transient-failure backoff: a busy or restarting daemon is
/// asked again within this long, never hammered.
const TRANSIENT_MAX: Duration = Duration::from_secs(8);

/// Causes that describe the daemon's momentary condition, not a decision
/// about the caller: it is out of capacity (request slots, follower slots,
/// connections) or over its rate window, draining, restarting for a newer
/// binary, or timed something out. A follow retries these with backoff;
/// every other refusal is a policy answer and stops it. The daemon marks
/// its own transient refusals `retryable`; this list is the fallback for an
/// answer that carries no such mark (an `error` frame).
pub const TRANSIENT_CAUSES: [&str; 10] = [
    "request_capacity_exhausted",
    "request_rate_exhausted",
    "daemon_shutting_down",
    CAUSE_DAEMON_OUTDATED,
    "deadline_exceeded",
    "internal_error",
    cause::FOLLOWER_CAPACITY_EXHAUSTED,
    cause::CONNECTION_CAPACITY_EXHAUSTED,
    cause::HANDSHAKE_TIMEOUT,
    cause::FOLLOW_EXPIRED,
];

/// True when `cause` is one of the [`TRANSIENT_CAUSES`].
#[must_use]
pub fn is_transient_cause(cause: &str) -> bool {
    TRANSIENT_CAUSES.contains(&cause)
}

impl RequestError {
    /// True when the failure says the daemon was briefly unavailable
    /// (connect or transport trouble, a missed reply, a daemon still
    /// booting or still draining, or a [`TRANSIENT_CAUSES`] refusal) rather
    /// than that the request is wrong or forbidden: worth asking again.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Connect { .. }
            | Self::Transport { .. }
            | Self::ReplyTimeout { .. }
            | Self::Ensure(
                ClientError::NotReady { .. }
                | ClientError::Probe { .. }
                | ClientError::ProbeTask { .. }
                | ClientError::LegacyDraining { .. },
            ) => true,
            Self::FollowRefused { cause, .. } => is_transient_cause(cause),
            _ => false,
        }
    }
}

/// How a follow ended: the terminal event a subscriber sees and the durable
/// answer that came with it.
#[derive(Debug, Clone, PartialEq)]
pub struct FollowEnd {
    /// `done` or `refused`.
    pub event: Event,
    /// The scoped `query` answer for the ticket, read from the daemon's
    /// store when the stream ended: body `{ticket, state, outcome,
    /// capability}`.
    pub response: Response,
}

/// Follows a ticket to its terminal `done`/`refused` event, calling `on_event` for each event
/// seen, the terminal one included, and returns that terminal event; gives up with
/// [`RequestError::FollowTimeout`] past `timeout`. [`follow_ticket_to_end`] with the durable
/// answer dropped.
pub async fn follow_ticket(
    base_dir: &Path,
    ticket: &str,
    timeout: Duration,
    on_event: impl FnMut(&Event),
) -> Result<Event, RequestError> {
    follow_ticket_to_end(base_dir, ticket, timeout, on_event)
        .await
        .map(|end| end.event)
}

/// Follows a ticket on the daemon's follow stream to its end and returns the terminal event with
/// the durable answer the daemon sent with it, so nothing has to be queried afterwards.
///
/// One connection is one follow: hello, `follow` (a waiting `query` for the ticket, which is the
/// authorisation and the one request row a follow costs), then the ticket's events and `end`. The
/// daemon attaches the follower before it reads the store again, so there is no moment in which
/// an ending can be missed, and it replays what it still holds of the earlier events: a follow
/// that joins late sees `queued` and `started`, and one that joins after the ending returns at
/// once.
///
/// The daemon's momentary condition is not a verdict. A refusal it marks `retryable`, an `error`
/// frame with a transient cause (see [`TRANSIENT_CAUSES`] — capacity, rate, a draining or
/// restarting daemon, an expired stream), a dropped connection and a failed connect are retried
/// with bounded backoff until `timeout`, each reconnect sending the last sequence number seen so
/// only newer events come back; a daemon that restarted meanwhile has a new epoch and its replay
/// is taken from the start. Only a real refusal ([`RequestError::FollowRefused`] with a
/// non-transient cause) or a client-side failure that retrying cannot fix ends the follow early.
pub async fn follow_ticket_to_end(
    base_dir: &Path,
    ticket: &str,
    timeout: Duration,
    mut on_event: impl FnMut(&Event),
) -> Result<FollowEnd, RequestError> {
    follow_with(
        base_dir,
        ticket,
        timeout,
        &DialOptions::from_env(),
        || ensure_daemon_for_dial(base_dir),
        &mut on_event,
    )
    .await
}

/// Why one follow connection did not reach the ticket's end, and whether
/// another connection may.
struct FollowFailure {
    error: RequestError,
    retry: bool,
}

impl FollowFailure {
    /// A failure whose own kind says whether it is worth another try.
    fn of(error: RequestError) -> Self {
        Self {
            retry: error.is_transient(),
            error,
        }
    }
}

/// [`follow_ticket_to_end`] with the dial options and the daemon-ensure step
/// injected: one loop of connect, follow, and — on anything transient —
/// back off and resume.
pub(crate) async fn follow_with<E, F>(
    base_dir: &Path,
    ticket: &str,
    timeout: Duration,
    options: &DialOptions,
    ensure: E,
    on_event: &mut dyn FnMut(&Event),
) -> Result<FollowEnd, RequestError>
where
    E: Fn() -> F,
    F: std::future::Future<Output = Result<(), RequestError>>,
{
    let deadline = Instant::now() + timeout;
    let timed_out = || RequestError::FollowTimeout {
        ticket: ticket.to_owned(),
        waited: timeout,
    };
    let mut resume = Resume::default();
    let mut superseded = false;
    let mut pause = options.backoff_min;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(timed_out());
        }
        let before = resume.clone();
        let attempt = follow_once(
            base_dir,
            ticket,
            options,
            &ensure,
            &mut resume,
            &mut superseded,
            on_event,
        );
        match tokio::time::timeout(remaining, attempt).await {
            Err(_elapsed) => return Err(timed_out()),
            Ok(Ok(end)) => return Ok(end),
            Ok(Err(failure)) if !failure.retry => return Err(failure.error),
            // A busy or restarting daemon is asked again, not abandoned.
            Ok(Err(_transient)) => {}
        }
        // A connection that got somewhere (a hello acknowledged, an event
        // delivered) starts the backoff over.
        if resume != before {
            pause = options.backoff_min;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(timed_out());
        }
        tokio::time::sleep(pause.min(remaining)).await;
        pause = (pause * 2).min(options.backoff_max);
    }
}

/// One follow connection, from the ensure step to the stream's `end`.
async fn follow_once<E, F>(
    base_dir: &Path,
    ticket: &str,
    options: &DialOptions,
    ensure: &E,
    resume: &mut Resume,
    superseded: &mut bool,
    on_event: &mut dyn FnMut(&Event),
) -> Result<FollowEnd, FollowFailure>
where
    E: Fn() -> F,
    F: std::future::Future<Output = Result<(), RequestError>>,
{
    ensure().await.map_err(FollowFailure::of)?;
    let dirs = options
        .dirs(base_dir)
        .map_err(|error| FollowFailure::of(error.into()))?;
    // A fresh id per connection: each is its own `query` request.
    let args = serde_json::json!({ "ticket": ticket });
    let envelope = build_envelope("query", args, true, QUERY_DEADLINE_MS, None);
    let opening = Duration::from_millis(QUERY_DEADLINE_MS) + REPLY_MARGIN;
    let followed = transport::follow(
        &options.dial(&dirs),
        &envelope,
        resume,
        &mut *on_event,
        opening,
    )
    .await;
    let failure = match followed {
        Ok(end) => return follow_end(ticket, end, on_event),
        Err(TransportError::LegacyDaemon) => {
            let again = !*superseded && options.session_dir.is_none();
            *superseded = true;
            FollowFailure {
                // The next connection's ensure supersedes that daemon, once.
                retry: again,
                error: options.legacy_error(base_dir).into(),
            }
        }
        Err(TransportError::Refused(frame)) => FollowFailure::of(RequestError::FollowRefused {
            ticket: ticket.to_owned(),
            cause: frame.cause,
            detail: frame.detail,
            recovery: frame.recovery,
        }),
        Err(error) => FollowFailure::of(options.request_error(&dirs, error)),
    };
    Err(failure)
}

/// What an `end` frame means for the follow: the terminal event and the
/// durable answer, a refusal (transient when the daemon marked it so, or by
/// its cause), or — for an answer that is neither a refusal nor a terminal
/// state — a refusal made here, because a follow fails closed.
fn follow_end(
    ticket: &str,
    end: End,
    on_event: &mut dyn FnMut(&Event),
) -> Result<FollowEnd, FollowFailure> {
    let event = match &end.response {
        Response::Refusal {
            cause,
            detail,
            recovery,
            retryable,
            ..
        } => {
            return Err(FollowFailure {
                retry: *retryable || is_transient_cause(cause),
                error: RequestError::FollowRefused {
                    ticket: ticket.to_owned(),
                    cause: cause.clone(),
                    detail: detail.clone(),
                    recovery: recovery.clone(),
                },
            });
        }
        // The state in the durable answer decides; the frame's own event is
        // what the daemon derived from that same state.
        Response::Result { body, .. } => {
            match body.get("state").and_then(serde_json::Value::as_str) {
                Some("done") => Some(Event::Done),
                Some("refused" | "failed") => Some(Event::Refused),
                _ => None,
            }
        }
        Response::Ticket { .. } => None,
    };
    let Some(event) = event else {
        return Err(FollowFailure::of(unavailable_follow(ticket)));
    };
    on_event(&event);
    Ok(FollowEnd {
        event,
        response: end.response,
    })
}

fn unavailable_follow(ticket: &str) -> RequestError {
    RequestError::FollowRefused {
        ticket: ticket.to_owned(),
        cause: "result_unavailable".to_owned(),
        detail: "The daemon did not return an authorized terminal request state.".to_owned(),
        recovery: "Check the original ticket and current repository access in the PAM GUI."
            .to_owned(),
    }
}

/// What the daemon-lock probe found, for `pam daemon stop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonStatus {
    /// Nobody holds the instance lock.
    NotRunning,
    /// A daemon holds the lock; `pid` when the lock file was readable.
    Running {
        /// The holder's pid.
        pid: Option<u32>,
    },
}

/// Probes whether a daemon holds the instance lock under `base_dir`,
/// reporting its pid (from the lock file) when it does.
pub fn probe_daemon(base_dir: &Path) -> Result<DaemonStatus, ClientError> {
    let dirs = RuntimeDir::paths_at_base(base_dir)?;
    let path = dirs.run_dir().join(LOCK_FILE);
    if !lock_is_held(&path)? {
        return Ok(DaemonStatus::NotRunning);
    }
    let pid = std::fs::read_to_string(&path)
        .ok()
        .and_then(|contents| contents.trim().parse().ok());
    Ok(DaemonStatus::Running { pid })
}

/// How `stop_daemon` went when it did not error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopOutcome {
    /// Nobody held the instance lock; there was nothing to stop.
    NotRunning,
    /// The daemon was signalled and released the lock within the wait.
    Stopped {
        /// The stopped daemon's pid.
        pid: u32,
    },
    /// The daemon was signalled but is still draining past the wait; it
    /// exits when the drain completes.
    StillDraining {
        /// The draining daemon's pid.
        pid: u32,
    },
}

/// Why [`stop_daemon`] could not signal the daemon.
#[derive(Debug, Error)]
pub enum StopError {
    /// Probing or waiting on the instance lock failed.
    #[error(transparent)]
    Client(#[from] ClientError),
    /// The lock is held but names no pid; the process must be stopped
    /// manually.
    #[error("the daemon lock file names no pid; stop the daemon process manually")]
    NoPid,
    /// Sending SIGTERM failed.
    #[error("cannot signal the daemon (pid {pid}): {detail}")]
    Signal {
        /// The pid the signal was aimed at.
        pid: u32,
        /// What went wrong sending it.
        detail: String,
    },
    /// This platform has no supported stop signal yet.
    #[error(
        "stopping the daemon is not supported on this platform yet; \
         end the pam daemon process manually"
    )]
    Unsupported,
}

/// Stops the daemon under `base_dir`: names the lock holder, sends it
/// SIGTERM (unix), and waits — bounded by `wait` — for the graceful
/// drain to release the instance lock. Shared by `pam daemon stop` and
/// the GUI bridge's stop command.
pub fn stop_daemon(base_dir: &Path, wait: Duration) -> Result<StopOutcome, StopError> {
    match probe_daemon(base_dir)? {
        DaemonStatus::NotRunning => Ok(StopOutcome::NotRunning),
        DaemonStatus::Running { pid } => {
            let pid = pid.ok_or(StopError::NoPid)?;
            signal_terminate(pid)?;
            if wait_for_daemon_exit(base_dir, wait)? {
                Ok(StopOutcome::Stopped { pid })
            } else {
                Ok(StopOutcome::StillDraining { pid })
            }
        }
    }
}

/// Where the system `kill` lives. A bare `kill` would be resolved through
/// `$PATH`, which a caller controls: an executable of that name planted ahead
/// of the real one would run with the human's rights.
#[cfg(unix)]
const KILL_BINARIES: [&str; 2] = ["/bin/kill", "/usr/bin/kill"];

/// SIGTERM through the system `kill` at its absolute path: the workspace
/// denies `unsafe`, which a direct `libc::kill` call would need. What `kill`
/// says when it refuses (`Operation not permitted` under a sandbox that
/// denies signals) is carried in the error instead of leaking onto the
/// caller's stderr.
#[cfg(unix)]
pub(crate) fn signal_terminate(pid: u32) -> Result<(), StopError> {
    let kill = KILL_BINARIES
        .iter()
        .find(|path| Path::new(path).is_file())
        .ok_or_else(|| StopError::Signal {
            pid,
            detail: "no system kill binary at /bin/kill or /usr/bin/kill".to_owned(),
        })?;
    let output = Command::new(kill)
        .arg("-TERM")
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .output()
        .map_err(|err| StopError::Signal {
            pid,
            detail: format!("cannot run {kill}: {err}"),
        })?;
    if output.status.success() {
        return Ok(());
    }
    let said = String::from_utf8_lossy(&output.stderr);
    let said = said.trim();
    Err(StopError::Signal {
        pid,
        detail: if said.is_empty() {
            format!("{kill} -TERM exited with {}", output.status)
        } else {
            format!("{kill} -TERM exited with {}: {said}", output.status)
        },
    })
}

/// No unix signals here; stopping is not supported yet.
#[cfg(not(unix))]
pub(crate) fn signal_terminate(_pid: u32) -> Result<(), StopError> {
    Err(StopError::Unsupported)
}

/// Waits (bounded) for the daemon lock under `base_dir` to be released:
/// `true` when it was released within `timeout`.
pub fn wait_for_daemon_exit(base_dir: &Path, timeout: Duration) -> Result<bool, ClientError> {
    let dirs = RuntimeDir::paths_at_base(base_dir)?;
    let path = dirs.run_dir().join(LOCK_FILE);
    let deadline = Instant::now() + timeout;
    loop {
        if !lock_is_held(&path)? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(READINESS_POLL);
    }
}
