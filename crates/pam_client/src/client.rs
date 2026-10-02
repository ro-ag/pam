//! Client-side daemon lifecycle: lazy auto-start. [`ensure_daemon`] probes for a daemon behind
//! `pam.sock`, spawns `pam daemon` detached if none, and waits (bounded, ~3 s, one respawn retry)
//! for readiness. Readiness is an **actual connect**: `daemon.lock` has an exclusive holder (a
//! shared-lock probe conflicts with it) **and** the socket accepts a connection, so a stale
//! `pam.sock` left behind by a crash never reads as ready. A lock holder whose socket is not up
//! yet is a daemon still booting (crash recovery, warm-up): the client waits for it instead of
//! spawning another process. The spawned daemon is isolated from the caller: its own process
//! group, a fixed working directory, and an explicit environment allowlist ([`daemon_env`])
//! instead of the caller's environment. Client path resolution never creates or chmods the
//! runtime directory; only daemon startup prepares it.
//!
//! [`send_request`] ensures the daemon, builds the envelope, and exchanges it over a zmq `DEALER`
//! (timeout `deadline_ms` + margin; the connect is bounded at 5 s and retries a restarting daemon's
//! socket inside that window), refusing the reserved GUI-only
//! `admin.*` namespace before touching the socket ([`send_admin`] is the GUI's path instead).
//! After a [`CAUSE_DAEMON_OUTDATED`] refusal the old daemon drains and a new one takes over: the
//! client waits for that replacement to be ready, then retries exactly once.
//! [`send_request_with_id`] takes the request id from the caller, so the id is known before
//! anything is sent. [`follow_ticket`] subscribes to `events.sock` and streams to a terminal
//! `done`/`refused`, reconciling against the daemon's store since zmq `PUB` has no replay; `pam
//! wait` follows quietly, `pam subscribe` prints each event. Events are hints only: transient
//! daemon refusals (capacity, rate, shutting down, restarting) and transport failures are retried
//! with bounded backoff until the caller's timeout, unknown event kinds are skipped, and a closed
//! event stream is reconnected, so a healthy request is never reported refused because the daemon
//! was briefly busy. Intermediate events stream at normal `PUB` latency; only a missed terminal
//! event falls back to the reconcile cadence.

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
use pam_proto::{Caller, Envelope, Event, PROTOCOL_VERSION, Response};
use thiserror::Error;
use zeromq::{DealerSocket, Socket, SocketOptions, SocketRecv, SocketSend, SubSocket, ZmqMessage};

use crate::request::{build_envelope_with_id, new_request_id};

/// How long [`ensure_daemon`] waits for a spawned daemon to become
/// ready, per spawn attempt.
pub const READINESS_WAIT: Duration = Duration::from_secs(3);

/// The session socket override: when `$PAM_SOCKET_DIR` names a directory,
/// public dials use the `pam.sock` and `events.sock` directly inside it
/// instead of `<base>/run`'s — the layout [`crate::relay`] (`pam listen`)
/// binds — and lazy daemon auto-start is off. The relay is the transport,
/// so a missing relay is an error naming `pam listen`, never a spawned
/// daemon.
pub const SOCKET_DIR_ENV: &str = "PAM_SOCKET_DIR";

/// [`SOCKET_DIR_ENV`] as the client sees it: set and non-empty.
fn session_socket_dir() -> Option<PathBuf> {
    let dir = std::env::var_os(SOCKET_DIR_ENV)?;
    (!dir.is_empty()).then_some(PathBuf::from(dir))
}

/// The runtime directories one public dial uses: the session override's
/// flat layout when set, `<base>/run` otherwise.
fn dial_dirs(base_dir: &Path) -> Result<RuntimeDir, RuntimeDirError> {
    dial_dirs_with(session_socket_dir().as_deref(), base_dir)
}

/// [`dial_dirs`] with the override injected — the resolution rule itself,
/// unit-testable without mutating process environment (which the
/// workspace's `unsafe` denial forbids in edition 2024).
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
    /// The blocking readiness probe ([`ensure_daemon`] on a worker
    /// thread) could not be joined: it panicked or the runtime is
    /// shutting down.
    #[error("the daemon readiness probe did not complete: {source}")]
    ProbeTask {
        /// The underlying join error.
        #[source]
        source: tokio::task::JoinError,
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
/// [`spawn_daemon_process`] wrapper).
///
/// A daemon that is already **booting** (it holds the instance lock but its
/// socket does not accept yet) is waited for, never raced with a second
/// spawn: the extra process would only lose the lock and exit.
pub(crate) fn ensure_daemon_with(
    base_dir: &Path,
    spawn: &mut dyn FnMut() -> io::Result<()>,
    wait: Duration,
    poll: Duration,
) -> Result<EnsureOutcome, ClientError> {
    let dirs = RuntimeDir::paths_at_base(base_dir)?;
    match daemon_state(&dirs)? {
        DaemonState::Ready => return Ok(EnsureOutcome::AlreadyRunning),
        DaemonState::Booting => {
            let budget = wait * SPAWN_ATTEMPTS;
            let deadline = Instant::now() + budget;
            while Instant::now() < deadline {
                std::thread::sleep(poll);
                match daemon_state(&dirs)? {
                    DaemonState::Ready => return Ok(EnsureOutcome::AlreadyRunning),
                    // The booting daemon died before binding: spawn below.
                    DaemonState::Absent => break,
                    DaemonState::Booting => {}
                }
            }
            if daemon_state(&dirs)? == DaemonState::Booting {
                return Err(ClientError::NotReady { waited: budget });
            }
        }
        DaemonState::Absent => {}
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

/// Where a daemon stands behind one runtime directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonState {
    /// The lock is held and the request socket accepts a connection.
    Ready,
    /// The lock is held but the socket does not accept yet: a daemon in
    /// crash recovery or warm-up (it binds after taking the lock).
    Booting,
    /// Nobody holds the lock; any socket file is a stale leftover.
    Absent,
}

fn daemon_state(dirs: &RuntimeDir) -> Result<DaemonState, ClientError> {
    if !lock_is_held(&dirs.run_dir().join(LOCK_FILE))? {
        return Ok(DaemonState::Absent);
    }
    Ok(if socket_accepts(dirs.router_socket()) {
        DaemonState::Ready
    } else {
        DaemonState::Booting
    })
}

/// True when a daemon holds the instance lock **and** the request socket
/// accepts a connection (see the module docs on the probe).
fn daemon_ready(dirs: &RuntimeDir) -> Result<bool, ClientError> {
    Ok(daemon_state(dirs)? == DaemonState::Ready)
}

/// How long the readiness probe waits for a connect to finish. A connect
/// that is still pending means a listener exists with a full backlog — a
/// live, busy daemon — so a timeout counts as accepting.
#[cfg(unix)]
const CONNECT_PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Whether something accepts connections on the unix socket at `path`: an
/// actual connect, so a stale socket file with no listener (a crashed
/// daemon's leftover) is never mistaken for a ready daemon. The connect
/// runs on a helper thread because a blocking unix connect to a full
/// backlog would otherwise park the caller.
#[cfg(unix)]
fn socket_accepts(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let target = path.to_path_buf();
    std::thread::spawn(move || {
        let outcome = std::os::unix::net::UnixStream::connect(&target)
            .map(|_stream| ())
            .map_err(|source| source.kind());
        let _ = tx.send(outcome);
    });
    match rx.recv_timeout(CONNECT_PROBE_TIMEOUT) {
        Ok(Ok(())) | Err(_) => true,
        Ok(Err(kind)) => kind == io::ErrorKind::WouldBlock,
    }
}

/// Without std unix sockets the probe falls back to the socket file's
/// existence; [`connect_dealer`]'s bounded retry covers the stale case.
#[cfg(not(unix))]
fn socket_accepts(path: &Path) -> bool {
    path.exists()
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
    /// The daemon could not be ensured.
    #[error(transparent)]
    Ensure(#[from] ClientError),
    /// The runtime directory is unusable.
    #[error(transparent)]
    RuntimeDir(#[from] RuntimeDirError),
    /// Connecting a socket failed.
    #[error("cannot connect to {endpoint}: {source}")]
    Connect {
        /// The `ipc://` endpoint that failed.
        endpoint: String,
        /// The underlying zmq error.
        #[source]
        source: zeromq::ZmqError,
    },
    /// The session relay (`PAM_SOCKET_DIR`) is not answering. The client
    /// never spawns a daemon while the override is set — the relay is the
    /// transport — so this names the way to start it instead.
    #[error(
        "no session relay answered in {dir} ($PAM_SOCKET_DIR); start one \
         outside the sandbox with `pam listen {dir}`"
    )]
    SessionUnreachable {
        /// The override directory whose sockets did not answer.
        dir: PathBuf,
        /// The underlying zmq error.
        #[source]
        source: zeromq::ZmqError,
    },
    /// The zmq exchange itself failed.
    #[error("transport failure talking to the daemon: {source}")]
    Transport {
        /// The underlying zmq error.
        #[source]
        source: zeromq::ZmqError,
    },
    /// The daemon's bytes did not parse as a [`Response`] / [`Event`].
    #[error("cannot parse the daemon's reply: {source}")]
    Parse {
        /// The underlying JSON error.
        #[source]
        source: serde_json::Error,
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
/// envelope, exchange over `pam.sock`, retry exactly once after a `daemon_outdated` refusal. The
/// daemon's answer (result, refusal, or ticket) is returned as-is; rendering and exit codes are the
/// caller's job (the `pam` binary's `render` module).
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
    send_envelope(base_dir, &envelope, &RetryTimings::DEFAULT).await
}

/// [`send_request`] that keeps asking through the daemon's momentary
/// conditions: a [`TRANSIENT_CAUSES`] refusal or a transient transport
/// failure ([`RequestError::is_transient`]) is retried with bounded backoff
/// for up to `patience`, then returned as it came. Meant for reads of a
/// request that is already known good (a terminal ticket), where a busy
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
/// The exchange runs once: a transport error or version refusal is returned without replaying the
/// operation, because a missing reply can follow an applied change — inspect the resulting state
/// before manually retrying. A capability outside `admin.*` errors with [`RequestError::NotAdmin`].
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
    ensure_daemon_async(base_dir).await?;
    pam_daemon::admin_transport::exchange(base_dir, &envelope)
        .await
        .map_err(|source| RequestError::AdminTransport { source })
}

/// The waits around the single `daemon_outdated` retry.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RetryTimings {
    /// Pause before waiting on the replacement daemon.
    pub(crate) pause: Duration,
    /// Longest wait for the old daemon's drain to hand over.
    pub(crate) replacement_wait: Duration,
}

impl RetryTimings {
    /// The production waits: the old daemon drains for up to ten seconds
    /// (`DEFAULT_DRAIN_TIMEOUT`) before the new binary takes over.
    pub(crate) const DEFAULT: Self = Self {
        pause: OUTDATED_RETRY_PAUSE,
        replacement_wait: Duration::from_secs(20),
    };
}

/// The public exchange loop behind [`send_request`]:
/// ensure the daemon, exchange over `pam.sock`, and after a
/// `daemon_outdated` refusal wait for the replacement daemon to be ready
/// and retry exactly once. With the session override active
/// the daemon probe is skipped and both endpoints come from the relay
/// directory instead of `<base>/run`.
pub(crate) async fn send_envelope(
    base_dir: &Path,
    envelope: &Envelope,
    timings: &RetryTimings,
) -> Result<Response, RequestError> {
    send_envelope_with(base_dir, envelope, timings, || {
        ensure_daemon_for_dial(base_dir)
    })
    .await
}

/// [`send_envelope`] with the daemon-ensure step injected, so the
/// wait-for-the-replacement behaviour is testable without spawning a real
/// `pam` (a test binary cannot).
pub(crate) async fn send_envelope_with<E, F>(
    base_dir: &Path,
    envelope: &Envelope,
    timings: &RetryTimings,
    ensure: E,
) -> Result<Response, RequestError>
where
    E: Fn() -> F,
    F: std::future::Future<Output = Result<(), RequestError>>,
{
    let mut retried = false;
    loop {
        ensure().await?;
        let dirs = dial_dirs(base_dir)?;
        let holder = lock_holder(base_dir);
        let response = exchange(&dirs, envelope).await?;
        if should_retry(&response) && !retried {
            retried = true;
            tokio::time::sleep(timings.pause).await;
            if session_socket_dir().is_none() {
                await_replacement(base_dir, holder, timings.replacement_wait).await;
            }
            // The loop head re-ensures: a daemon that did not respawn itself
            // is started, and readiness is a real connect, not a stale file.
            continue;
        }
        return Ok(response);
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

/// Maps a socket connect failure to its error: under the session override
/// the relay directory is the transport, so the error names `pam listen`
/// rather than an endpoint the sandboxed caller could not reach anyway.
fn connect_error(dirs: &RuntimeDir, source: zeromq::ZmqError) -> RequestError {
    match session_socket_dir() {
        Some(dir) => RequestError::SessionUnreachable { dir, source },
        None => RequestError::Connect {
            endpoint: dirs.router_endpoint(),
            source,
        },
    }
}

/// How long one connect may take before it fails. zeromq itself keeps
/// retrying a refused or missing `ipc` endpoint with backoff for its
/// 30 s default, which would park every command on a dead socket for half a
/// minute; a daemon that is merely restarting is back well inside this.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Socket options with the bounded [`CONNECT_TIMEOUT`].
fn bounded_options(timeout: Duration) -> SocketOptions {
    let mut options = SocketOptions::default();
    options.connect_timeout(timeout);
    options
}

/// Connects a `DEALER` to the request endpoint. The connect retries a
/// refused or missing endpoint internally (a daemon mid-restart is reached
/// as soon as it binds) for up to `timeout`, then fails.
pub(crate) async fn connect_dealer_within(
    dirs: &RuntimeDir,
    timeout: Duration,
) -> Result<DealerSocket, RequestError> {
    let mut dealer = DealerSocket::with_options(bounded_options(timeout));
    dealer
        .connect(&dirs.router_endpoint())
        .await
        .map_err(|source| connect_error(dirs, source))?;
    Ok(dealer)
}

/// [`connect_dealer_within`] with the default [`CONNECT_TIMEOUT`].
pub(crate) async fn connect_dealer(dirs: &RuntimeDir) -> Result<DealerSocket, RequestError> {
    connect_dealer_within(dirs, CONNECT_TIMEOUT).await
}

/// One `DEALER` exchange: connect, send the envelope, await its single
/// reply under `deadline_ms` plus [`REPLY_MARGIN`].
async fn exchange(dirs: &RuntimeDir, envelope: &Envelope) -> Result<Response, RequestError> {
    let mut dealer = connect_dealer(dirs).await?;
    let payload = serde_json::to_vec(envelope).map_err(|source| RequestError::Parse { source })?;
    dealer
        .send(ZmqMessage::from(payload))
        .await
        .map_err(|source| RequestError::Transport { source })?;

    let budget = Duration::from_millis(envelope.deadline_ms) + REPLY_MARGIN;
    let reply = tokio::time::timeout(budget, dealer.recv())
        .await
        .map_err(|_elapsed| RequestError::ReplyTimeout { waited: budget })?
        .map_err(|source| RequestError::Transport { source })?;
    let frames = reply.into_vec();
    let payload = frames
        .first()
        .map(|frame| frame.to_vec())
        .unwrap_or_default();
    serde_json::from_slice(&payload).map_err(|source| RequestError::Parse { source })
}

/// Deadline for each store reconciliation `query` request a follow
/// makes (see [`follow_ticket`]). Small in the common case — the answer
/// is a single indexed row read — but bounded generously: on a loaded
/// runner the daemon can serialize the read behind an active flow's
/// store work, and a too-tight deadline turned a healthy follow into a
/// `deadline_exceeded` refusal (Windows CI, 2026-09-17). The follow's
/// own timeout still bounds the whole wait.
const QUERY_DEADLINE_MS: u64 = 15_000;

/// First pause before a follow re-reconciles against the store; each
/// subsequent reconcile doubles it up to [`RECONCILE_MAX`], so a long
/// quiet follow stays cheap while a lost terminal event is still
/// noticed within seconds.
const RECONCILE_MIN: Duration = Duration::from_secs(1);

/// Cap on the reconcile back-off interval.
const RECONCILE_MAX: Duration = Duration::from_secs(30);

/// How long the follow's event-stream connect may take per attempt.
const SUBSCRIBE_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// First pause after a transient failure of the authorizing query, before
/// anything is subscribed; doubles up to [`TRANSIENT_MAX`].
const TRANSIENT_MIN: Duration = Duration::from_millis(500);

/// Cap on the transient-failure backoff: a busy or restarting daemon is
/// asked again within this long, never hammered.
const TRANSIENT_MAX: Duration = Duration::from_secs(8);

/// Refusal causes that describe the daemon's momentary condition, not a
/// decision about the caller: it is out of capacity or over its rate
/// window, draining, restarting for a newer binary, or timed the read out.
/// A follow retries these with backoff; every other refusal is a policy
/// answer and stops it.
pub const TRANSIENT_CAUSES: [&str; 6] = [
    "request_capacity_exhausted",
    "request_rate_exhausted",
    "daemon_shutting_down",
    CAUSE_DAEMON_OUTDATED,
    "deadline_exceeded",
    "internal_error",
];

/// True when `cause` is one of the [`TRANSIENT_CAUSES`].
#[must_use]
pub fn is_transient_cause(cause: &str) -> bool {
    TRANSIENT_CAUSES.contains(&cause)
}

impl RequestError {
    /// True when the failure says the daemon was briefly unavailable
    /// (connect or transport trouble, a missed reply, a daemon still
    /// booting, or a [`TRANSIENT_CAUSES`] refusal) rather than that the
    /// request is wrong or forbidden: worth asking again.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Connect { .. }
            | Self::Transport { .. }
            | Self::ReplyTimeout { .. }
            | Self::Ensure(
                ClientError::NotReady { .. }
                | ClientError::Probe { .. }
                | ClientError::ProbeTask { .. },
            ) => true,
            Self::FollowRefused { cause, .. } => is_transient_cause(cause),
            _ => false,
        }
    }
}

/// Follows a ticket's event stream on `events.sock` to a terminal `done`/`refused` event, calling
/// `on_event` for each one seen. Returns the terminal event; gives up with
/// [`RequestError::FollowTimeout`] past `timeout`. Two races can silently drop the terminal event:
/// zmq `PUB` has no replay, so an event published before this subscription registered is gone for
/// good; and `SubSocket::subscribe` only queues the subscription frame, so an event published in
/// the instant before `PUB` processes it is filtered out.
///
/// The store is therefore the authority on termination, never the event stream alone: authorize
/// through the scoped `query` capability, then reconcile whether the ticket is already terminal —
/// immediately after subscribing, and again on a backing-off interval while events are quiet —
/// surfaced as the synthesized terminal event. Events before the subscription (`queued`, `started`)
/// stay unreplayable, but the terminal event is now guaranteed to arrive.
///
/// Events are hints, and the daemon's momentary condition is not a verdict: a transient failure of
/// the query (see [`RequestError::is_transient`] — capacity or rate refusals, a draining or
/// restarting daemon, transport trouble) is retried with bounded backoff until `timeout`, a
/// closed event stream is reconnected (the durable query keeps reconciling meanwhile), and an
/// event this client does not know is skipped. Only a real refusal ([`RequestError::FollowRefused`]
/// with a non-transient cause) or a client-side failure that retrying cannot fix ends the follow
/// early.
pub async fn follow_ticket(
    base_dir: &Path,
    ticket: &str,
    timeout: Duration,
    mut on_event: impl FnMut(&Event),
) -> Result<Event, RequestError> {
    let deadline = Instant::now() + timeout;
    let timed_out = || RequestError::FollowTimeout {
        ticket: ticket.to_owned(),
        waited: timeout,
    };
    // Authorize before subscribing: unavailable tickets never consume PUB data.
    let mut transient_pause = TRANSIENT_MIN;
    loop {
        match reconcile_once(base_dir, ticket, deadline, &timed_out).await {
            Ok(Some(event)) => {
                on_event(&event);
                return Ok(event);
            }
            Ok(None) => break,
            Err(error) if error.is_transient() => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(timed_out());
                }
                tokio::time::sleep(transient_pause.min(remaining)).await;
                transient_pause = (transient_pause * 2).min(TRANSIENT_MAX);
            }
            Err(error) => return Err(error),
        }
    }

    let mut sub: Option<SubSocket> = None;
    let mut sub_pause = RECONCILE_MIN;
    let mut next_sub_attempt = Instant::now();
    let mut reconcile_pause = RECONCILE_MIN;
    let mut next_reconcile = Instant::now();
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(timed_out());
        }
        if sub.is_none() && now >= next_sub_attempt {
            match open_subscription(base_dir, ticket).await {
                Ok(opened) => {
                    sub = Some(opened);
                    sub_pause = RECONCILE_MIN;
                    // Reconcile right after (re)subscribing: closes the slow-joiner gap.
                    next_reconcile = Instant::now();
                }
                Err(error) if error.is_transient() => {
                    // The query keeps reconciling meanwhile; events are only hints.
                    next_sub_attempt = Instant::now() + sub_pause;
                    sub_pause = (sub_pause * 2).min(RECONCILE_MAX);
                }
                Err(error) => return Err(error),
            }
        }
        if Instant::now() >= next_reconcile {
            match reconcile_once(base_dir, ticket, deadline, &timed_out).await {
                Ok(Some(event)) => {
                    on_event(&event);
                    return Ok(event);
                }
                Ok(None) => {}
                // A busy or restarting daemon is asked again later, not abandoned.
                Err(error) if error.is_transient() => {}
                Err(error) => return Err(error),
            }
            next_reconcile = Instant::now() + reconcile_pause;
            reconcile_pause = (reconcile_pause * 2).min(RECONCILE_MAX);
        }
        let mut wake = deadline.min(next_reconcile);
        if sub.is_none() {
            wake = wake.min(next_sub_attempt);
        }
        let wait = wake.saturating_duration_since(Instant::now());
        let Some(stream) = sub.as_mut() else {
            tokio::time::sleep(wait).await;
            continue;
        };
        let Ok(received) = tokio::time::timeout(wait, stream.recv()).await else {
            // Reconcile due or deadline reached; the loop head decides.
            continue;
        };
        let message = match received {
            Ok(message) => message,
            Err(_closed) => {
                // The daemon restarted or the relay dropped the stream:
                // reconnect, and let the durable query settle what was missed.
                sub = None;
                next_sub_attempt = Instant::now();
                continue;
            }
        };
        let frames = message.into_vec();
        // PUB frames are [topic, payload]; anything shorter is noise.
        let Some(payload) = frames.get(1) else {
            continue;
        };
        // An event kind this client does not know (a newer daemon) is skipped.
        let Ok(event) = serde_json::from_slice::<Event>(payload) else {
            continue;
        };
        if matches!(event, Event::Done | Event::Refused) {
            // PUB is only a hint; recheck current scope and durable state before
            // exposing a terminal event or deciding the follow has finished.
            next_reconcile = Instant::now();
        } else {
            on_event(&event);
        }
    }
}

/// One reconcile of [`follow_ticket`] under the follow's overall deadline.
async fn reconcile_once(
    base_dir: &Path,
    ticket: &str,
    deadline: Instant,
    timed_out: &dyn Fn() -> RequestError,
) -> Result<Option<Event>, RequestError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    tokio::time::timeout(remaining, query_terminal(base_dir, ticket))
        .await
        .map_err(|_elapsed| timed_out())?
}

/// Connects a `SUB` socket to the events endpoint and subscribes to
/// `ticket`'s topic.
async fn open_subscription(base_dir: &Path, ticket: &str) -> Result<SubSocket, RequestError> {
    let dirs = dial_dirs(base_dir)?;
    let endpoint = dirs.events_endpoint();
    // Shorter than the request connect: the follow keeps reconciling through
    // the durable query while this retries, so it must not park the loop.
    let mut sub = SubSocket::with_options(bounded_options(SUBSCRIBE_CONNECT_TIMEOUT));
    sub.connect(&endpoint)
        .await
        .map_err(|source| match session_socket_dir() {
            Some(dir) => RequestError::SessionUnreachable { dir, source },
            None => RequestError::Connect { endpoint, source },
        })?;
    sub.subscribe(ticket)
        .await
        .map_err(|source| RequestError::Transport { source })?;
    Ok(sub)
}

/// One reconcile step of [`follow_ticket`]: asks the daemon (`query`
/// capability, request/reply — reliable, unlike `PUB`) for the ticket's
/// stored state. `Some(event)` maps a terminal state to the terminal
/// event a subscriber would have seen (`done` → [`Event::Done`],
/// `refused`/`failed` → [`Event::Refused`], matching what the daemon
/// publishes). Only an explicitly pending state returns `None`; refusals and
/// malformed responses fail closed instead of repeatedly querying or watching.
/// A refusal is surfaced as [`RequestError::FollowRefused`]; its cause says
/// whether it is transient ([`RequestError::is_transient`]).
async fn query_terminal(base_dir: &Path, ticket: &str) -> Result<Option<Event>, RequestError> {
    let args = serde_json::json!({ "ticket": ticket });
    let response = send_request(base_dir, "query", args, true, QUERY_DEADLINE_MS, None).await?;
    match response {
        Response::Refusal {
            cause,
            detail,
            recovery,
            ..
        } => Err(RequestError::FollowRefused {
            ticket: ticket.to_owned(),
            cause,
            detail,
            recovery,
        }),
        Response::Result { body, .. } => {
            match body.get("state").and_then(serde_json::Value::as_str) {
                Some("done") => Ok(Some(Event::Done)),
                Some("refused" | "failed") => Ok(Some(Event::Refused)),
                Some("queued" | "running" | "waiting_approval") => Ok(None),
                _ => Err(unavailable_follow(ticket)),
            }
        }
        Response::Ticket { .. } => Err(unavailable_follow(ticket)),
    }
}

fn unavailable_follow(ticket: &str) -> RequestError {
    RequestError::FollowRefused {
        ticket: ticket.to_owned(),
        cause: "request_unavailable".to_owned(),
        detail: "The daemon did not return an authorized request state.".to_owned(),
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
/// denies `unsafe`, which a direct `libc::kill` call would need.
#[cfg(unix)]
fn signal_terminate(pid: u32) -> Result<(), StopError> {
    let kill = KILL_BINARIES
        .iter()
        .find(|path| Path::new(path).is_file())
        .ok_or_else(|| StopError::Signal {
            pid,
            detail: "no system kill binary at /bin/kill or /usr/bin/kill".to_owned(),
        })?;
    let status = Command::new(kill)
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .map_err(|err| StopError::Signal {
            pid,
            detail: format!("cannot run {kill}: {err}"),
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(StopError::Signal {
            pid,
            detail: format!("{kill} -TERM exited with {status}"),
        })
    }
}

/// No unix signals here; stopping is not supported yet.
#[cfg(not(unix))]
fn signal_terminate(_pid: u32) -> Result<(), StopError> {
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
