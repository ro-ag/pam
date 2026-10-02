//! The session socket relay: `pam listen <dir>` binds one socket, `pam.sock`, inside a
//! caller-chosen directory — one an agent sandbox already permits — and forwards bytes to the
//! daemon's public socket, so a sandboxed client (`$PAM_SOCKET_DIR`) can reach the daemon through
//! a path the sandbox allows instead of one it blocks. A follow stream is just a long-lived
//! connection through the same pipe, so there is no second socket.
//!
//! The relay is deliberately dumb: a per-connection byte pipe and nothing else. It holds no
//! credential, makes no decision, and never inspects the frames, so every admission, scope and
//! budget check still happens in the daemon, which sees ordinary connections (its kernel peer is
//! the relay process; the client's hello says `via: relay`). One consequence is worth naming: a
//! listening socket inside a writable directory can be unlinked and rebound by another process of
//! the same user, which lets it *impersonate the daemon* to the agent (deception, not escalation —
//! the same user could talk to the real daemon anyway). See `docs/session-socket-relay.md` for the
//! full boundary.
//!
//! **Preparing the directory** ([`prepare`]) refuses what a hostile neighbour could use to point
//! the relay somewhere else, rather than repairing it: a `<dir>` or socket entry that is a
//! symbolic link, a `<dir>` that is not owned by the user or is writable by group or others, and a
//! socket entry that is not a socket. A missing directory is created `0700`. The directory is
//! opened once and its identity (device and inode) is compared before and after the bind, and the
//! socket is bound through the canonical path of that directory, so a link swapped in between
//! the checks and the bind is noticed. What remains is the check-then-bind window itself: another
//! process **of the same user** that wins that race can still redirect the path, and std offers no
//! `bindat`, so the window is narrowed and documented, not closed. Anyone who can do that can also
//! reach the real daemon directly.
//!
//! **Startup probe** (`check_daemon`): the relay dials the daemon's public socket with a hello.
//! A peer that greets in `ZMTP` (first byte `0xFF`) is a pre-migration daemon; the relay runs
//! outside the sandbox, so it supersedes that daemon the way `pam daemon stop` would
//! (`stop_daemon`, then `ensure_daemon`) — its sandboxed clients cannot. A daemon it cannot stop
//! ends the start with the instruction instead of forwarding to a dead end.
//!
//! A relay that a sandboxed agent can wedge would cut that agent off from the daemon with no way
//! to restart it, so the accept loop is hardened: a transient accept error (out of file
//! descriptors, an aborted handshake) is retried with backoff instead of ending the relay,
//! concurrent relayed connections are capped ([`MAX_CONNECTIONS`]; the excess is closed at once,
//! an honest transport error for that client), and the daemon-side dial is bounded
//! ([`DAEMON_CONNECT_TIMEOUT`]).

#[cfg(unix)]
use std::future::Future;
#[cfg(unix)]
use std::io;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
#[cfg(unix)]
use tokio::sync::{Semaphore, watch};

#[cfg(unix)]
use pam_daemon::framed::{self, First};
use pam_daemon::runtime_dir::RuntimeDir;
#[cfg(unix)]
use pam_proto::wire::{Frame, MAX_HELLO_BYTES, Via};

#[cfg(unix)]
use crate::client::{self, ClientError, EnsureOutcome, StopError, StopOutcome};

/// How many client connections the relay socket forwards at once. The daemon bounds its own
/// intake; this keeps a single sandboxed peer from exhausting the relay's file descriptors.
pub const MAX_CONNECTIONS: usize = 64;

/// How long the relay waits to reach the daemon's socket for one client.
pub const DAEMON_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the startup probe waits for the daemon to answer its hello.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a pre-migration daemon gets to drain after the relay signals it.
pub const SUPERSEDE_WAIT: Duration = Duration::from_secs(20);

/// First pause after a failed `accept`; doubles up to [`ACCEPT_BACKOFF_MAX`].
const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(10);

/// Cap on the accept-error backoff.
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// The second socket an older relay bound next to `pam.sock`. Nothing dials it any more; a stale
/// one is removed at startup.
#[cfg(unix)]
const LEGACY_EVENTS_SOCKET: &str = "events.sock";

/// Why the relay could not start or keep running.
#[derive(Debug, Error)]
pub enum RelayError {
    /// A socket path was unusable (too long, or the directory could not
    /// be prepared).
    #[error(transparent)]
    RuntimeDir(#[from] pam_daemon::runtime_dir::RuntimeDirError),
    /// A filesystem operation on a relay or daemon socket failed.
    #[error("cannot use socket {}: {source}", path.display())]
    Io {
        /// The socket the operation targeted.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Something already serves the session directory and answered, so
    /// binding over it would steal its clients.
    #[error(
        "a relay already answers in {dir}; use it as-is ($PAM_SOCKET_DIR={dir}), \
         or stop that `pam listen` first"
    )]
    AlreadyListening {
        /// The session directory holding the live socket.
        dir: PathBuf,
    },
    /// The session directory could be redirected or written to by someone
    /// else, so a socket bound in it could not be trusted.
    #[error(
        "the session directory {} is not safe for the relay: {reason}; choose a directory \
         you own that nobody else can write to (it is created with mode 0700 when missing), \
         or remove the link, and run `pam listen` again",
        dir.display()
    )]
    UnsafeDirectory {
        /// The directory as given.
        dir: PathBuf,
        /// What is wrong with it.
        reason: String,
    },
    /// The socket entry in the session directory is not something the relay
    /// may replace.
    #[error(
        "the session socket {} is not safe to replace: {reason}; move or remove it yourself \
         and run `pam listen` again",
        path.display()
    )]
    UnsafeSocket {
        /// The socket path.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },
    /// The daemon behind the relay is a pre-migration build and could not be
    /// replaced.
    #[error(
        "a pre-migration pam daemon{} is running and `pam listen` could not replace it: \
         {reason}. {recovery}",
        pid.map_or_else(String::new, |pid| format!(" (pid {pid})"))
    )]
    LegacyDaemon {
        /// The daemon's pid when the lock file named it.
        pid: Option<u32>,
        /// Why it could not be stopped or replaced.
        reason: String,
        /// What the human does about it.
        recovery: String,
    },
    /// Unix domain sockets are the relay's only transport.
    #[error("the session relay needs unix domain sockets; this platform is unsupported")]
    Unsupported,
}

/// The bound listener plus the two paths it forwards between.
#[derive(Debug)]
#[cfg(unix)]
pub struct RelayBindings {
    session_dir: PathBuf,
    socket: PathBuf,
    target: PathBuf,
    listener: tokio::net::UnixListener,
}

#[cfg(unix)]
impl RelayBindings {
    /// The session directory, canonicalised: the socket's parent.
    #[must_use]
    pub fn session_dir(&self) -> &Path {
        &self.session_dir
    }

    /// The socket the relay bound for sandboxed clients.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// The daemon socket every connection is forwarded to.
    #[must_use]
    pub fn target(&self) -> &Path {
        &self.target
    }

    /// Gives the bound socket back: removes its file and drops the listener.
    fn discard(self) {
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Binds the relay's socket inside `session_dir`, forwarding to the daemon's public socket under
/// `base_dir`. Refuses to take over a directory where something already answers; replaces only
/// stale, unanswered socket files; refuses a directory or socket entry that is not safe (see the
/// module docs). Removes a stale `events.sock` an older relay left behind.
///
/// # Errors
///
/// [`RelayError::AlreadyListening`] when the session socket is served,
/// [`RelayError::UnsafeDirectory`] and [`RelayError::UnsafeSocket`] for what the module docs list,
/// [`RelayError::Io`] when preparing or binding fails, and [`RelayError::RuntimeDir`] for a path
/// over the unix socket length limit.
#[cfg(unix)]
pub fn prepare(session_dir: &Path, base_dir: &Path) -> Result<RelayBindings, RelayError> {
    let daemon = RuntimeDir::paths_at_base(base_dir)?;
    let own = own_uid(session_dir)?;
    let directory = validate_session_dir(session_dir, own)?;
    let paths = RuntimeDir::paths_at_dir(&directory.canonical)?;
    let socket = directory
        .canonical
        .join(paths.public_socket().file_name().unwrap_or_default());
    // The canonical path is what is bound, and it can be longer than the one given (and
    // validated above): the same bound, terminator included, applies to it.
    let len = socket.as_os_str().len();
    if len >= pam_daemon::runtime_dir::MAX_SOCKET_PATH_BYTES {
        return Err(
            pam_daemon::runtime_dir::RuntimeDirError::SocketPathTooLong { path: socket, len }
                .into(),
        );
    }
    remove_legacy_events_socket(&directory.canonical, own);
    let listener = bind_forwarding_socket(&socket, &directory, own)?;
    Ok(RelayBindings {
        session_dir: directory.canonical,
        socket,
        target: daemon.public_socket().to_path_buf(),
        listener,
    })
}

/// The user the relay runs as, by the kernel's word (a local socket pair asks for our own
/// credentials; no environment variable or `unsafe` involved).
#[cfg(unix)]
fn own_uid(session_dir: &Path) -> Result<u32, RelayError> {
    pam_daemon::framed_unix::own_identity()
        .ok()
        .and_then(|identity| identity.uid())
        .ok_or_else(|| RelayError::Io {
            path: session_dir.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the operating system did not report this process's user id",
            ),
        })
}

/// A session directory that passed the checks: its canonical path and the identity it had when it
/// was opened.
#[cfg(unix)]
struct SessionDir {
    canonical: PathBuf,
    device: u64,
    inode: u64,
}

/// Why a directory with this owner and mode cannot hold the relay's socket, or `None` when it
/// can. `mode` is the permission bits only.
#[must_use]
pub fn directory_refusal(owner: u32, own: u32, mode: u32) -> Option<String> {
    if owner != own {
        return Some(format!(
            "it is owned by another user (uid {owner}), not by you (uid {own})"
        ));
    }
    if mode & 0o022 != 0 {
        return Some(format!(
            "it is writable by group or others (mode {:03o})",
            mode & 0o777
        ));
    }
    None
}

#[cfg(unix)]
fn validate_session_dir(given: &Path, own: u32) -> Result<SessionDir, RelayError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    // `a/b/` and `a/b` are the same path to a human but not to `lstat`: a trailing slash makes
    // the kernel follow a link at the last component. Normalise before looking.
    let dir: PathBuf = given.components().collect();
    let unsafe_dir = |reason: &str| RelayError::UnsafeDirectory {
        dir: given.to_path_buf(),
        reason: reason.to_owned(),
    };
    let io_error = |source: io::Error| RelayError::Io {
        path: dir.clone(),
        source,
    };

    match std::fs::symlink_metadata(&dir) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = dir.parent().filter(|parent| !parent.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent).map_err(io_error)?;
            }
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => {}
                // Somebody else created it first; it is checked like any existing entry.
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(io_error(error)),
            }
        }
        Err(error) => return Err(io_error(error)),
    }

    let before = std::fs::symlink_metadata(&dir).map_err(io_error)?;
    if before.file_type().is_symlink() {
        return Err(unsafe_dir("it is a symbolic link"));
    }
    if !before.is_dir() {
        return Err(unsafe_dir("it is not a directory"));
    }
    // One handle, opened after the link check: every later decision about this directory is made
    // on the handle, not on the name.
    let handle = std::fs::File::open(&dir).map_err(io_error)?;
    let opened = handle.metadata().map_err(io_error)?;
    if (opened.dev(), opened.ino()) != (before.dev(), before.ino()) {
        return Err(unsafe_dir("it was replaced while it was being checked"));
    }
    if let Some(reason) = directory_refusal(opened.uid(), own, opened.mode() & 0o777) {
        return Err(unsafe_dir(&reason));
    }
    if opened.mode() & 0o777 != 0o700 {
        handle
            .set_permissions(std::fs::Permissions::from_mode(0o700))
            .map_err(io_error)?;
    }
    let canonical = dir.canonicalize().map_err(io_error)?;
    let resolved = std::fs::symlink_metadata(&canonical).map_err(io_error)?;
    if resolved.file_type().is_symlink()
        || (resolved.dev(), resolved.ino()) != (opened.dev(), opened.ino())
    {
        return Err(unsafe_dir("it was replaced while it was being checked"));
    }
    Ok(SessionDir {
        canonical,
        device: opened.dev(),
        inode: opened.ino(),
    })
}

/// Removes the `events.sock` an older relay bound, if it is a socket this user owns. Anything
/// else under that name is not the relay's to touch and is left alone.
#[cfg(unix)]
fn remove_legacy_events_socket(directory: &Path, own: u32) {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let path = directory.join(LEGACY_EVENTS_SOCKET);
    if let Ok(metadata) = std::fs::symlink_metadata(&path)
        && metadata.file_type().is_socket()
        && metadata.uid() == own
    {
        let _ = pam_daemon::runtime_dir::remove_stale(&path);
    }
}

/// Binds the forwarding socket, refusing a live predecessor: a socket file that still answers
/// belongs to a running relay, and rebinding would take its clients. A socket file nobody answers
/// is a stale leftover and is removed; anything else at the path is refused.
#[cfg(unix)]
fn bind_forwarding_socket(
    socket: &Path,
    directory: &SessionDir,
    own: u32,
) -> Result<tokio::net::UnixListener, RelayError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    let unsafe_socket = |reason: &str| RelayError::UnsafeSocket {
        path: socket.to_path_buf(),
        reason: reason.to_owned(),
    };
    let io_error = |source: io::Error| RelayError::Io {
        path: socket.to_path_buf(),
        source,
    };

    match std::fs::symlink_metadata(socket) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(unsafe_socket("it is a symbolic link"));
        }
        Ok(metadata) if !metadata.file_type().is_socket() => {
            return Err(unsafe_socket("it is not a socket"));
        }
        Ok(metadata) if metadata.uid() != own => {
            return Err(unsafe_socket("it is owned by another user"));
        }
        Ok(_) => {
            if std::os::unix::net::UnixStream::connect(socket).is_ok() {
                return Err(RelayError::AlreadyListening {
                    dir: directory.canonical.clone(),
                });
            }
            pam_daemon::runtime_dir::remove_stale(socket).map_err(io_error)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(error)),
    }

    let listener = std::os::unix::net::UnixListener::bind(socket).map_err(io_error)?;

    // Bound through the canonical path; confirm the directory is still the one that was checked
    // and the entry is the socket just created, not a link put there in the meantime.
    let still = std::fs::symlink_metadata(&directory.canonical).map_err(io_error)?;
    let bound = std::fs::symlink_metadata(socket).map_err(io_error)?;
    if still.file_type().is_symlink()
        || (still.dev(), still.ino()) != (directory.device, directory.inode)
        || bound.file_type().is_symlink()
        || !bound.file_type().is_socket()
        || bound.uid() != own
    {
        drop(listener);
        return Err(RelayError::UnsafeDirectory {
            dir: directory.canonical.clone(),
            reason: "it was replaced while the socket was being bound".to_owned(),
        });
    }
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600)).map_err(io_error)?;
    listener.set_nonblocking(true).map_err(io_error)?;
    tokio::net::UnixListener::from_std(listener).map_err(io_error)
}

/// Forwards one accepted client connection to `target` for its whole life.
/// A daemon that does not answer (within [`DAEMON_CONNECT_TIMEOUT`]) closes
/// the client side immediately — the client's own transport error is the
/// honest signal, and the relay holds nothing to retry with.
#[cfg(unix)]
async fn pipe(mut client: tokio::net::UnixStream, target: PathBuf) {
    let dialed = tokio::time::timeout(
        DAEMON_CONNECT_TIMEOUT,
        tokio::net::UnixStream::connect(&target),
    )
    .await;
    if let Ok(Ok(mut daemon)) = dialed {
        let _ = tokio::io::copy_bidirectional(&mut client, &mut daemon).await;
    }
}

/// Something that yields client connections: the real
/// [`tokio::net::UnixListener`], or a scripted source in tests.
#[cfg(unix)]
pub(crate) trait Accept {
    /// Waits for the next client connection.
    fn accept_client(&self) -> impl Future<Output = io::Result<tokio::net::UnixStream>> + Send;
}

#[cfg(unix)]
impl Accept for tokio::net::UnixListener {
    async fn accept_client(&self) -> io::Result<tokio::net::UnixStream> {
        self.accept().await.map(|(stream, _)| stream)
    }
}

/// Accepts clients on the relay socket until `shutdown` fires, piping each
/// to its daemon-side target. An accept error never ends the relay — it is
/// retried with exponential backoff, because EMFILE or an aborted
/// connection says nothing about the listener itself — and at most
/// `max_connections` clients are forwarded at once.
#[cfg(unix)]
pub(crate) async fn forward_loop(
    listener: impl Accept,
    target: PathBuf,
    mut shutdown: watch::Receiver<bool>,
    max_connections: usize,
) {
    let slots = Arc::new(Semaphore::new(max_connections));
    let mut backoff = ACCEPT_BACKOFF_MIN;
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            accepted = listener.accept_client() => match accepted {
                Ok(client) => {
                    backoff = ACCEPT_BACKOFF_MIN;
                    let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
                        // Over the cap: dropping the stream closes it.
                        continue;
                    };
                    let target = target.clone();
                    tokio::spawn(async move {
                        pipe(client, target).await;
                        drop(slot);
                    });
                }
                Err(_transient) => {
                    tokio::select! {
                        _ = shutdown.changed() => return,
                        () = tokio::time::sleep(backoff) => {}
                    }
                    backoff = (backoff * 2).min(ACCEPT_BACKOFF_MAX);
                }
            },
        }
    }
}

/// Runs the forwarding loop until `shutdown`, then removes the socket
/// file so the next `pam listen` in this directory starts clean.
///
/// # Errors
///
/// None today: the forwarding loop survives transient accept errors, so
/// only `shutdown` ends it. The `Result` stays in the signature for the
/// caller's `?`.
#[cfg(unix)]
pub async fn serve(
    bindings: RelayBindings,
    shutdown: watch::Receiver<bool>,
) -> Result<(), RelayError> {
    let RelayBindings {
        socket,
        target,
        listener,
        ..
    } = bindings;
    forward_loop(listener, target, shutdown, MAX_CONNECTIONS).await;
    let _ = std::fs::remove_file(&socket);
    Ok(())
}

/// What the daemon's socket answered at startup.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// Nothing answered: no daemon yet, or a stale socket file.
    Unreachable,
    /// Something answered the hello with a frame of this protocol.
    Framed,
    /// A `ZMTP` greeting: a pre-migration daemon.
    LegacyZmtp,
}

/// Dials `socket` with a hello and says what answered. The probe sends no request: a framed
/// daemon acknowledges the hello and is then dropped by the closing connection, and a pre-migration
/// daemon greets before it reads anything, so its `0xFF` first byte shows either way.
#[cfg(unix)]
pub async fn probe(socket: &Path) -> Probe {
    let attempt = async {
        let mut stream = tokio::net::UnixStream::connect(socket).await.ok()?;
        let hello = Frame::Hello(framed::client_hello(Via::Direct));
        // A refused or failed write still leaves a greeting to read.
        let _ = framed::send(&mut stream, &hello, MAX_HELLO_BYTES).await;
        framed::read_first_frame(&mut stream, MAX_HELLO_BYTES)
            .await
            .ok()
    };
    match tokio::time::timeout(PROBE_TIMEOUT, attempt).await {
        Ok(Some(First::LegacyZmtp)) => Probe::LegacyZmtp,
        Ok(Some(_)) => Probe::Framed,
        _ => Probe::Unreachable,
    }
}

/// The two operations that replace a pre-migration daemon, so a test can observe them without
/// signalling a process or spawning the test binary. Both block.
#[cfg(unix)]
pub(crate) trait SupersedeOps: Send + Sync + 'static {
    /// `pam daemon stop`: signal the lock holder and wait for the lock.
    fn stop(&self, base: &Path) -> Result<StopOutcome, StopError>;
    /// Start this binary's daemon and wait until it serves.
    fn ensure(&self, base: &Path) -> Result<EnsureOutcome, ClientError>;
}

/// The real operations: [`client::stop_daemon`] and [`client::ensure_daemon`].
#[cfg(unix)]
struct RealOps;

#[cfg(unix)]
impl SupersedeOps for RealOps {
    fn stop(&self, base: &Path) -> Result<StopOutcome, StopError> {
        client::stop_daemon(base, SUPERSEDE_WAIT)
    }

    fn ensure(&self, base: &Path) -> Result<EnsureOutcome, ClientError> {
        client::ensure_daemon(base)
    }
}

/// How the daemon looked when the relay started.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DaemonNote {
    /// A daemon of this protocol answered.
    Reachable,
    /// Nothing answered; the relay forwards either way.
    NotRunning,
    /// A pre-migration daemon was stopped and this binary's daemon started.
    Superseded,
}

#[cfg(unix)]
fn legacy(pid: Option<u32>, reason: impl Into<String>, recovery: &str) -> RelayError {
    RelayError::LegacyDaemon {
        pid,
        reason: reason.into(),
        recovery: recovery.to_owned(),
    }
}

/// Recovery when the relay may not or cannot stop the old daemon.
#[cfg(unix)]
const RECOVERY_STOP_OUTSIDE: &str =
    "Run `pam daemon stop` in a terminal that may signal it, then start `pam listen` again.";

/// Recovery when the old daemon is still draining.
#[cfg(unix)]
const RECOVERY_STILL_DRAINING: &str =
    "It exits once its in-flight work finishes; wait a few seconds and start `pam listen` again.";

/// Probes the daemon behind `daemon_socket` and, if it is a pre-migration daemon, replaces it:
/// dial once more (another client may have done it first), signal and wait with
/// [`SupersedeOps::stop`], then [`SupersedeOps::ensure`]. The relay runs outside the sandbox, so
/// unlike its clients it may.
///
/// # Errors
///
/// [`RelayError::LegacyDaemon`] when the old daemon cannot be stopped, is still draining, or its
/// replacement does not start.
#[cfg(unix)]
pub(crate) async fn check_daemon<O: SupersedeOps>(
    daemon_socket: &Path,
    base: &Path,
    ops: &Arc<O>,
) -> Result<DaemonNote, RelayError> {
    match probe(daemon_socket).await {
        Probe::Unreachable => return Ok(DaemonNote::NotRunning),
        Probe::Framed => return Ok(DaemonNote::Reachable),
        Probe::LegacyZmtp => {}
    }
    // Another client may have superseded it in the meantime: if a hello now succeeds, skip the
    // signal. A daemon that vanished since is simply started below.
    match probe(daemon_socket).await {
        Probe::Framed => return Ok(DaemonNote::Reachable),
        Probe::Unreachable | Probe::LegacyZmtp => {}
    }
    let stop = {
        let (ops, base) = (Arc::clone(ops), base.to_path_buf());
        tokio::task::spawn_blocking(move || ops.stop(&base)).await
    };
    match stop {
        Ok(Ok(StopOutcome::NotRunning | StopOutcome::Stopped { .. })) => {}
        Ok(Ok(StopOutcome::StillDraining { pid })) => {
            return Err(legacy(
                Some(pid),
                format!(
                    "it was signalled but is still draining after {} seconds",
                    SUPERSEDE_WAIT.as_secs()
                ),
                RECOVERY_STILL_DRAINING,
            ));
        }
        Ok(Err(error)) => {
            let pid = match &error {
                StopError::Signal { pid, .. } => Some(*pid),
                _ => None,
            };
            return Err(legacy(pid, error.to_string(), RECOVERY_STOP_OUTSIDE));
        }
        Err(join) => {
            return Err(legacy(
                None,
                format!("the stop did not complete: {join}"),
                RECOVERY_STOP_OUTSIDE,
            ));
        }
    }
    let started = {
        let (ops, base) = (Arc::clone(ops), base.to_path_buf());
        tokio::task::spawn_blocking(move || ops.ensure(&base)).await
    };
    match started {
        Ok(Ok(_)) => Ok(DaemonNote::Superseded),
        Ok(Err(error)) => Err(legacy(
            None,
            format!("the old daemon stopped but its replacement did not start: {error}"),
            "Start it with `pam daemon`, then start `pam listen` again.",
        )),
        Err(join) => Err(legacy(
            None,
            format!("the replacement start did not complete: {join}"),
            "Start it with `pam daemon`, then start `pam listen` again.",
        )),
    }
}

/// One `pam listen` run: binds the relay, probes (and if needed supersedes) the daemon, prints
/// what it forwards and how sandboxed clients reach it, and serves until ctrl-c.
///
/// # Errors
///
/// As [`prepare`] and `check_daemon`; a ctrl-c shutdown is not an error. A start that fails
/// after the bind removes the socket it bound.
#[cfg(unix)]
pub async fn run(session_dir: &Path, base_dir: &Path) -> Result<(), RelayError> {
    let bindings = prepare(session_dir, base_dir)?;
    let note = match check_daemon(bindings.target(), base_dir, &Arc::new(RealOps)).await {
        Ok(note) => note,
        Err(error) => {
            bindings.discard();
            return Err(error);
        }
    };
    println!(
        "pam listen: forwarding {} → {}\n  daemon: {}\n  sandboxed clients: export PAM_SOCKET_DIR={}\n  stop with ctrl-c",
        bindings.socket().display(),
        bindings.target().display(),
        match note {
            DaemonNote::Reachable => "reachable",
            DaemonNote::NotRunning =>
                "not reachable yet (start pam daemon; the relay forwards either way)",
            DaemonNote::Superseded => "a pre-migration daemon was replaced; reachable",
        },
        bindings.session_dir().display(),
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = serve(bindings, shutdown_rx);
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => result,
        _ = tokio::signal::ctrl_c() => {
            let _ = shutdown_tx.send(true);
            server.await
        }
    }
}

/// [`run`] on unix; unsupported elsewhere.
#[cfg(not(unix))]
pub async fn run(_session_dir: &Path, _base_dir: &Path) -> Result<(), RelayError> {
    Err(RelayError::Unsupported)
}
