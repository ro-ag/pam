//! The session socket relay: `pam listen <dir>` binds `pam.sock` and
//! `events.sock` directly inside a caller-chosen directory — one an agent
//! sandbox already permits — and forwards bytes to the daemon's runtime
//! sockets, so a sandboxed client (`$PAM_SOCKET_DIR`) can reach the daemon
//! through a path the sandbox allows instead of one it blocks.
//!
//! The relay is deliberately dumb: a per-connection byte pipe and nothing
//! else. It holds no credential, makes no decision, and never inspects the
//! frames, so every admission, scope and budget check still happens in the
//! daemon, which sees ordinary connections. One consequence is worth
//! naming: a listening socket inside a writable directory can be unlinked
//! and rebound by another process of the same user, which lets it
//! *impersonate the daemon* to the agent (deception, not escalation — the
//! same user could talk to the real daemon anyway). The directory is
//! created `0700` and the sockets `0600` to keep other users out; see
//! `docs/session-socket-relay.md` for the full boundary.
//!
//! A relay that a sandboxed agent can wedge would cut that agent off from the
//! daemon with no way to restart it, so the accept loops are hardened: a
//! transient accept error (out of file descriptors, an aborted handshake) is
//! retried with backoff instead of ending the relay, concurrent relayed
//! connections are capped ([`MAX_CONNECTIONS`] per socket; the excess is
//! closed at once, an honest transport error for that client), and the
//! daemon-side dial is bounded ([`DAEMON_CONNECT_TIMEOUT`]).

use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::sync::{Semaphore, watch};

use pam_daemon::runtime_dir::RuntimeDir;

/// How many client connections one relay socket forwards at once. The daemon
/// bounds its own intake; this keeps a single sandboxed peer from exhausting
/// the relay's file descriptors.
pub const MAX_CONNECTIONS: usize = 64;

/// How long the relay waits to reach the daemon's socket for one client.
pub const DAEMON_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// First pause after a failed `accept`; doubles up to [`ACCEPT_BACKOFF_MAX`].
const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(10);

/// Cap on the accept-error backoff.
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

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
        /// The session directory holding the live sockets.
        dir: PathBuf,
    },
    /// Unix domain sockets are the relay's only transport.
    #[error("the session relay needs unix domain sockets; this platform is unsupported")]
    Unsupported,
}

/// The bound listeners plus the two endpoint pairs they forward between.
#[derive(Debug)]
pub struct RelayBindings {
    session_dir: PathBuf,
    daemon: RuntimeDir,
    paths: RuntimeDir,
    router_listener: tokio::net::UnixListener,
    events_listener: tokio::net::UnixListener,
}

/// Binds the relay's two sockets inside `session_dir`, forwarding to the
/// daemon runtime under `base_dir`. Refuses to take over a directory where
/// something already answers; replaces only stale, unanswered socket files.
///
/// # Errors
///
/// [`RelayError::AlreadyListening`] when the session directory is served,
/// [`RelayError::Io`] when preparing or binding a socket fails, and
/// [`RelayError::RuntimeDir`] for a path over the unix socket length limit.
#[cfg(unix)]
pub fn prepare(session_dir: &Path, base_dir: &Path) -> Result<RelayBindings, RelayError> {
    use std::os::unix::fs::PermissionsExt;

    let daemon = RuntimeDir::paths_at_base(base_dir)?;
    let paths = RuntimeDir::paths_at_dir(session_dir)?;
    std::fs::create_dir_all(session_dir).map_err(|source| RelayError::Io {
        path: session_dir.to_path_buf(),
        source,
    })?;
    std::fs::set_permissions(session_dir, std::fs::Permissions::from_mode(0o700)).map_err(
        |source| RelayError::Io {
            path: session_dir.to_path_buf(),
            source,
        },
    )?;

    let router_listener = bind_forwarding_socket(paths.router_socket())?;
    let events_listener = match bind_forwarding_socket(paths.events_socket()) {
        Ok(listener) => listener,
        Err(error) => {
            drop(listener_cleanup(paths.router_socket()));
            return Err(error);
        }
    };
    Ok(RelayBindings {
        session_dir: session_dir.to_path_buf(),
        daemon,
        paths,
        router_listener,
        events_listener,
    })
}

/// Binds one forwarding socket, refusing a live predecessor: a socket file
/// that still answers belongs to a running relay, and rebinding would take
/// its clients. A file nobody answers is a stale leftover and is removed.
#[cfg(unix)]
fn bind_forwarding_socket(session_socket: &Path) -> Result<tokio::net::UnixListener, RelayError> {
    if session_socket.exists() {
        let liveness = std::os::unix::net::UnixStream::connect(session_socket);
        if liveness.is_ok() {
            return Err(RelayError::AlreadyListening {
                dir: session_socket
                    .parent()
                    .unwrap_or(session_dir_fallback())
                    .to_path_buf(),
            });
        }
        pam_daemon::runtime_dir::remove_stale(session_socket).map_err(|source| RelayError::Io {
            path: session_socket.to_path_buf(),
            source,
        })?;
    }
    let listener = std::os::unix::net::UnixListener::bind(session_socket).map_err(|source| {
        RelayError::Io {
            path: session_socket.to_path_buf(),
            source,
        }
    })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| RelayError::Io {
            path: session_socket.to_path_buf(),
            source,
        })?;
    let listener =
        tokio::net::UnixListener::from_std(listener).map_err(|source| RelayError::Io {
            path: session_socket.to_path_buf(),
            source,
        })?;
    Ok(listener)
}

#[cfg(unix)]
fn session_dir_fallback() -> &'static Path {
    Path::new(".")
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

/// Accepts clients on one relay socket until `shutdown` fires, piping each
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

/// Runs both forwarding loops until `shutdown`, then removes the socket
/// files so the next `pam listen` in this directory starts clean.
///
/// # Errors
///
/// None today: the forwarding loops survive transient accept errors, so
/// only `shutdown` ends them. The `Result` stays in the signature for the
/// caller's `?`.
#[cfg(unix)]
pub async fn serve(
    bindings: RelayBindings,
    shutdown: watch::Receiver<bool>,
) -> Result<(), RelayError> {
    let router = forward_loop(
        bindings.router_listener,
        bindings.daemon.router_socket().to_path_buf(),
        shutdown.clone(),
        MAX_CONNECTIONS,
    );
    let events = forward_loop(
        bindings.events_listener,
        bindings.daemon.events_socket().to_path_buf(),
        shutdown,
        MAX_CONNECTIONS,
    );
    tokio::join!(router, events);
    for socket in [
        bindings.paths.router_socket(),
        bindings.paths.events_socket(),
    ] {
        let _ = std::fs::remove_file(socket);
    }
    Ok(())
}

/// One `pam listen` run: binds the relay, prints what it forwards and how
/// sandboxed clients reach it, and serves until ctrl-c.
///
/// # Errors
///
/// As [`prepare`]; a ctrl-c shutdown is not an error.
#[cfg(unix)]
pub async fn run(session_dir: &Path, base_dir: &Path) -> Result<(), RelayError> {
    let bindings = prepare(session_dir, base_dir)?;
    let daemon_reachable = tokio::net::UnixStream::connect(bindings.daemon.router_socket())
        .await
        .is_ok();
    let absolute = std::fs::canonicalize(&bindings.session_dir)
        .unwrap_or_else(|_| bindings.session_dir.clone());
    println!(
        "pam listen: forwarding {} → {}\n            forwarding {} → {}\n  daemon: {}\n  sandboxed clients: export PAM_SOCKET_DIR={}\n  stop with ctrl-c",
        bindings.paths.router_socket().display(),
        bindings.daemon.router_socket().display(),
        bindings.paths.events_socket().display(),
        bindings.daemon.events_socket().display(),
        if daemon_reachable {
            "reachable".to_owned()
        } else {
            "not reachable yet (start pam daemon; the relay forwards either way)".to_owned()
        },
        absolute.display(),
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

/// Best-effort removal of a bound socket file after a failed second bind.
#[cfg(unix)]
fn listener_cleanup(session_socket: &Path) -> impl Drop + '_ {
    struct Cleanup<'a>(&'a Path);
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0);
        }
    }
    Cleanup(session_socket)
}
