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

use std::path::{Path, PathBuf};

use thiserror::Error;
use tokio::sync::watch;

use pam_daemon::runtime_dir::RuntimeDir;

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
/// A daemon that does not answer closes the client side immediately — the
/// client's own transport error is the honest signal, and the relay holds
/// nothing to retry with.
#[cfg(unix)]
async fn pipe(mut client: tokio::net::UnixStream, target: PathBuf) {
    if let Ok(mut daemon) = tokio::net::UnixStream::connect(&target).await {
        let _ = tokio::io::copy_bidirectional(&mut client, &mut daemon).await;
    }
}

/// Accepts clients on one relay socket until `shutdown` fires, piping each
/// to its daemon-side target.
#[cfg(unix)]
async fn forward_loop(
    listener: tokio::net::UnixListener,
    session_socket: PathBuf,
    target: PathBuf,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), RelayError> {
    loop {
        tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            accepted = listener.accept() => match accepted {
                Ok((client, _)) => {
                    tokio::spawn(pipe(client, target.clone()));
                }
                Err(source) => {
                    return Err(RelayError::Io {
                        path: session_socket,
                        source,
                    });
                }
            },
        }
    }
}

/// Runs both forwarding loops until `shutdown`, then removes the socket
/// files so the next `pam listen` in this directory starts clean.
#[cfg(unix)]
pub async fn serve(
    bindings: RelayBindings,
    shutdown: watch::Receiver<bool>,
) -> Result<(), RelayError> {
    let router = forward_loop(
        bindings.router_listener,
        bindings.paths.router_socket().to_path_buf(),
        bindings.daemon.router_socket().to_path_buf(),
        shutdown.clone(),
    );
    let events = forward_loop(
        bindings.events_listener,
        bindings.paths.events_socket().to_path_buf(),
        bindings.daemon.events_socket().to_path_buf(),
        shutdown,
    );
    let result = tokio::try_join!(router, events);
    for socket in [
        bindings.paths.router_socket(),
        bindings.paths.events_socket(),
    ] {
        let _ = std::fs::remove_file(socket);
    }
    result.map(|_| ())
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
