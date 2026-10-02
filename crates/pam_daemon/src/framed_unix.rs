//! The unix endpoint of the framed transport: a `SOCK_STREAM` unix socket.
//!
//! [`UnixAcceptor::bind`] removes a stale socket file (safe only under the
//! daemon's instance lock, which the caller holds), binds, and sets the socket
//! to mode `0600`; who may connect is then decided by the filesystem (the
//! `0700` directory it sits in). tokio's listener does not unlink on drop, so
//! closing the acceptor removes the file — while the instance lock is still
//! held, as the caller's shutdown order guarantees.
//!
//! Each accepted connection comes with the kernel's view of its peer: uid, gid
//! and pid through tokio's safe `peer_cred` (`SO_PEERCRED` on Linux,
//! `getpeereid` and `LOCAL_PEERPID` on macOS). What is done with them is the
//! policy's business: the public plane records them, the administration plane
//! admits by them. Nothing here refuses a peer.

use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use tokio::net::{UnixListener, UnixStream};

use crate::framed::Accept;
use crate::ingress::PeerIdentity;
use crate::runtime_dir::{MAX_SOCKET_PATH_BYTES, remove_stale};

/// A bound unix stream socket, as a source of connections for
/// [`crate::framed::Listener`].
#[derive(Debug)]
pub struct UnixAcceptor {
    /// `None` once closed.
    listener: Option<UnixListener>,
    path: PathBuf,
}

impl UnixAcceptor {
    /// Removes a stale file at `path`, binds a stream socket there and sets
    /// it to mode `0600`. Must be called inside a tokio runtime, and only
    /// while holding whatever makes removing a stale socket safe (the
    /// daemon's instance lock).
    ///
    /// # Errors
    ///
    /// `InvalidInput` when `path` exceeds the unix socket path limit;
    /// otherwise the stale removal's, the bind's or the chmod's error.
    pub fn bind(path: &Path) -> io::Result<Self> {
        let length = path.as_os_str().len();
        // `sun_path` holds the path and its terminator.
        if length >= MAX_SOCKET_PATH_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "socket path {} is {length} bytes; a unix socket path must be shorter \
                     than {MAX_SOCKET_PATH_BYTES} bytes: use a shorter pam base directory",
                    path.display()
                ),
            ));
        }
        remove_stale(path)?;
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            listener: Some(listener),
            path: path.to_path_buf(),
        })
    }

    /// The socket file this acceptor serves.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Drops the listener and unlinks the socket file. Idempotent.
    fn unlink(&mut self) {
        if self.listener.take().is_some()
            && let Err(error) = std::fs::remove_file(&self.path)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(
                path = %self.path.display(),
                %error,
                "could not remove the socket file at shutdown"
            );
        }
    }
}

impl Accept for UnixAcceptor {
    type Stream = UnixStream;

    async fn accept(&mut self) -> io::Result<(UnixStream, PeerIdentity)> {
        let Some(listener) = &self.listener else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "the listener is closed",
            ));
        };
        let (stream, _) = listener.accept().await?;
        // A peer whose credentials cannot be read has already gone: that is
        // a connection that vanished, not a reason to pause the listener.
        let peer = peer_identity(&stream)
            .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, error))?;
        Ok((stream, peer))
    }

    fn reject(stream: UnixStream, frame: &[u8]) -> impl Future<Output = ()> + Send {
        // The descriptor stays non-blocking out of tokio: one write that
        // either fits the empty socket buffer or is dropped, then close.
        // Nothing here waits, so the future is already complete.
        if let Ok(stream) = stream.into_std() {
            let _ = (&stream).write(frame);
        }
        std::future::ready(())
    }

    fn close(&mut self) {
        self.unlink();
    }
}

impl Drop for UnixAcceptor {
    /// An acceptor dropped without [`Accept::close`] (its task was aborted)
    /// still leaves no socket file behind.
    fn drop(&mut self) {
        self.unlink();
    }
}

/// The kernel's uid, gid and pid for the other end of `stream`. A platform
/// that reports no pid yields `None` there, never a guess.
///
/// # Errors
///
/// The `peer_cred` error: the peer is gone.
pub fn peer_identity(stream: &UnixStream) -> io::Result<PeerIdentity> {
    let credentials = stream.peer_cred()?;
    Ok(PeerIdentity::Unix {
        uid: credentials.uid(),
        gid: credentials.gid(),
        pid: credentials.pid().and_then(|pid| u32::try_from(pid).ok()),
    })
}

/// This process's own identity as a peer would see it: a local socket pair
/// asks the kernel without unsafe FFI and without trusting the environment.
///
/// # Errors
///
/// The socket pair's or `peer_cred`'s error.
pub fn own_identity() -> io::Result<PeerIdentity> {
    let (stream, _other) = UnixStream::pair()?;
    peer_identity(&stream)
}

/// Connects the stream socket at `path`. The client never creates or chmods
/// the directory it sits in.
///
/// # Errors
///
/// The connect error: `NotFound` with no socket file, `ConnectionRefused`
/// with a stale one.
pub async fn connect(path: &Path) -> io::Result<UnixStream> {
    UnixStream::connect(path).await
}
