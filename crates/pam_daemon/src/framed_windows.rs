//! The Windows endpoint of the framed transport: loopback TCP behind an owner
//! nonce, parameterised by label and control-file path so both planes use it.
//!
//! Std and tokio have no unix sockets on Windows, and safe Rust has no way to
//! ask Windows which process owns the other end of a connection. So ownership
//! is proved another way. The daemon binds an ephemeral `127.0.0.1` port and
//! writes a control file — the port and a fresh 32-byte nonce — whole
//! (temporary file, then rename) into a directory only the owner can read
//! (NTFS inheritance from the profile directory: owner, SYSTEM,
//! Administrators). Being able to read that file is the standing a unix peer
//! has by being able to reach the socket.
//!
//! The handshake runs before any frame and is server-first: the daemon sends
//! `sha256(label ‖ nonce)`; the client compares it in constant time and only
//! then sends the raw nonce; the daemon compares that in constant time. A
//! client therefore never hands the nonce to a process that took the port
//! after a stale control file. The label separates the planes
//! ([`PUBLIC_LABEL`], [`ADMIN_LABEL`]): each has its own control file, port and
//! nonce, and one plane's nonce proves nothing on the other. Non-loopback peers
//! are dropped. The exchange runs under the handshake timeout, and only a
//! bounded number of connections may sit in it at once, outside the served
//! connection cap, so an unadmitted local process cannot eat the served budget.
//!
//! The recorded peer is [`PeerIdentity::OwnerNonce`]: there is no uid and no
//! pid. That is a platform limitation, not a fallback.
//!
//! The module is built on Windows and, for its tests, everywhere: the
//! handshake is plain loopback TCP. Only minting the nonce is Windows-only.

use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::framed::{Accept, HANDSHAKE_TIMEOUT};
use crate::ingress::PeerIdentity;

/// Bytes in the nonce and in every handshake message.
pub const NONCE_BYTES: usize = 32;

/// Domain separator of the public plane's server proof.
pub const PUBLIC_LABEL: &str = "pam-public-server";

/// Domain separator of the administration plane's server proof.
pub const ADMIN_LABEL: &str = "pam-admin-server";

/// Connections allowed to sit in the public nonce handshake at once.
pub const MAX_PUBLIC_PENDING: usize = 32;

/// How long a loopback connect may take before the port counts as dead.
///
/// A connect to a live loopback listener completes in well under a
/// millisecond. Windows, though, takes about two seconds to refuse a connect
/// to a port nobody listens on (it retransmits the SYN twice first), which a
/// control file left by a crashed daemon points at. Without this bound that
/// wait would outlast every readiness probe and be mistaken for a daemon too
/// busy to answer.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(300);

/// The control file's `schema_version`.
const CONTROL_SCHEMA: u32 = 1;

/// What the daemon publishes for its own owner.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Control {
    schema_version: u32,
    /// Loopback port the endpoint listens on.
    port: u16,
    /// Lowercase hex of the 32-byte nonce.
    nonce: String,
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn denied(detail: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, detail)
}

/// 32 fresh bytes from the operating system, per daemon boot.
#[cfg(windows)]
fn fresh_nonce() -> io::Result<[u8; NONCE_BYTES]> {
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|error| io::Error::other(error.to_string()))?;
    Ok(nonce)
}

/// Writes the control file whole-or-not: a reader never sees a torn
/// port/nonce pair.
fn write_control(path: &Path, port: u16, nonce: &[u8; NONCE_BYTES]) -> io::Result<()> {
    let control = Control {
        schema_version: CONTROL_SCHEMA,
        port,
        nonce: hex::encode(nonce),
    };
    let json = serde_json::to_vec_pretty(&control).map_err(io::Error::other)?;
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, json)?;
    let _ = std::fs::remove_file(path);
    std::fs::rename(&temp, path)
}

/// Reads the port and nonce a daemon published at `path`.
///
/// # Errors
///
/// `NotFound` when no daemon has published one (still booting, or not
/// running); `PermissionDenied` for anything but a regular file;
/// `InvalidData` for a file this build does not understand.
pub fn read_control(path: &Path) -> io::Result<(u16, [u8; NONCE_BYTES])> {
    let metadata = path.symlink_metadata()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(denied(
            "the control file must be a regular, non-symlink file",
        ));
    }
    let bytes = std::fs::read(path)?;
    let control: Control = serde_json::from_slice(&bytes).map_err(invalid)?;
    if control.schema_version != CONTROL_SCHEMA || control.port == 0 {
        return Err(invalid(
            "the control file is not one this build understands",
        ));
    }
    let decoded = hex::decode(&control.nonce).map_err(invalid)?;
    let nonce: [u8; NONCE_BYTES] = decoded
        .try_into()
        .map_err(|_| invalid("the control nonce has the wrong length"))?;
    Ok((control.port, nonce))
}

/// `sha256(label ‖ nonce)`: what the server sends first, proving it read the
/// owner's control file without revealing the nonce to a listener that did not.
#[must_use]
pub fn server_proof(label: &str, nonce: &[u8; NONCE_BYTES]) -> [u8; NONCE_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update(nonce);
    hasher.finalize().into()
}

/// Constant-time equality over fixed-size handshake messages.
#[must_use]
pub fn same(a: &[u8; NONCE_BYTES], b: &[u8; NONCE_BYTES]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn is_loopback(address: SocketAddr) -> bool {
    match address.ip() {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    }
}

/// Server side of the handshake: prove first, then demand the nonce. A wrong
/// nonce ends the connection before any frame byte is read. No timeout of
/// its own.
///
/// # Errors
///
/// `PermissionDenied` for a wrong nonce; otherwise the connection's error.
pub async fn admit_client(
    stream: &mut TcpStream,
    label: &str,
    nonce: &[u8; NONCE_BYTES],
) -> io::Result<()> {
    stream.write_all(&server_proof(label, nonce)).await?;
    let mut presented = [0u8; NONCE_BYTES];
    stream.read_exact(&mut presented).await?;
    if !same(&presented, nonce) {
        return Err(denied("the peer did not present the owner's control nonce"));
    }
    Ok(())
}

/// Client side of the handshake: verify the server's proof before sending
/// anything, then present the nonce. No timeout of its own.
///
/// # Errors
///
/// `PermissionDenied` when the port cannot prove it holds the nonce — the
/// nonce is then never sent; otherwise the connection's error.
pub async fn admit_server(
    stream: &mut TcpStream,
    label: &str,
    nonce: &[u8; NONCE_BYTES],
) -> io::Result<()> {
    let mut proof = [0u8; NONCE_BYTES];
    stream.read_exact(&mut proof).await?;
    if !same(&proof, &server_proof(label, nonce)) {
        return Err(denied(
            "the port did not prove it holds the owner's control nonce",
        ));
    }
    stream.write_all(nonce).await
}

/// A loopback listener with its published control file, as a source of
/// admitted connections for [`crate::framed::Listener`].
#[derive(Debug)]
pub struct LoopbackAcceptor {
    /// `None` once closed.
    listener: Option<TcpListener>,
    control: PathBuf,
    label: &'static str,
    nonce: [u8; NONCE_BYTES],
    /// Bounds the connections sitting in the nonce handshake.
    pending: Arc<Semaphore>,
    /// The handshakes in progress; each yields an admitted stream.
    admitting: JoinSet<io::Result<TcpStream>>,
}

impl LoopbackAcceptor {
    /// Binds `127.0.0.1:0`, mints a fresh nonce and publishes both at
    /// `control`, whose directory must already exist and be owner-only.
    /// `label` separates this plane's proof from the other's; at most
    /// `max_pending` connections may sit in the handshake at once. Must be
    /// called inside a tokio runtime.
    ///
    /// # Errors
    ///
    /// The bind's, the random source's or the control file write's error.
    #[cfg(windows)]
    pub fn bind(control: &Path, label: &'static str, max_pending: usize) -> io::Result<Self> {
        Self::bind_with_nonce(control, label, max_pending, fresh_nonce()?)
    }

    /// [`Self::bind`] with the nonce supplied: the portable half, which the
    /// tests drive on every platform.
    ///
    /// # Errors
    ///
    /// The bind's or the control file write's error.
    pub fn bind_with_nonce(
        control: &Path,
        label: &'static str,
        max_pending: usize,
        nonce: [u8; NONCE_BYTES],
    ) -> io::Result<Self> {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let listener = TcpListener::from_std(listener)?;
        // Published only after the bind: a reader never dials a port the
        // daemon does not hold yet.
        write_control(control, port, &nonce)?;
        Ok(Self {
            listener: Some(listener),
            control: control.to_path_buf(),
            label,
            nonce,
            pending: Arc::new(Semaphore::new(max_pending)),
            admitting: JoinSet::new(),
        })
    }

    /// The control file this acceptor published.
    #[must_use]
    pub fn control(&self) -> &Path {
        &self.control
    }

    /// Drops the listener, ends the handshakes in progress and removes the
    /// control file. Idempotent.
    fn unpublish(&mut self) {
        if self.listener.take().is_some() {
            self.admitting.abort_all();
            let _ = std::fs::remove_file(&self.control);
        }
    }
}

impl Accept for LoopbackAcceptor {
    type Stream = TcpStream;

    /// The next connection that proved it holds the nonce. Handshakes run
    /// concurrently in `admitting`, so a peer that stalls in one delays no
    /// one else. Cancel-safe: everything in progress lives in `self`.
    async fn accept(&mut self) -> io::Result<(TcpStream, PeerIdentity)> {
        loop {
            let Some(listener) = &self.listener else {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "the listener is closed",
                ));
            };
            tokio::select! {
                Some(admitted) = self.admitting.join_next(), if !self.admitting.is_empty() => {
                    match admitted {
                        Ok(Ok(stream)) => return Ok((stream, PeerIdentity::OwnerNonce)),
                        Ok(Err(error)) => {
                            tracing::debug!(
                                label = self.label,
                                kind = ?error.kind(),
                                "connection refused at the nonce handshake"
                            );
                            // A loopback peer that reached the admin port and
                            // could not prove the nonce is a boundary
                            // observation (no process identity exists for it).
                            if self.label == ADMIN_LABEL
                                && let Some(sink) = admin_sink_for_control(&self.control)
                            {
                                sink.record(crate::boundary::AdminContact::HandshakeFailed);
                            }
                        }
                        // A handshake task that was aborted or panicked.
                        Err(_) => {}
                    }
                }
                accepted = listener.accept() => {
                    let (mut stream, peer) = accepted?;
                    if !is_loopback(peer) {
                        continue;
                    }
                    // Only this small budget is spent before the peer proves
                    // itself; over it the connection is closed unanswered.
                    let Ok(permit) = Arc::clone(&self.pending).try_acquire_owned() else {
                        continue;
                    };
                    let (label, nonce) = (self.label, self.nonce);
                    self.admitting.spawn(async move {
                        let _permit = permit;
                        // Frames are small and answered at once.
                        stream.set_nodelay(true)?;
                        tokio::time::timeout(
                            HANDSHAKE_TIMEOUT,
                            admit_client(&mut stream, label, &nonce),
                        )
                        .await
                        .map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::TimedOut,
                                "the nonce handshake did not complete in time",
                            )
                        })??;
                        Ok(stream)
                    });
                }
            }
        }
    }

    fn reject(stream: TcpStream, frame: &[u8]) -> impl Future<Output = ()> + Send {
        // The descriptor stays non-blocking out of tokio: one write that
        // either fits the empty socket buffer or is dropped, then close.
        // Nothing here waits, so the future is already complete.
        if let Ok(stream) = stream.into_std() {
            let _ = (&stream).write(frame);
        }
        std::future::ready(())
    }

    fn close(&mut self) {
        self.unpublish();
    }
}

impl Drop for LoopbackAcceptor {
    /// An acceptor dropped without [`Accept::close`] (its task was aborted)
    /// still leaves no control file behind.
    fn drop(&mut self) {
        self.unpublish();
    }
}

/// Connects the endpoint published at `control`: reads the port and nonce as
/// the owner, dials loopback, verifies the server's proof for `label` and
/// only then presents the nonce. The caller bounds it with its own timeout.
///
/// # Errors
///
/// [`read_control`]'s errors; the connect error, with `ConnectionRefused` for
/// a port that did not accept within [`CONNECT_TIMEOUT`]; `PermissionDenied`
/// when the port is not loopback or cannot prove it holds the nonce.
pub async fn connect(control: &Path, label: &str) -> io::Result<TcpStream> {
    let (port, nonce) = read_control(control)?;
    let mut stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((Ipv4Addr::LOCALHOST, port)),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "nothing accepted the loopback connection in time",
        )
    })??;
    if !is_loopback(stream.peer_addr()?) {
        return Err(denied("the endpoint is not loopback"));
    }
    stream.set_nodelay(true)?;
    admit_server(&mut stream, label, &nonce).await?;
    Ok(stream)
}

/// The boundary sink registered for the base a control file sits under
/// (`<base>/admin/control.json`), if a daemon observes it.
fn admin_sink_for_control(control: &Path) -> Option<crate::boundary::AdminContactSink> {
    control
        .parent()
        .and_then(Path::parent)
        .and_then(crate::boundary::admin_sink_for)
}
