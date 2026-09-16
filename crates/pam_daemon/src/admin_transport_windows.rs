//! Owner-nonce admission for Windows administration over loopback TCP.
//!
//! Windows gives safe Rust no kernel peer credentials on a named pipe (tokio exposes
//! neither the client's process id nor an impersonation token, and an owner-only
//! security descriptor needs raw FFI the workspace forbids), so the adapter proves
//! ownership another way: the daemon binds an ephemeral `127.0.0.1` port and writes
//! `<base>\admin\control.json` — the port and a fresh 32-byte nonce — into the
//! owner's private base, whose NTFS ACL the profile directory inherits (owner,
//! SYSTEM, Administrators). Reading the nonce is possessing the owner's files, the
//! same standing a Unix peer proves through its uid. The handshake is server-first:
//! the daemon sends `sha256("pam-admin-server" ‖ nonce)` before reading anything, so
//! a stale control file never makes a client hand the nonce to a stranger that
//! reused the port; the client then sends the raw nonce, compared in constant time,
//! and only then is a request frame read. Everything after admission is the shared
//! framing. What this does not prove is the same as on Unix: GUI mode, code
//! integrity, or that a human asked (docs/admin-boundary.md).

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pam_proto::{Envelope, Response};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::{JoinHandle, JoinSet};

use super::frame::{
    DRAIN_TIMEOUT, HEADER_TIMEOUT, MAX_CONNECTIONS, denied, encode_request, exchange_on, invalid,
    serve, timed_out,
};
use crate::admin::AdminService;
use crate::lifecycle::LifecyclePhase;

/// Bytes in the nonce and in every handshake message.
pub(super) const NONCE_BYTES: usize = 32;
/// Domain separator for the server's proof of nonce knowledge.
const SERVER_PROOF_LABEL: &[u8] = b"pam-admin-server";
/// The control file's `schema_version`.
const CONTROL_SCHEMA: u32 = 1;
/// Connections allowed to sit in the nonce handshake at once. Held only until
/// admission, so an unadmitted local process idling sockets open cannot eat the
/// [`MAX_CONNECTIONS`] served budget out from under the owner's GUI.
pub(super) const MAX_PENDING_ADMISSIONS: usize = 8;

/// What the daemon publishes into the private base for its own owner.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Control {
    schema_version: u32,
    /// Loopback port the adapter listens on.
    port: u16,
    /// Lowercase hex of the 32-byte nonce.
    nonce: String,
}

pub(super) struct Listener {
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
    control: PathBuf,
}

impl Listener {
    pub(super) fn bind(
        base: &Path,
        admin: Arc<AdminService>,
        phase: watch::Sender<LifecyclePhase>,
    ) -> io::Result<Self> {
        let control = control_path(base, true)?;
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let listener = TcpListener::from_std(listener)?;
        let nonce = fresh_nonce()?;
        write_control(&control, port, &nonce)?;
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(accept(listener, admin, phase, receiver, nonce));
        Ok(Self {
            stop,
            task: Some(task),
            control,
        })
    }

    pub(super) async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        let _ = std::fs::remove_file(&self.control);
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        let _ = std::fs::remove_file(&self.control);
    }
}

/// The base must exist as a real directory under an absolute path; NTFS
/// inheritance from the profile directory is what keeps it owner-only, and a
/// symlinked base would let that inheritance come from somewhere else.
pub(super) fn prepare_base(base: &Path) -> io::Result<PathBuf> {
    if !base.is_absolute() {
        return Err(invalid("PAM base must be an absolute path"));
    }
    if !base.try_exists()? {
        std::fs::create_dir_all(base)?;
    }
    let metadata = base.symlink_metadata()?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(denied("PAM base must be a real, non-symlink directory"));
    }
    base.canonicalize()
}

fn control_path(base: &Path, create: bool) -> io::Result<PathBuf> {
    let directory = prepare_base(base)?.join("admin");
    if create && !directory.try_exists()? {
        std::fs::create_dir(&directory)?;
    }
    let metadata = directory.symlink_metadata()?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(denied(
            "private admin directory must be a real, non-symlink directory",
        ));
    }
    Ok(directory.join("control.json"))
}

fn fresh_nonce() -> io::Result<[u8; NONCE_BYTES]> {
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|error| io::Error::other(error.to_string()))?;
    Ok(nonce)
}

/// Writes the control file whole-or-not: a reader never sees a torn port/nonce pair.
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

fn read_control(path: &Path) -> io::Result<(u16, [u8; NONCE_BYTES])> {
    let metadata = path.symlink_metadata()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(denied(
            "admin control file must be a regular, non-symlink file",
        ));
    }
    let bytes = std::fs::read(path)?;
    let control: Control = serde_json::from_slice(&bytes).map_err(invalid)?;
    if control.schema_version != CONTROL_SCHEMA || control.port == 0 {
        return Err(invalid(
            "admin control file is not one this build understands",
        ));
    }
    let decoded = hex::decode(&control.nonce).map_err(invalid)?;
    let nonce: [u8; NONCE_BYTES] = decoded
        .try_into()
        .map_err(|_| invalid("admin control nonce has the wrong length"))?;
    Ok((control.port, nonce))
}

/// `sha256(label ‖ nonce)`: what the server sends first, proving it read the
/// owner's control file without revealing the nonce to a listener that did not.
pub(super) fn server_proof(nonce: &[u8; NONCE_BYTES]) -> [u8; NONCE_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(SERVER_PROOF_LABEL);
    hasher.update(nonce);
    hasher.finalize().into()
}

/// Constant-time equality over fixed-size handshake messages.
pub(super) fn same(a: &[u8; NONCE_BYTES], b: &[u8; NONCE_BYTES]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn is_loopback(address: SocketAddr) -> bool {
    match address.ip() {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    }
}

async fn accept(
    listener: TcpListener,
    admin: Arc<AdminService>,
    phase: watch::Sender<LifecyclePhase>,
    mut stop: watch::Receiver<bool>,
    nonce: [u8; NONCE_BYTES],
) {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let pending = Arc::new(Semaphore::new(MAX_PENDING_ADMISSIONS));
    let mut tasks = JoinSet::new();
    let mut lifecycle = phase.subscribe();
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            _ = lifecycle.changed() => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else { break; };
                if !is_loopback(peer) { continue; }
                // Only the small pre-admission budget is spent before the
                // peer proves itself; a served permit is taken once it has.
                let Ok(pending_permit) = Arc::clone(&pending).try_acquire_owned() else { continue; };
                let permits = Arc::clone(&permits);
                let admin = Arc::clone(&admin);
                let phase = phase.clone();
                tasks.spawn(async move {
                    let mut stream = stream;
                    let served = async {
                        admit_client(&mut stream, &nonce).await?;
                        drop(pending_permit);
                        let _permit = permits
                            .try_acquire_owned()
                            .map_err(|_| busy())?;
                        serve(&mut stream, &admin, &phase).await
                    };
                    if let Err(error) = served.await {
                        tracing::debug!(kind = ?error.kind(), "private admin connection ended");
                    }
                });
            }
        }
    }
    drop(listener);
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

/// The refusal when every served connection slot is taken by an admitted peer.
fn busy() -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        "private administration is serving its maximum number of connections",
    )
}

/// Server side of the handshake: prove first, then demand the nonce. A wrong
/// nonce ends the connection before any request byte is parsed.
pub(super) async fn admit_client(
    stream: &mut TcpStream,
    nonce: &[u8; NONCE_BYTES],
) -> io::Result<()> {
    tokio::time::timeout(HEADER_TIMEOUT, async {
        stream.write_all(&server_proof(nonce)).await?;
        let mut presented = [0u8; NONCE_BYTES];
        stream.read_exact(&mut presented).await?;
        if !same(&presented, nonce) {
            return Err(denied(
                "private administration requires the owner's admin control nonce",
            ));
        }
        Ok(())
    })
    .await
    .map_err(|_| timed_out())?
}

/// Client side: read the control file as the owner, verify the server's proof
/// before sending anything, then present the nonce.
async fn admit_server(stream: &mut TcpStream, nonce: &[u8; NONCE_BYTES]) -> io::Result<()> {
    let mut proof = [0u8; NONCE_BYTES];
    stream.read_exact(&mut proof).await?;
    if !same(&proof, &server_proof(nonce)) {
        return Err(denied(
            "the admin port did not prove it holds the owner's control nonce",
        ));
    }
    stream.write_all(nonce).await
}

pub(super) async fn exchange(base: &Path, envelope: &Envelope) -> io::Result<Response> {
    let encoded = encode_request(envelope)?;
    let (port, nonce) = read_control(&control_path(base, false)?)?;
    tokio::time::timeout(Duration::from_millis(envelope.deadline_ms), async {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
        if !is_loopback(stream.peer_addr()?) {
            return Err(denied("admin endpoint is not loopback"));
        }
        admit_server(&mut stream, &nonce).await?;
        exchange_on(&mut stream, envelope, &encoded).await
    })
    .await
    .map_err(|_| timed_out())?
}
