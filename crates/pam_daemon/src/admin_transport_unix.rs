//! Native framing and kernel-owner admission for macOS/Linux administration.
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pam_proto::{Envelope, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::{JoinHandle, JoinSet};

use crate::admin::AdminService;
use crate::lifecycle::LifecyclePhase;

pub(super) const MAX_REQUEST_BYTES: usize = 1024 * 1024;
pub(super) const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_MS: u64 = 300_000;
const MAX_CONNECTIONS: usize = 32;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct Listener {
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl Listener {
    pub(super) fn bind(
        base: &Path,
        admin: Arc<AdminService>,
        phase: watch::Sender<LifecyclePhase>,
    ) -> io::Result<Self> {
        let uid = owner()?;
        let path = endpoint(base, uid, true)?;
        if let Ok(metadata) = path.symlink_metadata() {
            validate_socket(&metadata, uid)?;
            std::fs::remove_file(&path)?;
        }
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(accept(listener, admin, phase, receiver, uid));
        Ok(Self {
            stop,
            task: Some(task),
        })
    }

    pub(super) async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

fn owner() -> io::Result<u32> {
    // A local pair asks the kernel for our credentials without unsafe FFI or
    // trusting an environment variable, PID in JSON or filesystem owner alone.
    let (stream, _other) = UnixStream::pair()?;
    let credentials = stream.peer_cred()?;
    if credentials.pid().is_none() {
        return Err(denied("kernel peer PID is unavailable"));
    }
    Ok(credentials.uid())
}

fn verify_peer(stream: &UnixStream, uid: u32) -> io::Result<()> {
    let credentials = stream.peer_cred()?;
    if credentials.uid() != uid || credentials.pid().is_none() {
        return Err(denied(
            "private administration requires the daemon's OS owner and kernel peer PID",
        ));
    }
    Ok(())
}

pub(super) fn prepare_base(base: &Path) -> io::Result<PathBuf> {
    let uid = owner()?;
    if !base.try_exists()? {
        let parent = base
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = parent.canonicalize()?;
        validate_ancestors(&parent, uid)?;
        let name = base
            .file_name()
            .ok_or_else(|| invalid("PAM base requires a final directory name"))?;
        let target = parent.join(name);
        std::fs::DirBuilder::new().mode(0o700).create(&target)?;
        return validate_base(&target, uid);
    }
    validate_base(base, uid)
}

fn validate_ancestors(path: &Path, uid: u32) -> io::Result<()> {
    for ancestor in path.ancestors() {
        let metadata = ancestor.symlink_metadata()?;
        let trusted_sticky = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if !metadata.is_dir()
            || (metadata.uid() != uid && metadata.uid() != 0)
            || (metadata.mode() & 0o022 != 0 && !trusted_sticky)
        {
            return Err(denied(
                "PAM ancestor directory permits untrusted replacement",
            ));
        }
    }
    Ok(())
}

fn validate_base(base: &Path, uid: u32) -> io::Result<PathBuf> {
    let metadata = base.symlink_metadata()?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(denied(
            "PAM base must be an owned, non-symlink directory without group/other write access",
        ));
    }
    let canonical = base.canonicalize()?;
    validate_ancestors(&canonical, uid)?;
    Ok(canonical)
}

fn endpoint(base: &Path, uid: u32, create: bool) -> io::Result<PathBuf> {
    let directory = validate_base(base, uid)?.join("admin");
    if create && !directory.try_exists()? {
        std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
    }
    let metadata = directory.symlink_metadata()?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(denied(
            "private admin directory must be owned, non-symlink and mode 0700",
        ));
    }
    let path = directory.join("control.sock");
    if path.as_os_str().len() >= crate::runtime_dir::MAX_SOCKET_PATH_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private admin socket path exceeds the Unix path limit",
        ));
    }
    Ok(path)
}

fn validate_socket(metadata: &std::fs::Metadata, uid: u32) -> io::Result<()> {
    if !metadata.file_type().is_socket()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(denied(
            "admin endpoint must be an owned socket with mode 0600",
        ));
    }
    Ok(())
}

async fn accept(
    listener: UnixListener,
    admin: Arc<AdminService>,
    phase: watch::Sender<LifecyclePhase>,
    mut stop: watch::Receiver<bool>,
    uid: u32,
) {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut tasks = JoinSet::new();
    let mut lifecycle = phase.subscribe();
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            _ = lifecycle.changed() => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { break; };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else { continue; };
                if verify_peer(&stream, uid).is_err() { continue; }
                let admin = Arc::clone(&admin);
                let phase = phase.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = serve(stream, admin, phase).await {
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

async fn serve(
    mut stream: UnixStream,
    admin: Arc<AdminService>,
    phase: watch::Sender<LifecyclePhase>,
) -> io::Result<()> {
    let payload = tokio::time::timeout(HEADER_TIMEOUT, read_frame(&mut stream, MAX_REQUEST_BYTES))
        .await
        .map_err(|_| timed_out())??;
    let envelope: Envelope = serde_json::from_slice(&payload).map_err(invalid)?;
    validate_envelope(&envelope)?;
    let response = if *phase.borrow() != LifecyclePhase::Serving {
        crate::daemon::shutting_down_refusal(&envelope.id)
    } else if envelope.client_version != crate::daemon::DAEMON_VERSION {
        phase.send_if_modified(|current| {
            if *current == LifecyclePhase::Serving {
                *current = LifecyclePhase::Restarting;
                true
            } else {
                false
            }
        });
        crate::daemon::outdated_refusal(&envelope.id, &envelope.client_version)
    } else {
        // Own the operation and its permit through terminal persistence. A
        // disconnected client cannot turn this into detached, unbounded work.
        admin.handle(&envelope).await
    };
    let encoded = serde_json::to_vec(&response).map_err(invalid)?;
    tokio::time::timeout(
        HEADER_TIMEOUT,
        write_frame(&mut stream, &encoded, MAX_RESPONSE_BYTES),
    )
    .await
    .map_err(|_| timed_out())?
}

pub(super) async fn exchange(base: &Path, envelope: &Envelope) -> io::Result<Response> {
    validate_envelope(envelope)?;
    let uid = owner()?;
    let path = endpoint(base, uid, false)?;
    validate_socket(&path.symlink_metadata()?, uid)?;
    let encoded = serde_json::to_vec(envelope).map_err(invalid)?;
    if encoded.len() > MAX_REQUEST_BYTES {
        return Err(invalid("admin request exceeds frame budget"));
    }
    tokio::time::timeout(Duration::from_millis(envelope.deadline_ms), async {
        let mut stream = UnixStream::connect(path).await?;
        verify_peer(&stream, uid)?;
        write_frame(&mut stream, &encoded, MAX_REQUEST_BYTES).await?;
        let payload = read_frame(&mut stream, MAX_RESPONSE_BYTES).await?;
        let response: Response = serde_json::from_slice(&payload).map_err(invalid)?;
        let (Response::Result { id, .. }
        | Response::Refusal { id, .. }
        | Response::Ticket { id, .. }) = &response;
        if id != &envelope.id {
            return Err(invalid("admin response does not match request identity"));
        }
        Ok(response)
    })
    .await
    .map_err(|_| timed_out())?
}

fn validate_envelope(envelope: &Envelope) -> io::Result<()> {
    if !envelope.capability.starts_with(crate::admin::ADMIN_PREFIX)
        || !envelope.wait
        || envelope.deadline_ms == 0
        || envelope.deadline_ms > MAX_REQUEST_MS
    {
        return Err(invalid(
            "admin transport requires a waiting admin request with deadline 1..=300000 ms",
        ));
    }
    Ok(())
}

async fn read_frame(stream: &mut UnixStream, maximum: usize) -> io::Result<Vec<u8>> {
    let length = usize::try_from(stream.read_u32().await?).map_err(invalid)?;
    if length == 0 || length > maximum {
        return Err(invalid("admin frame exceeds budget"));
    }
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn write_frame(stream: &mut UnixStream, payload: &[u8], maximum: usize) -> io::Result<()> {
    if payload.is_empty() || payload.len() > maximum {
        return Err(invalid("admin frame exceeds budget"));
    }
    stream
        .write_u32(u32::try_from(payload.len()).map_err(invalid)?)
        .await?;
    stream.write_all(payload).await
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
fn denied(detail: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, detail)
}
fn timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "private admin request timed out; inspect state before retrying an effect",
    )
}
