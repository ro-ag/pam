//! Kernel-owner admission for macOS/Linux administration over a Unix socket.
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pam_proto::{Envelope, Response};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::{JoinHandle, JoinSet};

use super::frame::{
    DRAIN_TIMEOUT, MAX_CONNECTIONS, denied, encode_request, exchange_on, invalid, serve, timed_out,
};
use crate::admin::AdminService;
use crate::lifecycle::LifecyclePhase;

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
                    let mut stream = stream;
                    if let Err(error) = serve(&mut stream, &admin, &phase).await {
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

pub(super) async fn exchange(base: &Path, envelope: &Envelope) -> io::Result<Response> {
    let encoded = encode_request(envelope)?;
    let uid = owner()?;
    let path = endpoint(base, uid, false)?;
    validate_socket(&path.symlink_metadata()?, uid)?;
    tokio::time::timeout(Duration::from_millis(envelope.deadline_ms), async {
        let mut stream = UnixStream::connect(path).await?;
        verify_peer(&stream, uid)?;
        exchange_on(&mut stream, envelope, &encoded).await
    })
    .await
    .map_err(|_| timed_out())?
}
