//! Kernel-owner admission for administration over a Unix socket.
//!
//! The endpoint is `<base>/admin/control.sock`, mode `0600` in a `0700`
//! directory, under a base whose ownership and ancestors are validated here
//! before anything is created or opened. Connections come from
//! [`crate::framed_unix::UnixAcceptor`] with the kernel's view of each peer and
//! are served by the shared administration policy, which admits only the
//! daemon's own uid. The client half checks the same thing in the other
//! direction before it writes a byte.
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::UnixStream;

use super::frame::{AdminLifecycle, AdminPolicy, Admission, denied, invalid};
use crate::admin::AdminService;
use crate::event_hub::EventHub;
use crate::framed::{self, Accept};
use crate::framed_unix::{self, UnixAcceptor};
use crate::ingress::PeerIdentity;

pub(super) struct Listener {
    inner: framed::Listener,
}

impl Listener {
    pub(super) fn bind(
        base: &Path,
        admin: Arc<AdminService>,
        lifecycle: AdminLifecycle,
        hub: Arc<EventHub>,
    ) -> io::Result<Self> {
        Self::bind_with(base, admin, lifecycle, hub, |acceptor| acceptor)
    }

    /// [`Self::bind`] with the bound acceptor handed through `wrap` first,
    /// so a test can put a scripted acceptor in front of the real socket.
    pub(super) fn bind_with<A: Accept>(
        base: &Path,
        admin: Arc<AdminService>,
        lifecycle: AdminLifecycle,
        hub: Arc<EventHub>,
        wrap: impl FnOnce(UnixAcceptor) -> A,
    ) -> io::Result<Self> {
        let uid = owner()?;
        let path = endpoint(base, uid, true)?;
        // Only a socket this owner left behind is replaced; anything else at
        // the path is refused rather than removed.
        if let Ok(metadata) = path.symlink_metadata() {
            validate_socket(&metadata, uid)?;
            std::fs::remove_file(&path)?;
        }
        let acceptor = UnixAcceptor::bind(&path)?;
        let policy = AdminPolicy::new(admin, lifecycle, hub, Admission::UnixOwner(uid));
        Ok(Self {
            inner: framed::Listener::spawn(wrap(acceptor), policy),
        })
    }

    /// Stops accepting, unlinks the socket, and gives in-flight connections
    /// the drain before aborting them.
    pub(super) async fn shutdown(self) {
        self.inner.shutdown().await;
    }
}

fn owner() -> io::Result<u32> {
    // A local pair asks the kernel for our credentials without unsafe FFI or
    // trusting an environment variable, PID in JSON or filesystem owner alone.
    match framed_unix::own_identity()? {
        PeerIdentity::Unix {
            uid, pid: Some(_), ..
        } => Ok(uid),
        _ => Err(denied("kernel peer PID is unavailable")),
    }
}

/// The client's check of the server: whoever answers on the socket must be
/// this owner, by the kernel's word, before anything is sent to it.
fn verify_peer(stream: &UnixStream, uid: u32) -> io::Result<()> {
    if !Admission::UnixOwner(uid).admits(&framed_unix::peer_identity(stream)?) {
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

/// Connects the private endpoint under `base` as its owner: the directory,
/// the socket file and the answering process are all checked before the
/// stream is handed back. The caller bounds it with its own timeout.
pub(super) async fn connect(base: &Path) -> io::Result<UnixStream> {
    let uid = owner()?;
    let path = endpoint(base, uid, false)?;
    validate_socket(&path.symlink_metadata()?, uid)?;
    let stream = framed_unix::connect(&path).await?;
    verify_peer(&stream, uid)?;
    Ok(stream)
}
