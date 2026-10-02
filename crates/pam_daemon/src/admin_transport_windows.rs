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
//! and only then is a frame read. What this does not prove is the same as on Unix:
//! GUI mode, code integrity, or that a human asked (docs/admin-boundary.md).
//!
//! The listener, the control file and the handshake are
//! [`crate::framed_windows`]'s, shared with the public plane under a different
//! label, file and nonce; what stays here is the private base and directory
//! validation and the choice of label. Everything after admission is the shared
//! administration policy.
//!
//! The module is built on Windows and, for its tests, everywhere: only minting
//! the nonce needs Windows.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::TcpStream;

use super::frame::{AdminLifecycle, AdminPolicy, Admission, denied, invalid};
use crate::admin::AdminService;
use crate::event_hub::EventHub;
use crate::framed;
use crate::framed_windows::{self, ADMIN_LABEL, LoopbackAcceptor};

/// Connections allowed to sit in the nonce handshake at once. Held only until
/// admission, so an unadmitted local process idling sockets open cannot eat
/// the served connection budget out from under the owner's GUI.
pub(super) const MAX_PENDING_ADMISSIONS: usize = 8;

pub(super) struct Listener {
    inner: framed::Listener,
}

impl Listener {
    #[cfg(windows)]
    pub(super) fn bind(
        base: &Path,
        admin: Arc<AdminService>,
        lifecycle: AdminLifecycle,
        hub: Arc<EventHub>,
    ) -> io::Result<Self> {
        let control = control_path(base, true)?;
        let acceptor = LoopbackAcceptor::bind(&control, ADMIN_LABEL, MAX_PENDING_ADMISSIONS)?;
        Ok(Self::serve(acceptor, admin, lifecycle, hub))
    }

    /// [`Self::bind`] with the nonce supplied: the portable half, which the
    /// tests drive on every platform.
    #[cfg(test)]
    pub(super) fn bind_with_nonce(
        base: &Path,
        admin: Arc<AdminService>,
        lifecycle: AdminLifecycle,
        hub: Arc<EventHub>,
        nonce: [u8; framed_windows::NONCE_BYTES],
    ) -> io::Result<Self> {
        let control = control_path(base, true)?;
        let acceptor = LoopbackAcceptor::bind_with_nonce(
            &control,
            ADMIN_LABEL,
            MAX_PENDING_ADMISSIONS,
            nonce,
        )?;
        Ok(Self::serve(acceptor, admin, lifecycle, hub))
    }

    fn serve(
        acceptor: LoopbackAcceptor,
        admin: Arc<AdminService>,
        lifecycle: AdminLifecycle,
        hub: Arc<EventHub>,
    ) -> Self {
        let policy = AdminPolicy::new(admin, lifecycle, hub, Admission::OwnerNonce);
        Self {
            inner: framed::Listener::spawn(acceptor, policy),
        }
    }

    /// Stops accepting, removes the control file, and gives in-flight
    /// connections the drain before aborting them.
    pub(super) async fn shutdown(self) {
        self.inner.shutdown().await;
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

/// Connects the private endpoint under `base` as its owner: reads the control
/// file, dials loopback, verifies the server's proof and only then presents
/// the nonce. The caller bounds it with its own timeout.
pub(super) async fn connect(base: &Path) -> io::Result<TcpStream> {
    framed_windows::connect(&control_path(base, false)?, ADMIN_LABEL).await
}
