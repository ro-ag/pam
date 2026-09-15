//! Privileged native ingress, separate from agent-accessible `ZeroMQ`.
//!
//! The OS sandbox must deny this endpoint and PAM's private state to agents.
//! Unix adapters identify the peer by kernel credentials; the Windows adapter by
//! possession of a nonce readable only from the owner's private base. Either
//! names an OS owner, NOT GUI mode. Unrestricted same-user processes remain
//! privileged; see docs/admin-boundary.md for the threat model.

use std::io;
use std::path::Path;

use pam_proto::{Envelope, Response};
use std::sync::Arc;
use tokio::sync::watch;

use crate::admin::AdminService;
use crate::lifecycle::LifecyclePhase;

#[path = "admin_transport_frame.rs"]
mod frame;

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[path = "admin_transport_unix.rs"]
mod platform;

#[cfg(windows)]
#[path = "admin_transport_windows.rs"]
mod platform;

#[cfg(all(test, windows))]
#[path = "admin_transport_windows_test.rs"]
mod platform_test;

/// Whether this build has a validated native administration adapter.
#[must_use]
pub const fn supported() -> bool {
    cfg!(any(target_os = "macos", target_os = "linux", windows))
}

/// Owned privileged listener. Unsupported platforms retain public read-only
/// operation but expose no administration fallback.
pub struct AdminTransport {
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    inner: platform::Listener,
}

impl std::fmt::Debug for AdminTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminTransport")
            .field("supported", &supported())
            .finish_non_exhaustive()
    }
}

impl AdminTransport {
    pub(crate) fn bind(
        base: &Path,
        admin: Arc<AdminService>,
        phase: watch::Sender<LifecyclePhase>,
    ) -> io::Result<Self> {
        #[cfg(any(target_os = "macos", target_os = "linux", windows))]
        {
            Ok(Self {
                inner: platform::Listener::bind(base, admin, phase)?,
            })
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        {
            let _ = (base, admin, phase);
            Ok(Self {})
        }
    }

    pub(crate) async fn shutdown(self) {
        #[cfg(any(target_os = "macos", target_os = "linux", windows))]
        self.inner.shutdown().await;
    }
}

/// One native request/reply. Never retries an uncertain effect and never sends
/// administration through public IPC. No credential is sent before peer checks.
pub async fn exchange(base: &Path, envelope: &Envelope) -> io::Result<Response> {
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    {
        platform::exchange(base, envelope).await
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = (base, envelope);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "admin_transport_unsupported: this platform has no validated private administration adapter",
        ))
    }
}

/// Validate the private base before runtime files or state are opened.
pub(crate) fn prepare_base(base: &Path) -> io::Result<std::path::PathBuf> {
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    {
        platform::prepare_base(base)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        Ok(base.to_path_buf())
    }
}
