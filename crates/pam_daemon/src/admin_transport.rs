//! Privileged native ingress, separate from the agent-accessible public plane.
//!
//! The OS sandbox must deny this endpoint and PAM's private state to agents.
//! Unix adapters identify the peer by kernel credentials; the Windows adapter by
//! possession of a nonce readable only from the owner's private base. Either
//! names an OS owner, NOT GUI mode. Unrestricted same-user processes remain
//! privileged; see docs/admin-boundary.md for the threat model.
//!
//! The plane speaks the framed protocol ([`crate::framed`],
//! [`pam_proto::wire`]) under its own policy. A connection is admitted by the
//! operating system's word about its peer, says `hello` (wire protocol 2, the
//! same version rule as the public plane), and then carries exactly one of:
//!
//! - `request` → `reply`: one waiting `admin.*` operation ([`exchange`]). Sent
//!   once and never replayed: a lost connection, timeout or lost reply can
//!   follow an applied change.
//! - `events` → `subscribed`, then `event`*: every lifecycle event the daemon
//!   publishes, unsanitised, with the ticket's admission metadata
//!   ([`events`]). The stream ends with an `error` frame; reconnecting is the
//!   caller's.
//!
//! A pre-migration GUI, which sends a bare envelope as its first frame, is
//! answered in the old shape with a `client_outdated` refusal.

use std::io;
use std::path::Path;
use std::time::Duration;

use pam_proto::wire::Via;
use pam_proto::{Envelope, Response};
use std::sync::Arc;
use tokio::sync::watch;

use crate::admin::AdminService;
use crate::event_hub::EventHub;
use crate::framed::{self, DialError};
use crate::image::ImageWatch;
use crate::lifecycle::LifecyclePhase;

#[path = "admin_transport_frame.rs"]
mod frame;

#[cfg(test)]
#[path = "admin_transport_frame_test.rs"]
mod frame_test;

#[path = "admin_transport_events.rs"]
mod events_stream;

#[cfg(test)]
#[path = "admin_transport_events_test.rs"]
mod events_stream_test;

#[cfg(target_os = "macos")]
#[path = "admin_transport_unix.rs"]
mod platform;

// The Windows adapter is loopback TCP behind a nonce, so everything but
// minting the nonce also builds, and is tested, on the other platforms.
#[cfg(any(windows, test))]
#[path = "admin_transport_windows.rs"]
mod loopback;

#[cfg(windows)]
use loopback as platform;

#[cfg(test)]
#[path = "admin_transport_windows_test.rs"]
mod loopback_test;

#[cfg(all(test, target_os = "macos"))]
#[path = "admin_transport_unix_test.rs"]
mod platform_test;

pub use events_stream::{AdminEvents, CAUSE_SUBSCRIBER_CAPACITY};

/// Whether this build has a validated native administration adapter.
#[must_use]
pub const fn supported() -> bool {
    cfg!(any(target_os = "macos", windows))
}

/// Owned privileged listener. Unsupported platforms retain public read-only
/// operation but expose no administration fallback.
pub struct AdminTransport {
    #[cfg(any(target_os = "macos", windows))]
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
    /// Binds the private endpoint under `base` and starts serving it. The
    /// listener keeps accepting until [`Self::shutdown`]: while the daemon
    /// drains, a request is answered with a `daemon_shutting_down` refusal
    /// rather than a refused connect, and event streams are closed.
    pub(crate) fn bind(
        base: &Path,
        admin: Arc<AdminService>,
        phase: watch::Sender<LifecyclePhase>,
        image: Arc<ImageWatch>,
        hub: Arc<EventHub>,
    ) -> io::Result<Self> {
        #[cfg(any(target_os = "macos", windows))]
        {
            let lifecycle = frame::AdminLifecycle { phase, image };
            Ok(Self {
                inner: platform::Listener::bind(base, admin, lifecycle, hub)?,
            })
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            let _ = (base, admin, phase, image, hub);
            Ok(Self {})
        }
    }

    pub(crate) async fn shutdown(self) {
        #[cfg(any(target_os = "macos", windows))]
        self.inner.shutdown().await;
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "admin_transport_unsupported: this platform has no validated private administration adapter",
    )
}

/// One native request/reply. Never retries an uncertain effect and never sends
/// administration through public IPC. No credential is sent before peer checks.
///
/// The hello carries `envelope.client_version` as the client's version. A
/// hello the daemon refuses (`client_version_mismatch`, `daemon_outdated`,
/// `protocol_mismatch`, `connection_capacity_exhausted`) comes back as
/// `Ok(Response::Refusal)` naming this request: the daemon closed before
/// reading the operation, so nothing ran. `retryable` is set for the causes
/// that pass on their own (`daemon_outdated`, `daemon_shutting_down`,
/// `connection_capacity_exhausted`, `handshake_timeout`).
///
/// # Errors
///
/// `InvalidData` before anything is dialled when the envelope is not a
/// waiting `admin.*` request with a deadline in `1..=300000` ms or does not
/// fit the 1 MiB request frame; `TimedOut` when the whole exchange outlasts
/// the envelope's deadline; otherwise the connection's error. After the hello
/// was accepted an error means the effect is unknown: inspect state, do not
/// replay.
pub async fn exchange(base: &Path, envelope: &Envelope) -> io::Result<Response> {
    #[cfg(any(target_os = "macos", windows))]
    {
        let request = frame::encode_request(envelope)?;
        tokio::time::timeout(Duration::from_millis(envelope.deadline_ms), async {
            let mut stream = platform::connect(base).await?;
            frame::exchange_on(&mut stream, envelope, &request).await
        })
        .await
        .map_err(|_| frame::timed_out())?
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = (base, envelope, Duration::ZERO);
        Err(unsupported())
    }
}

/// Opens the all-events stream of the daemon under `base`: connect, peer
/// checks, hello, `events`, and the daemon's confirmation that the
/// subscription is in place. Every event published after this returns is
/// delivered by [`AdminEvents::next`] or shows as a gap in `n`; nothing
/// published before is replayed.
///
/// The daemon core publishes no lifecycle events for control requests
/// (`status`, `query`, `cancel`): a caller that wants to observe a poll reads
/// its reply, not this stream.
///
/// It connects once. Reconnecting, and refreshing whatever was derived from
/// events that were missed in between, is the caller's.
///
/// # Errors
///
/// - [`DialError::Io`]: no daemon (`NotFound`, `ConnectionRefused`), the
///   endpoint failed its ownership checks (`PermissionDenied`), or the
///   daemon did not answer within the handshake timeout (`TimedOut`).
/// - [`DialError::Refused`]: the daemon's `error` frame —
///   `client_version_mismatch`, `daemon_outdated`, `protocol_mismatch`,
///   `connection_capacity_exhausted`, [`CAUSE_SUBSCRIBER_CAPACITY`], or
///   `daemon_shutting_down`.
pub async fn events(base: &Path) -> Result<AdminEvents, DialError> {
    #[cfg(any(target_os = "macos", windows))]
    {
        let opened = tokio::time::timeout(framed::HANDSHAKE_TIMEOUT, async {
            let stream = platform::connect(base).await?;
            let hello = framed::client_hello(Via::Direct);
            events_stream::subscribe_on(stream, &hello).await
        })
        .await;
        opened.unwrap_or_else(|_| {
            Err(DialError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "the daemon did not open the event stream within the handshake timeout",
            )))
        })
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = (base, Via::Direct, framed::HANDSHAKE_TIMEOUT);
        Err(DialError::Io(unsupported()))
    }
}

/// Validate the private base before runtime files or state are opened.
pub(crate) fn prepare_base(base: &Path) -> io::Result<std::path::PathBuf> {
    #[cfg(any(target_os = "macos", windows))]
    {
        platform::prepare_base(base)
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        Ok(base.to_path_buf())
    }
}
