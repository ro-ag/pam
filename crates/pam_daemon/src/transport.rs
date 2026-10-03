//! The public transport service: the framed listener on `pam.sock` (the
//! published control file on Windows) and the request type it hands the daemon
//! core.
//!
//! [`Transport::bind`] is the daemon's entry point. It clears what an older
//! daemon may have left in the run directory, binds the public endpoint
//! ([`RuntimeDir::public_socket`] on unix, [`RuntimeDir::public_control`] on
//! Windows) and starts the framed listener ([`crate::public_transport`]) on it.
//! Each connection carries one request: a unary call becomes an
//! [`IncomingRequest`] on the `mpsc` handed to `bind`, answered through its
//! `oneshot` by the connection task that owns it; a follow is served from the
//! event hub. The transport only forwards and never interprets past envelope
//! validation.
//!
//! The transport takes no admission permits: the dispatcher
//! ([`crate::daemon`]) is the single admission point, and it classifies requests through
//! [`crate::policy::admission_pool`].
//!
//! [`EventPublisher`] lives in [`crate::event_hub`] and is re-exported here:
//! services publish into the daemon's one event hub, and events reach a client
//! only as the per-ticket follow stream of the public plane or the all-events
//! stream of the private administration plane. There is no broadcast.
//! [`Transport::shutdown`] stops the listener — it stops accepting and removes
//! its socket file, connection tasks write their final frame — and only then
//! closes the hub.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use pam_proto::{Envelope, Response};
use pam_store::Store;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch};

use crate::event_hub::EventHub;
pub use crate::event_hub::{EventPublisher, PUBLIC_PROGRESS_NOTE, PublishError};
use crate::framed::Listener;
use crate::image::ImageWatch;
use crate::ingress::{Ingress, Origin, PublicPeer};
use crate::lifecycle::LifecyclePhase;
use crate::public_transport::PublicPolicy;
use crate::runtime_dir::{RuntimeDir, remove_stale};

/// Socket files a daemon of an earlier build bound in the run directory and
/// this one does not: the event broadcast socket, and the name the framed
/// listener had while it was developed. Removed at bind, under the instance
/// lock, so the directory holds only what is served.
const SUPERSEDED_SOCKETS: [&str; 2] = ["events.sock", "pam.next.sock"];

/// Why the transport could not start.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The public listener could not be started.
    #[error("cannot listen on {}: {source}", endpoint.display())]
    Listen {
        /// The socket path (unix) or control file (Windows) of the listener.
        endpoint: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
}

/// A validated request received from a client.
///
/// The daemon core answers by sending exactly one [`Response`] into
/// `reply`; the dispatcher's reply guard makes sure it always does.
#[derive(Debug)]
pub struct IncomingRequest {
    /// Which plane the request arrived on (see [`crate::ingress`]).
    pub origin: Origin,
    /// The connection the request arrived on, as the public listener saw it;
    /// `None` for requests the administration plane submits.
    pub peer: Option<PublicPeer>,
    /// The parsed request envelope.
    pub envelope: Envelope,
    /// Channel for this request's single response.
    pub reply: oneshot::Sender<Response>,
}

/// Running transport service: the public endpoint bound, its listener serving.
#[derive(Debug)]
pub struct Transport {
    hub: Arc<EventHub>,
    public: Listener,
}

impl Transport {
    /// Binds the public endpoint under `dirs` and starts the framed listener
    /// on it: [`RuntimeDir::public_socket`] (unix) or a loopback port behind
    /// [`RuntimeDir::public_control`] (Windows), serving from `store`,
    /// `phase`, `image` and the managed policy `managed` (a follow
    /// re-authorizes under its effective scopes). Valid requests arrive on `incoming`; events go
    /// through `hub`. Must be called inside a tokio runtime and while holding
    /// the daemon's instance lock: stale socket files are removed.
    ///
    /// # Errors
    ///
    /// [`TransportError::Listen`] when the endpoint cannot be bound.
    pub fn bind(
        dirs: &RuntimeDir,
        incoming: mpsc::Sender<IncomingRequest>,
        store: Arc<Store>,
        phase: watch::Sender<LifecyclePhase>,
        hub: Arc<EventHub>,
        image: Arc<ImageWatch>,
        managed: Arc<crate::managed_policy_service::PolicyHandle>,
    ) -> Result<Self, TransportError> {
        remove_superseded(dirs);
        let acceptor = bind_public(dirs)?;
        let policy = PublicPolicy::new(
            Ingress::new(incoming),
            store,
            phase,
            Arc::clone(&hub),
            image,
            managed,
        );
        Ok(Self {
            hub,
            public: Listener::spawn(acceptor, policy),
        })
    }

    /// Free connection permits of the public listener.
    #[must_use]
    pub fn public_connections_available(&self) -> usize {
        self.public.available_connections()
    }

    /// A new handle for publishing events.
    #[must_use]
    pub fn event_publisher(&self) -> EventPublisher {
        self.hub.publisher()
    }

    /// Stops the public listener (its socket file is removed, a connection
    /// with an answer in hand writes it, a follower is told the daemon is
    /// shutting down) and closes the event hub: a publish after this errors.
    pub async fn shutdown(self) {
        self.public.shutdown().await;
        self.hub.close();
    }
}

/// Removes what an older daemon left in the run directory and this one does
/// not serve (see [`SUPERSEDED_SOCKETS`]). On Windows that includes
/// `pam.sock` itself: a pre-migration daemon bound a socket file there, a
/// current one publishes a control file instead, and a client takes a
/// leftover `pam.sock` beside a held lock for a pre-migration daemon.
///
/// Nothing dials these names any more, so a file that cannot be removed is
/// logged and left: it must not keep the daemon from starting.
pub(crate) fn remove_superseded(dirs: &RuntimeDir) {
    let run = dirs.run_dir();
    let leftovers = SUPERSEDED_SOCKETS.iter().map(|name| run.join(name));
    #[cfg(windows)]
    let leftovers = leftovers.chain(std::iter::once(dirs.public_socket().to_path_buf()));
    for path in leftovers {
        if let Err(error) = remove_stale(&path) {
            tracing::warn!(
                path = %path.display(),
                %error,
                "could not remove a socket file left by an older daemon"
            );
        }
    }
}

/// Where the public listener's connections come from.
#[cfg(unix)]
type PublicAcceptor = crate::framed_unix::UnixAcceptor;

/// Where the public listener's connections come from.
#[cfg(windows)]
type PublicAcceptor = crate::framed_windows::LoopbackAcceptor;

/// Binds the public endpoint: a `0600` stream socket at
/// [`RuntimeDir::public_socket`], after removing a stale one.
#[cfg(unix)]
fn bind_public(dirs: &RuntimeDir) -> Result<PublicAcceptor, TransportError> {
    let path = dirs.public_socket();
    PublicAcceptor::bind(path).map_err(|source| TransportError::Listen {
        endpoint: path.to_path_buf(),
        source,
    })
}

/// Binds the public endpoint: a loopback port behind a fresh owner nonce,
/// published at [`RuntimeDir::public_control`].
#[cfg(windows)]
fn bind_public(dirs: &RuntimeDir) -> Result<PublicAcceptor, TransportError> {
    let control = dirs.public_control();
    PublicAcceptor::bind(
        control,
        crate::framed_windows::PUBLIC_LABEL,
        crate::framed_windows::MAX_PUBLIC_PENDING,
    )
    .map_err(|source| TransportError::Listen {
        endpoint: control.to_path_buf(),
        source,
    })
}

/// Whether the envelope's identity and scope fields fit their ceilings: a
/// non-empty id of at most 128 bytes; capability, client version, agent label
/// and idempotency key of at most 128 bytes each; a repository spelling of at
/// most 4,096 bytes. Checked before anything is retained.
pub(crate) fn envelope_within_limits(envelope: &Envelope) -> bool {
    !envelope.id.is_empty()
        && envelope.id.len() <= 128
        && envelope.capability.len() <= 128
        && envelope.client_version.len() <= 128
        && envelope.caller.agent.len() <= 128
        && envelope.caller.repo.len() <= 4096
        && envelope
            .idempotency_key
            .as_ref()
            .is_none_or(|key| key.len() <= 128)
}

/// Builds the immediate refusal for a request the transport cannot accept:
/// an envelope that does not parse, or one whose fields exceed their limits.
pub(crate) fn bad_request(id: String, detail: &str) -> Response {
    Response::Refusal {
        retryable: false,
        id,
        cause: "bad_request".to_owned(),
        detail: detail.to_owned(),
        recovery: "Upgrade pam and the pam GUI to matching versions, then retry from the GUI."
            .to_owned(),
    }
}
