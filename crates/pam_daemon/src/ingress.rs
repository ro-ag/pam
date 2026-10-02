//! Where a request entered the daemon.
//!
//! Every [`crate::transport::IncomingRequest`] carries an [`Origin`]. It is the
//! only thing the pipeline may use to tell a request that arrived on the public
//! socket from one the private administration plane submitted on a human's
//! behalf: `caller.agent`, `caller.repo` and `caller.pid` are self-reported
//! attribution and authorize nothing.
//!
//! The audit actor is decided by origin, never by label: a public `cancel` is
//! recorded as `system` whatever its `caller.agent` says, and only a request of
//! [`Origin::Admin`] is recorded as `human`.
//!
//! This is the transport-independent half of the ingress seam; nothing that
//! reads an origin depends on how the bytes arrived. The kernel's view of the
//! connection ([`PeerIdentity`]) and the relay marker travel beside the origin,
//! as [`PublicPeer`] on the [`crate::transport::IncomingRequest`]: `None` for a
//! request the administration plane submitted and for the legacy `ZeroMQ`
//! listener, which has no way to ask. They are recorded, never used to
//! authorize. [`Ingress`] is the seam itself: the one call a transport adapter
//! makes to run a request, whatever carried the bytes.
//!
//! What is recorded is [`recorded`]: the plane and the peer as the columns
//! of the request row ([`pam_store::RequestOrigin`]), written by the INSERT
//! that admits the request. A leased execution reads its origin back from
//! that row ([`Origin::of_row`]), so a request the administration plane
//! submitted is still an administration request when its lane reaches it.

use pam_proto::wire;
use pam_proto::{Envelope, Response};
use pam_store::{RequestIngress, RequestOrigin};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

use crate::transport::IncomingRequest;

/// Which plane a request arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Arrived on the public listener: an agent, the CLI, or anything else
    /// that can reach `pam.sock`.
    Public,
    /// Submitted by [`crate::admin::AdminService`] on behalf of a request that
    /// arrived on the private admin listener (the GUI: a run, an inspect, a
    /// cancel).
    Admin,
}

impl Origin {
    /// The origin recorded on a request row.
    #[must_use]
    pub const fn of_row(recorded: &RequestOrigin) -> Self {
        match recorded.ingress {
            RequestIngress::Public => Self::Public,
            RequestIngress::Admin => Self::Admin,
        }
    }

    /// The plane as the wire protocol names it (the all-events stream's
    /// `ingress` member).
    #[must_use]
    pub const fn wire(self) -> wire::Ingress {
        match self {
            Self::Public => wire::Ingress::Public,
            Self::Admin => wire::Ingress::Admin,
        }
    }
}

/// What the request row records about where a request entered the daemon.
///
/// The peer is recorded for a public request only: a request of
/// [`Origin::Admin`] was submitted in process, and whatever connection the
/// human's surface arrived on was already admitted by the administration
/// plane's own check. A public request with no peer came through a listener
/// that cannot ask the kernel (the legacy `ZeroMQ` socket).
#[must_use]
pub fn recorded(origin: Origin, peer: Option<PublicPeer>) -> RequestOrigin {
    match origin {
        Origin::Admin => RequestOrigin::ADMIN,
        Origin::Public => RequestOrigin {
            ingress: RequestIngress::Public,
            peer_uid: peer.and_then(|peer| peer.identity.uid()),
            peer_pid: peer.and_then(|peer| peer.identity.pid()),
            relayed: peer.is_some_and(|peer| peer.relayed),
        },
    }
}

/// What the operating system says about the other end of a connection.
///
/// Recorded, never used to authorize: who may connect to the public socket is
/// decided by the filesystem modes, and a pid names a short-lived process and
/// can be reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerIdentity {
    /// Kernel credentials of a unix-socket peer, read at accept.
    Unix {
        /// Effective user id of the peer.
        uid: u32,
        /// Effective group id of the peer.
        gid: u32,
        /// Process id of the peer, when the platform reports one.
        pid: Option<u32>,
    },
    /// Windows: the peer proved it can read the owner-only control file.
    /// Safe Rust cannot ask Windows which process owns the other end of a
    /// loopback connection, so there is no uid and no pid.
    OwnerNonce,
}

impl PeerIdentity {
    /// The peer's user id, where the kernel reported one.
    #[must_use]
    pub const fn uid(&self) -> Option<u32> {
        match self {
            Self::Unix { uid, .. } => Some(*uid),
            Self::OwnerNonce => None,
        }
    }

    /// The peer's process id, where the kernel reported one.
    #[must_use]
    pub const fn pid(&self) -> Option<u32> {
        match self {
            Self::Unix { pid, .. } => *pid,
            Self::OwnerNonce => None,
        }
    }
}

/// The connection a public request arrived on, as the framed listener saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicPeer {
    /// The kernel's view of the peer.
    pub identity: PeerIdentity,
    /// The hello's `via`: the client says it came through a `pam listen`
    /// relay, in which case [`Self::identity`] is the relay process.
    /// Self-reported; attribution only.
    pub relayed: bool,
}

/// Why the seam could not produce a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum IngressError {
    /// The daemon core is gone: nothing can answer any more.
    #[error("the daemon core is not accepting requests")]
    Closed,
    /// The request was handed over but its reply channel was dropped
    /// without an answer (the handler was aborted).
    #[error("the request was accepted but never answered")]
    Unanswered,
}

/// The transport-independent entry point into the daemon core: an
/// [`IncomingRequest`] on the dispatcher's channel and a wait on its `oneshot`.
///
/// A transport adapter calls this and nothing else in the daemon to run a
/// request; the public listener's follow handler is the seam's second entry
/// point and lives with that listener.
#[derive(Debug, Clone)]
pub struct Ingress {
    incoming: mpsc::Sender<IncomingRequest>,
}

impl Ingress {
    /// A seam over the dispatcher's request channel.
    #[must_use]
    pub fn new(incoming: mpsc::Sender<IncomingRequest>) -> Self {
        Self { incoming }
    }

    /// Hands one request to the daemon core. The receiver resolves with its
    /// single response; it errors only when the handler was aborted, which
    /// the caller must turn into a refusal rather than a bare end of file.
    pub async fn submit(
        &self,
        origin: Origin,
        peer: Option<PublicPeer>,
        envelope: Envelope,
    ) -> Result<oneshot::Receiver<Response>, IngressError> {
        let (reply, answer) = oneshot::channel();
        self.incoming
            .send(IncomingRequest {
                identity: Vec::new(),
                origin,
                peer,
                envelope,
                reply,
            })
            .await
            .map_err(|_| IngressError::Closed)?;
        Ok(answer)
    }

    /// [`Self::submit`] and the wait for the response.
    pub async fn call(
        &self,
        origin: Origin,
        peer: Option<PublicPeer>,
        envelope: Envelope,
    ) -> Result<Response, IngressError> {
        self.submit(origin, peer, envelope)
            .await?
            .await
            .map_err(|_| IngressError::Unanswered)
    }
}
