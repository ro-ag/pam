//! The administration policy on the framed transport, shared by every native
//! adapter: who is admitted, the hello and its version rule, the one request
//! and its reply, and the client half of the same exchange.
//!
//! The codec, the accept loop, the connection cap, the handshake timeout and
//! the drain are [`crate::framed`]'s; where connections come from is the
//! adapter's (`admin_transport_unix`, `admin_transport_windows`). What is left
//! here is what makes the plane private:
//!
//! - **Admission.** The peer the acceptor reported must be the daemon's owner
//!   ([`Admission`]): on Unix the kernel's uid for the connection equals the
//!   daemon's and a pid is known; on Windows the peer presented the owner
//!   nonce. Anyone else is logged and closed without a byte written or read.
//!   Nothing here trusts the envelope.
//! - **Hello.** Wire protocol 2 and the version rule both planes share
//!   ([`framed::version_rule`]): a hello whose version differs restarts the
//!   daemon only when its binary on disk was replaced (`daemon_outdated`);
//!   otherwise the client is refused `client_version_mismatch` and the phase
//!   does not move. A stale GUI is not a reason to drain running work.
//! - **A pre-migration GUI** sends a bare envelope as its first frame. It is
//!   answered in the shape it understands, a bare refusal `client_outdated`,
//!   and nothing is run.
//! - **One request.** A waiting `admin.*` envelope with a deadline inside
//!   `1..=`[`MAX_REQUEST_MS`] is handed to [`AdminService::handle`] and owned
//!   through terminal persistence, so a disconnected client cannot turn it
//!   into detached work; or `events`, the all-events stream (see
//!   `admin_transport_events`).
//!
//! The client half sends an operation once. It never retries: a lost
//! connection or a lost reply can follow an applied change.

use std::io;
use std::sync::Arc;

use pam_proto::wire::{
    Frame, FrameError, Hello, HelloAck, MAX_ADMIN_REPLY_BYTES, MAX_FRAME_BYTES, MAX_VERSION_BYTES,
    Via, WIRE_PROTOCOL, cause, salvage_envelope_id,
};
use pam_proto::{Envelope, Response};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;

use super::events_stream;
use crate::admin::AdminService;
use crate::event_hub::EventHub;
use crate::framed::{self, DialError, HandshakeError, Limits, Policy, WRITE_TIMEOUT};
use crate::image::ImageWatch;
use crate::ingress::PeerIdentity;
use crate::lifecycle::LifecyclePhase;

/// Largest request frame the plane reads.
pub(super) const MAX_REQUEST_BYTES: usize = MAX_FRAME_BYTES;
/// Largest reply frame the plane writes.
pub(super) const MAX_RESPONSE_BYTES: usize = MAX_ADMIN_REPLY_BYTES;
/// Longest deadline an admin envelope may carry.
pub(super) const MAX_REQUEST_MS: u64 = 300_000;

/// Refusal cause for a reply that outgrew [`MAX_RESPONSE_BYTES`].
pub(super) const CAUSE_RESPONSE_TOO_LARGE: &str = "admin_response_too_large";

/// Refusal cause for a pre-migration GUI, which sends a bare envelope where
/// this protocol expects a hello.
pub(super) const CAUSE_CLIENT_OUTDATED: &str = "client_outdated";

/// What the lifecycle branching around an admin request reads and may move:
/// the daemon's phase, and the boot image behind the restart policy.
#[derive(Clone)]
pub(super) struct AdminLifecycle {
    pub(super) phase: watch::Sender<LifecyclePhase>,
    pub(super) image: Arc<ImageWatch>,
}

/// Who the plane admits. Each build constructs only its own platform's rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Admission {
    /// Unix: the kernel's uid for the connection is this one (the daemon's
    /// own) and the kernel names the peer's pid.
    #[cfg_attr(not(any(unix, test)), allow(dead_code))]
    UnixOwner(u32),
    /// Windows: the peer presented the owner nonce, which the acceptor
    /// checked before yielding the connection.
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    OwnerNonce,
}

impl Admission {
    /// Whether `peer`, as the acceptor reported it, is the daemon's owner.
    pub(super) fn admits(self, peer: &PeerIdentity) -> bool {
        match (self, peer) {
            (
                Self::UnixOwner(owner),
                PeerIdentity::Unix {
                    uid, pid: Some(_), ..
                },
            ) => *uid == owner,
            (Self::OwnerNonce, PeerIdentity::OwnerNonce) => true,
            _ => false,
        }
    }
}

/// The administration plane's [`Policy`]: one per listener.
pub(super) struct AdminPolicy {
    admin: Arc<AdminService>,
    lifecycle: AdminLifecycle,
    hub: Arc<EventHub>,
    admission: Admission,
}

impl AdminPolicy {
    pub(super) fn new(
        admin: Arc<AdminService>,
        lifecycle: AdminLifecycle,
        hub: Arc<EventHub>,
        admission: Admission,
    ) -> Arc<Self> {
        Arc::new(Self {
            admin,
            lifecycle,
            hub,
            admission,
        })
    }

    /// Runs one parsed `request` and writes its `reply`.
    async fn request<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        envelope: &Envelope,
    ) -> io::Result<()> {
        let response = if let Err(error) = validate_envelope(envelope) {
            crate::transport::bad_request(envelope.id.clone(), &error.to_string())
        } else if !crate::transport::envelope_within_limits(envelope) {
            crate::transport::bad_request(
                envelope.id.chars().take(128).collect(),
                "an envelope field exceeds its length limit",
            )
        } else {
            answer(envelope, &self.admin, &self.lifecycle).await
        };
        write_reply(stream, &envelope.id, &response).await
    }
}

impl<S> Policy<S> for AdminPolicy
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn plane(&self) -> &'static str {
        "admin"
    }

    fn limits(&self) -> Limits {
        Limits::ADMIN
    }

    async fn serve(
        self: Arc<Self>,
        mut stream: S,
        peer: PeerIdentity,
        stop: watch::Receiver<bool>,
    ) {
        if !self.admission.admits(&peer) {
            // Who knocked is worth a line: a wrong uid on the owner-only
            // endpoint is either a misconfiguration or someone probing it.
            // Nothing is written to, or read from, such a peer.
            tracing::warn!(
                admission = ?self.admission,
                peer_uid = peer.uid(),
                peer_pid = peer.pid(),
                "private admin connection refused at peer verification"
            );
            return;
        }
        let limits = Limits::ADMIN;
        let deadline = framed::handshake_deadline(&limits);
        let hello =
            match framed::read_hello_within(&mut stream, deadline, limits.request_bytes).await {
                Ok(hello) => hello,
                Err(HandshakeError::Untyped(body)) => {
                    answer_outdated_client(&mut stream, &body).await;
                    return;
                }
                Err(error) => {
                    tracing::debug!(%error, "private admin connection ended at the hello");
                    return;
                }
            };
        // The same rule as on the public plane, by the same function: it
        // answers, reads off the request behind the hello, and only a
        // replaced binary moves the phase.
        let lifecycle = &self.lifecycle;
        if let Err(refusal) = framed::version_rule(
            &mut stream,
            &hello,
            &lifecycle.image,
            &lifecycle.phase,
            deadline,
        )
        .await
        {
            tracing::debug!(
                cause = %refusal.cause,
                peer_uid = peer.uid(),
                peer_pid = peer.pid(),
                "refused a hello on the private admin plane"
            );
            return;
        }
        let ack = HelloAck {
            proto: WIRE_PROTOCOL,
            version: crate::daemon::DAEMON_VERSION.to_owned(),
            epoch: self.hub.epoch().to_owned(),
        };
        let body =
            match framed::accept_hello(&mut stream, ack, limits.request_bytes, deadline).await {
                Ok(body) => body,
                Err(error) => {
                    tracing::debug!(%error, "private admin connection ended before its request");
                    return;
                }
            };
        let served = match Frame::decode(&body) {
            Ok(Frame::Request { envelope }) => self.request(&mut stream, &envelope).await,
            Ok(Frame::Events) => {
                events_stream::serve(
                    &mut stream,
                    &self.hub,
                    self.lifecycle.phase.subscribe(),
                    stop,
                )
                .await;
                Ok(())
            }
            // An envelope that does not parse concerns a request: it is
            // answered as one, naming the id when there is one to salvage.
            Err(FrameError::Invalid { t, detail }) if t == "request" => {
                let id = salvage_envelope_id(&body).unwrap_or_else(|| "unknown".to_owned());
                let refusal = crate::transport::bad_request(id.clone(), &detail);
                write_reply(&mut stream, &id, &refusal).await
            }
            Ok(other) => {
                refuse_bad_frame(
                    &mut stream,
                    &format!(
                        "the administration plane serves request and events, got {}",
                        other.type_name()
                    ),
                )
                .await;
                Ok(())
            }
            Err(error) => {
                refuse_bad_frame(&mut stream, &error.to_string()).await;
                Ok(())
            }
        };
        if let Err(error) = served {
            tracing::debug!(kind = ?error.kind(), "private admin connection ended");
        }
    }
}

async fn refuse_bad_frame<S: AsyncWrite + Unpin>(stream: &mut S, detail: &str) {
    framed::refuse(
        stream,
        cause::BAD_FRAME,
        detail,
        "Quit PAM and reopen it so the window and the daemon run the same build.",
    )
    .await;
}

/// Answers a first frame that carries no `"t"`. A pre-migration GUI sends a
/// bare envelope there and reads one bare response back, so that is what it
/// gets: a refusal naming its request, in the old shape, and nothing runs.
/// Anything else without a `"t"` is a bad frame.
async fn answer_outdated_client<S: AsyncWrite + Unpin>(stream: &mut S, body: &[u8]) {
    let Ok(envelope) = serde_json::from_slice::<Envelope>(body) else {
        refuse_bad_frame(stream, "the first frame has no \"t\" member").await;
        return;
    };
    tracing::warn!(
        client_version = %envelope.client_version.chars().take(MAX_VERSION_BYTES).collect::<String>(),
        "a pre-migration PAM window reached the private admin plane; refused client_outdated"
    );
    let refusal = Response::refusal(
        envelope.id,
        CAUSE_CLIENT_OUTDATED,
        format!(
            "this PAM window was started by an older build than the running daemon ({}) and \
             speaks the previous administration protocol; nothing was changed",
            crate::daemon::DAEMON_VERSION
        ),
        "Quit PAM and reopen it so the window and the daemon run the same build.",
    );
    let Ok(encoded) = serde_json::to_vec(&refusal) else {
        return;
    };
    let _ = tokio::time::timeout(
        WRITE_TIMEOUT,
        framed::write_frame(stream, &encoded, MAX_FRAME_BYTES),
    )
    .await;
}

/// Answers one already-admitted envelope: the shutting-down refusal first,
/// then the operation itself, owned through terminal persistence so a
/// disconnected client cannot turn it into detached work. The version rule
/// has already run, on the hello.
pub(super) async fn answer(
    envelope: &Envelope,
    admin: &AdminService,
    lifecycle: &AdminLifecycle,
) -> Response {
    if *lifecycle.phase.borrow() != LifecyclePhase::Serving {
        return crate::daemon::shutting_down_refusal(&envelope.id);
    }
    admin.handle(envelope).await
}

/// A `reply` frame over a borrowed response, so a reply of up to 16 MiB is
/// not cloned to be encoded.
#[derive(serde::Serialize)]
struct ReplyRef<'a> {
    t: &'static str,
    response: &'a Response,
}

/// A `request` frame over a borrowed envelope.
#[derive(serde::Serialize)]
struct RequestRef<'a> {
    t: &'static str,
    envelope: &'a Envelope,
}

/// Encodes the `reply` frame to `request_id`. A reply larger than
/// [`MAX_RESPONSE_BYTES`] is replaced by a small refusal naming the request:
/// the op has already executed and been audited by now, so the client must
/// learn *that* rather than see the frame write fail as a transport error.
pub(super) fn encode_reply(request_id: &str, response: &Response) -> io::Result<Vec<u8>> {
    let encoded = serde_json::to_vec(&ReplyRef {
        t: "reply",
        response,
    })
    .map_err(invalid)?;
    if encoded.len() <= MAX_RESPONSE_BYTES {
        return Ok(encoded);
    }
    let refusal = Response::Refusal {
        retryable: false,
        id: request_id.to_owned(),
        cause: CAUSE_RESPONSE_TOO_LARGE.to_owned(),
        detail: format!(
            "the reply to {request_id} is {} bytes, over the {MAX_RESPONSE_BYTES}-byte admin frame budget; the operation itself completed",
            encoded.len()
        ),
        recovery: "Ask for less at a time (a smaller limit or max_bytes) and inspect the audit row for what the operation did.".to_owned(),
    };
    serde_json::to_vec(&ReplyRef {
        t: "reply",
        response: &refusal,
    })
    .map_err(invalid)
}

/// Writes the `reply` to `request_id` under the write timeout.
async fn write_reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    request_id: &str,
    response: &Response,
) -> io::Result<()> {
    let encoded = encode_reply(request_id, response)?;
    tokio::time::timeout(
        WRITE_TIMEOUT,
        framed::write_frame(stream, &encoded, MAX_RESPONSE_BYTES),
    )
    .await
    .map_err(|_| timed_out())?
}

/// Encodes the `request` frame for `envelope` after checking it is an admin
/// request the plane carries at all and that it fits the request budget.
/// Nothing has been dialled when this refuses.
pub(super) fn encode_request(envelope: &Envelope) -> io::Result<Vec<u8>> {
    validate_envelope(envelope)?;
    if envelope.client_version.len() > MAX_VERSION_BYTES {
        return Err(invalid("admin client version exceeds the hello budget"));
    }
    let encoded = serde_json::to_vec(&RequestRef {
        t: "request",
        envelope,
    })
    .map_err(invalid)?;
    if encoded.len() > MAX_REQUEST_BYTES {
        return Err(invalid("admin request exceeds frame budget"));
    }
    Ok(encoded)
}

pub(super) fn validate_envelope(envelope: &Envelope) -> io::Result<()> {
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

/// The hello a client sends for `envelope`: this protocol, and the version
/// the envelope claims, which for a real client is its own build's.
fn hello_for(envelope: &Envelope) -> Hello {
    Hello {
        proto: WIRE_PROTOCOL,
        version: envelope.client_version.clone(),
        via: Via::Direct,
    }
}

/// Whether sending the same request again could be answered differently:
/// the daemon is on its way to a state that serves it.
fn transient(cause_name: &str) -> bool {
    [
        cause::DAEMON_OUTDATED,
        cause::DAEMON_SHUTTING_DOWN,
        cause::CONNECTION_CAPACITY_EXHAUSTED,
        cause::HANDSHAKE_TIMEOUT,
    ]
    .contains(&cause_name)
}

/// The client half once the peer is admitted: hello and the encoded
/// `request` (from [`encode_request`]) in one write, then the reply, which
/// must name this request.
///
/// A hello the daemon refuses is returned as a [`Response::Refusal`] for this
/// request: the daemon closed before reading the request frame, so the
/// operation did not run and the caller can show the cause like any other
/// refusal. Everything after the hello was accepted is an error instead: the
/// effect is then unknown and must be inspected, never replayed.
pub(super) async fn exchange_on<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    envelope: &Envelope,
    request: &[u8],
) -> io::Result<Response> {
    match framed::open_encoded(stream, &hello_for(envelope), request).await {
        Ok(_ack) => {}
        Err(DialError::Refused(error)) => {
            return Ok(Response::Refusal {
                retryable: transient(&error.cause),
                id: envelope.id.clone(),
                cause: error.cause,
                detail: error.detail,
                recovery: error.recovery,
            });
        }
        Err(error) => return Err(dial_error(error)),
    }
    let response = match framed::read_daemon_frame(stream, MAX_RESPONSE_BYTES).await {
        Ok(Frame::Reply { response }) => response,
        Ok(other) => {
            return Err(invalid(format!(
                "expected an admin reply, got {}",
                other.type_name()
            )));
        }
        Err(error) => return Err(dial_error(error)),
    };
    let (Response::Result { id, .. } | Response::Refusal { id, .. } | Response::Ticket { id, .. }) =
        &response;
    if id != &envelope.id {
        return Err(invalid("admin response does not match request identity"));
    }
    Ok(response)
}

/// A dial failure as the `io::Error` the admin client reports.
pub(super) fn dial_error(error: DialError) -> io::Error {
    match error {
        DialError::Io(error) => error,
        DialError::Refused(error) => io::Error::new(
            io::ErrorKind::ConnectionAborted,
            format!(
                "{}: {} ({}); inspect state before retrying an effect",
                error.cause, error.detail, error.recovery
            ),
        ),
        other @ (DialError::LegacyDaemon | DialError::Protocol(_)) => invalid(other),
    }
}

pub(super) fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

pub(super) fn denied(detail: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, detail)
}

pub(super) fn timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "private admin request timed out; inspect state before retrying an effect",
    )
}
