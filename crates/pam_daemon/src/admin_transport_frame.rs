//! What every native administration adapter shares: the length-prefixed framing, the
//! envelope rules, the lifecycle branching around [`AdminService::handle`], and the
//! error shapes. Peer admission stays platform-specific (kernel credentials on Unix,
//! the owner-only nonce handshake on Windows); nothing here trusts the envelope.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use pam_proto::{Envelope, Response};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;

use crate::admin::AdminService;
use crate::image::{ImageWatch, VersionVerdict};
use crate::lifecycle::LifecyclePhase;

/// Largest request frame an adapter reads.
pub(super) const MAX_REQUEST_BYTES: usize = 1024 * 1024;
/// Largest response frame an adapter writes.
pub(super) const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// How long a peer has to deliver a request frame (or read a reply) once connected.
pub(super) const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest deadline an admin envelope may carry.
pub(super) const MAX_REQUEST_MS: u64 = 300_000;
/// Concurrent private connections an adapter serves.
pub(super) const MAX_CONNECTIONS: usize = 32;
/// How long shutdown waits for in-flight admin connections.
pub(super) const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// What the lifecycle branching around an admin request reads and may move:
/// the daemon's phase, and the boot image behind the restart policy.
#[derive(Clone)]
pub(super) struct AdminLifecycle {
    pub(super) phase: watch::Sender<LifecyclePhase>,
    pub(super) image: Arc<ImageWatch>,
}

/// Answers one already-admitted envelope: the shutting-down refusal and the
/// version handshake first, then the operation itself, owned through terminal
/// persistence so a disconnected client cannot turn it into detached work.
///
/// The version rule is the public plane's (see [`crate::image`]): a differing
/// `client_version` restarts the daemon only when its binary on disk was
/// replaced; otherwise the client is refused and the phase does not move. The
/// private plane authenticates its peer, but a stale GUI is still not a reason
/// to drain running work.
pub(super) async fn answer(
    envelope: &Envelope,
    admin: &AdminService,
    lifecycle: &AdminLifecycle,
) -> Response {
    if *lifecycle.phase.borrow() != LifecyclePhase::Serving {
        return crate::daemon::shutting_down_refusal(&envelope.id);
    }
    match lifecycle
        .image
        .verdict(&envelope.client_version, crate::daemon::DAEMON_VERSION)
        .await
    {
        VersionVerdict::Match => admin.handle(envelope).await,
        VersionVerdict::Restart => {
            crate::daemon::request_restart(&lifecycle.phase);
            crate::daemon::outdated_refusal(
                &envelope.id,
                &envelope.client_version,
                lifecycle.image.boot_path(),
            )
        }
        VersionVerdict::Mismatch => crate::daemon::version_mismatch_refusal(
            &envelope.id,
            &envelope.client_version,
            lifecycle.image.boot_path(),
        ),
    }
}

/// Paces an accept loop through errors so it never ends on one.
///
/// A listener that stops accepting takes the whole private plane with it — the
/// GUI loses approvals, grants and every other admin op while the daemon keeps
/// serving public traffic, with nothing in the log. So accept errors are logged
/// and retried: a peer that vanished mid-handshake (`ConnectionAborted`) or a
/// signal (`Interrupted`) at once, anything else — descriptor or memory
/// exhaustion, or an error this code does not know — after a pause that starts
/// at [`Self::FIRST`] and doubles to [`Self::MAX`], so a persistent condition
/// neither spins a core nor floods the log.
#[derive(Debug)]
pub(super) struct AcceptBackoff {
    next: Duration,
}

impl AcceptBackoff {
    /// The first pause after a resource error.
    pub(super) const FIRST: Duration = Duration::from_millis(10);
    /// The longest pause.
    pub(super) const MAX: Duration = Duration::from_secs(1);

    pub(super) fn new() -> Self {
        Self { next: Self::FIRST }
    }

    /// An accept succeeded: the next error starts from the first pause.
    pub(super) fn reset(&mut self) {
        self.next = Self::FIRST;
    }

    /// How long to wait before accepting again after `error`.
    pub(super) fn after(&mut self, error: &io::Error) -> Duration {
        match error.kind() {
            io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted => Duration::ZERO,
            _ => {
                let pause = self.next;
                self.next = (self.next * 2).min(Self::MAX);
                pause
            }
        }
    }
}

/// Reads the request frame, answers it, writes the reply: the shared body of every
/// adapter's per-connection task once the peer is admitted.
pub(super) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    admin: &AdminService,
    lifecycle: &AdminLifecycle,
) -> io::Result<()> {
    let payload = tokio::time::timeout(HEADER_TIMEOUT, read_frame(stream, MAX_REQUEST_BYTES))
        .await
        .map_err(|_| timed_out())??;
    let envelope: Envelope = serde_json::from_slice(&payload).map_err(invalid)?;
    validate_envelope(&envelope)?;
    let response = answer(&envelope, admin, lifecycle).await;
    let encoded = encode_reply(&envelope.id, &response)?;
    tokio::time::timeout(
        HEADER_TIMEOUT,
        write_frame(stream, &encoded, MAX_RESPONSE_BYTES),
    )
    .await
    .map_err(|_| timed_out())?
}

/// Refusal cause for a reply that outgrew [`MAX_RESPONSE_BYTES`].
pub(super) const CAUSE_RESPONSE_TOO_LARGE: &str = "admin_response_too_large";

/// Encodes the reply to `request_id` for the wire. A reply larger than
/// [`MAX_RESPONSE_BYTES`] is replaced by a small refusal naming the request:
/// the op has already executed and been audited by now, so the client must
/// learn *that* rather than see the frame write fail as a transport error.
pub(super) fn encode_reply(request_id: &str, response: &Response) -> io::Result<Vec<u8>> {
    let encoded = serde_json::to_vec(response).map_err(invalid)?;
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
    serde_json::to_vec(&refusal).map_err(invalid)
}

/// The client half once the peer is admitted: send the envelope, read the reply,
/// and refuse a reply that does not name this request.
pub(super) async fn exchange_on<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    envelope: &Envelope,
    encoded: &[u8],
) -> io::Result<Response> {
    write_frame(stream, encoded, MAX_REQUEST_BYTES).await?;
    let payload = read_frame(stream, MAX_RESPONSE_BYTES).await?;
    let response: Response = serde_json::from_slice(&payload).map_err(invalid)?;
    let (Response::Result { id, .. } | Response::Refusal { id, .. } | Response::Ticket { id, .. }) =
        &response;
    if id != &envelope.id {
        return Err(invalid("admin response does not match request identity"));
    }
    Ok(response)
}

/// Encodes an envelope for the wire after checking it is an admin request an
/// adapter may carry at all.
pub(super) fn encode_request(envelope: &Envelope) -> io::Result<Vec<u8>> {
    validate_envelope(envelope)?;
    let encoded = serde_json::to_vec(envelope).map_err(invalid)?;
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

pub(super) async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    maximum: usize,
) -> io::Result<Vec<u8>> {
    let length = usize::try_from(stream.read_u32().await?).map_err(invalid)?;
    if length == 0 || length > maximum {
        return Err(invalid("admin frame exceeds budget"));
    }
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

pub(super) async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    payload: &[u8],
    maximum: usize,
) -> io::Result<()> {
    if payload.is_empty() || payload.len() > maximum {
        return Err(invalid("admin frame exceeds budget"));
    }
    stream
        .write_u32(u32::try_from(payload.len()).map_err(invalid)?)
        .await?;
    stream.write_all(payload).await
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
