//! The all-events stream of the administration plane, both halves.
//!
//! An admitted administration connection that sends `events` after its hello
//! becomes a stream of every lifecycle event the daemon publishes, straight
//! from the event hub's all-events view: the unsanitised event (the real
//! progress note), the ticket, and the admission metadata the daemon holds for
//! it (capability, repository, agent label, ingress), numbered by `n`. This is
//! what the GUI watches; richer content is acceptable here because the peer has
//! already proved it is the daemon's owner.
//!
//! **Server** (`serve`). The subscription is taken from the hub, then one
//! `subscribed` frame is written, then `event` frames in the hub's publish
//! order. The daemon core publishes no lifecycle events for control requests
//! (`status`, `query`, `cancel`), so the stream never carries a poll — the
//! subscriber's own included. The stream ends with an `error` frame and a
//! close:
//!
//! | Cause | When |
//! | --- | --- |
//! | `subscriber_capacity_exhausted` | the hub already has its four subscribers |
//! | `subscriber_lagged` | this subscriber's bounded queue overflowed |
//! | `daemon_shutting_down` | the phase left `Serving`, the listener stopped, or the hub closed |
//! | `bad_frame` | the client sent anything after `events` |
//!
//! A peer that does not read a frame within the write timeout, or that closes,
//! is simply dropped; its subscriber slot is freed with the connection. Nothing
//! here can slow `publish`: the hub queues per subscriber and never waits.
//!
//! **Client** ([`AdminEvents`]). `events` connects, says hello, sends `events`
//! and waits for `subscribed`, so that when it returns every event published
//! from then on will be delivered or reported as a gap. There is no replay and
//! no reconnect here: a stream that ends is over, and the caller connects
//! again and refreshes whatever it derived from the events it may have missed.

use std::sync::Arc;

use pam_proto::wire::{
    EventFrame, Frame, Hello, HelloAck, MAX_ADMIN_REPLY_BYTES, MAX_FRAME_BYTES, cause,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::sync::watch;

use crate::event_hub::{EventHub, SubscribeError, Subscribed};
use crate::framed::{self, DialError, FrameReader};
use crate::lifecycle::LifecyclePhase;

/// `error` cause for an `events` request beyond the hub's subscriber cap
/// ([`crate::event_hub::MAX_SUBSCRIBERS`]): the wire's
/// [`cause::SUBSCRIBER_CAPACITY_EXHAUSTED`]. Transient: a slot frees when
/// another window closes.
pub const CAUSE_SUBSCRIBER_CAPACITY: &str = cause::SUBSCRIBER_CAPACITY_EXHAUSTED;

/// Largest `event` frame either half handles: the plane's reply budget.
const MAX_EVENT_BYTES: usize = MAX_ADMIN_REPLY_BYTES;

async fn shutting_down<S: AsyncWrite + Unpin>(stream: &mut S) {
    framed::refuse(
        stream,
        cause::DAEMON_SHUTTING_DOWN,
        "the daemon is draining in-flight work before it exits",
        "Reconnect with backoff; the stream resumes against the next daemon.",
    )
    .await;
}

/// Serves one `events` request to its end (see the module docs). `phase` is
/// the daemon's lifecycle and `stop` the listener's stop flag; either ends the
/// stream with `daemon_shutting_down`.
pub(super) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    hub: &Arc<EventHub>,
    mut phase: watch::Receiver<LifecyclePhase>,
    mut stop: watch::Receiver<bool>,
) {
    if *phase.borrow() != LifecyclePhase::Serving || *stop.borrow() {
        shutting_down(stream).await;
        return;
    }
    let mut subscriber = match hub.subscribe_all() {
        Ok(subscriber) => subscriber,
        Err(SubscribeError::Capacity) => {
            framed::refuse(
                stream,
                CAUSE_SUBSCRIBER_CAPACITY,
                &format!(
                    "the daemon already streams events to its maximum of {} subscribers",
                    crate::event_hub::MAX_SUBSCRIBERS
                ),
                "Close another PAM window, or retry shortly.",
            )
            .await;
            return;
        }
        Err(SubscribeError::Closed) => {
            shutting_down(stream).await;
            return;
        }
    };
    // From here on every publish is queued for this subscriber, so the client
    // may be told: what it sees after this frame has no hole at the start.
    if framed::send(stream, &Frame::Subscribed, MAX_FRAME_BYTES)
        .await
        .is_err()
    {
        return;
    }
    let mut probe = [0u8; 1];
    loop {
        tokio::select! {
            biased;
            () = framed::stopped(&mut stop) => {
                shutting_down(stream).await;
                return;
            }
            () = framed::left_serving(&mut phase) => {
                shutting_down(stream).await;
                return;
            }
            // After `events` the client sends nothing: end of file ends the
            // stream, a byte is a protocol error.
            read = stream.read(&mut probe) => {
                if matches!(read, Ok(count) if count > 0) {
                    framed::refuse(
                        stream,
                        cause::BAD_FRAME,
                        "the client sends nothing after events",
                        "Reconnect and send events once.",
                    )
                    .await;
                }
                return;
            }
            next = subscriber.next() => match next {
                Subscribed::Event(event) => {
                    match framed::send(stream, &event.into_frame(), MAX_EVENT_BYTES).await {
                        Ok(()) => {}
                        // One event that cannot be framed is dropped; the
                        // gap in `n` tells the subscriber to refresh.
                        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                            tracing::warn!(%error, "an event did not fit an admin frame; dropped");
                        }
                        // The peer is gone or not reading: drop it.
                        Err(_) => return,
                    }
                }
                Subscribed::Lagged => {
                    framed::refuse(
                        stream,
                        cause::SUBSCRIBER_LAGGED,
                        "this subscriber fell behind and its event queue overflowed",
                        "Reconnect and refresh from admin.activity.list.",
                    )
                    .await;
                    return;
                }
                Subscribed::Closed => {
                    shutting_down(stream).await;
                    return;
                }
            }
        }
    }
}

/// The client's end of one all-events stream: what `events` returns.
///
/// Read it with [`Self::next`] until it errors. It never reconnects; a stream
/// that ended is replaced by a new one, and the events published in between
/// are not replayed.
pub struct AdminEvents {
    stream: Box<dyn AsyncRead + Send + Unpin>,
    reader: FrameReader,
    ack: HelloAck,
}

impl std::fmt::Debug for AdminEvents {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdminEvents")
            .field("ack", &self.ack)
            .finish_non_exhaustive()
    }
}

impl AdminEvents {
    /// The daemon's boot epoch. `n` counts within one epoch: a stream whose
    /// epoch differs from the previous one's is a restarted daemon, and its
    /// `n` starts over.
    #[must_use]
    pub fn epoch(&self) -> &str {
        &self.ack.epoch
    }

    /// The version of the daemon that is streaming.
    #[must_use]
    pub fn daemon_version(&self) -> &str {
        &self.ack.version
    }

    /// The next event, in the daemon's publish order. `n` increases by one
    /// per event; a larger step means events were dropped for this
    /// subscriber and whatever was derived from the stream should be
    /// refreshed.
    ///
    /// Cancel-safe: a call dropped mid-frame (a timeout, a `select!`) loses
    /// nothing, and the next call continues.
    ///
    /// # Errors
    ///
    /// The stream is over after any error:
    /// - [`DialError::Refused`] carries the daemon's `error` frame:
    ///   `subscriber_lagged` (reconnect at once and refresh),
    ///   `daemon_shutting_down` (reconnect with backoff);
    /// - [`DialError::Io`] with `UnexpectedEof` when the daemon went away
    ///   without saying so, or another kind when the connection failed;
    /// - [`DialError::Protocol`] for a frame the stream does not allow.
    pub async fn next(&mut self) -> Result<EventFrame, DialError> {
        match self.reader.daemon_frame(&mut self.stream).await? {
            Frame::Event(event) => Ok(event),
            other => Err(DialError::Protocol(format!(
                "expected event, got {}",
                other.type_name()
            ))),
        }
    }
}

/// Client half over a connected, admitted stream: hello and `events` in one
/// write, then the daemon's `hello_ack` and `subscribed`. No timeout of its
/// own.
///
/// # Errors
///
/// [`DialError::Refused`] when the daemon refuses the hello
/// (`client_version_mismatch`, `daemon_outdated`, `protocol_mismatch`) or the
/// subscription (`subscriber_capacity_exhausted`, `daemon_shutting_down`).
pub(super) async fn subscribe_on<S>(mut stream: S, hello: &Hello) -> Result<AdminEvents, DialError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ack = framed::open(&mut stream, hello, &Frame::Events).await?;
    match framed::read_daemon_frame(&mut stream, MAX_FRAME_BYTES).await? {
        Frame::Subscribed => {}
        other => {
            return Err(DialError::Protocol(format!(
                "expected subscribed, got {}",
                other.type_name()
            )));
        }
    }
    Ok(AdminEvents {
        stream: Box::new(stream),
        reader: FrameReader::new(MAX_EVENT_BYTES),
        ack,
    })
}
