//! The client's side of the framed public transport, and the only client file that knows about
//! frames.
//!
//! A public connection carries a hello, one request and its answer ([`pam_proto::wire`]); the
//! daemon closes it. This module dials the platform's public endpoint
//! ([`pam_daemon::framed::connect_public`]: the stream socket at
//! [`RuntimeDir::public_socket`] on unix; on Windows the loopback port published in
//! [`RuntimeDir::public_control`], reached only after the server proved it holds the owner nonce)
//! and speaks three exchanges over it:
//!
//! - [`call`]: hello, `request`, `reply`.
//! - [`follow`]: hello, `follow` with the resume position, then `following`, `event`* and `end`.
//!   Events at or below the resume position are not delivered twice, a frame type or an event kind
//!   this build does not know is skipped, a gap in `seq` needs no action, and a changed `epoch`
//!   (a restarted daemon) resets the position.
//! - [`probe`]: hello only. What the lazy start calls readiness, and where a pre-migration daemon
//!   or a daemon of another build is first noticed.
//!
//! Failures are typed ([`TransportError`]): a ZMTP greeting is
//! [`TransportError::LegacyDaemon`] (nothing is spoken back), an `error` frame is
//! [`TransportError::Refused`] with its cause, detail and recovery. What a failure means for the
//! command — retry, supersede a pre-migration daemon, give up — is decided in
//! [`crate::client`], never here.

use std::io;
use std::time::Duration;

use pam_daemon::framed::{self, DialError, First, FrameReader, PublicStream};
use pam_daemon::runtime_dir::RuntimeDir;
use pam_proto::wire::{
    End, ErrorFrame, Frame, FrameError, Hello, HelloAck, MAX_FRAME_BYTES, MAX_HELLO_BYTES, Via,
    WIRE_PROTOCOL,
};
use pam_proto::{Envelope, Event, Response};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

/// First pause between two connect attempts inside one bounded connect.
const CONNECT_RETRY_MIN: Duration = Duration::from_millis(25);

/// Longest pause between two connect attempts inside one bounded connect.
const CONNECT_RETRY_MAX: Duration = Duration::from_millis(250);

/// Why an exchange with the daemon failed below the level of a [`Response`].
#[derive(Debug, Error)]
pub enum TransportError {
    /// Nothing accepted the connection within the bound: no daemon, a daemon still booting, a
    /// stale socket file, or (Windows) an endpoint that could not prove it holds the owner nonce.
    #[error("cannot connect to the pam daemon: {0}")]
    Connect(#[source] io::Error),
    /// The connection failed or ended before the answer was complete.
    #[error("the connection to the pam daemon failed: {0}")]
    Io(#[source] io::Error),
    /// The answer did not arrive within the bound the caller gave.
    #[error("no answer from the pam daemon within {waited:?}")]
    Timeout {
        /// How long the client waited.
        waited: Duration,
    },
    /// The peer greeted in ZMTP: a pre-migration daemon is listening. Nothing was spoken back.
    #[error("a pre-migration pam daemon answered with a ZMTP greeting")]
    LegacyDaemon,
    /// The daemon answered with an `error` frame and closed.
    #[error("{}: {}", .0.cause, .0.detail)]
    Refused(ErrorFrame),
    /// The daemon sent something this protocol does not allow at that point.
    #[error("the pam daemon broke the wire protocol: {0}")]
    Protocol(String),
}

impl From<DialError> for TransportError {
    fn from(error: DialError) -> Self {
        match error {
            DialError::Io(source) => Self::Io(source),
            DialError::LegacyDaemon => Self::LegacyDaemon,
            DialError::Refused(frame) => Self::Refused(frame),
            DialError::Protocol(detail) => Self::Protocol(detail),
        }
    }
}

/// Where and as whom one exchange dials.
#[derive(Debug, Clone)]
pub struct Dial<'a> {
    /// The runtime directory whose public endpoint is dialled.
    pub dirs: &'a RuntimeDir,
    /// The hello sent first: this build's version, and how the daemon is reached.
    pub hello: Hello,
    /// How long the connect may take, retries of a missing or refusing endpoint included.
    pub connect_timeout: Duration,
}

impl<'a> Dial<'a> {
    /// A dial of `dirs` with this build's hello.
    #[must_use]
    pub fn new(dirs: &'a RuntimeDir, via: Via, connect_timeout: Duration) -> Self {
        Self {
            dirs,
            hello: framed::client_hello(via),
            connect_timeout,
        }
    }
}

/// What the public endpoint of `dirs` is called in an error message: the socket path on unix,
/// the control file on Windows.
#[must_use]
pub fn endpoint_label(dirs: &RuntimeDir) -> String {
    #[cfg(windows)]
    let endpoint = dirs.public_control();
    #[cfg(not(windows))]
    let endpoint = dirs.public_socket();
    endpoint.display().to_string()
}

/// Whether a failed connect is worth repeating inside the bound: the endpoint is not there yet
/// (a daemon between its lock and its bind) or nobody listens on it (a stale file the next
/// daemon is about to replace). On Windows a control file that fails the server proof is the
/// same moment seen from the other side: the port belongs to the daemon that just went away.
fn connect_may_succeed_later(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
    ) || (cfg!(windows)
        && matches!(
            error.kind(),
            io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidData
        ))
}

/// Connects the public endpoint, retrying a missing or refusing endpoint with a short backoff
/// until `dial.connect_timeout` has passed: a daemon that is mid-restart is reached as soon as it
/// binds, and a socket nobody ever binds fails within the bound.
///
/// # Errors
///
/// [`TransportError::Connect`] with the last connect error, or `TimedOut` when a connect was
/// still pending at the bound.
pub async fn connect(dial: &Dial<'_>) -> Result<PublicStream, TransportError> {
    let deadline = Instant::now() + dial.connect_timeout;
    let mut pause = CONNECT_RETRY_MIN;
    loop {
        let attempt = tokio::time::timeout_at(deadline, framed::connect_public(dial.dirs)).await;
        let error = match attempt {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => error,
            Err(_) => {
                return Err(TransportError::Connect(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "the connect did not complete within {:?}",
                        dial.connect_timeout
                    ),
                )));
            }
        };
        if !connect_may_succeed_later(&error) || Instant::now() + pause >= deadline {
            return Err(TransportError::Connect(error));
        }
        tokio::time::sleep(pause).await;
        pause = (pause * 2).min(CONNECT_RETRY_MAX);
    }
}

/// One unary call on a connected stream: hello, `request`, `reply`.
///
/// # Errors
///
/// See [`TransportError`]; no timeout of its own.
pub async fn call_on<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    hello: &Hello,
    envelope: &Envelope,
) -> Result<Response, TransportError> {
    let (_ack, response) = framed::call(stream, hello, envelope, MAX_FRAME_BYTES).await?;
    Ok(response)
}

/// One unary call: a bounded [`connect`], then [`call_on`] under `reply_budget`.
///
/// # Errors
///
/// [`TransportError::Timeout`] when no reply came within `reply_budget` of the connect;
/// otherwise as [`connect`] and [`call_on`].
pub async fn call(
    dial: &Dial<'_>,
    envelope: &Envelope,
    reply_budget: Duration,
) -> Result<Response, TransportError> {
    let mut stream = connect(dial).await?;
    tokio::time::timeout(reply_budget, call_on(&mut stream, &dial.hello, envelope))
        .await
        .map_err(|_| TransportError::Timeout {
            waited: reply_budget,
        })?
}

/// Where a follow left off: what a reconnect sends so the daemon replays only what is new.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resume {
    /// The epoch of the daemon the position was counted under; `None` before the first hello.
    pub epoch: Option<String>,
    /// The highest sequence number delivered under that epoch.
    pub after_seq: u64,
}

impl Resume {
    /// Records the daemon's epoch. A different one is a restarted daemon whose sequence numbers
    /// start again, so the position goes back to zero and whatever it replays is new.
    fn acknowledge(&mut self, epoch: &str) {
        if self.epoch.as_deref() != Some(epoch) {
            self.epoch = Some(epoch.to_owned());
            self.after_seq = 0;
        }
    }

    /// Whether an event with this sequence number is new, advancing the position when it is. A
    /// gap is fine: the stream never carries state the store does not have.
    fn advance(&mut self, seq: Option<u64>) -> bool {
        match seq {
            Some(seq) if seq <= self.after_seq => false,
            Some(seq) => {
                self.after_seq = seq;
                true
            }
            None => true,
        }
    }
}

/// The `seq` of an `event` frame whose event this build could not decode, so a skipped event
/// still moves the resume position.
fn salvage_seq(body: &[u8]) -> Option<u64> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()?
        .get("seq")?
        .as_u64()
}

/// One follow on a connected stream: hello and `follow` with the position in `resume`, then the
/// stream up to its `end`, which is returned. `on_event` is called for every event not delivered
/// before; `resume` is kept current so the caller can reconnect where this stream stopped.
///
/// `opening` bounds the part every follow answers promptly: the hello's acknowledgement and the
/// first frame after it (`following` once the authorising query ran, or `end`). After that a
/// quiet stream is a ticket still running and is not bounded here.
///
/// # Errors
///
/// [`TransportError::Timeout`] when the opening took longer than `opening`;
/// [`TransportError::Io`] when the stream ended before `end`; otherwise see [`TransportError`].
pub async fn follow_on<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    hello: &Hello,
    envelope: &Envelope,
    resume: &mut Resume,
    on_event: &mut dyn FnMut(&Event),
    opening: Duration,
) -> Result<End, TransportError> {
    let mut reader = FrameReader::new(MAX_FRAME_BYTES);
    let opened = tokio::time::timeout(opening, async {
        let ack = framed::follow(
            stream,
            hello,
            envelope,
            resume.after_seq,
            resume.epoch.as_deref(),
        )
        .await?;
        resume.acknowledge(&ack.epoch);
        reader.read(stream).await.map_err(TransportError::Io)
    })
    .await
    .map_err(|_| TransportError::Timeout { waited: opening })?;
    let mut body = opened?;
    loop {
        match Frame::decode(&body) {
            Ok(Frame::Following(following)) => resume.acknowledge(&following.epoch),
            Ok(Frame::Event(frame)) => {
                if resume.advance(frame.seq) {
                    on_event(&frame.event);
                }
            }
            Ok(Frame::End(end)) => return Ok(end),
            Ok(Frame::Error(error)) => return Err(TransportError::Refused(error)),
            // A frame type a newer daemon added: skipped.
            Err(FrameError::UnknownType(_)) => {}
            // An event kind a newer daemon added: skipped, but it was still counted.
            Err(FrameError::Invalid { t, .. }) if t == "event" => {
                resume.advance(salvage_seq(&body));
            }
            Ok(other) => {
                return Err(TransportError::Protocol(format!(
                    "a follow stream carried a {} frame",
                    other.type_name()
                )));
            }
            Err(error) => return Err(TransportError::Protocol(error.to_string())),
        }
        body = reader.read(stream).await.map_err(TransportError::Io)?;
    }
}

/// One follow connection: a bounded [`connect`], then [`follow_on`].
///
/// # Errors
///
/// As [`connect`] and [`follow_on`].
pub async fn follow(
    dial: &Dial<'_>,
    envelope: &Envelope,
    resume: &mut Resume,
    on_event: &mut dyn FnMut(&Event),
    opening: Duration,
) -> Result<End, TransportError> {
    let mut stream = connect(dial).await?;
    follow_on(
        &mut stream,
        &dial.hello,
        envelope,
        resume,
        on_event,
        opening,
    )
    .await
}

/// A hello and nothing else on a connected stream: the daemon's acknowledgement, or what it
/// answered instead. The connection is then dropped; the daemon reads end of file where the
/// request would have been and closes its side without a row or an audit entry.
///
/// # Errors
///
/// See [`TransportError`]; no timeout of its own.
pub async fn hello_on<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    hello: &Hello,
) -> Result<HelloAck, TransportError> {
    // A peer that refuses may close before it reads, so a failed write still reads: the
    // greeting or the refusal is what the caller needs to see.
    let written = framed::send(stream, &Frame::Hello(hello.clone()), MAX_HELLO_BYTES).await;
    let first = match (
        framed::read_first_frame(stream, MAX_HELLO_BYTES).await,
        written,
    ) {
        (Ok(first), _) => first,
        (Err(_), Err(error)) | (Err(error), Ok(())) => return Err(TransportError::Io(error)),
    };
    let body = match first {
        First::Frame(body) => body,
        First::LegacyZmtp => return Err(TransportError::LegacyDaemon),
        First::Reserved(byte) => {
            return Err(TransportError::Protocol(format!(
                "the peer answered in text (first byte {byte:#04x})"
            )));
        }
    };
    match Frame::decode(&body) {
        Ok(Frame::HelloAck(ack)) if ack.proto == WIRE_PROTOCOL => Ok(ack),
        Ok(Frame::HelloAck(ack)) => Err(TransportError::Protocol(format!(
            "the daemon acknowledged wire protocol {}, not {WIRE_PROTOCOL}",
            ack.proto
        ))),
        Ok(Frame::Error(error)) => Err(TransportError::Refused(error)),
        Ok(other) => Err(TransportError::Protocol(format!(
            "expected hello_ack, got {}",
            other.type_name()
        ))),
        Err(error) => Err(TransportError::Protocol(error.to_string())),
    }
}

/// What a hello found behind the public endpoint.
#[derive(Debug)]
pub enum Probe {
    /// The daemon acknowledged the hello: it is this build and it is serving.
    Ready(HelloAck),
    /// Nothing accepted the connection, or it ended without an answer: no listener yet, a stale
    /// socket file, a listener on its way out.
    Unreachable(io::Error),
    /// The peer greeted in ZMTP: a pre-migration daemon.
    Legacy,
    /// The daemon answered the hello with an `error` frame.
    Refused(ErrorFrame),
    /// Something is listening and did not answer in time, or answered with bytes that are not a
    /// frame: a daemon too busy to greet, at best. The request's own exchange reports what it
    /// meets.
    Silent,
}

/// [`probe`] for a caller that is already inside an async runtime.
pub async fn probe_async(dirs: &RuntimeDir, hello: &Hello, timeout: Duration) -> Probe {
    let attempt = async {
        let mut stream = framed::connect_public(dirs)
            .await
            .map_err(TransportError::Connect)?;
        hello_on(&mut stream, hello).await
    };
    match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(ack)) => Probe::Ready(ack),
        Ok(Err(TransportError::Connect(error) | TransportError::Io(error))) => {
            Probe::Unreachable(error)
        }
        Ok(Err(TransportError::LegacyDaemon)) => Probe::Legacy,
        Ok(Err(TransportError::Refused(frame))) => Probe::Refused(frame),
        Ok(Err(TransportError::Protocol(_) | TransportError::Timeout { .. })) | Err(_) => {
            Probe::Silent
        }
    }
}

/// Sends one hello to the public endpoint of `dirs` and reports what answered, within `timeout`.
///
/// Blocking, for the synchronous readiness wait. It runs on a helper thread with a runtime of
/// its own, so it is safe to call from any thread, including one that is driving async tasks.
#[must_use]
pub fn probe(dirs: &RuntimeDir, hello: &Hello, timeout: Duration) -> Probe {
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime.block_on(probe_async(dirs, hello, timeout)),
                Err(error) => Probe::Unreachable(error),
            }
        });
        worker
            .join()
            .unwrap_or_else(|_| Probe::Unreachable(io::Error::other("the hello probe panicked")))
    })
}
