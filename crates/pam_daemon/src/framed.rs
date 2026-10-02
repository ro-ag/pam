//! The length-prefixed frame transport both daemon planes are served on.
//!
//! One module, two policies. Everything the public and the administration
//! listener do alike lives here once, generic over the byte stream
//! (`AsyncRead + AsyncWrite`): the codec, the first-byte sniff, the limits,
//! the server half of the hello handshake, the accept loop, and the
//! client-side dial primitives. What differs — the endpoint, what is done with
//! the peer's identity, which requests are served — is a [`Policy`], and where
//! connections come from is an [`Accept`] (a unix stream socket in
//! `framed_unix`, loopback TCP behind an owner nonce in `framed_windows`, a
//! script in tests).
//!
//! **Codec.** A frame is a 4-byte big-endian length `N` followed by `N` bytes
//! of JSON ([`pam_proto::wire`]). `N` is at least 1 and at most the direction's
//! limit, and it is checked before any buffer is allocated or any body byte is
//! read ([`read_frame`]).
//!
//! **First byte.** A first frame is at most 4 KiB, so its first length byte is
//! `0x00`. `0xFF` is a ZMTP greeting from a pre-migration peer and an ASCII
//! letter is reserved for a text protocol on the same listener; neither is
//! answered ([`sniff`], [`read_first_frame`]).
//!
//! **Accept loop.** [`Listener`] runs one loop per endpoint. Accept errors
//! never end it: descriptor or memory exhaustion and unknown errors are logged
//! and retried after a pause that doubles from 10 ms to one second, a peer that
//! vanished or a signal at once ([`AcceptBackoff`]). A connection over the cap
//! gets one non-blocking write of `error connection_capacity_exhausted` and is
//! closed, so a client can tell a full daemon from a legacy one. Every served
//! connection is a task holding its connection permit for its whole life. Stop
//! closes the acceptor (which removes the socket or control file), signals the
//! connection tasks, waits out the drain and aborts the rest.
//!
//! **Handshake.** [`read_hello`] and [`accept_hello`] are the server half:
//! hello in, `hello_ack` out, then the one request frame, all before one
//! deadline; a failure is answered with an `error` frame where the peer can
//! read one. The version rule between the two steps is the policy's.
//!
//! **Dial.** [`open`], [`call`], [`follow`] and [`read_daemon_frame`] are the
//! client half over an already connected stream; [`connect_public`] connects
//! the platform's public endpoint. They impose no timeout of their own.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use pam_proto::wire::{
    ErrorFrame, Frame, FrameError, Hello, HelloAck, MAX_ADMIN_REPLY_BYTES, MAX_FRAME_BYTES,
    MAX_HELLO_BYTES, MAX_VERSION_BYTES, Via, WIRE_PROTOCOL, ZMTP_GREETING_FIRST_BYTE, cause,
};
use pam_proto::{Envelope, Response};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Semaphore, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;

use crate::ingress::PeerIdentity;

/// How long a peer has to deliver its hello and its request frame.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long one frame write may take: a peer that does not read is
/// disconnected.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a stopping listener waits for its connection tasks.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Inbound public connections served at once, handshakes included.
pub const MAX_PUBLIC_CONNECTIONS: usize = 256;

/// Inbound administration connections served at once.
pub const MAX_ADMIN_CONNECTIONS: usize = 32;

/// The numbers one plane's listener enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Connections served at once; the next one is told and closed.
    pub max_connections: usize,
    /// Largest request frame read.
    pub request_bytes: usize,
    /// Largest frame written.
    pub reply_bytes: usize,
    /// How long the hello and the request frame may take together.
    pub handshake: Duration,
    /// How long stop waits for connection tasks before aborting them.
    pub drain: Duration,
}

impl Limits {
    /// The public plane: 256 connections, 1 MiB frames both ways.
    pub const PUBLIC: Self = Self {
        max_connections: MAX_PUBLIC_CONNECTIONS,
        request_bytes: MAX_FRAME_BYTES,
        reply_bytes: MAX_FRAME_BYTES,
        handshake: HANDSHAKE_TIMEOUT,
        drain: DRAIN_TIMEOUT,
    };

    /// The administration plane: 32 connections, 1 MiB in, 16 MiB out.
    pub const ADMIN: Self = Self {
        max_connections: MAX_ADMIN_CONNECTIONS,
        request_bytes: MAX_FRAME_BYTES,
        reply_bytes: MAX_ADMIN_REPLY_BYTES,
        handshake: HANDSHAKE_TIMEOUT,
        drain: DRAIN_TIMEOUT,
    };
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn write_timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "the peer did not read a frame within the write timeout",
    )
}

/// The body length a frame header announces, or why it is not acceptable.
/// Nothing has been allocated or read past the header when this refuses.
fn body_length(header: [u8; 4], maximum: usize) -> Result<usize, String> {
    let announced = u32::from_be_bytes(header);
    match usize::try_from(announced) {
        Ok(length) if (1..=maximum).contains(&length) => Ok(length),
        _ => Err(format!(
            "frame length {announced} is outside 1..={maximum} bytes"
        )),
    }
}

/// What the first byte of a connection says about the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstByte {
    /// `0x00`: this protocol (every valid first frame is under 16 MiB).
    Frame,
    /// `0xFF`: a ZMTP greeting from a pre-migration peer.
    LegacyZmtp,
    /// An ASCII letter: reserved for a text protocol on the same listener.
    Ascii,
    /// Anything else: not a frame this protocol would send first.
    Other,
}

/// Classifies the first byte a peer sent.
#[must_use]
pub const fn sniff(first: u8) -> FirstByte {
    match first {
        0x00 => FirstByte::Frame,
        ZMTP_GREETING_FIRST_BYTE => FirstByte::LegacyZmtp,
        byte if byte.is_ascii_alphabetic() => FirstByte::Ascii,
        _ => FirstByte::Other,
    }
}

/// What a connection opened with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum First {
    /// A frame of this protocol: its body.
    Frame(Vec<u8>),
    /// A ZMTP greeting. Only its first four bytes were read; nothing is
    /// spoken back.
    LegacyZmtp,
    /// An ASCII letter (the byte), reserved.
    Reserved(u8),
}

/// One inbound header and what it led to.
enum Inbound {
    Body(Vec<u8>),
    LegacyZmtp,
    Reserved(u8),
    /// The announced length is zero or over the limit; the body was not read.
    Length(String),
}

async fn read_inbound<S: AsyncRead + Unpin>(
    stream: &mut S,
    maximum: usize,
    first: bool,
) -> io::Result<Inbound> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if first {
        match sniff(header[0]) {
            FirstByte::LegacyZmtp => return Ok(Inbound::LegacyZmtp),
            FirstByte::Ascii => return Ok(Inbound::Reserved(header[0])),
            FirstByte::Frame | FirstByte::Other => {}
        }
    }
    let length = match body_length(header, maximum) {
        Ok(length) => length,
        Err(detail) => return Ok(Inbound::Length(detail)),
    };
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    Ok(Inbound::Body(body))
}

/// Reads one frame body of at most `maximum` bytes. A zero or over-limit
/// length is `InvalidData`, decided from the header alone: no buffer is
/// allocated and no body byte is read.
pub async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    maximum: usize,
) -> io::Result<Vec<u8>> {
    match read_inbound(stream, maximum, false).await? {
        Inbound::Body(body) => Ok(body),
        Inbound::Length(detail) => Err(invalid(detail)),
        // Unreachable without the sniff; refuse rather than assume.
        Inbound::LegacyZmtp | Inbound::Reserved(_) => Err(invalid("unexpected first-byte sniff")),
    }
}

/// [`read_frame`] for the first frame of a connection, with the first-byte
/// sniff applied before the length is looked at.
pub async fn read_first_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    maximum: usize,
) -> io::Result<First> {
    match read_inbound(stream, maximum, true).await? {
        Inbound::Body(body) => Ok(First::Frame(body)),
        Inbound::LegacyZmtp => Ok(First::LegacyZmtp),
        Inbound::Reserved(byte) => Ok(First::Reserved(byte)),
        Inbound::Length(detail) => Err(invalid(detail)),
    }
}

/// A frame body with its length prefix, refused when empty or over `maximum`.
fn prefixed(body: &[u8], maximum: usize) -> io::Result<Vec<u8>> {
    if body.is_empty() || body.len() > maximum {
        return Err(invalid(format!(
            "frame length {} is outside 1..={maximum} bytes",
            body.len()
        )));
    }
    let length = u32::try_from(body.len()).map_err(invalid)?;
    let mut bytes = Vec::with_capacity(4 + body.len());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(body);
    Ok(bytes)
}

/// Writes one frame: the length prefix, then `body`. Refuses an empty body or
/// one over `maximum` before writing anything. No timeout of its own.
pub async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    body: &[u8],
    maximum: usize,
) -> io::Result<()> {
    if body.is_empty() || body.len() > maximum {
        return Err(invalid(format!(
            "frame length {} is outside 1..={maximum} bytes",
            body.len()
        )));
    }
    let length = u32::try_from(body.len()).map_err(invalid)?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

/// Encodes and writes one frame under [`WRITE_TIMEOUT`]. A peer that does not
/// read in time is a `TimedOut` error; the caller drops the connection.
pub async fn send<S: AsyncWrite + Unpin>(
    stream: &mut S,
    frame: &Frame,
    maximum: usize,
) -> io::Result<()> {
    let bytes = prefixed(&frame.encode().map_err(invalid)?, maximum)?;
    tokio::time::timeout(WRITE_TIMEOUT, async {
        stream.write_all(&bytes).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| write_timed_out())?
}

/// Best-effort `error` frame before the connection is dropped. Never fails:
/// a peer that cannot be told is simply closed.
pub async fn refuse<S: AsyncWrite + Unpin>(
    stream: &mut S,
    cause: &str,
    detail: &str,
    recovery: &str,
) {
    let _ = send(
        stream,
        &Frame::error(cause, detail, recovery),
        MAX_FRAME_BYTES,
    )
    .await;
}

/// One poll of one write: the whole of `bytes` goes out now or not at all,
/// and the caller never waits. For in-memory streams; a socket adapter writes
/// through its non-blocking descriptor instead. Returns whether it went out.
pub async fn write_once<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> bool {
    std::future::poll_fn(|context| {
        let written = Pin::new(&mut *stream).poll_write(context, bytes);
        Poll::Ready(matches!(written, Poll::Ready(Ok(count)) if count == bytes.len()))
    })
    .await
}

/// Resolves when a listener's stop flag is set or its handle is gone. What a
/// connection task selects on beside its own work.
pub async fn stopped(stop: &mut watch::Receiver<bool>) {
    // An error means the listener (sender) is gone: treat as stop.
    let _ = stop.wait_for(|stop| *stop).await;
}

/// Why the server half of the handshake did not produce a request.
#[derive(Debug, Error)]
pub enum HandshakeError {
    /// The peer opened with a ZMTP greeting: a pre-migration client. Nothing
    /// was written; the policy logs it and closes.
    #[error("the peer greeted in ZMTP: a pre-migration pam client")]
    LegacyZmtp,
    /// The peer opened with an ASCII letter. Nothing was written.
    #[error("the first byte {0:#04x} is reserved")]
    Reserved(u8),
    /// The first frame is a JSON object with no `\"t\"`: the shape of a
    /// pre-migration client's bare envelope. Nothing was written; the policy
    /// answers (the administration plane in the old shape).
    #[error("the first frame has no \"t\" member")]
    Untyped(Vec<u8>),
    /// A frame was malformed, out of order or outside its limit. The peer
    /// was sent `error bad_frame`.
    #[error("bad frame: {0}")]
    BadFrame(String),
    /// The hello's `proto` is not spoken here. The peer was sent
    /// `error protocol_mismatch`.
    #[error("wire protocol {0} is not spoken by this daemon")]
    ProtocolMismatch(u32),
    /// The hello and the request frame did not arrive before the deadline.
    /// The peer was sent `error handshake_timeout`, best effort.
    #[error("the handshake did not complete in time")]
    Timeout,
    /// The connection failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// The moment by which a connection accepted now must have delivered its
/// hello and its request frame.
#[must_use]
pub fn handshake_deadline(limits: &Limits) -> Instant {
    Instant::now() + limits.handshake
}

async fn refuse_timeout<S: AsyncWrite + Unpin>(stream: &mut S) -> HandshakeError {
    refuse(
        stream,
        cause::HANDSHAKE_TIMEOUT,
        "the hello and the request frame were not delivered within five seconds",
        "Retry; if it persists the pam client and daemon versions may not match.",
    )
    .await;
    HandshakeError::Timeout
}

async fn refuse_bad_frame<S: AsyncWrite + Unpin>(stream: &mut S, detail: String) -> HandshakeError {
    refuse(
        stream,
        cause::BAD_FRAME,
        &detail,
        "Upgrade pam and the pam GUI to matching versions, then retry.",
    )
    .await;
    HandshakeError::BadFrame(detail)
}

/// Server half, step one: reads the connection's first frame before
/// `deadline` and returns it when it is a `hello` of this protocol. Every
/// other outcome is a [`HandshakeError`], already answered on the wire where
/// its documentation says so. The version rule is the caller's next step.
pub async fn read_hello<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    deadline: Instant,
) -> Result<Hello, HandshakeError> {
    let first =
        tokio::time::timeout_at(deadline, read_inbound(stream, MAX_HELLO_BYTES, true)).await;
    let body = match first {
        Err(_) => return Err(refuse_timeout(stream).await),
        Ok(Err(error)) => return Err(HandshakeError::Io(error)),
        Ok(Ok(Inbound::LegacyZmtp)) => return Err(HandshakeError::LegacyZmtp),
        Ok(Ok(Inbound::Reserved(byte))) => return Err(HandshakeError::Reserved(byte)),
        Ok(Ok(Inbound::Length(detail))) => return Err(refuse_bad_frame(stream, detail).await),
        Ok(Ok(Inbound::Body(body))) => body,
    };
    let hello = match Frame::decode(&body) {
        Ok(Frame::Hello(hello)) => hello,
        Ok(other) => {
            let detail = format!("expected hello, got {}", other.type_name());
            return Err(refuse_bad_frame(stream, detail).await);
        }
        Err(FrameError::Untyped) => return Err(HandshakeError::Untyped(body)),
        Err(error) => return Err(refuse_bad_frame(stream, error.to_string()).await),
    };
    if hello.proto != WIRE_PROTOCOL {
        refuse(
            stream,
            cause::PROTOCOL_MISMATCH,
            &format!(
                "this daemon speaks pam wire protocol {WIRE_PROTOCOL}; the client sent {}",
                hello.proto
            ),
            &format!(
                "Use the pam binary that matches the running daemon ({}).",
                crate::daemon::DAEMON_VERSION
            ),
        )
        .await;
        return Err(HandshakeError::ProtocolMismatch(hello.proto));
    }
    if hello.version.len() > MAX_VERSION_BYTES {
        let detail = format!("hello version exceeds {MAX_VERSION_BYTES} bytes");
        return Err(refuse_bad_frame(stream, detail).await);
    }
    Ok(hello)
}

/// Server half, step two: writes `hello_ack`, then reads the one request
/// frame (at most `request_bytes`) before `deadline` and returns its body,
/// undecoded: what a body that does not parse is answered with (a
/// `bad_request` reply, `error bad_frame`) is the policy's decision.
pub async fn accept_hello<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    ack: HelloAck,
    request_bytes: usize,
    deadline: Instant,
) -> Result<Vec<u8>, HandshakeError> {
    send(stream, &Frame::HelloAck(ack), MAX_FRAME_BYTES).await?;
    match tokio::time::timeout_at(deadline, read_inbound(stream, request_bytes, false)).await {
        Err(_) => Err(refuse_timeout(stream).await),
        Ok(Err(error)) => Err(HandshakeError::Io(error)),
        Ok(Ok(Inbound::Length(detail))) => Err(refuse_bad_frame(stream, detail).await),
        Ok(Ok(Inbound::Body(body))) => Ok(body),
        Ok(Ok(Inbound::LegacyZmtp | Inbound::Reserved(_))) => Err(HandshakeError::BadFrame(
            "unexpected first-byte sniff".to_owned(),
        )),
    }
}

/// Where a listener's connections come from. Production acceptors are the
/// unix and the Windows endpoint; tests script one.
pub trait Accept: Send + 'static {
    /// The byte stream of one connection.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// The next connection and the operating system's view of its peer, or
    /// the error the kernel reported. Must be cancel-safe: the loop drops
    /// this future whenever something else needs its attention.
    fn accept(&mut self) -> impl Future<Output = io::Result<(Self::Stream, PeerIdentity)>> + Send;

    /// One non-blocking write of `frame` to a connection the listener will
    /// not serve, then close. Must not wait on the peer.
    fn reject(stream: Self::Stream, frame: &[u8]) -> impl Future<Output = ()> + Send;

    /// Stop listening and remove what the endpoint published (the socket
    /// file, the control file). Called once, when the loop stops accepting
    /// and before it waits for connection tasks.
    fn close(&mut self);
}

/// What one plane does with its connections.
pub trait Policy<S>: Send + Sync + 'static {
    /// `public` or `admin`: names the plane in log lines and refusals.
    fn plane(&self) -> &'static str;

    /// The numbers this plane's listener enforces.
    fn limits(&self) -> Limits;

    /// Serves one connection to its end. The connection permit is held until
    /// the returned future completes or is aborted by the drain. `stop` is
    /// set when the listener is stopping ([`stopped`]).
    fn serve(
        self: Arc<Self>,
        stream: S,
        peer: PeerIdentity,
        stop: watch::Receiver<bool>,
    ) -> impl Future<Output = ()> + Send;
}

/// Paces an accept loop through errors so it never ends on one.
///
/// A listener that stops accepting takes its whole plane with it while the
/// rest of the daemon keeps running, with nothing in the log. So accept errors
/// are logged and retried: a peer that vanished mid-handshake
/// (`ConnectionAborted`) or a signal (`Interrupted`) at once, anything else —
/// descriptor or memory exhaustion, or an error this code does not know —
/// after a pause that starts at [`Self::FIRST`] and doubles to [`Self::MAX`],
/// so a persistent condition neither spins a core nor floods the log.
#[derive(Debug)]
pub struct AcceptBackoff {
    next: Duration,
}

impl AcceptBackoff {
    /// The first pause after a resource error.
    pub const FIRST: Duration = Duration::from_millis(10);
    /// The longest pause.
    pub const MAX: Duration = Duration::from_secs(1);

    /// A backoff at its first pause.
    #[must_use]
    pub const fn new() -> Self {
        Self { next: Self::FIRST }
    }

    /// An accept succeeded: the next error starts from the first pause.
    pub const fn reset(&mut self) {
        self.next = Self::FIRST;
    }

    /// How long to wait before accepting again after `error`.
    pub fn after(&mut self, error: &io::Error) -> Duration {
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

impl Default for AcceptBackoff {
    fn default() -> Self {
        Self::new()
    }
}

/// The length-prefixed `error connection_capacity_exhausted` frame a listener
/// writes to a connection over its cap.
fn capacity_frame(plane: &str, limits: &Limits) -> Vec<u8> {
    Frame::error(
        cause::CONNECTION_CAPACITY_EXHAUSTED,
        &format!(
            "the {plane} listener is serving its maximum of {} connections",
            limits.max_connections
        ),
        "Retry shortly; if it persists, inspect what holds connections open with pam status.",
    )
    .encode()
    .ok()
    .and_then(|body| prefixed(&body, MAX_FRAME_BYTES).ok())
    .unwrap_or_default()
}

/// A running listener: one accept loop and its connection tasks.
#[derive(Debug)]
pub struct Listener {
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
    permits: Arc<Semaphore>,
}

impl Listener {
    /// Starts the accept loop for `acceptor` under `policy`.
    pub fn spawn<A, P>(acceptor: A, policy: Arc<P>) -> Self
    where
        A: Accept,
        P: Policy<A::Stream>,
    {
        let permits = Arc::new(Semaphore::new(policy.limits().max_connections));
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(accept_loop(
            acceptor,
            policy,
            Arc::clone(&permits),
            receiver,
        ));
        Self {
            stop,
            task: Some(task),
            permits,
        }
    }

    /// Connection permits free right now.
    #[must_use]
    pub fn available_connections(&self) -> usize {
        self.permits.available_permits()
    }

    /// Stops accepting, closes the acceptor, signals the connection tasks,
    /// waits up to the policy's drain for them and aborts the rest.
    pub async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

async fn accept_loop<A, P>(
    mut acceptor: A,
    policy: Arc<P>,
    permits: Arc<Semaphore>,
    mut stop: watch::Receiver<bool>,
) where
    A: Accept,
    P: Policy<A::Stream>,
{
    let limits = policy.limits();
    let plane = policy.plane();
    let busy = capacity_frame(plane, &limits);
    let mut tasks = JoinSet::new();
    let mut backoff = AcceptBackoff::new();
    loop {
        tokio::select! {
            biased;
            // A dropped handle (an error here) is a stop too.
            _ = stop.changed() => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            accepted = acceptor.accept() => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => {
                        backoff.reset();
                        accepted
                    }
                    // An accept error never ends the listener (see
                    // `AcceptBackoff`): log it, pause, accept again.
                    Err(error) => {
                        let pause = backoff.after(&error);
                        tracing::warn!(
                            plane,
                            kind = ?error.kind(),
                            %error,
                            pause_ms = u64::try_from(pause.as_millis()).unwrap_or(u64::MAX),
                            "accept failed; retrying"
                        );
                        if pause.is_zero() {
                            // Retry at once, but never spin without yielding.
                            tokio::task::yield_now().await;
                        } else {
                            tokio::select! {
                                _ = stop.changed() => break,
                                () = tokio::time::sleep(pause) => {}
                            }
                        }
                        continue;
                    }
                };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    // Never left without an answer: a client can tell a full
                    // daemon from a legacy one.
                    A::reject(stream, &busy).await;
                    continue;
                };
                let policy = Arc::clone(&policy);
                let stop = stop.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    policy.serve(stream, peer, stop).await;
                });
            }
        }
    }
    acceptor.close();
    drop(acceptor);
    let _ = tokio::time::timeout(limits.drain, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

/// Why a dial primitive failed.
#[derive(Debug, Error)]
pub enum DialError {
    /// The connection failed, ended early, or a frame was outside its limit.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The peer answered with a ZMTP greeting: a pre-migration daemon is
    /// listening. Nothing was spoken back.
    #[error("the peer greeted in ZMTP: a pre-migration pam daemon is listening")]
    LegacyDaemon,
    /// The daemon answered with an `error` frame and closed.
    #[error("{}: {}", .0.cause, .0.detail)]
    Refused(ErrorFrame),
    /// The daemon sent something this protocol does not allow here.
    #[error("protocol violation: {0}")]
    Protocol(String),
}

/// The hello this build's client sends.
#[must_use]
pub fn client_hello(via: Via) -> Hello {
    Hello {
        proto: WIRE_PROTOCOL,
        version: crate::daemon::DAEMON_VERSION.to_owned(),
        via,
    }
}

/// A `request` frame over a borrowed envelope, so dialling does not clone
/// up to 1 MiB of arguments to encode them.
#[derive(serde::Serialize)]
struct RequestRef<'a> {
    t: &'static str,
    envelope: &'a Envelope,
}

/// A `follow` frame over a borrowed envelope.
#[derive(serde::Serialize)]
struct FollowRef<'a> {
    t: &'static str,
    envelope: &'a Envelope,
    after_seq: u64,
    epoch: Option<&'a str>,
}

async fn open_encoded<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    hello: &Hello,
    request: &[u8],
) -> Result<HelloAck, DialError> {
    let mut bytes = prefixed(
        &Frame::Hello(hello.clone()).encode().map_err(invalid)?,
        MAX_HELLO_BYTES,
    )?;
    bytes.extend_from_slice(&prefixed(request, MAX_FRAME_BYTES)?);
    // Hello and request go out back to back. A daemon that refuses the hello
    // may close before reading the request, so a failed write still reads:
    // the refusal is what the caller needs to see.
    let written = async {
        stream.write_all(&bytes).await?;
        stream.flush().await
    }
    .await;
    let first = match (read_first_frame(stream, MAX_HELLO_BYTES).await, written) {
        (Ok(first), _) => first,
        (Err(_), Err(error)) | (Err(error), Ok(())) => return Err(DialError::Io(error)),
    };
    let body = match first {
        First::Frame(body) => body,
        First::LegacyZmtp => return Err(DialError::LegacyDaemon),
        First::Reserved(byte) => {
            return Err(DialError::Protocol(format!(
                "the peer answered in text (first byte {byte:#04x})"
            )));
        }
    };
    match Frame::decode(&body) {
        Ok(Frame::HelloAck(ack)) if ack.proto == WIRE_PROTOCOL => Ok(ack),
        Ok(Frame::HelloAck(ack)) => Err(DialError::Protocol(format!(
            "the daemon acknowledged wire protocol {}, not {WIRE_PROTOCOL}",
            ack.proto
        ))),
        Ok(Frame::Error(error)) => Err(DialError::Refused(error)),
        Ok(other) => Err(DialError::Protocol(format!(
            "expected hello_ack, got {}",
            other.type_name()
        ))),
        Err(error) => Err(DialError::Protocol(error.to_string())),
    }
}

/// Client half: writes `hello` and `request` back to back on a connected
/// stream and reads the daemon's answer to the hello.
///
/// # Errors
///
/// [`DialError::LegacyDaemon`] when the peer greets in ZMTP,
/// [`DialError::Refused`] when the daemon refuses the hello.
pub async fn open<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    hello: &Hello,
    request: &Frame,
) -> Result<HelloAck, DialError> {
    open_encoded(stream, hello, &request.encode().map_err(invalid)?).await
}

/// Reads the next daemon frame of at most `maximum` bytes. An `error` frame
/// is [`DialError::Refused`]; a frame whose type this build does not know is
/// skipped, as a newer daemon may add one.
pub async fn read_daemon_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    maximum: usize,
) -> Result<Frame, DialError> {
    loop {
        let body = read_frame(stream, maximum).await?;
        match Frame::decode(&body) {
            Ok(Frame::Error(error)) => return Err(DialError::Refused(error)),
            Ok(frame) => return Ok(frame),
            Err(FrameError::UnknownType(_)) => {}
            Err(error) => return Err(DialError::Protocol(error.to_string())),
        }
    }
}

/// One unary call on a connected stream: hello, `request`, and the `reply`
/// of at most `reply_bytes`. The response is not matched against the
/// envelope's id: a refusal raised before the envelope parsed names
/// `unknown`.
pub async fn call<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    hello: &Hello,
    envelope: &Envelope,
    reply_bytes: usize,
) -> Result<(HelloAck, Response), DialError> {
    let request = serde_json::to_vec(&RequestRef {
        t: "request",
        envelope,
    })
    .map_err(invalid)?;
    let ack = open_encoded(stream, hello, &request).await?;
    match read_daemon_frame(stream, reply_bytes).await? {
        Frame::Reply { response } => Ok((ack, response)),
        other => Err(DialError::Protocol(format!(
            "expected reply, got {}",
            other.type_name()
        ))),
    }
}

/// Starts one follow on a connected stream: hello and `follow` with the
/// resume position (`0` and `None` for a fresh follow). The caller then reads
/// `following`, `event`* and `end` with [`read_daemon_frame`] and sends
/// nothing more.
pub async fn follow<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    hello: &Hello,
    envelope: &Envelope,
    after_seq: u64,
    epoch: Option<&str>,
) -> Result<HelloAck, DialError> {
    let request = serde_json::to_vec(&FollowRef {
        t: "follow",
        envelope,
        after_seq,
        epoch,
    })
    .map_err(invalid)?;
    open_encoded(stream, hello, &request).await
}

/// The stream type of the platform's public endpoint.
#[cfg(unix)]
pub type PublicStream = tokio::net::UnixStream;

/// The stream type of the platform's public endpoint.
#[cfg(windows)]
pub type PublicStream = tokio::net::TcpStream;

/// Connects the daemon's framed public endpoint: the stream socket at
/// [`crate::runtime_dir::RuntimeDir::public_socket`] on unix.
#[cfg(unix)]
pub async fn connect_public(dirs: &crate::runtime_dir::RuntimeDir) -> io::Result<PublicStream> {
    crate::framed_unix::connect(dirs.public_socket()).await
}

/// Connects the daemon's framed public endpoint: loopback TCP behind the
/// owner nonce in [`crate::runtime_dir::RuntimeDir::public_control`] on
/// Windows. The server's proof is verified before the nonce is sent.
#[cfg(windows)]
pub async fn connect_public(dirs: &crate::runtime_dir::RuntimeDir) -> io::Result<PublicStream> {
    crate::framed_windows::connect(dirs.public_control(), crate::framed_windows::PUBLIC_LABEL).await
}
