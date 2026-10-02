//! The framed transport over in-memory streams and a scripted acceptor, so
//! every test runs on every platform and timing runs on the paused clock.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use pam_proto::wire::{
    End, Following, Frame, Hello, HelloAck, MAX_ADMIN_REPLY_BYTES, MAX_FRAME_BYTES,
    MAX_HELLO_BYTES, Via, WIRE_PROTOCOL, cause,
};
use pam_proto::{Caller, Envelope, Event, Outcome, PROTOCOL_VERSION, Response};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::{Semaphore, mpsc, watch};

use crate::framed::{
    Accept, AcceptBackoff, DialError, First, FirstByte, FrameReader, HANDSHAKE_TIMEOUT,
    HandshakeError, Limits, Listener, Policy, accept_hello, call, client_hello, discard_frame,
    follow, handshake_deadline, open, open_encoded, read_daemon_frame, read_first_frame,
    read_frame, read_hello, read_hello_within, refuse, send, sniff, stopped, version_rule,
    write_frame, write_once,
};
use crate::image::{BootImage, FileFacts, ImageProbe, ImageWatch};
use crate::ingress::PeerIdentity;
use crate::lifecycle::LifecyclePhase;

pub(crate) const PATIENCE: Duration = Duration::from_secs(60);

/// The 64-byte greeting both ZMTP peers send before reading.
fn zmtp_greeting() -> Vec<u8> {
    let mut greeting = vec![0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0x7F, 3, 0];
    greeting.extend_from_slice(b"NULL");
    greeting.resize(64, 0);
    greeting
}

pub(crate) fn envelope(id: &str) -> Envelope {
    Envelope {
        v: PROTOCOL_VERSION,
        id: id.to_owned(),
        capability: "echo".to_owned(),
        client_version: env!("CARGO_PKG_VERSION").to_owned(),
        caller: Caller {
            agent: "test".to_owned(),
            repo: "/repo".to_owned(),
            pid: std::process::id(),
        },
        args: serde_json::json!({ "text": "hi" }),
        idempotency_key: None,
        deadline_ms: 5_000,
        wait: true,
    }
}

pub(crate) fn result(id: &str) -> Response {
    Response::Result {
        id: id.to_owned(),
        outcome: Outcome::Solved,
        body: serde_json::json!({ "echo": "hi" }),
        evidence: Vec::new(),
    }
}

pub(crate) fn ack() -> HelloAck {
    HelloAck {
        proto: WIRE_PROTOCOL,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        epoch: "01JB2M5T8Q0V7K3W9X4Y6Z1ABC".to_owned(),
    }
}

/// The frame as it travels: length prefix and body.
async fn wire_bytes(frame: &Frame) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &frame.encode().unwrap(), MAX_ADMIN_REPLY_BYTES)
        .await
        .unwrap();
    bytes
}

pub(crate) async fn error_cause<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let body = read_frame(stream, MAX_FRAME_BYTES).await.unwrap();
    match Frame::decode(&body).unwrap() {
        Frame::Error(error) => {
            assert!(!error.detail.is_empty() && !error.recovery.is_empty());
            error.cause
        }
        other => panic!("expected an error frame, got {other:?}"),
    }
}

/// The paused clock rounds each timer up to its millisecond tick, so elapsed
/// virtual time is compared with a little slack, never for equality.
fn assert_elapsed(started: tokio::time::Instant, expected: Duration) {
    let elapsed = started.elapsed();
    assert!(
        elapsed >= expected && elapsed < expected + Duration::from_millis(8),
        "expected about {expected:?}, measured {elapsed:?}"
    );
}

/// Polls `condition` on the (possibly paused) clock until it holds.
pub(crate) async fn eventually(condition: impl Fn() -> bool) {
    tokio::time::timeout(PATIENCE, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("condition holds in time");
}

/// Yields the four header bytes, then would block forever on the body and
/// counts every attempt to read it.
struct HeaderOnly {
    header: [u8; 4],
    given: usize,
    body_polls: Arc<AtomicUsize>,
}

impl AsyncRead for HeaderOnly {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.given < 4 {
            let count = (4 - self.given).min(buffer.remaining());
            buffer.put_slice(&self.header[self.given..self.given + count]);
            self.given += count;
            return Poll::Ready(Ok(()));
        }
        self.body_polls.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
}

#[tokio::test(start_paused = true)]
async fn a_bad_length_is_refused_from_the_header_alone() {
    let maximum = 1024;
    for announced in [0u32, 1025, 16 * 1024 * 1024, u32::MAX] {
        let body_polls = Arc::new(AtomicUsize::new(0));
        let mut reader = HeaderOnly {
            header: announced.to_be_bytes(),
            given: 0,
            body_polls: Arc::clone(&body_polls),
        };
        // The reader would block on the body: an answer at all proves the
        // length was judged first, and the counter proves nothing was read.
        let error = tokio::time::timeout(Duration::from_secs(1), read_frame(&mut reader, maximum))
            .await
            .expect("refused without waiting for a body")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{announced}");
        assert!(error.to_string().contains("1..=1024"), "{error}");
        assert_eq!(body_polls.load(Ordering::SeqCst), 0, "{announced}");
    }
    // The same reader does see a body read for a length inside the limit.
    let body_polls = Arc::new(AtomicUsize::new(0));
    let mut reader = HeaderOnly {
        header: 1024u32.to_be_bytes(),
        given: 0,
        body_polls: Arc::clone(&body_polls),
    };
    assert!(
        tokio::time::timeout(Duration::from_secs(1), read_frame(&mut reader, maximum))
            .await
            .is_err()
    );
    assert!(body_polls.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn a_frame_is_a_big_endian_length_and_its_body() {
    let (mut near, mut far) = tokio::io::duplex(1024);
    write_frame(&mut near, b"{\"t\":\"x\"}", 1024)
        .await
        .unwrap();
    let mut raw = [0u8; 13];
    far.read_exact(&mut raw).await.unwrap();
    assert_eq!(&raw[..4], &[0, 0, 0, 9]);
    assert_eq!(&raw[4..], b"{\"t\":\"x\"}");

    write_frame(&mut near, b"exactly-16-bytes", 16)
        .await
        .unwrap();
    assert_eq!(read_frame(&mut far, 16).await.unwrap(), b"exactly-16-bytes");

    // An empty or over-limit body is refused before anything is written.
    for body in [&b""[..], &b"seventeen bytes.."[..]] {
        let error = write_frame(&mut near, body, 16).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
    let over = send(&mut near, &Frame::error("c", "d", "r"), 8)
        .await
        .unwrap_err();
    assert_eq!(over.kind(), io::ErrorKind::InvalidData);
    drop(near);
    let mut rest = Vec::new();
    far.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty(), "nothing was written for a refused frame");
}

#[test]
fn the_first_byte_tells_this_protocol_from_zmtp_and_text() {
    assert_eq!(sniff(0x00), FirstByte::Frame);
    assert_eq!(sniff(0xFF), FirstByte::LegacyZmtp);
    for byte in *b"GPaz" {
        assert_eq!(sniff(byte), FirstByte::Ascii);
    }
    for byte in [0x01, 0x7F, b'{', b'1', b' ', 0xFE] {
        assert_eq!(sniff(byte), FirstByte::Other);
    }
    // Every limit a first frame can have keeps the first byte 0x00.
    for limit in [MAX_HELLO_BYTES, MAX_FRAME_BYTES] {
        let header = u32::try_from(limit).unwrap().to_be_bytes();
        assert_eq!(sniff(header[0]), FirstByte::Frame);
    }
    assert_eq!(sniff(zmtp_greeting()[0]), FirstByte::LegacyZmtp);
}

#[tokio::test]
async fn the_first_frame_is_sniffed_before_its_length_is_trusted() {
    // A ZMTP greeting: recognised from four bytes, the rest left unread.
    let (mut near, mut far) = tokio::io::duplex(1024);
    near.write_all(&zmtp_greeting()).await.unwrap();
    drop(near);
    assert_eq!(
        read_first_frame(&mut far, MAX_HELLO_BYTES).await.unwrap(),
        First::LegacyZmtp
    );
    let mut unread = Vec::new();
    far.read_to_end(&mut unread).await.unwrap();
    assert_eq!(unread.len(), 60);

    // Text: reserved, not parsed as a length.
    let (mut near, mut far) = tokio::io::duplex(1024);
    near.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    assert_eq!(
        read_first_frame(&mut far, MAX_HELLO_BYTES).await.unwrap(),
        First::Reserved(b'G')
    );

    // This protocol.
    let (mut near, mut far) = tokio::io::duplex(1024);
    let hello = Frame::Hello(client_hello(Via::Direct));
    near.write_all(&wire_bytes(&hello).await).await.unwrap();
    let First::Frame(body) = read_first_frame(&mut far, MAX_HELLO_BYTES).await.unwrap() else {
        panic!("expected a frame");
    };
    assert_eq!(Frame::decode(&body).unwrap(), hello);

    // A first byte that is neither: an over-limit length, refused unread.
    let (mut near, mut far) = tokio::io::duplex(1024);
    near.write_all(&[0x01, 0, 0, 0]).await.unwrap();
    let error = read_first_frame(&mut far, MAX_HELLO_BYTES)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn a_hello_and_its_request_are_served_and_answered() {
    let (mut client, mut server) = tokio::io::duplex(64 * 1024);
    let serving = tokio::spawn(async move {
        let deadline = handshake_deadline(&Limits::PUBLIC);
        let hello = read_hello(&mut server, deadline).await.unwrap();
        let body = accept_hello(&mut server, ack(), MAX_FRAME_BYTES, deadline)
            .await
            .unwrap();
        let Frame::Request { envelope } = Frame::decode(&body).unwrap() else {
            panic!("expected a request");
        };
        let reply = Frame::Reply {
            response: result(&envelope.id),
        };
        send(&mut server, &reply, MAX_FRAME_BYTES).await.unwrap();
        (hello, envelope)
    });
    let request = envelope("req_call");
    let (got, response) = call(
        &mut client,
        &client_hello(Via::Relay),
        &request,
        MAX_FRAME_BYTES,
    )
    .await
    .unwrap();
    assert_eq!(got, ack());
    assert_eq!(response, result("req_call"));
    let (hello, received) = serving.await.unwrap();
    assert_eq!(
        hello,
        Hello {
            proto: WIRE_PROTOCOL,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            via: Via::Relay,
        }
    );
    assert_eq!(received, request);
}

#[tokio::test(start_paused = true)]
async fn a_silent_peer_is_told_and_dropped_at_the_handshake_timeout() {
    // Nothing at all: the hello never comes.
    let (mut client, mut server) = tokio::io::duplex(64 * 1024);
    let started = tokio::time::Instant::now();
    let outcome = read_hello(&mut server, handshake_deadline(&Limits::PUBLIC)).await;
    assert!(
        matches!(outcome, Err(HandshakeError::Timeout)),
        "{outcome:?}"
    );
    assert_elapsed(started, HANDSHAKE_TIMEOUT);
    assert_eq!(error_cause(&mut client).await, cause::HANDSHAKE_TIMEOUT);

    // A hello and then nothing: the request frame shares the same deadline.
    let (mut client, mut server) = tokio::io::duplex(64 * 1024);
    let hello = Frame::Hello(client_hello(Via::Direct));
    client.write_all(&wire_bytes(&hello).await).await.unwrap();
    let started = tokio::time::Instant::now();
    let deadline = handshake_deadline(&Limits::PUBLIC);
    read_hello(&mut server, deadline).await.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let outcome = accept_hello(&mut server, ack(), MAX_FRAME_BYTES, deadline).await;
    assert!(
        matches!(outcome, Err(HandshakeError::Timeout)),
        "{outcome:?}"
    );
    assert_elapsed(started, HANDSHAKE_TIMEOUT);
    let acked = read_frame(&mut client, MAX_FRAME_BYTES).await.unwrap();
    assert!(matches!(Frame::decode(&acked).unwrap(), Frame::HelloAck(_)));
    assert_eq!(error_cause(&mut client).await, cause::HANDSHAKE_TIMEOUT);
}

/// Feeds `first` to the server half of the handshake and returns its verdict
/// plus everything the peer was sent.
async fn hello_verdict(first: Vec<u8>) -> (Result<Hello, HandshakeError>, Vec<u8>) {
    let (mut client, mut server) = tokio::io::duplex(64 * 1024);
    client.write_all(&first).await.unwrap();
    // End of file after these bytes: a short read is an error, not a wait.
    client.shutdown().await.unwrap();
    let verdict = read_hello(&mut server, handshake_deadline(&Limits::PUBLIC)).await;
    drop(server);
    let mut sent = Vec::new();
    client.read_to_end(&mut sent).await.unwrap();
    (verdict, sent)
}

fn sent_cause(sent: &[u8]) -> String {
    match Frame::decode(&sent[4..]).unwrap() {
        Frame::Error(error) => error.cause,
        other => panic!("expected an error frame, got {other:?}"),
    }
}

#[tokio::test]
async fn a_first_frame_that_is_not_this_protocols_hello_is_named_and_answered_where_possible() {
    // A pre-migration client: nothing is spoken back.
    let (verdict, sent) = hello_verdict(zmtp_greeting()).await;
    assert!(
        matches!(verdict, Err(HandshakeError::LegacyZmtp)),
        "{verdict:?}"
    );
    assert!(sent.is_empty());

    let (verdict, sent) = hello_verdict(b"GET / HTTP/1.1\r\n".to_vec()).await;
    assert!(
        matches!(verdict, Err(HandshakeError::Reserved(b'G'))),
        "{verdict:?}"
    );
    assert!(sent.is_empty());

    // A bare envelope (no "t"): handed back for the policy to answer.
    let bare = serde_json::to_vec(&envelope("req_old")).unwrap();
    let mut framed = Vec::new();
    write_frame(&mut framed, &bare, MAX_HELLO_BYTES)
        .await
        .unwrap();
    let (verdict, sent) = hello_verdict(framed).await;
    assert!(
        matches!(&verdict, Err(HandshakeError::Untyped(body)) if *body == bare),
        "{verdict:?}"
    );
    assert!(sent.is_empty());

    // Everything else is `bad_frame`, said on the wire.
    let mut not_json = Vec::new();
    write_frame(&mut not_json, b"not json", MAX_HELLO_BYTES)
        .await
        .unwrap();
    let unknown = b"\x00\x00\x00\x0f{\"t\":\"hellooo\"}".to_vec();
    let out_of_order = wire_bytes(&Frame::Events).await;
    let oversized = u32::try_from(MAX_HELLO_BYTES + 1)
        .unwrap()
        .to_be_bytes()
        .to_vec();
    let long_version = wire_bytes(&Frame::Hello(Hello {
        proto: WIRE_PROTOCOL,
        version: "9".repeat(65),
        via: Via::Direct,
    }))
    .await;
    for first in [not_json, unknown, out_of_order, oversized, long_version] {
        let (verdict, sent) = hello_verdict(first).await;
        assert!(
            matches!(verdict, Err(HandshakeError::BadFrame(_))),
            "{verdict:?}"
        );
        assert_eq!(sent_cause(&sent), cause::BAD_FRAME);
    }

    // A protocol number this daemon does not speak.
    let future = wire_bytes(&Frame::Hello(Hello {
        proto: 3,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        via: Via::Direct,
    }))
    .await;
    let (verdict, sent) = hello_verdict(future).await;
    assert!(
        matches!(verdict, Err(HandshakeError::ProtocolMismatch(3))),
        "{verdict:?}"
    );
    assert_eq!(sent_cause(&sent), cause::PROTOCOL_MISMATCH);

    // A peer that hangs up before a whole header.
    let (verdict, sent) = hello_verdict(vec![0, 0]).await;
    assert!(matches!(verdict, Err(HandshakeError::Io(_))), "{verdict:?}");
    assert!(sent.is_empty());
}

#[tokio::test]
async fn an_over_limit_request_frame_is_refused_unread() {
    let (mut client, mut server) = tokio::io::duplex(64 * 1024);
    let hello = Frame::Hello(client_hello(Via::Direct));
    client.write_all(&wire_bytes(&hello).await).await.unwrap();
    client
        .write_all(&u32::try_from(MAX_FRAME_BYTES + 1).unwrap().to_be_bytes())
        .await
        .unwrap();
    let deadline = handshake_deadline(&Limits::PUBLIC);
    read_hello(&mut server, deadline).await.unwrap();
    let outcome = accept_hello(&mut server, ack(), MAX_FRAME_BYTES, deadline).await;
    assert!(
        matches!(outcome, Err(HandshakeError::BadFrame(_))),
        "{outcome:?}"
    );
    read_frame(&mut client, MAX_FRAME_BYTES).await.unwrap();
    assert_eq!(error_cause(&mut client).await, cause::BAD_FRAME);
}

#[tokio::test]
async fn dialling_names_a_legacy_daemon_a_refusal_and_a_protocol_violation() {
    // An old daemon greets in ZMTP as soon as a client connects.
    let (mut client, mut server) = tokio::io::duplex(64 * 1024);
    server.write_all(&zmtp_greeting()).await.unwrap();
    let outcome = call(
        &mut client,
        &client_hello(Via::Direct),
        &envelope("req_1"),
        MAX_FRAME_BYTES,
    )
    .await;
    assert!(
        matches!(outcome, Err(DialError::LegacyDaemon)),
        "{outcome:?}"
    );

    // A refused hello: the error frame, even though the daemon closed
    // without reading the request frame.
    let (mut client, mut server) = tokio::io::duplex(64 * 1024);
    refuse(
        &mut server,
        cause::CLIENT_VERSION_MISMATCH,
        "daemon is 0.5.0",
        "Use the matching pam.",
    )
    .await;
    drop(server);
    let outcome = call(
        &mut client,
        &client_hello(Via::Direct),
        &envelope("req_1"),
        MAX_FRAME_BYTES,
    )
    .await;
    assert!(
        matches!(&outcome, Err(DialError::Refused(error)) if error.cause == cause::CLIENT_VERSION_MISMATCH),
        "{outcome:?}"
    );
    assert_eq!(
        outcome.unwrap_err().to_string(),
        "client_version_mismatch: daemon is 0.5.0"
    );

    // A daemon that acknowledges another protocol, or answers out of order.
    let (mut client, mut server) = tokio::io::duplex(64 * 1024);
    let wrong = Frame::HelloAck(HelloAck { proto: 3, ..ack() });
    send(&mut server, &wrong, MAX_FRAME_BYTES).await.unwrap();
    let request = Frame::Request {
        envelope: envelope("req_1"),
    };
    let outcome = open(&mut client, &client_hello(Via::Direct), &request).await;
    assert!(
        matches!(outcome, Err(DialError::Protocol(_))),
        "{outcome:?}"
    );

    let (mut client, mut server) = tokio::io::duplex(64 * 1024);
    send(&mut server, &Frame::HelloAck(ack()), MAX_FRAME_BYTES)
        .await
        .unwrap();
    send(
        &mut server,
        &Frame::follow_event(1, Event::Started),
        MAX_FRAME_BYTES,
    )
    .await
    .unwrap();
    let outcome = call(
        &mut client,
        &client_hello(Via::Direct),
        &envelope("req_1"),
        MAX_FRAME_BYTES,
    )
    .await;
    assert!(
        matches!(outcome, Err(DialError::Protocol(_))),
        "{outcome:?}"
    );

    // A daemon that is simply gone.
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    drop(server);
    let outcome = call(
        &mut client,
        &client_hello(Via::Direct),
        &envelope("req_1"),
        MAX_FRAME_BYTES,
    )
    .await;
    assert!(matches!(outcome, Err(DialError::Io(_))), "{outcome:?}");
}

#[tokio::test]
async fn a_follow_carries_its_resume_position_and_skips_frames_it_does_not_know() {
    let (mut client, mut server) = tokio::io::duplex(64 * 1024);
    let serving = tokio::spawn(async move {
        let deadline = handshake_deadline(&Limits::PUBLIC);
        read_hello(&mut server, deadline).await.unwrap();
        let body = accept_hello(&mut server, ack(), MAX_FRAME_BYTES, deadline)
            .await
            .unwrap();
        let following = Frame::Following(Following {
            ticket: "req_ticket".to_owned(),
            epoch: ack().epoch,
            state: "running".to_owned(),
            seq: 3,
        });
        send(&mut server, &following, MAX_FRAME_BYTES)
            .await
            .unwrap();
        send(
            &mut server,
            &Frame::follow_event(4, Event::Started),
            MAX_FRAME_BYTES,
        )
        .await
        .unwrap();
        // A frame type from a newer daemon.
        write_frame(&mut server, br#"{"t":"heartbeat","at":1}"#, MAX_FRAME_BYTES)
            .await
            .unwrap();
        let end = Frame::End(End {
            seq: Some(5),
            event: Some(Event::Done),
            response: result("req_follow"),
        });
        send(&mut server, &end, MAX_FRAME_BYTES).await.unwrap();
        Frame::decode(&body).unwrap()
    });
    let query = envelope("req_follow");
    let acked = follow(
        &mut client,
        &client_hello(Via::Direct),
        &query,
        3,
        Some("01OLDEPOCH"),
    )
    .await
    .unwrap();
    assert_eq!(acked, ack());
    let mut seen = Vec::new();
    loop {
        let frame = read_daemon_frame(&mut client, MAX_FRAME_BYTES)
            .await
            .unwrap();
        let last = matches!(frame, Frame::End(_));
        seen.push(frame.type_name());
        if last {
            break;
        }
    }
    assert_eq!(seen, ["following", "event", "end"]);
    let Frame::Follow(sent) = serving.await.unwrap() else {
        panic!("expected a follow frame");
    };
    assert_eq!(
        (sent.envelope, sent.after_seq, sent.epoch.as_deref()),
        (query, 3, Some("01OLDEPOCH"))
    );

    // A stream cut by an error frame is a refusal, not a protocol error.
    let (mut client, mut server) = tokio::io::duplex(64 * 1024);
    refuse(
        &mut server,
        cause::DAEMON_SHUTTING_DOWN,
        "draining",
        "Reconnect.",
    )
    .await;
    let outcome = read_daemon_frame(&mut client, MAX_FRAME_BYTES).await;
    assert!(
        matches!(&outcome, Err(DialError::Refused(error)) if error.cause == cause::DAEMON_SHUTTING_DOWN),
        "{outcome:?}"
    );
}

/// A source of in-memory connections and scripted accept errors. Every
/// connection is reported with the peer its dialer names.
pub(crate) struct Scripted {
    script: mpsc::UnboundedReceiver<io::Result<(DuplexStream, PeerIdentity)>>,
    closed: Arc<AtomicBool>,
}

impl Accept for Scripted {
    type Stream = DuplexStream;

    async fn accept(&mut self) -> io::Result<(DuplexStream, PeerIdentity)> {
        match self.script.recv().await {
            Some(next) => next,
            None => std::future::pending().await,
        }
    }

    async fn reject(mut stream: DuplexStream, frame: &[u8]) {
        assert!(write_once(&mut stream, frame).await);
    }

    fn close(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

/// The far end of a [`Scripted`] acceptor.
pub(crate) struct Dialer {
    script: mpsc::UnboundedSender<io::Result<(DuplexStream, PeerIdentity)>>,
    closed: Arc<AtomicBool>,
}

impl Dialer {
    pub(crate) fn connect(&self) -> DuplexStream {
        self.connect_as(PeerIdentity::OwnerNonce)
    }

    /// A connection the acceptor reports as coming from `peer`.
    pub(crate) fn connect_as(&self, peer: PeerIdentity) -> DuplexStream {
        let (client, server) = tokio::io::duplex(64 * 1024);
        self.script.send(Ok((server, peer))).unwrap();
        client
    }

    pub(crate) fn fail(&self, error: io::Error) {
        self.script.send(Err(error)).unwrap();
    }

    /// Whether the listener closed the acceptor.
    pub(crate) fn closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

pub(crate) fn scripted() -> (Scripted, Dialer) {
    let (tx, rx) = mpsc::unbounded_channel();
    let closed = Arc::new(AtomicBool::new(false));
    (
        Scripted {
            script: rx,
            closed: Arc::clone(&closed),
        },
        Dialer { script: tx, closed },
    )
}

/// Serves the handshake and answers a `request` with a result for its id.
pub(crate) struct Answering {
    limits: Limits,
    pub(crate) peers: std::sync::Mutex<Vec<PeerIdentity>>,
}

impl Answering {
    pub(crate) fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            peers: std::sync::Mutex::new(Vec::new()),
        })
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> Policy<S> for Answering {
    fn plane(&self) -> &'static str {
        "test"
    }

    fn limits(&self) -> Limits {
        self.limits
    }

    async fn serve(
        self: Arc<Self>,
        mut stream: S,
        peer: PeerIdentity,
        _stop: watch::Receiver<bool>,
    ) {
        self.peers.lock().unwrap().push(peer);
        let deadline = handshake_deadline(&self.limits);
        let Ok(_hello) = read_hello(&mut stream, deadline).await else {
            return;
        };
        let Ok(body) = accept_hello(&mut stream, ack(), self.limits.request_bytes, deadline).await
        else {
            return;
        };
        let Ok(Frame::Request { envelope }) = Frame::decode(&body) else {
            return;
        };
        let reply = Frame::Reply {
            response: result(&envelope.id),
        };
        let _ = send(&mut stream, &reply, self.limits.reply_bytes).await;
    }
}

async fn ask(dialer: &Dialer, id: &str) -> Response {
    let mut client = dialer.connect();
    let (_, response) = tokio::time::timeout(
        PATIENCE,
        call(
            &mut client,
            &client_hello(Via::Direct),
            &envelope(id),
            MAX_FRAME_BYTES,
        ),
    )
    .await
    .expect("answered in time")
    .expect("served");
    response
}

/// EMFILE on unix; an uncategorised error everywhere.
pub(crate) fn too_many_open_files() -> io::Error {
    io::Error::from_raw_os_error(24)
}

async fn the_loop_survives_resource_errors_under(limits: Limits) {
    let (acceptor, dialer) = scripted();
    let listener = Listener::spawn(acceptor, Answering::new(limits));

    // Descriptor exhaustion three times, then a connection: the loop is
    // still running, it paused 10 + 20 + 40 ms, and the connection is served.
    let started = tokio::time::Instant::now();
    for _ in 0..3 {
        dialer.fail(too_many_open_files());
    }
    assert_eq!(
        ask(&dialer, "req_after_emfile").await,
        result("req_after_emfile")
    );
    assert_elapsed(started, Duration::from_millis(70));

    // A success resets the pause; memory exhaustion and an error this code
    // has never heard of are paced the same way.
    let started = tokio::time::Instant::now();
    dialer.fail(io::Error::from(io::ErrorKind::OutOfMemory));
    dialer.fail(io::Error::other("something new"));
    assert_eq!(ask(&dialer, "req_again").await, result("req_again"));
    assert_elapsed(started, Duration::from_millis(30));

    // A peer that vanished mid-handshake or a signal: retried at once.
    let started = tokio::time::Instant::now();
    dialer.fail(io::Error::from(io::ErrorKind::ConnectionAborted));
    dialer.fail(io::Error::from(io::ErrorKind::Interrupted));
    assert_eq!(ask(&dialer, "req_at_once").await, result("req_at_once"));
    assert!(
        started.elapsed() < AcceptBackoff::FIRST,
        "{:?}",
        started.elapsed()
    );

    assert_eq!(listener.available_connections(), limits.max_connections);
    listener.shutdown().await;
    assert!(dialer.closed.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn the_accept_loop_survives_emfile_under_both_policies() {
    tokio::time::timeout(PATIENCE, async {
        the_loop_survives_resource_errors_under(Limits::PUBLIC).await;
        the_loop_survives_resource_errors_under(Limits::ADMIN).await;
    })
    .await
    .expect("test within deadline");
}

#[test]
fn accept_backoff_retries_gone_peers_at_once_and_paces_everything_else() {
    let mut backoff = AcceptBackoff::new();
    assert_eq!(
        backoff.after(&io::Error::from(io::ErrorKind::ConnectionAborted)),
        Duration::ZERO
    );
    assert_eq!(
        backoff.after(&io::Error::from(io::ErrorKind::Interrupted)),
        Duration::ZERO
    );
    let mut pauses = Vec::new();
    for _ in 0..10 {
        pauses.push(backoff.after(&too_many_open_files()));
    }
    assert_eq!(pauses[0], AcceptBackoff::FIRST);
    assert_eq!(pauses[1], AcceptBackoff::FIRST * 2);
    assert_eq!(pauses[2], AcceptBackoff::FIRST * 4);
    assert!(pauses.windows(2).all(|pair| pair[0] <= pair[1]));
    assert_eq!(*pauses.last().unwrap(), AcceptBackoff::MAX);
    backoff.reset();
    assert_eq!(backoff.after(&too_many_open_files()), AcceptBackoff::FIRST);
}

/// Counts drops: proof that a connection task's state was released.
struct Released(Arc<AtomicUsize>);

impl Drop for Released {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// Holds each connection the way its first byte asks.
pub(crate) struct Holding {
    limits: Limits,
    pub(crate) started: AtomicUsize,
    pub(crate) released: Arc<AtomicUsize>,
    /// One permit lets one `h` connection return.
    pub(crate) gate: Semaphore,
}

impl Holding {
    pub(crate) fn new(max_connections: usize) -> Arc<Self> {
        Arc::new(Self {
            limits: Limits {
                max_connections,
                ..Limits::PUBLIC
            },
            started: AtomicUsize::new(0),
            released: Arc::new(AtomicUsize::new(0)),
            gate: Semaphore::new(0),
        })
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> Policy<S> for Holding {
    fn plane(&self) -> &'static str {
        "test"
    }

    fn limits(&self) -> Limits {
        self.limits
    }

    async fn serve(
        self: Arc<Self>,
        mut stream: S,
        _peer: PeerIdentity,
        mut stop: watch::Receiver<bool>,
    ) {
        let _released = Released(Arc::clone(&self.released));
        let mode = stream.read_u8().await.unwrap_or(b'h');
        self.started.fetch_add(1, Ordering::SeqCst);
        match mode {
            // Hold until the test opens the gate, then return normally.
            b'h' => self.gate.acquire().await.unwrap().forget(),
            b'p' => panic!("a connection handler panicked (expected by the test)"),
            // Finish one second after the listener says stop.
            b's' => {
                stopped(&mut stop).await;
                tokio::time::sleep(Duration::from_secs(1)).await;
                let _ = stream.write_all(b"bye").await;
            }
            // Never finish: only the drain's abort ends this one.
            _ => std::future::pending::<()>().await,
        }
    }
}

async fn hold(dialer: &Dialer, mode: u8) -> DuplexStream {
    let mut client = dialer.connect();
    client.write_u8(mode).await.unwrap();
    client
}

#[tokio::test(start_paused = true)]
async fn a_connection_over_the_cap_is_told_and_every_exit_returns_its_permit() {
    tokio::time::timeout(PATIENCE, async {
        let (acceptor, dialer) = scripted();
        let policy = Holding::new(2);
        let listener = Listener::spawn(acceptor, Arc::clone(&policy));
        assert_eq!(listener.available_connections(), 2);

        let _first = hold(&dialer, b'h').await;
        let _second = hold(&dialer, b'h').await;
        eventually(|| policy.started.load(Ordering::SeqCst) == 2).await;
        assert_eq!(listener.available_connections(), 0);

        // Over the cap: never left without an answer, and never served.
        let mut refused = dialer.connect();
        assert_eq!(
            error_cause(&mut refused).await,
            cause::CONNECTION_CAPACITY_EXHAUSTED
        );
        let mut rest = Vec::new();
        refused.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty(), "closed after the one frame");
        assert_eq!(policy.started.load(Ordering::SeqCst), 2);

        // A handler that returns frees its permit.
        policy.gate.add_permits(1);
        eventually(|| listener.available_connections() == 1).await;
        // So does one that panics.
        let _panicking = hold(&dialer, b'p').await;
        eventually(|| policy.started.load(Ordering::SeqCst) == 3).await;
        eventually(|| listener.available_connections() == 1).await;
        // And the freed slot is served again.
        let _third = hold(&dialer, b'h').await;
        eventually(|| policy.started.load(Ordering::SeqCst) == 4).await;
        assert_eq!(listener.available_connections(), 0);
        assert_eq!(policy.released.load(Ordering::SeqCst), 2);

        // Stop: the two still held are aborted by the drain, which is the
        // last way a connection task can end.
        listener.shutdown().await;
        assert_eq!(policy.released.load(Ordering::SeqCst), 4);
    })
    .await
    .expect("test within deadline");
}

#[tokio::test(start_paused = true)]
async fn stop_closes_the_endpoint_signals_connections_and_bounds_the_drain() {
    tokio::time::timeout(PATIENCE, async {
        // A connection that finishes shortly after the stop is waited for.
        let (acceptor, dialer) = scripted();
        let policy = Holding::new(4);
        let listener = Listener::spawn(acceptor, Arc::clone(&policy));
        let mut finishing = hold(&dialer, b's').await;
        eventually(|| policy.started.load(Ordering::SeqCst) == 1).await;
        assert!(!dialer.closed.load(Ordering::SeqCst));
        let started = tokio::time::Instant::now();
        listener.shutdown().await;
        assert_elapsed(started, Duration::from_secs(1));
        assert!(
            dialer.closed.load(Ordering::SeqCst),
            "the endpoint was closed"
        );
        let mut farewell = Vec::new();
        finishing.read_to_end(&mut farewell).await.unwrap();
        assert_eq!(farewell, b"bye", "the handler ran to its end");

        // One that never finishes is aborted when the drain runs out.
        let (acceptor, dialer) = scripted();
        let policy = Holding::new(4);
        let listener = Listener::spawn(acceptor, Arc::clone(&policy));
        let _stuck = hold(&dialer, b'n').await;
        eventually(|| policy.started.load(Ordering::SeqCst) == 1).await;
        let started = tokio::time::Instant::now();
        listener.shutdown().await;
        assert_elapsed(started, Limits::PUBLIC.drain);
        assert_eq!(policy.released.load(Ordering::SeqCst), 1);

        // A handle that is dropped instead of shut down stops the loop too.
        let (acceptor, dialer) = scripted();
        let listener = Listener::spawn(acceptor, Holding::new(4));
        drop(listener);
        eventually(|| dialer.closed.load(Ordering::SeqCst)).await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn a_served_connection_comes_with_the_peer_the_acceptor_reported() {
    let (acceptor, dialer) = scripted();
    let policy = Answering::new(Limits::PUBLIC);
    let listener = Listener::spawn(acceptor, Arc::clone(&policy));
    assert_eq!(ask(&dialer, "req_peer").await, result("req_peer"));
    assert_eq!(
        *policy.peers.lock().unwrap(),
        vec![PeerIdentity::OwnerNonce]
    );
    listener.shutdown().await;
}

#[test]
fn the_two_planes_keep_their_documented_limits() {
    assert_eq!(Limits::PUBLIC.max_connections, 256);
    assert_eq!(Limits::PUBLIC.request_bytes, 1024 * 1024);
    assert_eq!(Limits::PUBLIC.reply_bytes, 1024 * 1024);
    assert_eq!(Limits::ADMIN.max_connections, 32);
    assert_eq!(Limits::ADMIN.request_bytes, 1024 * 1024);
    assert_eq!(Limits::ADMIN.reply_bytes, 16 * 1024 * 1024);
    for limits in [Limits::PUBLIC, Limits::ADMIN] {
        assert_eq!(limits.handshake, Duration::from_secs(5));
        assert_eq!(limits.drain, Duration::from_secs(5));
    }
    assert_eq!(client_hello(Via::Direct).proto, 2);
}

/// The administration plane's hello: an untyped first frame larger than a
/// hello comes back whole for the policy to answer, with nothing written; a
/// typed frame is still held to the hello limit, and the plain `read_hello`
/// still refuses the long frame by its length.
#[tokio::test]
async fn a_raised_first_frame_limit_only_admits_an_untyped_frame() {
    let deadline = || handshake_deadline(&Limits::ADMIN);
    let limit = Limits::ADMIN.request_bytes;
    let bare = serde_json::to_vec(&Envelope {
        args: serde_json::json!({ "pad": "x".repeat(16 * MAX_HELLO_BYTES) }),
        ..envelope("req_bare")
    })
    .unwrap();
    let mut framed_bare = Vec::new();
    write_frame(&mut framed_bare, &bare, limit).await.unwrap();

    let verdict_within = |first: Vec<u8>| async move {
        let (mut client, mut server) = tokio::io::duplex(256 * 1024);
        client.write_all(&first).await.unwrap();
        client.shutdown().await.unwrap();
        let verdict = read_hello_within(&mut server, deadline(), limit).await;
        drop(server);
        let mut sent = Vec::new();
        client.read_to_end(&mut sent).await.unwrap();
        (verdict, sent)
    };

    let (verdict, sent) = verdict_within(framed_bare).await;
    assert!(
        matches!(&verdict, Err(HandshakeError::Untyped(body)) if body == &bare),
        "{verdict:?}"
    );
    assert!(sent.is_empty(), "the policy answers, not the handshake");

    // A hello padded past the hello limit is refused although it fits the
    // raised one.
    let mut fat = serde_json::to_value(Frame::Hello(client_hello(Via::Direct))).unwrap();
    fat["pad"] = serde_json::json!("x".repeat(MAX_HELLO_BYTES));
    let mut framed_fat = Vec::new();
    write_frame(&mut framed_fat, &serde_json::to_vec(&fat).unwrap(), limit)
        .await
        .unwrap();
    let (verdict, sent) = verdict_within(framed_fat).await;
    assert!(
        matches!(verdict, Err(HandshakeError::BadFrame(_))),
        "{verdict:?}"
    );
    assert_eq!(sent_cause(&sent), cause::BAD_FRAME);

    // A hello inside the limit is a hello under either reader.
    let (verdict, sent) =
        verdict_within(wire_bytes(&Frame::Hello(client_hello(Via::Direct))).await).await;
    assert!(verdict.is_ok(), "{verdict:?}");
    assert!(sent.is_empty());

    // Without the raised limit a bare frame longer than a hello is a bad
    // frame (one small enough for the helper's 64 KiB stream).
    let shorter = serde_json::to_vec(&Envelope {
        args: serde_json::json!({ "pad": "x".repeat(2 * MAX_HELLO_BYTES) }),
        ..envelope("req_bare")
    })
    .unwrap();
    let mut framed_shorter = Vec::new();
    write_frame(&mut framed_shorter, &shorter, limit)
        .await
        .unwrap();
    let (verdict, sent) = hello_verdict(framed_shorter).await;
    assert!(
        matches!(verdict, Err(HandshakeError::BadFrame(_))),
        "{verdict:?}"
    );
    assert_eq!(sent_cause(&sent), cause::BAD_FRAME);
}

/// A request the caller encoded itself is sized before anything is written:
/// an over-limit one never reaches the daemon.
#[tokio::test]
async fn an_encoded_request_over_the_limit_is_refused_before_any_write() {
    let (mut client, mut server) = tokio::io::duplex(64 * 1024);
    let hello = client_hello(Via::Direct);
    for request in [vec![b'x'; MAX_FRAME_BYTES + 1], Vec::new()] {
        let outcome = open_encoded(&mut client, &hello, &request).await;
        assert!(
            matches!(&outcome, Err(DialError::Io(error)) if error.kind() == io::ErrorKind::InvalidData),
            "{outcome:?}"
        );
    }
    drop(client);
    let mut seen = Vec::new();
    server.read_to_end(&mut seen).await.unwrap();
    assert!(seen.is_empty(), "nothing was written: {} bytes", seen.len());
}

/// A read that is dropped mid-frame, in the header or in the body, resumes
/// where it stopped: a stream read under a timeout never loses its place.
#[tokio::test(start_paused = true)]
async fn a_frame_reader_resumes_a_read_that_was_dropped_mid_frame() {
    let tick = Duration::from_millis(5);
    let (mut near, mut far) = tokio::io::duplex(1024);
    let mut reader = FrameReader::new(64);
    let first = br#"{"t":"one"}"#;
    let second = br#"{"t":"two","pad":"xxxxxxxx"}"#;
    let header = |body: &[u8]| u32::try_from(body.len()).unwrap().to_be_bytes();

    // Two header bytes, then nothing: the read is dropped by the timeout.
    far.write_all(&header(first)[..2]).await.unwrap();
    assert!(
        tokio::time::timeout(tick, reader.read(&mut near))
            .await
            .is_err()
    );
    // The rest of the header and half the body: dropped again.
    far.write_all(&header(first)[2..]).await.unwrap();
    far.write_all(&first[..5]).await.unwrap();
    assert!(
        tokio::time::timeout(tick, reader.read(&mut near))
            .await
            .is_err()
    );
    // The remainder, with the whole next frame right behind it.
    far.write_all(&first[5..]).await.unwrap();
    far.write_all(&header(second)).await.unwrap();
    far.write_all(second).await.unwrap();
    assert_eq!(reader.read(&mut near).await.unwrap(), first);
    assert_eq!(reader.read(&mut near).await.unwrap(), second);

    // The peer closing between frames, or inside one, is an end of file.
    far.write_all(&header(first)).await.unwrap();
    drop(far);
    let error = reader.read(&mut near).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    let (mut near, far) = tokio::io::duplex(1024);
    drop(far);
    let error = FrameReader::new(64).read(&mut near).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);

    // A bad length is refused from the header alone, body unread.
    for announced in [0u32, 65, u32::MAX] {
        let body_polls = Arc::new(AtomicUsize::new(0));
        let mut source = HeaderOnly {
            header: announced.to_be_bytes(),
            given: 0,
            body_polls: Arc::clone(&body_polls),
        };
        let error = tokio::time::timeout(tick, FrameReader::new(64).read(&mut source))
            .await
            .expect("refused without waiting for a body")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{announced}");
        assert_eq!(body_polls.load(Ordering::SeqCst), 0, "{announced}");
    }
}

/// The image probe a test flips to "the binary on disk was replaced".
struct Flip {
    replaced: AtomicBool,
}

impl ImageProbe for Flip {
    fn facts(&self, path: &std::path::Path) -> Option<FileFacts> {
        Some(FileFacts {
            canonical: path.to_path_buf(),
            len: 100,
            modified: None,
            identity: Some((1, u64::from(self.replaced.load(Ordering::SeqCst)))),
        })
    }
}

fn image_over(probe: &Arc<Flip>) -> Arc<ImageWatch> {
    let boot = BootImage::from_paths(
        vec![std::path::PathBuf::from("/opt/pam/bin/pam")],
        probe.as_ref(),
    );
    ImageWatch::with_boot(boot, Arc::clone(probe) as Arc<dyn ImageProbe>)
}

fn hello_claiming(version: &str) -> Hello {
    Hello {
        version: version.to_owned(),
        ..client_hello(Via::Direct)
    }
}

/// What the version rule did with a hello claiming `version`, with a request
/// frame and three more bytes already written behind that hello: its verdict,
/// the frames the peer was sent, and what was left unread after it.
async fn version_verdict(
    version: &str,
    image: &ImageWatch,
    phase: &watch::Sender<LifecyclePhase>,
) -> (Result<(), pam_proto::wire::ErrorFrame>, Vec<u8>, Vec<u8>) {
    let (mut client, mut server) = tokio::io::duplex(64 * 1024);
    let request = wire_bytes(&Frame::Request {
        envelope: envelope("req_behind"),
    })
    .await;
    client.write_all(&request).await.unwrap();
    client.write_all(b"xyz").await.unwrap();
    client.shutdown().await.unwrap();
    let verdict = version_rule(
        &mut server,
        &hello_claiming(version),
        image,
        phase,
        handshake_deadline(&Limits::PUBLIC),
    )
    .await;
    let mut unread = Vec::new();
    server.read_to_end(&mut unread).await.unwrap();
    drop(server);
    let mut sent = Vec::new();
    client.read_to_end(&mut sent).await.unwrap();
    (verdict, sent, unread)
}

/// The version rule both planes call: an equal version passes untouched; any
/// other is refused by what the daemon's own binary on disk says, never by
/// what the client claims; only a replaced binary moves the phase, and only
/// from `Serving`; and a refusal reads off exactly the one request frame the
/// client wrote behind its hello.
#[tokio::test]
async fn the_version_rule_refuses_by_the_image_and_reads_off_the_request_behind_the_hello() {
    let probe = Arc::new(Flip {
        replaced: AtomicBool::new(false),
    });
    let (phase, _) = watch::channel(LifecyclePhase::Serving);
    let whole_request = wire_bytes(&Frame::Request {
        envelope: envelope("req_behind"),
    })
    .await;

    // This build: nothing is written, nothing is read, the request stays.
    let image = image_over(&probe);
    let (verdict, sent, unread) = version_verdict(env!("CARGO_PKG_VERSION"), &image, &phase).await;
    assert_eq!(verdict, Ok(()));
    assert!(
        sent.is_empty(),
        "an accepted hello is acked by accept_hello"
    );
    assert_eq!(unread, [whole_request.as_slice(), b"xyz"].concat());

    // Another build, the binary on disk unchanged: refused, nothing moves.
    for claimed in ["9.9.9", "0.0.1", "not a version"] {
        let (verdict, sent, unread) = version_verdict(claimed, &image, &phase).await;
        let error = verdict.unwrap_err();
        assert_eq!(error.cause, cause::CLIENT_VERSION_MISMATCH);
        assert!(error.detail.contains(claimed), "{}", error.detail);
        assert!(
            error.detail.contains(env!("CARGO_PKG_VERSION"))
                && error.detail.contains("/opt/pam/bin/pam"),
            "the refusal names the daemon's version and executable: {}",
            error.detail
        );
        // What was returned is what was written, as one `error` frame.
        assert_eq!(Frame::decode(&sent[4..]).unwrap(), Frame::Error(error));
        // Exactly the request frame was read off: the close is not held up
        // waiting for more, and nothing past the frame is consumed.
        assert_eq!(unread, b"xyz");
        assert_eq!(*phase.borrow(), LifecyclePhase::Serving);
    }

    // The binary was replaced: the daemon hands over. (A fresh watch: the
    // one above has just cached "unchanged" for its re-check interval.)
    let replaced = Arc::new(Flip {
        replaced: AtomicBool::new(false),
    });
    let image_replaced = image_over(&replaced);
    replaced.replaced.store(true, Ordering::SeqCst);
    let (verdict, sent, unread) = version_verdict("9.9.9", &image_replaced, &phase).await;
    let error = verdict.unwrap_err();
    assert_eq!(error.cause, cause::DAEMON_OUTDATED);
    assert_eq!(Frame::decode(&sent[4..]).unwrap(), Frame::Error(error));
    assert_eq!(unread, b"xyz");
    assert_eq!(*phase.borrow(), LifecyclePhase::Restarting);

    // A daemon that is already draining keeps its phase, and an equal
    // version is never a reason to look at the image at all.
    let (draining, _) = watch::channel(LifecyclePhase::Draining);
    let (verdict, _, _) = version_verdict("9.9.9", &image_replaced, &draining).await;
    assert_eq!(verdict.unwrap_err().cause, cause::DAEMON_OUTDATED);
    assert_eq!(*draining.borrow(), LifecyclePhase::Draining);
    let (verdict, _, _) = version_verdict(env!("CARGO_PKG_VERSION"), &image, &draining).await;
    assert_eq!(verdict, Ok(()));
}

/// A hello refused after it was read whole (wrong protocol, wrong type, not a
/// frame) takes the request behind it with it; a first frame refused from its
/// header alone is not waited on.
#[tokio::test(start_paused = true)]
async fn a_refused_hello_takes_the_request_behind_it_and_a_bad_length_does_not_wait() {
    let request = wire_bytes(&Frame::Request {
        envelope: envelope("req_behind"),
    })
    .await;
    let future = wire_bytes(&Frame::Hello(Hello {
        proto: 3,
        ..client_hello(Via::Direct)
    }))
    .await;
    let wrong_type = wire_bytes(&Frame::Subscribed).await;
    let mut not_json = Vec::new();
    write_frame(&mut not_json, b"not json", MAX_HELLO_BYTES)
        .await
        .unwrap();
    for (first, expected) in [
        (future, cause::PROTOCOL_MISMATCH),
        (wrong_type, cause::BAD_FRAME),
        (not_json, cause::BAD_FRAME),
    ] {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        client.write_all(&first).await.unwrap();
        client.write_all(&request).await.unwrap();
        client.write_all(b"xyz").await.unwrap();
        let started = tokio::time::Instant::now();
        let verdict = read_hello(&mut server, handshake_deadline(&Limits::PUBLIC)).await;
        assert!(verdict.is_err(), "{verdict:?}");
        // The client is still connected and silent, yet nothing was waited
        // for: the request was already there.
        assert_eq!(started.elapsed(), Duration::ZERO, "{expected}");
        assert_eq!(error_cause(&mut client).await, expected);
        let mut left = [0u8; 3];
        server.read_exact(&mut left).await.unwrap();
        assert_eq!(&left, b"xyz", "{expected}: exactly one frame was read off");
    }

    // An over-limit length: refused from the header, no body awaited.
    let (mut client, mut server) = tokio::io::duplex(64 * 1024);
    let oversized = u32::try_from(MAX_HELLO_BYTES + 1).unwrap().to_be_bytes();
    client.write_all(&oversized).await.unwrap();
    let started = tokio::time::Instant::now();
    let verdict = read_hello(&mut server, handshake_deadline(&Limits::PUBLIC)).await;
    assert!(
        matches!(verdict, Err(HandshakeError::BadFrame(_))),
        "{verdict:?}"
    );
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert_eq!(error_cause(&mut client).await, cause::BAD_FRAME);
}

/// `discard_frame` drops one frame without trusting its length and gives up
/// at the deadline when the peer sends nothing.
#[tokio::test(start_paused = true)]
async fn discarding_a_frame_is_bounded_in_bytes_and_in_time() {
    // A length far over the limit: at most one frame's worth is dropped.
    let (mut client, mut server) = tokio::io::duplex(256 * 1024);
    let feeding = tokio::spawn(async move {
        client.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        let chunk = vec![7u8; 64 * 1024];
        let mut written = 0usize;
        while written < MAX_FRAME_BYTES + 64 * 1024 {
            if client.write_all(&chunk).await.is_err() {
                break;
            }
            written += chunk.len();
        }
        client
    });
    discard_frame(&mut server, tokio::time::Instant::now() + HANDSHAKE_TIMEOUT).await;
    let mut rest = Vec::new();
    let mut client = feeding.await.unwrap();
    client.shutdown().await.unwrap();
    server.read_to_end(&mut rest).await.unwrap();
    assert_eq!(
        rest.len(),
        64 * 1024,
        "one frame's worth was dropped, no more"
    );

    // A silent peer: the wait ends at the deadline.
    let (_client, mut server) = tokio::io::duplex(1024);
    let started = tokio::time::Instant::now();
    discard_frame(&mut server, started + HANDSHAKE_TIMEOUT).await;
    assert_elapsed(started, HANDSHAKE_TIMEOUT);
}

/// The cancel-safe reader decodes like `read_daemon_frame`: an `error` frame
/// is the refusal, an unknown type is skipped, and a read dropped mid-frame
/// loses nothing.
#[tokio::test(start_paused = true)]
async fn a_frame_reader_reads_daemon_frames_and_keeps_its_place() {
    let tick = Duration::from_millis(5);
    let (mut near, mut far) = tokio::io::duplex(64 * 1024);
    let mut reader = FrameReader::new(MAX_FRAME_BYTES);
    let event = wire_bytes(&Frame::follow_event(1, Event::Started)).await;

    // Half an event, a dropped read, the other half behind an unknown frame.
    far.write_all(b"\x00\x00\x00\x0b{\"t\":\"new\"}")
        .await
        .unwrap();
    far.write_all(&event[..9]).await.unwrap();
    assert!(
        tokio::time::timeout(tick, reader.daemon_frame(&mut near))
            .await
            .is_err()
    );
    far.write_all(&event[9..]).await.unwrap();
    assert_eq!(
        reader.daemon_frame(&mut near).await.unwrap(),
        Frame::follow_event(1, Event::Started)
    );

    far.write_all(&wire_bytes(&Frame::Subscribed).await)
        .await
        .unwrap();
    assert_eq!(
        reader.daemon_frame(&mut near).await.unwrap(),
        Frame::Subscribed
    );

    let refusal = Frame::error(cause::DAEMON_SHUTTING_DOWN, "draining", "Reconnect.");
    far.write_all(&wire_bytes(&refusal).await).await.unwrap();
    let refused = reader.daemon_frame(&mut near).await;
    assert!(
        matches!(&refused, Err(DialError::Refused(error)) if error.cause == cause::DAEMON_SHUTTING_DOWN),
        "{refused:?}"
    );

    far.write_all(b"\x00\x00\x00\x08not json").await.unwrap();
    assert!(matches!(
        reader.daemon_frame(&mut near).await,
        Err(DialError::Protocol(_))
    ));
    drop(far);
    assert!(matches!(
        reader.daemon_frame(&mut near).await,
        Err(DialError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof
    ));
}
