//! Tests of the framed client transport, and the fake daemons the client tests share.
//!
//! A [`FakeDaemon`] is "another process" as far as a test can make one: it holds the instance
//! lock, binds the real public endpoint of a temp base and serves it from a runtime of its own,
//! so a test that blocks its own thread (the synchronous readiness wait) never starves it. What
//! it says on each connection is the test's script.

use std::future::Future;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pam_daemon::framed::{self, Accept};
use pam_daemon::lifecycle::{InstanceLock, acquire_instance_lock};
use pam_daemon::runtime_dir::RuntimeDir;
use pam_proto::wire::{
    End, EventFrame, Following, Frame, Hello, HelloAck, MAX_FRAME_BYTES, Via, WIRE_PROTOCOL, cause,
};
use pam_proto::{Event, Outcome, Response};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::transport::{self, Dial, Probe, Resume, TransportError};

/// The epoch the fakes acknowledge with unless a test says otherwise.
pub(crate) const EPOCH: &str = "01JB2M5T8Q0V7K3W9X4Y6Z1ABC";

/// The 64-byte greeting a ZMTP peer sends as soon as a connection opens.
pub(crate) fn zmtp_greeting() -> Vec<u8> {
    let mut greeting = vec![0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0x7F, 3, 0];
    greeting.extend_from_slice(b"NULL");
    greeting.resize(64, 0);
    greeting
}

/// The acceptor of the platform's public endpoint.
#[cfg(unix)]
type PublicAcceptor = pam_daemon::framed_unix::UnixAcceptor;

/// The acceptor of the platform's public endpoint.
#[cfg(windows)]
type PublicAcceptor = pam_daemon::framed_windows::LoopbackAcceptor;

#[cfg(unix)]
fn bind_public(dirs: &RuntimeDir) -> PublicAcceptor {
    PublicAcceptor::bind(dirs.public_socket()).expect("the public socket binds")
}

#[cfg(windows)]
fn bind_public(dirs: &RuntimeDir) -> PublicAcceptor {
    PublicAcceptor::bind(
        dirs.public_control(),
        pam_daemon::framed_windows::PUBLIC_LABEL,
        pam_daemon::framed_windows::MAX_PUBLIC_PENDING,
    )
    .expect("the public endpoint binds")
}

/// The daemon's end of one connection, with the steps a script is made of. Reads answer `None`
/// when the client has gone, so a script ends quietly instead of panicking in a detached task.
pub(crate) struct Peer<S> {
    pub(crate) stream: S,
    /// Which connection of the fake this is, counted from zero.
    pub(crate) connection: usize,
}

/// A [`Peer`] on the real public endpoint.
pub(crate) type DaemonPeer = Peer<framed::PublicStream>;

impl<S: AsyncRead + AsyncWrite + Unpin> Peer<S> {
    /// The next frame the client wrote, as JSON.
    pub(crate) async fn frame(&mut self) -> Option<serde_json::Value> {
        let body = framed::read_frame(&mut self.stream, MAX_FRAME_BYTES)
            .await
            .ok()?;
        serde_json::from_slice(&body).ok()
    }

    /// The client's hello.
    pub(crate) async fn hello(&mut self) -> Option<Hello> {
        let frame = self.frame().await?;
        match serde_json::from_value(frame).ok()? {
            Frame::Hello(hello) => Some(hello),
            _ => None,
        }
    }

    pub(crate) async fn send(&mut self, frame: &Frame) {
        let _ = framed::send(&mut self.stream, frame, MAX_FRAME_BYTES).await;
    }

    /// A frame this build's [`Frame`] cannot express (an unknown type, an unknown event kind).
    pub(crate) async fn send_json(&mut self, value: &serde_json::Value) {
        let body = serde_json::to_vec(value).expect("JSON serializes");
        let _ = framed::write_frame(&mut self.stream, &body, MAX_FRAME_BYTES).await;
    }

    /// Bytes that are not a frame at all.
    pub(crate) async fn raw(&mut self, bytes: &[u8]) {
        let _ = self.stream.write_all(bytes).await;
        let _ = self.stream.flush().await;
    }

    pub(crate) async fn ack(&mut self, epoch: &str) {
        self.send(&Frame::HelloAck(HelloAck {
            proto: WIRE_PROTOCOL,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            epoch: epoch.to_owned(),
        }))
        .await;
    }

    /// Hello in, acknowledgement out, then the one request frame (`request` or `follow`).
    pub(crate) async fn greet(&mut self, epoch: &str) -> Option<serde_json::Value> {
        self.hello().await?;
        self.ack(epoch).await;
        self.frame().await
    }

    pub(crate) async fn event(&mut self, seq: u64, event: Event) {
        self.send(&Frame::follow_event(seq, event)).await;
    }

    pub(crate) async fn following(&mut self, epoch: &str, seq: u64) {
        self.send(&Frame::Following(Following {
            ticket: "req_followed".to_owned(),
            epoch: epoch.to_owned(),
            state: "running".to_owned(),
            seq,
        }))
        .await;
    }

    /// `end` with the durable answer of a ticket that finished in `state`.
    pub(crate) async fn end(&mut self, id: &str, state: &str) {
        let event = if state == "done" {
            Event::Done
        } else {
            Event::Refused
        };
        self.send(&Frame::End(End {
            seq: None,
            event: Some(event),
            response: Response::Result {
                id: id.to_owned(),
                outcome: Outcome::Solved,
                body: serde_json::json!({
                    "ticket": "req_followed", "state": state, "outcome": "solved",
                    "capability": "echo",
                }),
                evidence: Vec::new(),
            },
        }))
        .await;
    }

    /// `end` carrying a refusal of the follow itself.
    pub(crate) async fn end_refused(&mut self, id: &str, cause: &str, retryable: bool) {
        self.send(&Frame::End(End {
            seq: None,
            event: None,
            response: Response::Refusal {
                retryable,
                id: id.to_owned(),
                cause: cause.to_owned(),
                detail: "the daemon said no".to_owned(),
                recovery: "do what it says".to_owned(),
            },
        }))
        .await;
    }

    /// Keeps the connection open, discarding what arrives, until the client closes it.
    pub(crate) async fn until_closed(&mut self) {
        let mut sink = [0u8; 256];
        while matches!(self.stream.read(&mut sink).await, Ok(count) if count > 0) {}
    }
}

/// The id of the envelope inside a `request` or `follow` frame.
pub(crate) fn envelope_id(frame: &serde_json::Value) -> String {
    frame["envelope"]["id"]
        .as_str()
        .unwrap_or("unknown")
        .to_owned()
}

/// A fake daemon on the real public endpoint of a temp base (see the module docs).
pub(crate) struct FakeDaemon {
    lock: Option<InstanceLock>,
    connections: Arc<AtomicUsize>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    stopped: std::sync::mpsc::Receiver<()>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl FakeDaemon {
    /// Takes the instance lock of `base`, binds its public endpoint and runs `serve` for every
    /// connection.
    pub(crate) fn start<H, F>(base: &Path, serve: H) -> Self
    where
        H: Fn(DaemonPeer) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let dirs = RuntimeDir::at_base(base).expect("runtime dir");
        let lock = acquire_instance_lock(dirs.run_dir()).expect("the instance lock is free");
        Self::listen(&dirs, Some(lock), serve)
    }

    /// Binds the public endpoint of `dirs` without any lock: what a session relay's directory
    /// looks like to a client.
    pub(crate) fn listen<H, F>(dirs: &RuntimeDir, lock: Option<InstanceLock>, serve: H) -> Self
    where
        H: Fn(DaemonPeer) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("the fake's runtime starts");
        let mut acceptor = {
            let _context = runtime.enter();
            bind_public(dirs)
        };
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&connections);
        let (stop, mut stop_requested) = tokio::sync::oneshot::channel();
        let (acknowledge, stopped) = std::sync::mpsc::channel();
        runtime.spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut stop_requested => break,
                    accepted = acceptor.accept() => {
                        let Ok((stream, _peer)) = accepted else { break };
                        let connection = counter.fetch_add(1, Ordering::SeqCst);
                        tokio::spawn(serve(Peer { stream, connection }));
                    }
                }
            }
            // Removes the socket (or control) file, as a daemon's shutdown does.
            acceptor.close();
            drop(acceptor);
            let _ = acknowledge.send(());
        });
        Self {
            lock,
            connections,
            stop: Some(stop),
            stopped,
            runtime: Some(runtime),
        }
    }

    /// Connections accepted so far.
    pub(crate) fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// Stops listening, removes the endpoint and only then releases the lock: the order a
    /// daemon's shutdown keeps.
    pub(crate) fn stop(mut self) {
        self.halt();
    }

    fn halt(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
            let _ = self.stopped.recv_timeout(Duration::from_secs(5));
        }
        if let Some(runtime) = self.runtime.take() {
            // Never blocks, so a fake may be dropped inside an async test.
            runtime.shutdown_background();
        }
        self.lock = None;
    }
}

impl Drop for FakeDaemon {
    fn drop(&mut self) {
        self.halt();
    }
}

/// Everything a scripted daemon was sent, in arrival order.
pub(crate) type Seen = Arc<Mutex<Vec<serde_json::Value>>>;

/// A fake daemon that answers every unary request through `reply` and records the envelopes it
/// received. `None` takes the request and never answers, leaving the client to its own budget.
pub(crate) fn answering(
    base: &Path,
    reply: impl Fn(&serde_json::Value) -> Option<Response> + Send + Sync + 'static,
) -> (FakeDaemon, Seen) {
    let seen: Seen = Arc::default();
    let record = Arc::clone(&seen);
    let reply = Arc::new(reply);
    let daemon = FakeDaemon::start(base, move |mut peer| {
        let record = Arc::clone(&record);
        let reply = Arc::clone(&reply);
        async move {
            // A hello with nothing behind it (the readiness probe) ends here.
            let Some(frame) = peer.greet(EPOCH).await else {
                return;
            };
            let envelope = frame["envelope"].clone();
            record.lock().unwrap().push(envelope.clone());
            match reply(&envelope) {
                Some(response) => peer.send(&Frame::Reply { response }).await,
                None => peer.until_closed().await,
            }
        }
    });
    (daemon, seen)
}

/// A fake pre-migration daemon: it greets in ZMTP the moment a connection opens.
pub(crate) fn legacy(base: &Path) -> FakeDaemon {
    FakeDaemon::start(base, |mut peer| async move {
        peer.raw(&zmtp_greeting()).await;
        peer.until_closed().await;
    })
}

fn envelope() -> pam_proto::Envelope {
    crate::request::build_envelope("echo", serde_json::json!({ "n": 1 }), true, 1_000, None)
}

fn hello() -> Hello {
    framed::client_hello(Via::Direct)
}

fn solved(id: &str) -> Response {
    Response::Result {
        id: id.to_owned(),
        outcome: Outcome::Solved,
        body: serde_json::json!({ "echo": { "n": 1 } }),
        evidence: Vec::new(),
    }
}

/// An in-memory connection: the client end, and the daemon end as a [`Peer`].
fn pair() -> (tokio::io::DuplexStream, Peer<tokio::io::DuplexStream>) {
    let (near, far) = tokio::io::duplex(64 * 1024);
    (
        near,
        Peer {
            stream: far,
            connection: 0,
        },
    )
}

const OPENING: Duration = Duration::from_secs(5);

#[tokio::test]
async fn a_call_is_hello_request_reply_on_one_connection() {
    let (mut near, mut peer) = pair();
    let request = envelope();
    let id = request.id.clone();
    let daemon = tokio::spawn(async move {
        let hello = peer.hello().await.expect("a hello comes first");
        peer.ack(EPOCH).await;
        let frame = peer.frame().await.expect("then the request");
        peer.send(&Frame::Reply {
            response: solved(&envelope_id(&frame)),
        })
        .await;
        (hello, frame)
    });
    let relayed = Hello {
        via: Via::Relay,
        ..hello()
    };
    let response = transport::call_on(&mut near, &relayed, &request)
        .await
        .expect("the reply arrives");
    assert_eq!(response, solved(&id));
    let (hello, frame) = daemon.await.unwrap();
    assert_eq!(hello.proto, WIRE_PROTOCOL);
    assert_eq!(hello.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(
        hello.via,
        Via::Relay,
        "the hello says how the daemon is reached"
    );
    assert_eq!(frame["t"], "request");
    assert_eq!(frame["envelope"]["id"], id.as_str());
    assert_eq!(frame["envelope"]["capability"], "echo");
}

/// A pre-migration daemon greets in ZMTP before it reads. The client recognises it from the
/// first byte, and everything it wrote is this protocol's frames: no ZMTP is spoken back.
#[tokio::test]
async fn a_zmtp_greeting_is_a_legacy_daemon_and_nothing_is_spoken_back() {
    for probe_only in [false, true] {
        let (mut near, mut peer) = pair();
        peer.raw(&zmtp_greeting()).await;
        let outcome = if probe_only {
            transport::hello_on(&mut near, &hello()).await.map(drop)
        } else {
            transport::call_on(&mut near, &hello(), &envelope())
                .await
                .map(drop)
        };
        assert!(
            matches!(outcome, Err(TransportError::LegacyDaemon)),
            "{outcome:?}"
        );
        drop(near);
        let mut written = Vec::new();
        peer.stream.read_to_end(&mut written).await.unwrap();
        assert_eq!(
            written.first(),
            Some(&0x00),
            "the client wrote a length-prefixed hello, never a ZMTP greeting"
        );
        let length = usize::try_from(u32::from_be_bytes(written[..4].try_into().unwrap())).unwrap();
        let first: serde_json::Value = serde_json::from_slice(&written[4..4 + length]).unwrap();
        assert_eq!(first["t"], "hello");
    }
}

#[tokio::test]
async fn an_error_frame_is_typed_with_its_cause_detail_and_recovery() {
    let (mut near, mut peer) = pair();
    let daemon = tokio::spawn(async move {
        peer.hello().await;
        peer.send(&Frame::error(
            cause::CLIENT_VERSION_MISMATCH,
            "client version 9.9.9 does not match",
            "Use the matching binary.",
        ))
        .await;
        peer.until_closed().await;
    });
    let refused = transport::call_on(&mut near, &hello(), &envelope()).await;
    let Err(TransportError::Refused(frame)) = refused else {
        panic!("expected the error frame, got {refused:?}");
    };
    assert_eq!(frame.cause, cause::CLIENT_VERSION_MISMATCH);
    assert_eq!(frame.detail, "client version 9.9.9 does not match");
    assert_eq!(frame.recovery, "Use the matching binary.");
    drop(near);
    daemon.await.unwrap();
}

/// The stream of one follow: replayed and live events are delivered once each, a frame type and
/// an event kind this build does not know are skipped, a gap in `seq` is not an error, and the
/// position ends at the last sequence number seen.
#[tokio::test]
async fn a_follow_delivers_events_in_order_and_skips_what_it_does_not_know() {
    let (mut near, mut peer) = pair();
    let request = envelope();
    let id = request.id.clone();
    let daemon = tokio::spawn(async move {
        let frame = peer.greet(EPOCH).await.expect("a follow frame");
        peer.following(EPOCH, 2).await;
        peer.event(1, Event::Queued).await;
        peer.event(2, Event::Started).await;
        peer.send_json(&serde_json::json!({"t": "heartbeat", "beat": 1}))
            .await;
        peer.send_json(
            &serde_json::json!({"t": "event", "seq": 3, "event": {"kind": "from_the_future"}}),
        )
        .await;
        // 4 was dropped for this follower: a gap.
        peer.event(
            5,
            Event::Progress {
                pct: Some(40),
                note: "Task progress updated".to_owned(),
            },
        )
        .await;
        peer.end(&envelope_id(&frame), "done").await;
        frame
    });
    let mut resume = Resume::default();
    let mut seen = Vec::new();
    let end = transport::follow_on(
        &mut near,
        &hello(),
        &request,
        &mut resume,
        &mut |event| seen.push(event.clone()),
        OPENING,
    )
    .await
    .expect("the stream reaches its end");
    let frame = daemon.await.unwrap();
    assert_eq!(frame["t"], "follow");
    assert_eq!(frame["after_seq"], 0, "a fresh follow has no position");
    assert_eq!(frame["epoch"], serde_json::Value::Null);
    assert_eq!(frame["envelope"]["id"], id.as_str());
    assert_eq!(
        seen,
        [
            Event::Queued,
            Event::Started,
            Event::Progress {
                pct: Some(40),
                note: "Task progress updated".to_owned()
            }
        ]
    );
    assert_eq!(
        end.event,
        Some(Event::Done),
        "the terminal event travels in `end`"
    );
    assert!(matches!(end.response, Response::Result { .. }));
    assert_eq!(
        resume,
        Resume {
            epoch: Some(EPOCH.to_owned()),
            after_seq: 5
        }
    );
}

/// A reconnect sends where the last stream stopped, and an event the daemon replays anyway is
/// not delivered a second time.
#[tokio::test]
async fn a_resumed_follow_sends_its_position_and_delivers_only_what_is_new() {
    let (mut near, mut peer) = pair();
    let daemon = tokio::spawn(async move {
        let frame = peer.greet(EPOCH).await.expect("a follow frame");
        peer.following(EPOCH, 4).await;
        peer.event(3, Event::Started).await;
        peer.event(4, Event::ApprovalPending).await;
        peer.end(&envelope_id(&frame), "done").await;
        frame
    });
    let mut resume = Resume {
        epoch: Some(EPOCH.to_owned()),
        after_seq: 3,
    };
    let mut seen = Vec::new();
    transport::follow_on(
        &mut near,
        &hello(),
        &envelope(),
        &mut resume,
        &mut |event| seen.push(event.clone()),
        OPENING,
    )
    .await
    .unwrap();
    let frame = daemon.await.unwrap();
    assert_eq!(frame["after_seq"], 3);
    assert_eq!(frame["epoch"], EPOCH);
    assert_eq!(seen, [Event::ApprovalPending], "3 was delivered before");
    assert_eq!(resume.after_seq, 4);
}

/// A different epoch is a restarted daemon: its sequence numbers start again, so the position
/// goes back to zero and its replay is taken from the start.
#[tokio::test]
async fn a_changed_epoch_starts_the_position_over() {
    let (mut near, mut peer) = pair();
    let daemon = tokio::spawn(async move {
        let frame = peer.greet("01JNEWDAEMONEPOCH0000000000").await.unwrap();
        peer.following("01JNEWDAEMONEPOCH0000000000", 2).await;
        peer.event(1, Event::Queued).await;
        peer.event(2, Event::Started).await;
        peer.end(&envelope_id(&frame), "done").await;
    });
    let mut resume = Resume {
        epoch: Some(EPOCH.to_owned()),
        after_seq: 7,
    };
    let mut seen = Vec::new();
    transport::follow_on(
        &mut near,
        &hello(),
        &envelope(),
        &mut resume,
        &mut |event| seen.push(event.clone()),
        OPENING,
    )
    .await
    .unwrap();
    daemon.await.unwrap();
    assert_eq!(
        seen,
        [Event::Queued, Event::Started],
        "sequence numbers below the old position are new under the new epoch"
    );
    assert_eq!(
        resume,
        Resume {
            epoch: Some("01JNEWDAEMONEPOCH0000000000".to_owned()),
            after_seq: 2
        }
    );
}

/// A stream cut before `end` is an I/O failure, and the position it reached is kept for the
/// reconnect.
#[tokio::test]
async fn a_follow_cut_before_its_end_keeps_the_position_it_reached() {
    let (mut near, mut peer) = pair();
    let daemon = tokio::spawn(async move {
        peer.greet(EPOCH).await.unwrap();
        peer.following(EPOCH, 1).await;
        peer.event(1, Event::Queued).await;
        // The daemon is killed here: no `end`, no `error`.
    });
    let mut resume = Resume::default();
    let cut = transport::follow_on(
        &mut near,
        &hello(),
        &envelope(),
        &mut resume,
        &mut |_| {},
        OPENING,
    )
    .await;
    daemon.await.unwrap();
    assert!(
        matches!(&cut, Err(TransportError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof),
        "{cut:?}"
    );
    assert_eq!(resume.after_seq, 1);
    assert_eq!(resume.epoch.as_deref(), Some(EPOCH));
}

/// An `error` frame inside the stream ends it with the frame's cause; frames the protocol does
/// not allow in a follow are a protocol error, not silently skipped.
#[tokio::test]
async fn a_follow_reports_error_frames_and_frames_that_do_not_belong() {
    let (mut near, mut peer) = pair();
    let daemon = tokio::spawn(async move {
        peer.greet(EPOCH).await.unwrap();
        peer.following(EPOCH, 0).await;
        peer.send(&Frame::error(
            cause::DAEMON_SHUTTING_DOWN,
            "the daemon is draining",
            "Reconnect shortly.",
        ))
        .await;
    });
    let ended = transport::follow_on(
        &mut near,
        &hello(),
        &envelope(),
        &mut Resume::default(),
        &mut |_| {},
        OPENING,
    )
    .await;
    daemon.await.unwrap();
    assert!(
        matches!(&ended, Err(TransportError::Refused(frame)) if frame.cause == cause::DAEMON_SHUTTING_DOWN),
        "{ended:?}"
    );

    let (mut near, mut peer) = pair();
    let daemon = tokio::spawn(async move {
        peer.greet(EPOCH).await.unwrap();
        peer.send(&Frame::Reply {
            response: solved("req_x"),
        })
        .await;
    });
    let ended = transport::follow_on(
        &mut near,
        &hello(),
        &envelope(),
        &mut Resume::default(),
        &mut |_| {},
        OPENING,
    )
    .await;
    daemon.await.unwrap();
    assert!(
        matches!(ended, Err(TransportError::Protocol(_))),
        "{ended:?}"
    );
}

/// A daemon that takes the follow and then says nothing does not hold the client for the whole
/// follow timeout: the opening (acknowledgement and first frame) has its own bound.
#[tokio::test]
async fn the_opening_of_a_follow_is_bounded() {
    let (mut near, mut peer) = pair();
    let daemon = tokio::spawn(async move {
        peer.greet(EPOCH).await;
        peer.until_closed().await;
    });
    let opening = Duration::from_millis(150);
    let stalled = transport::follow_on(
        &mut near,
        &hello(),
        &envelope(),
        &mut Resume::default(),
        &mut |_| {},
        opening,
    )
    .await;
    assert!(
        matches!(stalled, Err(TransportError::Timeout { waited }) if waited == opening),
        "{stalled:?}"
    );
    drop(near);
    daemon.await.unwrap();
}

/// A follow frame as the daemon decodes it, for the assertion that the client's bytes are the
/// wire type and not merely JSON of the right shape.
#[tokio::test]
async fn the_follow_frame_decodes_as_the_wire_type() {
    let (mut near, mut peer) = pair();
    let daemon = tokio::spawn(async move {
        peer.hello().await.unwrap();
        peer.ack(EPOCH).await;
        let body = framed::read_frame(&mut peer.stream, MAX_FRAME_BYTES)
            .await
            .unwrap();
        let decoded = Frame::decode(&body);
        peer.end_refused("req_x", "result_unavailable", false).await;
        decoded
    });
    let mut resume = Resume {
        epoch: Some(EPOCH.to_owned()),
        after_seq: 9,
    };
    let end = transport::follow_on(
        &mut near,
        &hello(),
        &envelope(),
        &mut resume,
        &mut |_| {},
        OPENING,
    )
    .await
    .unwrap();
    assert!(matches!(end.response, Response::Refusal { .. }));
    assert_eq!(end.event, None);
    let Ok(Frame::Follow(follow)) = daemon.await.unwrap() else {
        panic!("the daemon decodes a follow frame");
    };
    assert_eq!(follow.after_seq, 9);
    assert_eq!(follow.epoch.as_deref(), Some(EPOCH));
    assert_eq!(follow.envelope.capability, "echo");
}

/// An all-events frame has no `seq`; a follow frame without one is still delivered.
#[tokio::test]
async fn an_event_without_a_sequence_number_is_delivered() {
    let (mut near, mut peer) = pair();
    let daemon = tokio::spawn(async move {
        let frame = peer.greet(EPOCH).await.unwrap();
        peer.send(&Frame::Event(EventFrame {
            seq: None,
            n: None,
            ticket: None,
            capability: None,
            repo: None,
            agent: None,
            ingress: None,
            event: Event::Started,
        }))
        .await;
        peer.end(&envelope_id(&frame), "refused").await;
    });
    let mut seen = Vec::new();
    let end = transport::follow_on(
        &mut near,
        &hello(),
        &envelope(),
        &mut Resume::default(),
        &mut |event| seen.push(event.clone()),
        OPENING,
    )
    .await
    .unwrap();
    daemon.await.unwrap();
    assert_eq!(seen, [Event::Started]);
    assert_eq!(end.event, Some(Event::Refused));
}

// --- the real endpoint --------------------------------------------------------

/// Short absolute temp path: macOS caps unix socket paths at 104 bytes.
pub(crate) fn short_tempdir() -> tempfile::TempDir {
    #[cfg(unix)]
    {
        tempfile::Builder::new()
            .prefix("pam")
            .tempdir_in("/tmp")
            .expect("tempdir under /tmp")
    }
    #[cfg(not(unix))]
    {
        tempfile::tempdir().expect("tempdir")
    }
}

/// A connect that fails because the daemon is mid-restart is retried inside the bound instead
/// of failing the first command, and an endpoint nobody ever binds fails within the bound.
#[tokio::test]
async fn connect_waits_for_a_late_daemon_but_only_within_its_bound() {
    let tmp = short_tempdir();
    let dirs = RuntimeDir::at_base(tmp.path()).unwrap();
    let base = tmp.path().to_path_buf();
    let binder = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        let (daemon, _seen) = answering(&base, |request| {
            Some(solved(request["id"].as_str().unwrap()))
        });
        std::thread::sleep(Duration::from_secs(3));
        drop(daemon);
    });
    let dial = Dial::new(&dirs, Via::Direct, Duration::from_secs(8));
    let request = envelope();
    let response = transport::call(&dial, &request, Duration::from_secs(5))
        .await
        .expect("a daemon that binds within the bound is reached");
    assert_eq!(response, solved(&request.id));
    binder.join().unwrap();

    let none = short_tempdir();
    let dirs = RuntimeDir::at_base(none.path()).unwrap();
    let dial = Dial::new(&dirs, Via::Direct, Duration::from_millis(600));
    let started = std::time::Instant::now();
    let failed = transport::connect(&dial).await;
    let Err(TransportError::Connect(error)) = failed else {
        panic!("nothing ever binds");
    };
    assert_eq!(error.kind(), io::ErrorKind::NotFound, "{error}");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(300) && elapsed < Duration::from_secs(5),
        "retried inside the bound, and bounded: {elapsed:?}"
    );
}

/// A daemon that takes the request and never answers is a timeout after exactly the budget.
#[tokio::test]
async fn a_call_without_a_reply_times_out_at_its_budget() {
    let tmp = short_tempdir();
    let dirs = RuntimeDir::at_base(tmp.path()).unwrap();
    let (daemon, seen) = answering(tmp.path(), |_| None);
    let dial = Dial::new(&dirs, Via::Direct, Duration::from_secs(5));
    let budget = Duration::from_millis(300);
    let unanswered = transport::call(&dial, &envelope(), budget).await;
    assert!(
        matches!(unanswered, Err(TransportError::Timeout { waited }) if waited == budget),
        "{unanswered:?}"
    );
    assert_eq!(seen.lock().unwrap().len(), 1, "the request was sent once");
    drop(daemon);
}

const PROBE: Duration = Duration::from_millis(400);

/// The hello probe tells apart everything the lazy start has to act on. It is called here from
/// inside an async test on purpose: it must be safe on a thread that drives tasks.
#[tokio::test]
async fn a_probe_tells_ready_legacy_refused_unreachable_and_silent_apart() {
    let hello = hello();

    let nothing = short_tempdir();
    let dirs = RuntimeDir::at_base(nothing.path()).unwrap();
    let probed = transport::probe(&dirs, &hello, PROBE);
    assert!(matches!(probed, Probe::Unreachable(_)), "{probed:?}");

    let ready = short_tempdir();
    let dirs = RuntimeDir::at_base(ready.path()).unwrap();
    let (daemon, seen) = answering(ready.path(), |_| None);
    let probed = transport::probe(&dirs, &hello, PROBE);
    let Probe::Ready(ack) = probed else {
        panic!("a daemon that acknowledges is ready, got {probed:?}");
    };
    assert_eq!(ack.epoch, EPOCH);
    assert_eq!(ack.proto, WIRE_PROTOCOL);
    drop(daemon);
    assert!(
        seen.lock().unwrap().is_empty(),
        "a probe is a hello and nothing else: no request reached the daemon"
    );

    let old = short_tempdir();
    let dirs = RuntimeDir::at_base(old.path()).unwrap();
    let daemon = legacy(old.path());
    let probed = transport::probe(&dirs, &hello, PROBE);
    assert!(matches!(probed, Probe::Legacy), "{probed:?}");
    drop(daemon);

    let other = short_tempdir();
    let dirs = RuntimeDir::at_base(other.path()).unwrap();
    let daemon = FakeDaemon::start(other.path(), |mut peer| async move {
        peer.hello().await;
        peer.send(&Frame::error(cause::DAEMON_OUTDATED, "replaced", "retry"))
            .await;
        peer.until_closed().await;
    });
    let probed = transport::probe(&dirs, &hello, PROBE);
    assert!(
        matches!(&probed, Probe::Refused(frame) if frame.cause == cause::DAEMON_OUTDATED),
        "{probed:?}"
    );
    drop(daemon);

    let mute = short_tempdir();
    let dirs = RuntimeDir::at_base(mute.path()).unwrap();
    let daemon = FakeDaemon::start(mute.path(), |mut peer| async move {
        peer.until_closed().await;
    });
    let started = std::time::Instant::now();
    let probed = transport::probe(&dirs, &hello, PROBE);
    assert!(matches!(probed, Probe::Silent), "{probed:?}");
    assert!(started.elapsed() < PROBE + Duration::from_secs(2));
    assert_eq!(daemon.connections(), 1);
    drop(daemon);

    // A listener that accepts and hangs up without a word is on its way out, not ready.
    let closing = short_tempdir();
    let dirs = RuntimeDir::at_base(closing.path()).unwrap();
    let daemon = FakeDaemon::start(closing.path(), |peer| async move { drop(peer) });
    let probed = transport::probe(&dirs, &hello, PROBE);
    assert!(matches!(probed, Probe::Unreachable(_)), "{probed:?}");
    drop(daemon);
}

/// A crashed daemon's leftover socket file has no listener: unreachable, never ready.
#[cfg(unix)]
#[test]
fn a_stale_socket_file_is_unreachable() {
    let tmp = short_tempdir();
    let dirs = RuntimeDir::at_base(tmp.path()).unwrap();
    drop(std::os::unix::net::UnixListener::bind(dirs.public_socket()).unwrap());
    assert!(dirs.public_socket().exists());
    let probed = transport::probe(&dirs, &hello(), PROBE);
    assert!(
        matches!(&probed, Probe::Unreachable(error) if error.kind() == io::ErrorKind::ConnectionRefused),
        "{probed:?}"
    );
}
