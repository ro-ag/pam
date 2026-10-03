//! The administration policy over in-memory streams: every test here runs on
//! every platform, with the peer's identity chosen by the test.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use pam_proto::wire::{
    ErrorFrame, Frame, Hello, HelloAck, MAX_HELLO_BYTES, Via, WIRE_PROTOCOL, cause,
};
use pam_proto::{Caller, Envelope, Outcome, PROTOCOL_VERSION, Response};
use pam_store::Store;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::watch;

use super::frame::{
    AdminLifecycle, AdminPolicy, Admission, CAUSE_CLIENT_OUTDATED, CAUSE_RESPONSE_TOO_LARGE,
    MAX_REQUEST_BYTES, MAX_REQUEST_MS, MAX_RESPONSE_BYTES, encode_reply, encode_request,
    exchange_on, validate_envelope,
};
use crate::admin::{ADMIN_CALLER_AGENT, AdminService, OP_PROFILE_GET};
use crate::approval::ApprovalService;
use crate::connector_service::ConnectorService;
use crate::event_hub::EventHub;
use crate::framed::{self, Listener, Policy};
use crate::framed_test::{scripted, too_many_open_files};
use crate::image::{BootImage, FileFacts, FsProbe, ImageProbe, ImageWatch};
use crate::ingress::PeerIdentity;
use crate::lifecycle::LifecyclePhase;
use crate::log_service::LogService;
use crate::model_service::ModelService;
use crate::transport::EventPublisher;

/// Bound on every test in the administration transport suites.
pub(super) const DEADLINE: Duration = Duration::from_secs(30);

/// The uid the in-memory plane treats as the daemon's owner.
pub(super) const OWNER: u32 = 4242;

/// The owner as the kernel would report it.
pub(super) const OWNER_PEER: PeerIdentity = PeerIdentity::Unix {
    uid: OWNER,
    gid: 20,
    pid: Some(77),
};

pub(super) async fn admin_service_over(store: &Arc<Store>) -> Arc<AdminService> {
    let (events, _rx) = EventPublisher::for_tests();
    let approvals = Arc::new(ApprovalService::new(
        Arc::clone(store),
        events,
        Duration::from_mins(10),
    ));
    let models = ModelService::new(Arc::clone(store)).await.unwrap();
    let logs = LogService::new(Arc::clone(store), Arc::clone(&models));
    let connectors = Arc::new(ConnectorService::from_parts(Arc::clone(store), None, None));
    let flows = crate::flow_service_test::flows_for_tests(
        Path::new("pam-tests-have-no-flow-library"),
        store,
        &approvals,
        &connectors,
        &logs,
    )
    .await;
    Arc::new(AdminService::new(
        Arc::clone(store),
        approvals,
        models,
        logs,
        connectors,
        flows,
        crate::flow_service_test::closed_submit(),
    ))
}

pub(super) async fn admin_service() -> Arc<AdminService> {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    admin_service_over(&store).await
}

/// A lifecycle whose image is never "replaced": a differing version is a
/// plain mismatch.
pub(super) fn lifecycle() -> AdminLifecycle {
    let (phase, _) = watch::channel(LifecyclePhase::Serving);
    let probe: Arc<dyn ImageProbe> = Arc::new(FsProbe);
    AdminLifecycle {
        phase,
        image: ImageWatch::with_boot(BootImage::from_paths(Vec::new(), probe.as_ref()), probe),
    }
}

pub(super) fn admin_envelope(id: &str, capability: &str) -> Envelope {
    Envelope {
        v: PROTOCOL_VERSION,
        id: id.to_owned(),
        capability: capability.to_owned(),
        client_version: env!("CARGO_PKG_VERSION").to_owned(),
        caller: Caller {
            agent: ADMIN_CALLER_AGENT.to_owned(),
            repo: "/repo".to_owned(),
            pid: std::process::id(),
        },
        args: serde_json::json!({}),
        idempotency_key: None,
        deadline_ms: 5_000,
        wait: true,
    }
}

pub(super) fn profile_get(id: &str) -> Envelope {
    admin_envelope(id, OP_PROFILE_GET)
}

/// The image probe a test flips to "the binary on disk was replaced".
struct Flip {
    replaced: AtomicBool,
}

impl ImageProbe for Flip {
    fn facts(&self, path: &Path) -> Option<FileFacts> {
        Some(FileFacts {
            canonical: path.to_path_buf(),
            len: 100,
            modified: None,
            identity: Some((1, u64::from(self.replaced.load(Ordering::SeqCst)))),
        })
    }
}

/// The administration policy with everything a test wants to look at, served
/// over in-memory streams without a listener.
pub(super) struct Plane {
    pub(super) policy: Arc<AdminPolicy>,
    pub(super) hub: Arc<EventHub>,
    pub(super) phase: watch::Sender<LifecyclePhase>,
    pub(super) store: Arc<Store>,
    pub(super) stop: watch::Sender<bool>,
    probe: Arc<Flip>,
}

impl Plane {
    pub(super) async fn new() -> Self {
        let store = Arc::new(Store::open_in_memory().await.unwrap());
        let admin = admin_service_over(&store).await;
        let probe = Arc::new(Flip {
            replaced: AtomicBool::new(false),
        });
        let boot = BootImage::from_paths(vec![PathBuf::from("/opt/pam/bin/pam")], probe.as_ref());
        let (phase, _) = watch::channel(LifecyclePhase::Serving);
        let lifecycle = AdminLifecycle {
            phase: phase.clone(),
            image: ImageWatch::with_boot(boot, Arc::clone(&probe) as Arc<dyn ImageProbe>),
        };
        let hub = EventHub::new();
        let policy = AdminPolicy::new(
            admin,
            lifecycle,
            Arc::clone(&hub),
            Admission::UnixOwner(OWNER),
        );
        let (stop, _) = watch::channel(false);
        Self {
            policy,
            hub,
            phase,
            store,
            stop,
            probe,
        }
    }

    /// The daemon's binary on disk is replaced from now on.
    fn replace_image(&self) {
        self.probe.replaced.store(true, Ordering::SeqCst);
    }

    /// A connection the acceptor reported as coming from `peer`.
    pub(super) fn connect_as(&self, peer: PeerIdentity) -> DuplexStream {
        // Room for a whole request frame, so a client's single write never
        // waits on a server that has decided not to read.
        let (client, server) = tokio::io::duplex(2 * MAX_REQUEST_BYTES);
        tokio::spawn(<AdminPolicy as Policy<DuplexStream>>::serve(
            Arc::clone(&self.policy),
            server,
            peer,
            self.stop.subscribe(),
        ));
        client
    }

    /// A connection from the daemon's owner.
    pub(super) fn connect(&self) -> DuplexStream {
        self.connect_as(OWNER_PEER)
    }

    /// One whole client exchange from the owner.
    async fn exchange(&self, envelope: &Envelope) -> io::Result<Response> {
        let request = encode_request(envelope)?;
        exchange_on(&mut self.connect(), envelope, &request).await
    }

    async fn has_row(&self, id: &str) -> bool {
        self.store.get_request(id).await.unwrap().is_some()
    }
}

pub(super) fn hello(version: &str) -> Hello {
    Hello {
        proto: WIRE_PROTOCOL,
        version: version.to_owned(),
        via: Via::Direct,
    }
}

pub(super) async fn write(stream: &mut DuplexStream, frame: &Frame) {
    framed::send(stream, frame, MAX_REQUEST_BYTES)
        .await
        .unwrap();
}

/// The next frame the daemon sent.
pub(super) async fn read(stream: &mut DuplexStream) -> Frame {
    let body = framed::read_frame(stream, MAX_RESPONSE_BYTES)
        .await
        .unwrap();
    Frame::decode(&body).unwrap()
}

/// The `error` frame the daemon sent next.
pub(super) async fn read_error(stream: &mut DuplexStream) -> ErrorFrame {
    match read(stream).await {
        Frame::Error(error) => {
            assert!(!error.detail.is_empty() && !error.recovery.is_empty());
            error
        }
        other => panic!("expected an error frame, got {other:?}"),
    }
}

/// Everything the daemon wrote before it closed.
async fn rest(stream: &mut DuplexStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    bytes
}

pub(super) fn refusal_cause(response: &Response) -> &str {
    match response {
        Response::Refusal { cause, .. } => cause,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

pub(super) async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("test within deadline")
}

/// The envelope rules every adapter shares, as a table: only a waiting
/// `admin.*` request with a deadline inside `1..=MAX_REQUEST_MS` is carried.
#[test]
fn validate_envelope_limits_table() {
    let cases: [(&str, bool, u64, bool); 8] = [
        ("admin.status", true, 1, true),
        ("admin.status", true, MAX_REQUEST_MS, true),
        ("admin.status", true, 0, false),
        ("admin.status", true, MAX_REQUEST_MS + 1, false),
        ("admin.status", false, 1_000, false),
        ("status", true, 1_000, false),
        ("admin", true, 1_000, false),
        ("", true, 1_000, false),
    ];
    for (capability, wait, deadline_ms, accepted) in cases {
        let request = Envelope {
            wait,
            deadline_ms,
            ..admin_envelope("req_frame", capability)
        };
        let verdict = validate_envelope(&request);
        assert_eq!(
            verdict.is_ok(),
            accepted,
            "{capability:?} wait={wait} deadline={deadline_ms}: {verdict:?}"
        );
        if let Err(error) = verdict {
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }
    let oversized = Envelope {
        args: serde_json::json!({ "pad": "x".repeat(MAX_REQUEST_BYTES) }),
        ..admin_envelope("req_frame", "admin.status")
    };
    assert_eq!(
        encode_request(&oversized).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

/// Who is admitted, as a table: the daemon's own uid with a kernel pid on
/// Unix, the nonce holder on Windows, and nobody across the two.
#[test]
fn admission_is_the_operating_systems_word_about_the_peer() {
    let unix = |uid, pid| PeerIdentity::Unix { uid, gid: 20, pid };
    let cases = [
        (Admission::UnixOwner(OWNER), unix(OWNER, Some(1)), true),
        (Admission::UnixOwner(OWNER), unix(OWNER, None), false),
        (Admission::UnixOwner(OWNER), unix(OWNER + 1, Some(1)), false),
        (Admission::UnixOwner(OWNER), unix(0, Some(1)), false),
        (Admission::UnixOwner(OWNER), PeerIdentity::OwnerNonce, false),
        (Admission::OwnerNonce, PeerIdentity::OwnerNonce, true),
        (Admission::OwnerNonce, unix(OWNER, Some(1)), false),
    ];
    for (admission, peer, admitted) in cases {
        assert_eq!(admission.admits(&peer), admitted, "{admission:?} {peer:?}");
    }
}

/// `hello`, `hello_ack`, `request`, `reply`: the operation runs once and is recorded.
#[tokio::test]
async fn an_owner_request_is_answered_with_one_reply() {
    bounded(async {
        let plane = Plane::new().await;
        let request = profile_get("req_round_trip");
        let mut client = plane.connect();
        write(&mut client, &Frame::Hello(hello(&request.client_version))).await;
        let Frame::HelloAck(HelloAck {
            proto,
            version,
            epoch,
            pid,
        }) = read(&mut client).await
        else {
            panic!("expected hello_ack");
        };
        assert_eq!(proto, WIRE_PROTOCOL);
        assert_eq!(version, crate::daemon::DAEMON_VERSION);
        assert_eq!(epoch, plane.hub.epoch());
        assert_eq!(pid, std::process::id(), "the ack names the daemon process");
        write(
            &mut client,
            &Frame::Request {
                envelope: request.clone(),
            },
        )
        .await;
        let Frame::Reply { response } = read(&mut client).await else {
            panic!("expected reply");
        };
        assert!(
            matches!(&response, Response::Result { id, outcome: Outcome::Verified, .. } if id == &request.id),
            "{response:?}"
        );
        // One request per connection: the daemon closes after the reply.
        assert!(rest(&mut client).await.is_empty());
        assert!(plane.has_row(&request.id).await);

        // The client half speaks the same sequence.
        let response = plane.exchange(&profile_get("req_client")).await.unwrap();
        assert!(matches!(response, Response::Result { .. }), "{response:?}");
    })
    .await;
}

/// A peer the kernel does not name as the daemon's owner gets nothing: no
/// byte is written to it, its request is never read, and nothing is recorded.
#[tokio::test]
async fn a_peer_that_is_not_the_daemons_owner_is_closed_unanswered() {
    bounded(async {
        let plane = Plane::new().await;
        let forged = [
            PeerIdentity::Unix {
                uid: OWNER + 1,
                gid: 20,
                pid: Some(77),
            },
            // The right uid without a kernel pid is not an identified peer.
            PeerIdentity::Unix {
                uid: OWNER,
                gid: 20,
                pid: None,
            },
            // A nonce holder proves nothing to a Unix listener.
            PeerIdentity::OwnerNonce,
        ];
        for (index, peer) in forged.into_iter().enumerate() {
            let request = profile_get(&format!("req_forged_{index}"));
            let mut client = plane.connect_as(peer);
            // Everything a well-formed owner client would send.
            write(&mut client, &Frame::Hello(hello(&request.client_version))).await;
            write(
                &mut client,
                &Frame::Request {
                    envelope: request.clone(),
                },
            )
            .await;
            assert!(
                rest(&mut client).await.is_empty(),
                "{peer:?} was written to"
            );
            assert!(!plane.has_row(&request.id).await, "{peer:?} ran a request");

            // The client half reports it as a failed connection, not a reply.
            let encoded = encode_request(&request).unwrap();
            let outcome = exchange_on(&mut plane.connect_as(peer), &request, &encoded).await;
            assert!(outcome.is_err(), "{peer:?}: {outcome:?}");
            assert!(!plane.has_row(&request.id).await);
        }
        // The owner is still served.
        let response = plane.exchange(&profile_get("req_owner")).await.unwrap();
        assert!(matches!(response, Response::Result { .. }), "{response:?}");
    })
    .await;
}

/// What a pre-migration GUI does: one bare envelope frame out, one bare
/// response frame back, which must name the request.
async fn old_exchange(stream: &mut DuplexStream, envelope: &Envelope) -> Response {
    let encoded = serde_json::to_vec(envelope).unwrap();
    framed::write_frame(stream, &encoded, MAX_REQUEST_BYTES)
        .await
        .unwrap();
    let payload = framed::read_frame(stream, MAX_RESPONSE_BYTES)
        .await
        .unwrap();
    serde_json::from_slice(&payload).expect("a bare response, the old shape")
}

/// An old GUI process left running across the upgrade sends a bare envelope
/// as its first frame. It is answered in the shape it can display, told to
/// reopen PAM, and its operation does not run.
#[tokio::test]
async fn a_pre_migration_gui_is_answered_client_outdated_in_the_old_shape() {
    bounded(async {
        let plane = Plane::new().await;
        let small = Envelope {
            client_version: "0.4.3".to_owned(),
            ..profile_get("req_old_gui")
        };
        // An old GUI's first frame can be far larger than a hello.
        let large = Envelope {
            args: serde_json::json!({ "flow": "y".repeat(64 * MAX_HELLO_BYTES) }),
            ..admin_envelope("req_old_gui_large", "admin.flows.save")
        };
        for envelope in [small, large] {
            let mut client = plane.connect();
            let response = old_exchange(&mut client, &envelope).await;
            match &response {
                Response::Refusal {
                    id,
                    cause,
                    detail,
                    recovery,
                    retryable,
                } => {
                    assert_eq!(id, &envelope.id);
                    assert_eq!(cause, CAUSE_CLIENT_OUTDATED);
                    assert!(!retryable);
                    assert!(detail.contains(crate::daemon::DAEMON_VERSION), "{detail}");
                    assert!(
                        recovery.contains("Quit PAM and reopen it"),
                        "the human is told what to do: {recovery}"
                    );
                }
                other => panic!("expected a refusal, got {other:?}"),
            }
            assert!(rest(&mut client).await.is_empty(), "then the daemon closes");
            assert!(!plane.has_row(&envelope.id).await, "nothing ran");
        }
        assert_eq!(*plane.phase.borrow(), LifecyclePhase::Serving);

        // A first frame without "t" that is not an envelope is just a bad frame.
        let mut client = plane.connect();
        framed::write_frame(&mut client, br#"{"hello":"there"}"#, MAX_REQUEST_BYTES)
            .await
            .unwrap();
        assert_eq!(read_error(&mut client).await.cause, cause::BAD_FRAME);
    })
    .await;
}

/// The public plane's version rule, on the hello: a client of another build
/// is refused before its request is read, and the daemon restarts only when
/// its own binary on disk was replaced.
#[tokio::test]
async fn a_differing_hello_version_is_refused_and_only_a_replaced_image_restarts() {
    bounded(async {
        // Unchanged image: the client is refused, the daemon keeps serving.
        let plane = Plane::new().await;
        let request = Envelope {
            client_version: "9.9.9".to_owned(),
            ..profile_get("req_other_build")
        };
        let mut client = plane.connect();
        write(&mut client, &Frame::Hello(hello("9.9.9"))).await;
        write(
            &mut client,
            &Frame::Request {
                envelope: request.clone(),
            },
        )
        .await;
        let error = read_error(&mut client).await;
        assert_eq!(error.cause, cause::CLIENT_VERSION_MISMATCH);
        assert!(error.detail.contains("9.9.9"), "{}", error.detail);
        assert!(
            error.detail.contains(crate::daemon::DAEMON_VERSION),
            "{}",
            error.detail
        );
        assert!(rest(&mut client).await.is_empty(), "no hello_ack, no reply");
        assert_eq!(*plane.phase.borrow(), LifecyclePhase::Serving);
        assert!(!plane.has_row(&request.id).await);

        // The client half turns the refused hello into a refusal for the
        // request, which the GUI shows like any other; it is not retryable.
        let response = plane.exchange(&request).await.unwrap();
        assert!(
            matches!(&response, Response::Refusal { id, cause: named, retryable: false, .. }
                if id == &request.id && named == cause::CLIENT_VERSION_MISMATCH),
            "{response:?}"
        );
        // A matching client is still served by the same plane.
        let response = plane
            .exchange(&profile_get("req_same_build"))
            .await
            .unwrap();
        assert!(matches!(response, Response::Result { .. }), "{response:?}");

        // Replaced image: the daemon hands over, and says so.
        let plane = Plane::new().await;
        plane.replace_image();
        let response = plane.exchange(&request).await.unwrap();
        assert!(
            matches!(&response, Response::Refusal { id, cause: named, retryable: true, .. }
                if id == &request.id && named == cause::DAEMON_OUTDATED),
            "{response:?}"
        );
        assert_eq!(*plane.phase.borrow(), LifecyclePhase::Restarting);
        assert!(!plane.has_row(&request.id).await);

        // An equal version never looks at the image and is answered: while
        // the daemon restarts, with the shutting-down refusal as a reply.
        let response = plane
            .exchange(&profile_get("req_during_restart"))
            .await
            .unwrap();
        assert_eq!(refusal_cause(&response), cause::DAEMON_SHUTTING_DOWN);
    })
    .await;
}

/// A daemon that is draining still answers: a refusal frame for the request,
/// never a refused connect or a bare end of file, and nothing runs.
#[tokio::test]
async fn a_draining_daemon_answers_a_request_with_a_refusal_frame() {
    bounded(async {
        let plane = Plane::new().await;
        plane.phase.send_replace(LifecyclePhase::Draining);
        let request = profile_get("req_draining");
        let response = plane.exchange(&request).await.unwrap();
        assert!(
            matches!(&response, Response::Refusal { id, cause: named, retryable: true, .. }
                if id == &request.id && named == cause::DAEMON_SHUTTING_DOWN),
            "{response:?}"
        );
        assert!(!plane.has_row(&request.id).await);
    })
    .await;
}

/// The plane carries one waiting `admin.*` request or `events`; everything
/// else is refused by name and never reaches the service.
#[tokio::test]
async fn what_is_not_a_waiting_admin_request_is_refused_and_never_run() {
    bounded(async {
        let plane = Plane::new().await;
        let version = env!("CARGO_PKG_VERSION");

        // A public capability, a non-waiting request and an over-long id are
        // parsed requests: each gets a `reply` carrying `bad_request`.
        let public = admin_envelope("req_public_cap", "echo");
        let detached = Envelope {
            wait: false,
            ..profile_get("req_detached")
        };
        let long_id = profile_get(&"i".repeat(200));
        for envelope in [public, detached, long_id] {
            let mut client = plane.connect();
            write(&mut client, &Frame::Hello(hello(version))).await;
            assert!(matches!(read(&mut client).await, Frame::HelloAck(_)));
            write(
                &mut client,
                &Frame::Request {
                    envelope: envelope.clone(),
                },
            )
            .await;
            let Frame::Reply { response } = read(&mut client).await else {
                panic!("expected reply");
            };
            assert_eq!(refusal_cause(&response), "bad_request", "{response:?}");
            assert!(!plane.has_row(&envelope.id).await, "{} ran", envelope.id);
        }

        // An envelope that does not parse is still answered as a request,
        // naming the id it could salvage.
        let mut client = plane.connect();
        write(&mut client, &Frame::Hello(hello(version))).await;
        assert!(matches!(read(&mut client).await, Frame::HelloAck(_)));
        framed::write_frame(
            &mut client,
            br#"{"t":"request","envelope":{"id":"req_torn","capability":7}}"#,
            MAX_REQUEST_BYTES,
        )
        .await
        .unwrap();
        let Frame::Reply { response } = read(&mut client).await else {
            panic!("expected reply");
        };
        assert!(
            matches!(&response, Response::Refusal { id, cause: named, .. }
                if id == "req_torn" && named == "bad_request"),
            "{response:?}"
        );

        // A frame type the plane does not serve, the public plane's follow,
        // an unknown type and something that is not JSON are bad frames.
        let misplaced = br#"{"t":"hello_ack","proto":2,"version":"x","epoch":"y"}"#.as_slice();
        let follow = Frame::Follow(pam_proto::wire::Follow {
            envelope: profile_get("req_follow"),
            after_seq: 0,
            epoch: None,
        })
        .encode()
        .unwrap();
        for body in [
            misplaced,
            follow.as_slice(),
            br#"{"t":"mystery"}"#.as_slice(),
            b"not json".as_slice(),
        ] {
            let mut client = plane.connect();
            write(&mut client, &Frame::Hello(hello(version))).await;
            assert!(matches!(read(&mut client).await, Frame::HelloAck(_)));
            framed::write_frame(&mut client, body, MAX_REQUEST_BYTES)
                .await
                .unwrap();
            assert_eq!(read_error(&mut client).await.cause, cause::BAD_FRAME);
        }

        // A wire protocol this daemon does not speak is refused at the hello.
        let mut client = plane.connect();
        write(
            &mut client,
            &Frame::Hello(Hello {
                proto: WIRE_PROTOCOL + 1,
                ..hello(version)
            }),
        )
        .await;
        assert_eq!(
            read_error(&mut client).await.cause,
            cause::PROTOCOL_MISMATCH
        );
    })
    .await;
}

/// The frame budgets, in both directions: a length over the limit is refused
/// from its header alone. A peer that announced such a frame and never sent
/// its body is answered at once, which only happens if nothing waited to read
/// (and so nothing was allocated for) the body.
#[tokio::test]
async fn oversized_frames_are_refused_before_allocation_in_both_directions() {
    bounded(async {
        let plane = Plane::new().await;
        let version = env!("CARGO_PKG_VERSION");
        let over = |limit: usize| u32::try_from(limit + 1).unwrap().to_be_bytes();

        // Inbound, first frame: over the 1 MiB request budget.
        let mut client = plane.connect();
        client.write_all(&over(MAX_REQUEST_BYTES)).await.unwrap();
        let error = read_error(&mut client).await;
        assert_eq!(error.cause, cause::BAD_FRAME);
        assert!(error.detail.contains("outside"), "{}", error.detail);

        // Inbound, a hello over the 4 KiB hello budget (but under 1 MiB).
        let mut client = plane.connect();
        let fat = Frame::Hello(hello(version)).encode().unwrap();
        let mut padded = fat[..fat.len() - 1].to_vec();
        padded.extend_from_slice(br#","pad":""#);
        padded.extend(std::iter::repeat_n(b'x', MAX_HELLO_BYTES));
        padded.extend_from_slice(br#""}"#);
        framed::write_frame(&mut client, &padded, MAX_REQUEST_BYTES)
            .await
            .unwrap();
        assert_eq!(read_error(&mut client).await.cause, cause::BAD_FRAME);

        // Inbound, the request frame: header only, over the budget.
        let mut client = plane.connect();
        write(&mut client, &Frame::Hello(hello(version))).await;
        assert!(matches!(read(&mut client).await, Frame::HelloAck(_)));
        client.write_all(&over(MAX_REQUEST_BYTES)).await.unwrap();
        assert_eq!(read_error(&mut client).await.cause, cause::BAD_FRAME);

        // Outbound from the client: an over-budget request is refused before
        // anything is dialled.
        let request = Envelope {
            args: serde_json::json!({ "pad": "x".repeat(MAX_REQUEST_BYTES) }),
            ..profile_get("req_too_big")
        };
        assert_eq!(
            encode_request(&request).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        // Inbound to the client: a daemon that announces a reply over the
        // 16 MiB budget and never sends it. The client gives up on the header.
        let request = profile_get("req_fat_reply");
        let encoded = encode_request(&request).unwrap();
        let (mut client, mut daemon) = tokio::io::duplex(2 * MAX_REQUEST_BYTES);
        let acked = Frame::HelloAck(HelloAck {
            proto: WIRE_PROTOCOL,
            version: version.to_owned(),
            epoch: "01JB2M5T8Q0V7K3W9X4Y6Z1ABC".to_owned(),
            pid: std::process::id(),
        });
        framed::send(&mut daemon, &acked, MAX_REQUEST_BYTES)
            .await
            .unwrap();
        daemon.write_all(&over(MAX_RESPONSE_BYTES)).await.unwrap();
        let outcome = exchange_on(&mut client, &request, &encoded).await;
        assert_eq!(outcome.unwrap_err().kind(), io::ErrorKind::InvalidData);
        drop(daemon);
    })
    .await;
}

/// A reply that outgrew the response budget is replaced by a small refusal
/// carrying the request id: the op already ran and was audited, and the
/// client must learn that rather than see a transport failure.
#[test]
fn an_oversized_reply_becomes_a_small_refusal_naming_the_request() {
    let reply = |encoded: &[u8]| match Frame::decode(encoded).unwrap() {
        Frame::Reply { response } => response,
        other => panic!("expected a reply frame, got {other:?}"),
    };
    let small = Response::Result {
        id: "req_small".to_owned(),
        outcome: Outcome::Verified,
        body: serde_json::json!({ "ok": true }),
        evidence: Vec::new(),
    };
    let encoded = encode_reply("req_small", &small).unwrap();
    assert_eq!(reply(&encoded), small);

    let huge = Response::Result {
        id: "req_huge".to_owned(),
        outcome: Outcome::Verified,
        body: serde_json::json!({ "text": "x".repeat(MAX_RESPONSE_BYTES) }),
        evidence: Vec::new(),
    };
    let encoded = encode_reply("req_huge", &huge).unwrap();
    assert!(
        encoded.len() < 4096,
        "the substitute is small: {} bytes",
        encoded.len()
    );
    match reply(&encoded) {
        Response::Refusal {
            id, cause, detail, ..
        } => {
            assert_eq!(id, "req_huge");
            assert_eq!(cause, CAUSE_RESPONSE_TOO_LARGE);
            assert!(detail.contains("completed"), "{detail}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// What the client makes of each way a daemon can answer. Only a refused
/// hello is a refusal for the request (nothing ran); after the hello was
/// accepted, anything but the reply to this request is an error whose effect
/// is unknown.
#[tokio::test]
async fn the_client_reports_a_refused_hello_as_a_refusal_and_anything_later_as_an_error() {
    bounded(async {
        let request = profile_get("req_mapping");
        let encoded = encode_request(&request).unwrap();
        let ack = Frame::HelloAck(HelloAck {
            proto: WIRE_PROTOCOL,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            epoch: "01JB2M5T8Q0V7K3W9X4Y6Z1ABC".to_owned(),
            pid: std::process::id(),
        });
        let busy = Frame::error(cause::CONNECTION_CAPACITY_EXHAUSTED, "full", "Retry.");
        let other_id = Frame::Reply {
            response: Response::refusal("req_someone_else", "x", "y", "z"),
        };

        // A full listener answers instead of the hello: transient refusal.
        let (mut client, mut daemon) = tokio::io::duplex(64 * 1024);
        framed::send(&mut daemon, &busy, MAX_REQUEST_BYTES)
            .await
            .unwrap();
        let response = exchange_on(&mut client, &request, &encoded).await.unwrap();
        assert!(
            matches!(&response, Response::Refusal { id, cause: named, retryable: true, .. }
                if id == &request.id && named == cause::CONNECTION_CAPACITY_EXHAUSTED),
            "{response:?}"
        );

        // After the ack: an `error` frame, a reply for another request, a
        // frame of the wrong type and a bare end of file are all errors.
        let late_error = Frame::error(cause::BAD_FRAME, "no", "Reopen.");
        let wrong_type = Frame::follow_event(1, pam_proto::Event::Done);
        for (after_ack, kind) in [
            (Some(&late_error), io::ErrorKind::ConnectionAborted),
            (Some(&other_id), io::ErrorKind::InvalidData),
            (Some(&wrong_type), io::ErrorKind::InvalidData),
            (None, io::ErrorKind::UnexpectedEof),
        ] {
            let (mut client, mut daemon) = tokio::io::duplex(64 * 1024);
            framed::send(&mut daemon, &ack, MAX_REQUEST_BYTES)
                .await
                .unwrap();
            if let Some(frame) = after_ack {
                framed::send(&mut daemon, frame, MAX_REQUEST_BYTES)
                    .await
                    .unwrap();
            }
            // The daemon read nothing and is gone: the client's write may
            // fail too, and the answer already on the wire still decides.
            drop(daemon);
            let outcome = exchange_on(&mut client, &request, &encoded).await;
            assert_eq!(outcome.unwrap_err().kind(), kind, "{after_ack:?}");
        }
    })
    .await;
}

/// The administration listener on the shared accept loop: descriptor
/// exhaustion and every other accept error are survived, and the owner is
/// served afterwards. The loop used to end on the first one.
#[tokio::test]
async fn the_admin_policy_keeps_serving_after_accept_errors() {
    bounded(async {
        let plane = Plane::new().await;
        let (acceptor, dialer) = scripted();
        let listener = Listener::spawn(acceptor, Arc::clone(&plane.policy));
        dialer.fail(too_many_open_files());
        dialer.fail(io::Error::from(io::ErrorKind::ConnectionAborted));
        dialer.fail(io::Error::from(io::ErrorKind::Interrupted));
        dialer.fail(io::Error::from(io::ErrorKind::OutOfMemory));
        dialer.fail(io::Error::other("something new"));
        for id in ["req_after_errors", "req_again"] {
            let request = profile_get(id);
            let encoded = encode_request(&request).unwrap();
            let mut client = dialer.connect_as(OWNER_PEER);
            let response = exchange_on(&mut client, &request, &encoded).await.unwrap();
            assert!(
                matches!(&response, Response::Result { id: got, .. } if got == id),
                "{response:?}"
            );
        }
        // A stranger arriving through the same loop is still refused.
        let mut stranger = dialer.connect();
        assert!(rest(&mut stranger).await.is_empty());
        listener.shutdown().await;
        assert!(dialer.closed(), "shutdown closes the endpoint");
    })
    .await;
}
