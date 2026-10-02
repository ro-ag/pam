//! The framed public listener against a real daemon: hello, one request, one
//! reply, dialled with the client primitives of [`pam_daemon::framed`] on
//! [`pam_daemon::runtime_dir::RuntimeDir::public_socket`].
//!
//! What is asserted here is what a client and an auditor can observe: the
//! frames on the wire, the request and audit rows, the lifecycle phase, and
//! the listener's permits. The follow stream has its own file
//! (`public_follow.rs`).

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use pam_daemon::admin::CAUSE_ADMIN_DENIED;
use pam_daemon::daemon::{
    CAUSE_DAEMON_OUTDATED, DAEMON_VERSION, DaemonConfig, DaemonHandle, WORK_SLOTS,
};
use pam_daemon::framed::{self, DialError, MAX_PUBLIC_CONNECTIONS, PublicStream};
use pam_daemon::image::{FileFacts, ImageProbe, RECHECK_INTERVAL};
use pam_daemon::lifecycle::LifecyclePhase;
use pam_daemon::queue::ACTION_CANCEL;
use pam_proto::wire::{Frame, Hello, MAX_FRAME_BYTES, MAX_HELLO_BYTES, Via, WIRE_PROTOCOL, cause};
use pam_proto::{Envelope, Outcome, Response};
use pam_store::{Actor, RequestIngress, RequestState};
use pam_testkit::{
    TestDaemon, envelope_for_repo, seed_relaxed, seed_repository_scope, short_tempdir,
    with_deadline,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A real daemon with the relaxed profile and one approved repository, so
/// scoped reads (`query`) succeed for requests admitted under it.
struct Fixture {
    daemon: TestDaemon,
    repo: tempfile::TempDir,
}

impl Fixture {
    async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    async fn start_with(mutate: impl FnOnce(&mut DaemonConfig)) -> Self {
        let tmp = short_tempdir();
        seed_relaxed(&tmp).await;
        let repo = tempfile::tempdir().expect("a repository directory");
        seed_repository_scope(&tmp, repo.path(), &[]).await;
        let daemon = TestDaemon::spawn_at_with(tmp, mutate).await;
        Self { daemon, repo }
    }

    fn handle(&self) -> &DaemonHandle {
        self.daemon.handle()
    }

    /// The approved repository as admission records it.
    fn repo(&self) -> String {
        self.repo
            .path()
            .canonicalize()
            .expect("the repository exists")
            .to_string_lossy()
            .into_owned()
    }

    fn envelope(
        &self,
        id: &str,
        capability: &str,
        args: serde_json::Value,
        wait: bool,
    ) -> Envelope {
        envelope_for_repo(&self.repo(), id, capability, args, wait)
    }

    async fn dial(&self) -> PublicStream {
        framed::connect_public(self.handle().runtime_dir())
            .await
            .expect("the public listener accepts")
    }

    /// One unary call as this build's client makes it.
    async fn call(&self, envelope: &Envelope) -> Response {
        self.call_as(&framed::client_hello(Via::Direct), envelope)
            .await
            .expect("the daemon answers")
    }

    async fn call_as(&self, hello: &Hello, envelope: &Envelope) -> Result<Response, DialError> {
        let mut stream = self.dial().await;
        framed::call(&mut stream, hello, envelope, MAX_FRAME_BYTES)
            .await
            .map(|(_, response)| response)
    }
}

/// Polls `check` until it holds, panicking legibly when it never does.
async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !check().await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "never happened: {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn refusal(response: &Response) -> (&str, bool) {
    match response {
        Response::Refusal {
            cause, retryable, ..
        } => (cause.as_str(), *retryable),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn hello_claiming(version: &str) -> Hello {
    Hello {
        proto: WIRE_PROTOCOL,
        version: version.to_owned(),
        via: Via::Direct,
    }
}

/// Writes one frame the way a client would, without the dial helpers.
async fn write(stream: &mut PublicStream, frame: &Frame, maximum: usize) {
    let body = frame.encode().expect("the frame encodes");
    framed::write_frame(stream, &body, maximum)
        .await
        .expect("the frame is written");
}

/// Sends this build's hello and returns once the daemon acknowledged it.
async fn greet(stream: &mut PublicStream) {
    write(
        stream,
        &Frame::Hello(framed::client_hello(Via::Direct)),
        MAX_HELLO_BYTES,
    )
    .await;
    let ack = framed::read_daemon_frame(stream, MAX_HELLO_BYTES)
        .await
        .expect("the hello is acknowledged");
    assert!(matches!(ack, Frame::HelloAck(_)), "{ack:?}");
}

#[tokio::test]
async fn a_request_round_trips_and_its_row_records_the_public_peer() {
    with_deadline(async {
        let fixture = Fixture::start().await;
        let store = fixture.daemon.store();

        let args = serde_json::json!({ "msg": "hi" });
        let request = fixture.envelope("req_framed", "echo", args.clone(), true);
        let mut stream = fixture.dial().await;
        let (ack, response) = framed::call(
            &mut stream,
            &framed::client_hello(Via::Direct),
            &request,
            MAX_FRAME_BYTES,
        )
        .await
        .expect("the daemon answers");

        // The hello is answered with the daemon's version and its epoch.
        assert_eq!(ack.proto, WIRE_PROTOCOL);
        assert_eq!(ack.version, DAEMON_VERSION);
        assert_eq!(ack.epoch, fixture.handle().event_hub().epoch());
        let Response::Result {
            id, outcome, body, ..
        } = response
        else {
            panic!("expected a result, got {response:?}");
        };
        assert_eq!(id, "req_framed");
        assert_eq!(outcome, Outcome::Solved);
        assert_eq!(body, serde_json::json!({ "echo": args }));
        // One request per connection: the daemon closed it after the reply.
        let mut rest = [0u8; 1];
        assert!(matches!(stream.read(&mut rest).await, Ok(0) | Err(_)));

        let row = store.get_request("req_framed").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Done);
        assert_eq!(row.origin.ingress, RequestIngress::Public);
        assert!(!row.origin.relayed);
        #[cfg(unix)]
        {
            // The kernel's view of this very process, not anything it said.
            let own = pam_daemon::framed_unix::own_identity().expect("own identity");
            assert_eq!(row.origin.peer_uid, own.uid());
            assert_eq!(row.origin.peer_pid, Some(std::process::id()));
            assert_ne!(row.origin.peer_pid, Some(request.caller.pid));
        }

        // A client that says it came through a relay is recorded as such;
        // the peer is still whoever the kernel saw.
        let relayed = fixture.envelope("req_relayed", "echo", serde_json::json!({}), true);
        fixture
            .call_as(&framed::client_hello(Via::Relay), &relayed)
            .await
            .expect("the daemon answers");
        let row = store.get_request("req_relayed").await.unwrap().unwrap();
        assert!(row.origin.relayed);
        #[cfg(unix)]
        assert_eq!(row.origin.peer_pid, Some(std::process::id()));

        // The envelope's own version decides nothing on this plane: the
        // hello did.
        let mut stale = fixture.envelope("req_stale_field", "echo", serde_json::json!({}), true);
        stale.client_version = "0.0.1".to_owned();
        assert!(matches!(
            fixture.call(&stale).await,
            Response::Result { .. }
        ));

        fixture.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn admin_operations_are_refused_on_the_public_socket_before_any_row() {
    with_deadline(async {
        let fixture = Fixture::start().await;
        let store = fixture.daemon.store();

        // Even claiming to be the GUI.
        let mut request = fixture.envelope(
            "req_admin_public",
            "admin.grants.list",
            serde_json::json!({}),
            true,
        );
        request.caller.agent = "pam-gui".to_owned();
        let response = fixture.call(&request).await;
        assert_eq!(refusal(&response), (CAUSE_ADMIN_DENIED, false));

        assert!(
            store
                .get_request("req_admin_public")
                .await
                .unwrap()
                .is_none(),
            "an admin envelope on the public socket must not be recorded"
        );
        assert!(
            store
                .audit_for_request("req_admin_public")
                .await
                .unwrap()
                .is_empty()
        );
        // And the daemon keeps serving.
        let echo = fixture.envelope("req_after_admin", "echo", serde_json::json!({}), true);
        assert!(matches!(fixture.call(&echo).await, Response::Result { .. }));

        fixture.daemon.stop().await;
    })
    .await;
}

/// The audit actor follows the plane a request arrived on. A public client
/// that calls itself the GUI is still a public client.
#[tokio::test]
async fn a_self_reported_gui_label_does_not_change_the_audit_actor() {
    with_deadline(async {
        let fixture = Fixture::start().await;
        let store = fixture.daemon.store();

        // One echo holds the repository's lane; a second queues behind it.
        let holder = fixture.envelope(
            "req_holder",
            "echo",
            serde_json::json!({ "delay_ms": 20_000, "n": 1 }),
            false,
        );
        assert!(matches!(
            fixture.call(&holder).await,
            Response::Ticket { .. }
        ));
        let queued = fixture.envelope(
            "req_queued",
            "echo",
            serde_json::json!({ "delay_ms": 20_000, "n": 2 }),
            false,
        );
        assert!(matches!(
            fixture.call(&queued).await,
            Response::Ticket { .. }
        ));
        eventually("the second echo is queued", || async {
            store
                .get_request("req_queued")
                .await
                .unwrap()
                .is_some_and(|row| row.state == RequestState::Queued)
        })
        .await;

        // The queue writes a queued cancellation's audit row itself, as
        // whoever the cancel acted as.
        let mut cancel = fixture.envelope(
            "req_cancel_labelled",
            "cancel",
            serde_json::json!({ "ticket": "req_queued" }),
            true,
        );
        cancel.caller.agent = "pam-gui".to_owned();
        let response = fixture.call(&cancel).await;
        let Response::Result { body, .. } = &response else {
            panic!("expected a result, got {response:?}");
        };
        assert_eq!(body["result"], "cancelled_queued");

        let audit = store.audit_for_request("req_queued").await.unwrap();
        let cancelled: Vec<_> = audit
            .iter()
            .filter(|row| row.action == ACTION_CANCEL)
            .collect();
        assert_eq!(cancelled.len(), 1, "{audit:?}");
        assert_eq!(
            cancelled[0].actor,
            Actor::System,
            "a label on the public socket never makes an actor human"
        );
        // The cancel itself is on record as public, from this process.
        let row = store
            .get_request("req_cancel_labelled")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.origin.ingress, RequestIngress::Public);
        assert_eq!(row.caller_agent, "pam-gui");
        #[cfg(unix)]
        assert_eq!(row.origin.peer_pid, Some(std::process::id()));

        let stop = fixture.envelope(
            "req_cancel_holder",
            "cancel",
            serde_json::json!({ "ticket": "req_holder" }),
            true,
        );
        let _ = fixture.call(&stop).await;
        fixture.daemon.stop().await;
    })
    .await;
}

/// A probe over one scripted file: the daemon's own executable as a test
/// wants it to look.
#[derive(Default)]
struct ScriptedImage {
    /// Bumped to make the file at every path look replaced.
    generation: AtomicU64,
}

impl ImageProbe for ScriptedImage {
    fn facts(&self, path: &Path) -> Option<FileFacts> {
        let generation = self.generation.load(Ordering::SeqCst);
        Some(FileFacts {
            canonical: path.to_path_buf(),
            len: 1_000 + generation,
            modified: None,
            identity: Some((1, 42 + generation)),
        })
    }
}

fn refused(result: Result<Response, DialError>) -> pam_proto::wire::ErrorFrame {
    match result {
        Err(DialError::Refused(error)) => error,
        other => panic!("expected the hello to be refused, got {other:?}"),
    }
}

#[tokio::test]
async fn a_version_claim_is_refused_at_the_hello_and_only_a_replaced_binary_restarts() {
    with_deadline(async {
        let image = Arc::new(ScriptedImage::default());
        let probe = Arc::clone(&image);
        let fixture = Fixture::start_with(move |config| config.image_probe = Some(probe)).await;
        let store = fixture.daemon.store();
        let lifecycle = fixture.handle().lifecycle();
        let boot_path = fixture
            .handle()
            .boot_image_path()
            .expect("the platform names the test binary");

        // The binary on disk is the one running: whatever a client claims,
        // it is refused at the hello, nothing moves, nothing is recorded.
        for (index, claimed) in ["9.9.9", "0.0.1", "not a version"].into_iter().enumerate() {
            let id = format!("req_claim_{index}");
            let request = fixture.envelope(&id, "echo", serde_json::json!({}), true);
            let error = refused(fixture.call_as(&hello_claiming(claimed), &request).await);
            assert_eq!(error.cause, cause::CLIENT_VERSION_MISMATCH);
            assert!(error.detail.contains(claimed), "{}", error.detail);
            assert!(error.detail.contains(DAEMON_VERSION), "{}", error.detail);
            assert!(
                error.detail.contains(&boot_path.display().to_string()),
                "the refusal names the daemon's executable: {}",
                error.detail
            );
            assert_eq!(*lifecycle.borrow(), LifecyclePhase::Serving);
            assert!(
                store.get_request(&id).await.unwrap().is_none(),
                "a refused hello records no request row"
            );
        }
        // A wire protocol this daemon does not speak is refused the same way.
        let future = Hello {
            proto: WIRE_PROTOCOL + 1,
            ..framed::client_hello(Via::Direct)
        };
        let request = fixture.envelope("req_proto", "echo", serde_json::json!({}), true);
        let error = refused(fixture.call_as(&future, &request).await);
        assert_eq!(error.cause, cause::PROTOCOL_MISMATCH);
        assert!(store.get_request("req_proto").await.unwrap().is_none());

        // A matching client is still served.
        let request = fixture.envelope("req_same_build", "echo", serde_json::json!({}), true);
        assert!(matches!(
            fixture.call(&request).await,
            Response::Result { .. }
        ));

        // Now the binary really is replaced (the re-check is cached for a
        // second). The next differing hello finds it and hands over.
        image.generation.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(RECHECK_INTERVAL + Duration::from_millis(100)).await;
        let request = fixture.envelope("req_newer", "echo", serde_json::json!({}), true);
        let error = refused(fixture.call_as(&hello_claiming("9.9.9"), &request).await);
        assert_eq!(error.cause, cause::DAEMON_OUTDATED);
        assert_eq!(*lifecycle.borrow(), LifecyclePhase::Restarting);
        assert!(store.get_request("req_newer").await.unwrap().is_none());

        // While it restarts, a client of the old build is told to wait for
        // the replacement — as a refusal it can retry, not a closed socket.
        let request = fixture.envelope("req_during_restart", "echo", serde_json::json!({}), true);
        let response = fixture.call(&request).await;
        assert_eq!(refusal(&response), (CAUSE_DAEMON_OUTDATED, true));

        // The daemon started its own drain; joining it is enough.
        fixture.daemon.join().await;
    })
    .await;
}

#[tokio::test]
async fn a_legacy_zmtp_greeting_is_closed_and_the_daemon_keeps_serving() {
    with_deadline(async {
        let fixture = Fixture::start().await;
        // The path a pre-migration client dials is the one this daemon serves.
        #[cfg(unix)]
        assert_eq!(
            fixture.handle().runtime_dir().public_socket().file_name(),
            Some(std::ffi::OsStr::new("pam.sock"))
        );

        // What a pre-migration DEALER sends the moment it connects.
        let mut greeting = [0u8; 64];
        greeting[0] = 0xFF;
        greeting[8] = 0x01;
        greeting[9] = 0x7F;
        greeting[10] = 3;
        greeting[12..16].copy_from_slice(b"NULL");
        for _ in 0..3 {
            let mut stream = fixture.dial().await;
            // The daemon may close before the whole greeting is written.
            let _ = stream.write_all(&greeting).await;
            let mut answer = [0u8; 64];
            // Nothing is spoken back: not a frame, not a greeting.
            assert!(
                matches!(stream.read(&mut answer).await, Ok(0) | Err(_)),
                "a ZMTP greeting must be closed unanswered"
            );
        }
        eventually("the legacy connections were released", || async {
            fixture.handle().public_connections_available() == MAX_PUBLIC_CONNECTIONS
        })
        .await;

        let request = fixture.envelope("req_after_zmtp", "echo", serde_json::json!({}), true);
        assert!(matches!(
            fixture.call(&request).await,
            Response::Result { .. }
        ));

        fixture.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn a_client_that_disconnects_mid_request_frees_its_permit_and_the_work_completes() {
    with_deadline(async {
        let fixture = Fixture::start().await;
        let store = fixture.daemon.store();
        let handle = fixture.handle();

        let request = fixture.envelope(
            "req_abandoned",
            "echo",
            serde_json::json!({ "delay_ms": 2_500 }),
            true,
        );
        let mut stream = fixture.dial().await;
        framed::open(
            &mut stream,
            &framed::client_hello(Via::Direct),
            &Frame::Request {
                envelope: request.clone(),
            },
        )
        .await
        .expect("the hello is acknowledged");
        eventually("the request is in flight", || async {
            store
                .get_request("req_abandoned")
                .await
                .unwrap()
                .is_some_and(|row| row.state == RequestState::Running)
        })
        .await;
        assert_eq!(
            handle.public_connections_available(),
            MAX_PUBLIC_CONNECTIONS - 1
        );
        assert_eq!(handle.admission_available().work, WORK_SLOTS - 1);

        // The client goes away without its answer.
        drop(stream);
        eventually("the connection permit is released", || async {
            handle.public_connections_available() == MAX_PUBLIC_CONNECTIONS
        })
        .await;
        eventually("the parked handler lets go of its slot", || async {
            handle.admission_available().work == WORK_SLOTS
        })
        .await;
        let row = store.get_request("req_abandoned").await.unwrap().unwrap();
        assert!(
            !row.state.is_terminal(),
            "a disconnect must not end the work: {row:?}"
        );

        // The work finishes on its own and is readable by ticket.
        eventually("the abandoned request finishes", || async {
            store
                .get_request("req_abandoned")
                .await
                .unwrap()
                .is_some_and(|row| row.state == RequestState::Done)
        })
        .await;
        let query = fixture.envelope(
            "req_query_abandoned",
            "query",
            serde_json::json!({ "ticket": "req_abandoned" }),
            true,
        );
        let response = fixture.call(&query).await;
        let Response::Result { body, .. } = &response else {
            panic!("expected a result, got {response:?}");
        };
        assert_eq!(body["state"], "done");
        assert_eq!(body["outcome"], "solved");
        let audit = store.audit_for_request("req_abandoned").await.unwrap();
        assert!(
            audit.iter().all(|row| row.action != ACTION_CANCEL),
            "a disconnect must not be recorded as a cancellation: {audit:?}"
        );

        fixture.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn an_oversized_frame_is_refused_from_its_header_alone() {
    with_deadline(async {
        let fixture = Fixture::start().await;
        let patience = Duration::from_secs(2);

        // A request frame one byte over the limit: only the header is sent.
        // The refusal arrives well inside the handshake timeout, so the
        // daemon decided from the header and never waited for a body.
        let mut stream = fixture.dial().await;
        greet(&mut stream).await;
        let announced = u32::try_from(MAX_FRAME_BYTES + 1).unwrap();
        stream.write_all(&announced.to_be_bytes()).await.unwrap();
        let answer = tokio::time::timeout(
            patience,
            framed::read_daemon_frame(&mut stream, MAX_FRAME_BYTES),
        )
        .await
        .expect("refused without waiting for the body");
        let Err(DialError::Refused(error)) = answer else {
            panic!("expected error bad_frame, got {answer:?}");
        };
        assert_eq!(error.cause, cause::BAD_FRAME);

        // The same for a hello over 4 KiB, and for a zero-length frame.
        for announced in [u32::try_from(MAX_HELLO_BYTES + 1).unwrap(), 0] {
            let mut stream = fixture.dial().await;
            stream.write_all(&announced.to_be_bytes()).await.unwrap();
            let answer = tokio::time::timeout(
                patience,
                framed::read_daemon_frame(&mut stream, MAX_FRAME_BYTES),
            )
            .await
            .expect("refused without waiting for the body");
            let Err(DialError::Refused(error)) = answer else {
                panic!("expected error bad_frame, got {answer:?}");
            };
            assert_eq!(error.cause, cause::BAD_FRAME);
        }

        eventually("the refused connections were released", || async {
            fixture.handle().public_connections_available() == MAX_PUBLIC_CONNECTIONS
        })
        .await;
        fixture.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn malformed_requests_keep_their_shapes_and_leave_no_row() {
    with_deadline(async {
        let fixture = Fixture::start().await;
        let store = fixture.daemon.store();

        // Not JSON: there is no request to answer.
        let mut stream = fixture.dial().await;
        greet(&mut stream).await;
        framed::write_frame(&mut stream, b"not json", MAX_FRAME_BYTES)
            .await
            .unwrap();
        let answer = framed::read_daemon_frame(&mut stream, MAX_FRAME_BYTES).await;
        let Err(DialError::Refused(error)) = answer else {
            panic!("expected error bad_frame, got {answer:?}");
        };
        assert_eq!(error.cause, cause::BAD_FRAME);

        // A request whose envelope does not parse: a `bad_request` refusal
        // that still names the request it answers.
        let mut stream = fixture.dial().await;
        greet(&mut stream).await;
        let body = br#"{"t":"request","envelope":{"id":"req_salvaged","capability":7}}"#;
        framed::write_frame(&mut stream, body, MAX_FRAME_BYTES)
            .await
            .unwrap();
        let answer = framed::read_daemon_frame(&mut stream, MAX_FRAME_BYTES)
            .await
            .expect("a reply frame");
        let Frame::Reply { response } = answer else {
            panic!("expected a reply, got {answer:?}");
        };
        assert_eq!(refusal(&response), ("bad_request", false));
        assert_eq!(response.id(), "req_salvaged");
        assert!(store.get_request("req_salvaged").await.unwrap().is_none());

        // An envelope over its field limits is refused before it is retained.
        let mut huge = fixture.envelope("req_long_label", "echo", serde_json::json!({}), true);
        huge.caller.agent = "a".repeat(129);
        assert_eq!(refusal(&fixture.call(&huge).await), ("bad_request", false));
        assert!(store.get_request("req_long_label").await.unwrap().is_none());

        // The envelope's `client_version` decides nothing any more, but it is
        // caller-chosen text that is stored: bounded like every other field.
        let mut versioned =
            fixture.envelope("req_long_version", "echo", serde_json::json!({}), true);
        versioned.client_version = "9".repeat(129);
        assert_eq!(
            refusal(&fixture.call(&versioned).await),
            ("bad_request", false)
        );
        assert!(
            store
                .get_request("req_long_version")
                .await
                .unwrap()
                .is_none()
        );
        // At the limit it is carried to the daemon core and served.
        let mut carried = fixture.envelope("req_ok_version", "echo", serde_json::json!({}), true);
        carried.client_version = "9".repeat(128);
        assert!(matches!(
            fixture.call(&carried).await,
            Response::Result { .. }
        ));
        let row = store.get_request("req_ok_version").await.unwrap().unwrap();
        assert_eq!(row.origin.ingress, RequestIngress::Public);

        // The all-events stream belongs to the private plane.
        let mut stream = fixture.dial().await;
        let answer = framed::open(
            &mut stream,
            &framed::client_hello(Via::Direct),
            &Frame::Events,
        )
        .await;
        assert!(answer.is_ok(), "the hello itself is fine: {answer:?}");
        let answer = framed::read_daemon_frame(&mut stream, MAX_FRAME_BYTES).await;
        let Err(DialError::Refused(error)) = answer else {
            panic!("expected error bad_frame, got {answer:?}");
        };
        assert_eq!(error.cause, cause::BAD_FRAME);

        // Bytes after the one request are a protocol error; the request
        // itself is not cancelled.
        let slow = fixture.envelope(
            "req_chatty",
            "echo",
            serde_json::json!({ "delay_ms": 300 }),
            true,
        );
        let mut stream = fixture.dial().await;
        framed::open(
            &mut stream,
            &framed::client_hello(Via::Direct),
            &Frame::Request { envelope: slow },
        )
        .await
        .unwrap();
        stream.write_all(b"more").await.unwrap();
        let answer = framed::read_daemon_frame(&mut stream, MAX_FRAME_BYTES).await;
        let Err(DialError::Refused(error)) = answer else {
            panic!("expected error bad_frame, got {answer:?}");
        };
        assert_eq!(error.cause, cause::BAD_FRAME);
        eventually("the request still finishes", || async {
            store
                .get_request("req_chatty")
                .await
                .unwrap()
                .is_some_and(|row| row.state == RequestState::Done)
        })
        .await;

        fixture.daemon.stop().await;
    })
    .await;
}

/// The drain: a waiting request in flight when shutdown starts is answered
/// with a frame, and the listener leaves nothing behind.
#[tokio::test]
async fn shutdown_flushes_the_in_flight_reply_and_removes_the_socket() {
    with_deadline(async {
        let fixture = Fixture::start_with(|config| {
            config.drain_timeout = Duration::from_millis(200);
        })
        .await;
        let store = fixture.daemon.store();
        let dirs = fixture.handle().runtime_dir().clone();
        let hub = fixture.handle().event_hub();
        hub.publish("req_early", pam_proto::Event::Queued)
            .expect("a serving daemon's hub takes events");

        let request = fixture.envelope(
            "req_draining",
            "echo",
            serde_json::json!({ "delay_ms": 20_000 }),
            true,
        );
        let mut stream = fixture.dial().await;
        framed::open(
            &mut stream,
            &framed::client_hello(Via::Direct),
            &Frame::Request { envelope: request },
        )
        .await
        .expect("the hello is acknowledged");
        eventually("the request is in flight", || async {
            store
                .get_request("req_draining")
                .await
                .unwrap()
                .is_some_and(|row| row.state == RequestState::Running)
        })
        .await;

        let reader =
            tokio::spawn(
                async move { framed::read_daemon_frame(&mut stream, MAX_FRAME_BYTES).await },
            );
        let Fixture {
            daemon,
            repo: _repo,
        } = fixture;
        daemon.stop().await;

        // A reply frame — a result or a refusal — never a bare end of file.
        let answer = reader.await.unwrap().expect("a frame, not end of file");
        let Frame::Reply { response } = answer else {
            panic!("expected a reply, got {answer:?}");
        };
        assert_eq!(response.id(), "req_draining");
        assert!(matches!(response, Response::Refusal { .. }), "{response:?}");

        #[cfg(unix)]
        assert!(
            !dirs.public_socket().exists(),
            "the socket file is unlinked at shutdown"
        );
        #[cfg(windows)]
        assert!(
            !dirs.public_control().exists(),
            "the control file is removed at shutdown"
        );
        assert!(framed::connect_public(&dirs).await.is_err());
        // The hub went with the transport: a late publish is an error the
        // publisher can see, not an event queued for nobody.
        assert!(hub.publish("req_late", pam_proto::Event::Done).is_err());
    })
    .await;
}

/// The run directory of a base an older daemon used: its event broadcast
/// socket, and the socket name the framed listener had during development,
/// are removed at bind (under the instance lock), and the public socket is
/// served at `pam.sock`, replacing the dead one of that name.
#[cfg(unix)]
#[tokio::test]
async fn socket_files_an_older_daemon_left_are_removed_at_bind() {
    use std::os::unix::fs::FileTypeExt;

    with_deadline(async {
        let tmp = short_tempdir();
        seed_relaxed(&tmp).await;
        let run = pam_testkit::base_of(&tmp).join("run");
        std::fs::create_dir_all(&run).expect("the run directory");
        // The daemon serves the canonical base (`/tmp` is a link on macOS).
        let run = run.canonicalize().expect("the run directory exists");
        // Dead sockets, as a daemon that did not exit cleanly leaves them.
        for name in ["pam.sock", "events.sock", "pam.next.sock"] {
            drop(std::os::unix::net::UnixListener::bind(run.join(name)).expect("a stale socket"));
            assert!(run.join(name).exists());
        }

        let daemon = TestDaemon::spawn_at(tmp).await;
        let dirs = daemon.handle().runtime_dir().clone();
        assert_eq!(dirs.public_socket(), run.join("pam.sock"));
        assert!(
            std::fs::metadata(dirs.public_socket())
                .expect("the public socket")
                .file_type()
                .is_socket()
        );
        assert!(!run.join("events.sock").exists(), "events.sock is gone");
        assert!(!run.join("pam.next.sock").exists(), "pam.next.sock is gone");
        // Only what this daemon serves is left: its socket and its lock.
        let mut entries: Vec<String> = std::fs::read_dir(&run)
            .expect("the run directory lists")
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        assert_eq!(entries, ["daemon.lock", "pam.sock"]);

        // And it is this daemon that answers there.
        let mut stream = framed::connect_public(&dirs).await.expect("connect");
        greet(&mut stream).await;

        daemon.stop().await;
        assert!(!run.join("pam.sock").exists());
    })
    .await;
}
