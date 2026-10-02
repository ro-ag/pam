//! Both planes of one real daemon at once: a work request arrives on the
//! framed public socket while a public follower and an administration
//! all-events subscriber watch it, and the daemon is stopped under all three.
//!
//! Each half has its own suite (`public_transport.rs`, `public_follow.rs`,
//! `admin_events.rs`). What is asserted here is what only shows when the two
//! are served together: one hub and one epoch behind both listeners, the same
//! lifecycle seen content-free on one plane and whole on the other, the plane
//! and the kernel's peer on the request rows, control requests in neither
//! stream, and one drain that answers both planes before either endpoint
//! goes away.
#![cfg(any(unix, windows))]

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use pam_daemon::admin_transport::{self, AdminEvents};
use pam_daemon::daemon::DaemonConfig;
use pam_daemon::event_hub::PUBLIC_PROGRESS_NOTE;
use pam_daemon::framed::{self, DialError, FrameReader, PublicStream};
use pam_daemon::image::{FileFacts, ImageProbe, RECHECK_INTERVAL};
use pam_daemon::lifecycle::LifecyclePhase;
use pam_daemon::runtime_dir::RuntimeDir;
use pam_proto::wire::{
    End, ErrorFrame, EventFrame, Following, Frame, Hello, Ingress, MAX_FRAME_BYTES, Via, cause,
};
use pam_proto::{Envelope, Event, Outcome, Response};
use pam_store::{RequestIngress, RequestState};
use pam_testkit::{
    TestDaemon, envelope_for_repo, seed_relaxed, seed_repository_scope, short_tempdir,
    with_deadline,
};
use serde_json::json;

/// Every wait on a frame is bounded by this, far under the follow's
/// fifteen-second store re-check: a stream that only ends because of that
/// backstop fails the test.
const PATIENCE: Duration = Duration::from_secs(8);

/// What a flow step would publish: prose that names private things.
const REAL_NOTE: &str = "step build: cargo test in /private/repo";

/// A real daemon with the relaxed profile and one approved repository.
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

    fn dirs(&self) -> RuntimeDir {
        self.daemon.handle().runtime_dir().clone()
    }

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

    /// An administration envelope as the GUI sends one.
    fn admin(&self, id: &str, operation: &str, args: serde_json::Value) -> Envelope {
        let mut envelope = self.envelope(id, operation, args, true);
        "pam-gui".clone_into(&mut envelope.caller.agent);
        envelope
    }
}

/// One unary call over the framed public socket.
async fn call(dirs: &RuntimeDir, envelope: &Envelope) -> Result<Response, DialError> {
    let mut stream = framed::connect_public(dirs).await?;
    let hello = framed::client_hello(Via::Direct);
    framed::call(&mut stream, &hello, envelope, MAX_FRAME_BYTES)
        .await
        .map(|(_, response)| response)
}

/// One follow connection, client side, read the way a client reads it: with
/// a [`FrameReader`], so a read that sits under a timeout keeps its place.
struct Follower {
    stream: PublicStream,
    reader: FrameReader,
    /// The epoch the hello was acknowledged under.
    epoch: String,
}

impl Follower {
    async fn open(dirs: &RuntimeDir, query: &Envelope) -> Self {
        let mut stream = framed::connect_public(dirs)
            .await
            .expect("the public listener accepts");
        let hello = framed::client_hello(Via::Direct);
        let ack = framed::follow(&mut stream, &hello, query, 0, None)
            .await
            .expect("the hello is acknowledged");
        Self {
            stream,
            reader: FrameReader::new(MAX_FRAME_BYTES),
            epoch: ack.epoch,
        }
    }

    async fn frame(&mut self) -> Result<Frame, DialError> {
        tokio::time::timeout(PATIENCE, self.reader.daemon_frame(&mut self.stream))
            .await
            .expect("a frame within the test's patience")
    }

    async fn following(&mut self) -> Following {
        match self.frame().await {
            Ok(Frame::Following(following)) => following,
            other => panic!("expected following, got {other:?}"),
        }
    }

    /// Reads `event` frames until `end`.
    async fn until_end(&mut self) -> (Vec<EventFrame>, End) {
        let mut events = Vec::new();
        loop {
            match self.frame().await {
                Ok(Frame::Event(event)) => events.push(event),
                Ok(Frame::End(end)) => return (events, end),
                other => panic!("expected event or end, got {other:?}"),
            }
        }
    }
}

/// The next all-events frame, bounded.
async fn next_event(events: &mut AdminEvents) -> Result<EventFrame, DialError> {
    tokio::time::timeout(PATIENCE, events.next())
        .await
        .expect("an all-events frame within the test's patience")
}

/// Reads the all-events stream through `ticket`'s terminal event.
async fn through_terminal(events: &mut AdminEvents, ticket: &str) -> Vec<EventFrame> {
    let mut seen = Vec::new();
    loop {
        let frame = next_event(events).await.expect("an event frame");
        let last = frame.ticket.as_deref() == Some(ticket)
            && matches!(frame.event, Event::Done | Event::Refused);
        seen.push(frame);
        if last {
            return seen;
        }
    }
}

fn progress(pct: u8) -> Event {
    Event::Progress {
        pct: Some(pct),
        note: REAL_NOTE.to_owned(),
    }
}

/// What a public follower is shown of `event`: progress prose replaced by
/// the constant note, everything else as published.
fn public_view(event: &Event) -> Event {
    match event {
        Event::Progress { pct, .. } => Event::Progress {
            pct: *pct,
            note: PUBLIC_PROGRESS_NOTE.to_owned(),
        },
        other => other.clone(),
    }
}

fn refusal_cause(response: &Response) -> &str {
    match response {
        Response::Refusal { cause, .. } => cause,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// What both planes saw of one work request.
struct Watched {
    /// The work request's ticket.
    ticket: String,
    /// The agent label the work request carried.
    agent: String,
    /// The public follower's `event` frames, in order.
    events: Vec<EventFrame>,
    /// The public follower's last frame.
    end: End,
    /// The administration subscriber's frames through the terminal event.
    seen: Vec<EventFrame>,
}

/// Runs a slow echo over the framed public socket with an administration
/// subscriber opened before it and a public follower
/// attached to it, publishes progress the way a flow step does with a
/// `status` poll in between, and reads both streams to the end.
async fn watch_one_request(fixture: &Fixture, watcher: &mut AdminEvents) -> Watched {
    let dirs = fixture.dirs();
    let hub = fixture.daemon.handle().event_hub();

    // The work: an echo slow enough to be watched, as a ticket.
    let work = fixture.envelope(
        "pl_work",
        "echo",
        json!({ "delay_ms": 4_000, "tag": "pl_work" }),
        false,
    );
    let response = call(&dirs, &work).await.expect("the daemon answers");
    let Response::Ticket { ticket, .. } = response else {
        panic!("expected a ticket, got {response:?}");
    };

    // The follower: one waiting query for that ticket, on the same socket.
    let query = fixture.envelope("pl_follow", "query", json!({ "ticket": ticket }), true);
    let mut follower = Follower::open(&dirs, &query).await;
    // One hub behind both listeners: one epoch on both planes.
    assert_eq!(follower.epoch, hub.epoch());
    assert_eq!(watcher.epoch(), hub.epoch());
    let following = follower.following().await;
    assert_eq!(following.ticket, ticket);
    assert_eq!(following.epoch, hub.epoch());
    assert!(
        ["queued", "running"].contains(&following.state.as_str()),
        "{following:?}"
    );

    // What a flow step does while the work runs, then a status poll, then
    // more progress: the poll sits between two events of the ticket.
    hub.publish(&ticket, progress(40)).expect("the hub is open");
    let status = fixture.envelope("pl_status", "status", json!({}), true);
    let polled = call(&dirs, &status).await.expect("status is answered");
    assert!(
        matches!(
            &polled,
            Response::Result {
                outcome: Outcome::Verified,
                ..
            }
        ),
        "{polled:?}"
    );
    hub.publish(&ticket, progress(80)).expect("the hub is open");

    let (events, end) = follower.until_end().await;
    // The daemon closes after `end`.
    assert!(
        matches!(follower.frame().await, Err(DialError::Io(_))),
        "nothing follows end"
    );
    let seen = through_terminal(watcher, &ticket).await;
    Watched {
        ticket,
        agent: work.caller.agent,
        events,
        end,
        seen,
    }
}

/// The public follower's view: content-free, in order, then `end` with the
/// durable answer.
fn assert_followed_content_free(watched: &Watched) {
    let Watched {
        ticket,
        events,
        end,
        ..
    } = watched;
    let mut last = 0;
    for frame in events {
        let seq = frame.seq.expect("a follow event carries seq");
        assert!(seq > last, "seq must increase: {events:?}");
        last = seq;
        // Nothing but the sequence number and the sanitised event.
        let metadata = (
            &frame.n,
            &frame.ticket,
            &frame.capability,
            &frame.repo,
            &frame.agent,
            &frame.ingress,
        );
        assert_eq!(
            metadata,
            (&None, &None, &None, &None, &None, &None),
            "{frame:?}"
        );
        if let Event::Progress { note, .. } = &frame.event {
            assert_eq!(note, PUBLIC_PROGRESS_NOTE, "{frame:?}");
        }
    }
    let wire = serde_json::to_string(events).unwrap() + &serde_json::to_string(end).unwrap();
    assert!(!wire.contains("/private/repo"), "{wire}");
    // Attached within the replay window and never slow: no gap from 1.
    let numbers: Vec<u64> = events.iter().filter_map(|frame| frame.seq).collect();
    let expected: Vec<u64> = (1..=last).collect();
    assert_eq!(numbers, expected, "{events:?}");
    assert_eq!(end.event, Some(Event::Done), "{end:?}");
    assert_eq!(end.seq, Some(last + 1), "{end:?}");
    match &end.response {
        Response::Result { id, body, .. } => {
            assert_eq!(id, "pl_follow");
            assert_eq!(body["ticket"], ticket.as_str());
            assert_eq!(body["state"], "done");
            assert_eq!(body["capability"], "echo");
        }
        other => panic!("expected the durable answer, got {other:?}"),
    }
}

/// The administration subscriber's view: the same lifecycle, whole, and
/// nothing of the control requests.
fn assert_watched_whole(watched: &Watched, repo: &str) {
    let Watched {
        ticket,
        agent,
        events,
        end,
        seen,
    } = watched;
    let numbers: Vec<u64> = seen.iter().map(|frame| frame.n.expect("n")).collect();
    assert!(
        numbers.windows(2).all(|pair| pair[1] == pair[0] + 1),
        "n has a gap: {numbers:?}"
    );
    // Only the work ticket ever published: neither the status poll nor the
    // follower's query has a lifecycle.
    for frame in seen {
        assert_eq!(frame.ticket.as_deref(), Some(ticket.as_str()), "{seen:?}");
        assert_eq!(frame.capability.as_deref(), Some("echo"), "{frame:?}");
        assert_eq!(frame.ingress, Some(Ingress::Public), "{frame:?}");
        assert_eq!(frame.repo.as_deref(), Some(repo), "{frame:?}");
        assert_eq!(frame.agent.as_deref(), Some(agent.as_str()), "{frame:?}");
        assert_eq!(frame.seq, None, "{frame:?}");
    }
    let notes: Vec<&str> = seen
        .iter()
        .filter_map(|frame| match &frame.event {
            Event::Progress { note, .. } => Some(note.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(notes, [REAL_NOTE, REAL_NOTE], "the real notes, in order");
    // Event for event what the follower was shown, before sanitising.
    let whole: Vec<Event> = seen.iter().map(|frame| public_view(&frame.event)).collect();
    let mut shown: Vec<Event> = events.iter().map(|frame| frame.event.clone()).collect();
    shown.extend(end.event.clone());
    assert_eq!(whole, shown);
}

/// A work request on the framed public socket, watched from both planes.
///
/// The follower sees the ticket's lifecycle content-free, with increasing
/// sequence numbers, ending in `end` with the durable answer. The
/// administration subscriber sees the same lifecycle whole: the real progress
/// note and what admission knew, `ingress: "public"`. The rows record the
/// plane and the kernel's peer. A `status` poll made in between, and the
/// follower's own authorising `query`, appear in neither stream.
#[tokio::test]
async fn a_public_request_is_followed_content_free_and_watched_whole_on_the_admin_plane() {
    with_deadline(async {
        let fixture = Fixture::start().await;
        let base = fixture.daemon.base_dir();
        let store = fixture.daemon.store();

        // The administration subscriber first: from `subscribed` on, nothing
        // published is missed.
        let mut subscriber = admin_transport::events(&base)
            .await
            .expect("the all-events stream opens");
        let watched = watch_one_request(&fixture, &mut subscriber).await;
        assert_followed_content_free(&watched);
        assert_watched_whole(&watched, &fixture.repo());
        let ticket = watched.ticket.as_str();

        // The rows: the plane, and the kernel's word about the peer.
        let row = store
            .get_request(ticket)
            .await
            .unwrap()
            .expect("the work row");
        assert_eq!(row.state, RequestState::Done);
        assert_eq!(row.origin.ingress, RequestIngress::Public);
        assert!(!row.origin.relayed);
        let follow_row = store
            .get_request("pl_follow")
            .await
            .unwrap()
            .expect("a follow is one query row");
        assert_eq!(follow_row.capability, "query");
        assert_eq!(follow_row.origin.ingress, RequestIngress::Public);
        #[cfg(unix)]
        for origin in [&row.origin, &follow_row.origin] {
            assert_eq!(origin.peer_pid, Some(std::process::id()), "{origin:?}");
            assert!(origin.peer_uid.is_some(), "{origin:?}");
        }
        assert!(
            store.get_request("pl_status").await.unwrap().is_none(),
            "a status poll writes no row"
        );

        // The same facts through the administration plane, whose own
        // operation is recorded as that plane's.
        let listing = admin_transport::exchange(
            &base,
            &fixture.admin("pl_activity", "admin.activity.list", json!({})),
        )
        .await
        .expect("the admin plane answers");
        let Response::Result { body, .. } = &listing else {
            panic!("expected the activity list, got {listing:?}");
        };
        let listed = body["requests"]
            .as_array()
            .expect("requests")
            .iter()
            .find(|request| request["id"] == ticket)
            .expect("the work ticket is listed");
        assert_eq!(listed["ingress"], "public", "{listed}");
        assert_eq!(listed["relayed"], false, "{listed}");
        #[cfg(unix)]
        assert_eq!(listed["peer_pid"], std::process::id(), "{listed}");
        let operation = store
            .get_request("pl_activity")
            .await
            .unwrap()
            .expect("the admin operation's row");
        assert_eq!(operation.origin.ingress, RequestIngress::Admin);
        assert_eq!(operation.origin.peer_pid, None);

        // Nothing else was published while the streams were read: the
        // admin operation has no lifecycle either.
        let quiet = tokio::time::timeout(Duration::from_millis(300), subscriber.next()).await;
        assert!(quiet.is_err(), "unexpected event: {quiet:?}");

        fixture.daemon.assert_invariant_clean().await;
        fixture.daemon.stop().await;
    })
    .await;
}

/// One drain for both planes. While the daemon drains, both listeners still
/// answer: a newcomer on either plane gets a `daemon_shutting_down` refusal
/// frame, not a refused connect. The follower and the subscriber are told by
/// name at once. The waiting request that was in flight gets its reply frame.
/// Only then do both endpoints go away.
#[tokio::test]
async fn one_drain_answers_both_planes_before_either_endpoint_goes_away() {
    with_deadline(async {
        let fixture = Fixture::start().await;
        let dirs = fixture.dirs();
        let base = fixture.daemon.base_dir();
        let store = fixture.daemon.store();
        let mut phase = fixture.daemon.handle().lifecycle();

        let mut watcher = admin_transport::events(&base)
            .await
            .expect("the all-events stream opens");

        // A waiting request in flight across the drain.
        let waiting = fixture.envelope(
            "pl_inflight",
            "echo",
            json!({ "delay_ms": 3_000, "tag": "pl_inflight" }),
            true,
        );
        let in_flight = tokio::spawn({
            let dirs = dirs.clone();
            async move { call(&dirs, &waiting).await }
        });
        fixture
            .daemon
            .wait_for_row("pl_inflight", |row| row.state == RequestState::Running)
            .await;
        let query = fixture.envelope(
            "pl_drain_follow",
            "query",
            json!({ "ticket": "pl_inflight" }),
            true,
        );
        let mut follower = Follower::open(&dirs, &query).await;
        assert_eq!(follower.following().await.state, "running");

        let late_public = fixture.envelope("pl_late", "echo", json!({ "tag": "late" }), true);
        let late_admin = fixture.admin("pl_late_admin", "admin.profile.get", json!({}));
        let public_endpoint = dirs.public_socket().to_path_buf();
        let admin_endpoint = base.join("admin").join("control.sock");
        if cfg!(unix) {
            assert!(public_endpoint.exists() && admin_endpoint.exists());
        }

        let stopping = tokio::spawn(fixture.daemon.stop());
        tokio::time::timeout(PATIENCE, phase.wait_for(|phase| *phase != LifecyclePhase::Serving))
            .await
            .expect("the drain starts")
            .expect("the daemon is still there");

        // Both streams are cut by name as soon as the phase leaves Serving.
        let cut = loop {
            match follower.frame().await {
                Ok(Frame::Event(_)) => {}
                other => break other,
            }
        };
        assert!(
            matches!(&cut, Err(DialError::Refused(error)) if error.cause == cause::DAEMON_SHUTTING_DOWN),
            "{cut:?}"
        );
        let ended = loop {
            match next_event(&mut watcher).await {
                Ok(_) => {}
                Err(error) => break error,
            }
        };
        assert!(
            matches!(&ended, DialError::Refused(error) if error.cause == cause::DAEMON_SHUTTING_DOWN),
            "{ended:?}"
        );

        // Both listeners still accept while the in-flight work drains, and
        // answer a newcomer with a refusal frame it can read.
        let refused = call(&dirs, &late_public).await.expect("a reply frame");
        assert_eq!(refusal_cause(&refused), cause::DAEMON_SHUTTING_DOWN);
        let refused = admin_transport::exchange(&base, &late_admin)
            .await
            .expect("a reply frame");
        assert_eq!(refusal_cause(&refused), cause::DAEMON_SHUTTING_DOWN);
        let again = admin_transport::events(&base).await;
        assert!(
            matches!(&again, Err(DialError::Refused(error)) if error.cause == cause::DAEMON_SHUTTING_DOWN),
            "{again:?}"
        );

        // The drain flushes the reply that was owed: a frame, never a bare
        // end of file.
        let reply = in_flight
            .await
            .expect("the caller task")
            .expect("a reply frame, not an end of file");
        assert!(
            matches!(&reply, Response::Result { id, .. } | Response::Refusal { id, .. } if id == "pl_inflight"),
            "{reply:?}"
        );

        let _tmp = stopping.await.expect("the daemon stops");
        // Neither refused newcomer left a row; the work that drained did.
        for id in ["pl_late", "pl_late_admin"] {
            assert!(store.get_request(id).await.unwrap().is_none(), "{id} left a row");
        }
        let row = store.get_request("pl_inflight").await.unwrap().expect("the work row");
        assert!(row.state.is_terminal(), "{row:?}");

        // Both endpoints are gone: nothing to connect to on either plane.
        if cfg!(unix) {
            assert!(!public_endpoint.exists(), "the public socket was unlinked");
            assert!(!admin_endpoint.exists(), "the admin socket was unlinked");
        }
        assert!(framed::connect_public(&dirs).await.is_err());
        let down = admin_transport::events(&base).await;
        assert!(matches!(&down, Err(DialError::Io(_))), "{down:?}");
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

/// What the public plane answers a hello that claims `version`.
async fn public_hello_answer(dirs: &RuntimeDir, version: &str, request: &Envelope) -> ErrorFrame {
    let mut stream = framed::connect_public(dirs)
        .await
        .expect("the public listener accepts");
    let hello = Hello {
        version: version.to_owned(),
        ..framed::client_hello(Via::Direct)
    };
    match framed::call(&mut stream, &hello, request, MAX_FRAME_BYTES).await {
        Err(DialError::Refused(error)) => error,
        other => panic!("expected the public hello to be refused, got {other:?}"),
    }
}

/// What the administration plane answers a hello that claims `version`. The
/// admin client says its envelope's `client_version` in the hello and hands a
/// refused hello back as a refusal of the request.
async fn admin_hello_answer(base: &Path, version: &str, mut request: Envelope) -> ErrorFrame {
    request.client_version = version.to_owned();
    match admin_transport::exchange(base, &request).await {
        Ok(Response::Refusal {
            cause,
            detail,
            recovery,
            ..
        }) => ErrorFrame {
            cause,
            detail,
            recovery,
        },
        other => panic!("expected the admin hello to be refused, got {other:?}"),
    }
}

/// One version rule for both planes: the same claim gets the same answer,
/// word for word, whichever socket it is made on; neither plane records a
/// row for it; and only the daemon's own binary being replaced on disk moves
/// the phase, whichever plane happened to be asked first.
#[tokio::test]
async fn a_version_claim_gets_the_same_answer_on_both_planes() {
    with_deadline(async {
        let image = Arc::new(ScriptedImage::default());
        let probe = Arc::clone(&image);
        let fixture = Fixture::start_with(move |config| config.image_probe = Some(probe)).await;
        let dirs = fixture.dirs();
        let base = fixture.daemon.base_dir();
        let store = fixture.daemon.store();
        let phase = fixture.daemon.handle().lifecycle();

        // The binary on disk is the one running: both planes refuse the
        // claim, in the same words, and nothing moves.
        for (index, claimed) in ["9.9.9", "0.0.1"].into_iter().enumerate() {
            let public_id = format!("pl_claim_public_{index}");
            let admin_id = format!("pl_claim_admin_{index}");
            let on_public = public_hello_answer(
                &dirs,
                claimed,
                &fixture.envelope(&public_id, "echo", json!({}), true),
            )
            .await;
            let on_admin = admin_hello_answer(
                &base,
                claimed,
                fixture.admin(&admin_id, "admin.profile.get", json!({})),
            )
            .await;
            assert_eq!(on_public.cause, cause::CLIENT_VERSION_MISMATCH);
            assert_eq!(on_public, on_admin, "the planes disagree about {claimed}");
            assert!(on_public.detail.contains(claimed), "{}", on_public.detail);
            assert_eq!(*phase.borrow(), LifecyclePhase::Serving);
            for id in [&public_id, &admin_id] {
                assert!(
                    store.get_request(id).await.unwrap().is_none(),
                    "a refused hello recorded {id}"
                );
            }
        }
        // A wire protocol this daemon does not speak: refused before the
        // version is looked at, on the admin plane exactly as on the public.
        let future = Hello {
            proto: pam_proto::wire::WIRE_PROTOCOL + 1,
            ..framed::client_hello(Via::Direct)
        };
        let mut stream = framed::connect_public(&dirs).await.unwrap();
        let request = fixture.envelope("pl_proto", "echo", json!({}), true);
        let refused = framed::call(&mut stream, &future, &request, MAX_FRAME_BYTES).await;
        assert!(
            matches!(&refused, Err(DialError::Refused(error)) if error.cause == cause::PROTOCOL_MISMATCH),
            "{refused:?}"
        );

        // Both planes still serve this build.
        let served = call(&dirs, &fixture.envelope("pl_same", "echo", json!({}), true)).await;
        assert!(matches!(served, Ok(Response::Result { .. })), "{served:?}");
        let served = admin_transport::exchange(
            &base,
            &fixture.admin("pl_same_admin", "admin.profile.get", json!({})),
        )
        .await;
        assert!(matches!(served, Ok(Response::Result { .. })), "{served:?}");

        // The binary is replaced (the re-check is cached for a second). The
        // claim is made on the administration plane first: that is enough to
        // move the daemon, and the public plane then gives the same answer.
        image.generation.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(RECHECK_INTERVAL + Duration::from_millis(100)).await;
        let on_admin = admin_hello_answer(
            &base,
            "9.9.9",
            fixture.admin("pl_newer_admin", "admin.profile.get", json!({})),
        )
        .await;
        assert_eq!(on_admin.cause, cause::DAEMON_OUTDATED);
        assert_eq!(*phase.borrow(), LifecyclePhase::Restarting);
        let on_public = public_hello_answer(
            &dirs,
            "9.9.9",
            &fixture.envelope("pl_newer_public", "echo", json!({}), true),
        )
        .await;
        assert_eq!(on_public, on_admin);
        for id in ["pl_newer_admin", "pl_newer_public"] {
            assert!(store.get_request(id).await.unwrap().is_none(), "{id}");
        }

        // The daemon started its own drain; joining it is enough.
        fixture.daemon.join().await;
    })
    .await;
}
