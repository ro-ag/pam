//! Unit tests of the public policy and its per-connection handler.
//!
//! Most of them drive [`PublicPolicy`] over an in-memory stream with the test
//! playing the daemon core: it receives the [`IncomingRequest`] the policy
//! submits and answers (or does not answer) it, while a real store and a real
//! event hub back the follow path's re-authorisation. That is how the cases a
//! real daemon cannot be made to produce on demand are forced: a reply over
//! the frame limit, a handler that drops its reply, a terminal event that
//! lands exactly between a follow's authorisation and its attach. The last
//! module runs a real daemon with its queue wedged, for the hard handler
//! deadline as a framed client sees it.

use std::sync::Arc;
use std::time::Duration;

use pam_proto::wire::{End, Frame, MAX_FRAME_BYTES, Via, cause};
use pam_proto::{Envelope, Event, Outcome, Response};
use pam_store::{Actor, AuditEntry, Decision, RequestState, Store};
use tokio::io::DuplexStream;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::daemon::{
    CAUSE_DAEMON_OUTDATED, CAUSE_DAEMON_SHUTTING_DOWN, CAUSE_DEADLINE_EXCEEDED,
    CAUSE_INTERNAL_ERROR,
};
use crate::event_hub::EventHub;
use crate::framed::{self, DialError, Limits, Policy};
use crate::image::{FsProbe, ImageWatch};
use crate::ingress::{Ingress, Origin, PeerIdentity, PublicPeer};
use crate::lifecycle::LifecyclePhase;
use crate::public_transport::{
    CAUSE_RESPONSE_BUDGET, FollowTimes, LEGACY_LOG_INTERVAL, LegacyLog, PublicPolicy, reply_body,
};
use crate::transport::IncomingRequest;

const PATIENCE: Duration = Duration::from_secs(10);

/// The peer every scripted connection claims the kernel reported.
const PEER: PeerIdentity = PeerIdentity::Unix {
    uid: 501,
    gid: 20,
    pid: Some(4242),
};

/// A public policy over a real store and hub, with the test as the core.
struct Rig {
    policy: Arc<PublicPolicy>,
    core: mpsc::Receiver<IncomingRequest>,
    store: Arc<Store>,
    hub: Arc<EventHub>,
    phase: watch::Sender<LifecyclePhase>,
    /// Stops every connection of this rig, as the listener's stop would.
    stop: watch::Sender<bool>,
    repo: tempfile::TempDir,
    /// Bytes the in-memory connection buffers in each direction.
    buffer: usize,
    /// The managed policy the follow path reads.
    managed: Arc<crate::managed_policy_service::PolicyHandle>,
}

impl Rig {
    async fn new(follow: FollowTimes) -> Self {
        Self::under(follow, None).await
    }

    /// [`Self::new`] whose follow path reads the managed policy from
    /// `source`; `None` is no policy.
    async fn under(
        follow: FollowTimes,
        source: Option<Arc<crate::policy_test::SwitchablePolicy>>,
    ) -> Self {
        let store = Arc::new(Store::open_in_memory().await.expect("a store"));
        let managed = match &source {
            Some(source) => crate::policy_test::managed_handle(&store, source).await,
            None => crate::managed_policy_service::PolicyHandle::none(),
        };
        let repo = tempfile::tempdir().expect("a repository directory");
        let root = repo.path().canonicalize().expect("the repository exists");
        store
            .set_setting(
                crate::scope_policy::SETTING_SCOPE_POLICY,
                &serde_json::json!({
                    "version": 1,
                    "repositories": [{ "root": root, "connectors": [] }],
                })
                .to_string(),
            )
            .await
            .expect("the scope policy persists");
        let (incoming, core) = mpsc::channel(16);
        let (phase, _) = watch::channel(LifecyclePhase::Serving);
        let (stop, _) = watch::channel(false);
        let hub = EventHub::new();
        let policy = PublicPolicy::with_limits(
            Ingress::new(incoming),
            Arc::clone(&store),
            phase.clone(),
            Arc::clone(&hub),
            ImageWatch::capture(Arc::new(FsProbe)),
            Limits::PUBLIC,
            follow,
            Arc::clone(&managed),
        );
        let managed_for_rig = managed;
        Self {
            policy,
            core,
            store,
            hub,
            phase,
            stop,
            repo,
            buffer: 64 * 1024,
            managed: managed_for_rig,
        }
    }

    /// Re-reads the managed policy now, as `admin.policy.reload` does.
    async fn policy_reload(&self) {
        self.managed
            .reload(crate::managed_policy_service::Trigger::Reload { request_id: None })
            .await;
    }

    fn repo(&self) -> String {
        self.repo
            .path()
            .canonicalize()
            .expect("the repository exists")
            .to_string_lossy()
            .into_owned()
    }

    fn envelope(&self, id: &str, capability: &str, args: serde_json::Value) -> Envelope {
        pam_testkit::envelope_for_repo(&self.repo(), id, capability, args, true)
    }

    /// One served connection: the client's end, and the serving task.
    fn connect(&self) -> (DuplexStream, JoinHandle<()>) {
        let (client, server) = tokio::io::duplex(self.buffer);
        let serving = tokio::spawn(Policy::serve(
            Arc::clone(&self.policy),
            server,
            PEER,
            self.stop.subscribe(),
        ));
        (client, serving)
    }

    /// The next request the policy handed to the core.
    async fn submitted(&mut self) -> IncomingRequest {
        tokio::time::timeout(PATIENCE, self.core.recv())
            .await
            .expect("a request reaches the core")
            .expect("the policy holds the ingress")
    }

    /// Admits `ticket` under this rig's repository, in flight.
    async fn admit(&self, ticket: &str) {
        self.store
            .insert_admitted_request(
                ticket,
                "echo",
                &self.repo(),
                "claude",
                "{}",
                None,
                9_000_000_000_000,
            )
            .await
            .expect("the ticket is admitted");
    }

    /// Ends `ticket` durably, as the pipeline's terminal write does.
    async fn finish(&self, ticket: &str) {
        self.store
            .finish_request(
                ticket,
                RequestState::Done,
                Some("solved"),
                AuditEntry {
                    action: "execute",
                    decision: Decision::Allow,
                    actor: Actor::System,
                    detail: None,
                },
            )
            .await
            .expect("the terminal write");
    }

    /// Opens a follow of `ticket`, plays the core for its authorising query
    /// (answering that the ticket is `running`) and returns the client's end
    /// with the serving task. `before_answer` runs while the query is held:
    /// the moment between authorisation and attach.
    async fn follow(
        &mut self,
        ticket: &str,
        before_answer: impl AsyncFnOnce(&Self),
    ) -> (DuplexStream, JoinHandle<()>) {
        let query = self.envelope(
            "req_follow",
            "query",
            serde_json::json!({ "ticket": ticket }),
        );
        let (mut client, serving) = self.connect();
        let dialled = tokio::spawn(async move {
            framed::follow(
                &mut client,
                &framed::client_hello(Via::Direct),
                &query,
                0,
                None,
            )
            .await
            .map(|_| client)
        });
        let request = self.submitted().await;
        assert_eq!(request.envelope.capability, "query");
        before_answer(&*self).await;
        request
            .reply
            .send(Response::Result {
                id: request.envelope.id,
                outcome: Outcome::Blocked,
                body: serde_json::json!({
                    "ticket": ticket,
                    "state": "running",
                    "outcome": null,
                    "capability": "echo",
                }),
                evidence: Vec::new(),
            })
            .expect("the policy waits for the query");
        let client = dialled.await.unwrap().expect("the hello is acknowledged");
        (client, serving)
    }
}

async fn frame(client: &mut DuplexStream) -> Result<Frame, DialError> {
    tokio::time::timeout(PATIENCE, framed::read_daemon_frame(client, MAX_FRAME_BYTES))
        .await
        .expect("a frame within the test's patience")
}

async fn end(client: &mut DuplexStream) -> End {
    loop {
        match frame(client).await {
            Ok(Frame::End(end)) => return end,
            Ok(Frame::Event(_)) => {}
            other => panic!("expected end, got {other:?}"),
        }
    }
}

async fn following(client: &mut DuplexStream) -> pam_proto::wire::Following {
    match frame(client).await {
        Ok(Frame::Following(following)) => following,
        other => panic!("expected following, got {other:?}"),
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

fn state_of(response: &Response) -> &str {
    match response {
        Response::Result { body, .. } => body["state"].as_str().expect("a state"),
        other => panic!("expected a result, got {other:?}"),
    }
}

/// One unary call over a scripted connection.
async fn call(client: &mut DuplexStream, envelope: &Envelope) -> Result<Response, DialError> {
    tokio::time::timeout(
        PATIENCE,
        framed::call(
            client,
            &framed::client_hello(Via::Direct),
            envelope,
            MAX_FRAME_BYTES,
        ),
    )
    .await
    .expect("an answer within the test's patience")
    .map(|(_, response)| response)
}

#[tokio::test]
async fn legacy_greetings_are_logged_at_most_once_a_minute() {
    let log = LegacyLog::default();
    let start = tokio::time::Instant::now();
    // The first one is logged; nothing was held back before it.
    assert_eq!(log.admit(start), Some(0));
    // A stale binary retrying in a loop is counted, not logged.
    assert_eq!(log.admit(start + Duration::from_secs(1)), None);
    assert_eq!(log.admit(start + Duration::from_secs(30)), None);
    assert_eq!(
        log.admit(start + LEGACY_LOG_INTERVAL - Duration::from_millis(1)),
        None
    );
    // The next line says how many it stands for.
    assert_eq!(log.admit(start + LEGACY_LOG_INTERVAL), Some(3));
    assert_eq!(log.admit(start + LEGACY_LOG_INTERVAL * 2), Some(0));
}

#[test]
fn a_reply_that_does_not_fit_one_frame_becomes_the_budget_refusal() {
    let reply = |text_bytes: usize| Response::Result {
        id: "req_big".to_owned(),
        outcome: Outcome::Solved,
        body: serde_json::json!({ "text": "x".repeat(text_bytes) }),
        evidence: Vec::new(),
    };
    let decoded = |body: &[u8]| match Frame::decode(body) {
        Ok(Frame::Reply { response }) => response,
        other => panic!("expected a reply frame, got {other:?}"),
    };

    // A reply that fits travels as it is.
    let small = reply(16);
    assert_eq!(decoded(&reply_body(&small, MAX_FRAME_BYTES)), small);

    // The frame, not the response inside it, is what must fit: this
    // response is under the limit on its own and one byte over once framed.
    let overhead = reply_body(&reply(0), MAX_FRAME_BYTES).len();
    let exact = reply(MAX_FRAME_BYTES - overhead);
    assert_eq!(reply_body(&exact, MAX_FRAME_BYTES).len(), MAX_FRAME_BYTES);
    assert_eq!(decoded(&reply_body(&exact, MAX_FRAME_BYTES)), exact);
    let over = reply(MAX_FRAME_BYTES - overhead + 1);
    assert!(serde_json::to_vec(&over).unwrap().len() <= MAX_FRAME_BYTES);
    let body = reply_body(&over, MAX_FRAME_BYTES);
    assert!(body.len() < 1024, "the refusal is small: {}", body.len());
    let refused = decoded(&body);
    assert_eq!(refusal(&refused), (CAUSE_RESPONSE_BUDGET, false));
    assert_eq!(refused.id(), "req_big");

    // A request id the refusal cannot carry is not echoed back.
    let long_id = Response::Result {
        id: "i".repeat(MAX_FRAME_BYTES),
        outcome: Outcome::Solved,
        body: serde_json::json!({}),
        evidence: Vec::new(),
    };
    assert_eq!(
        decoded(&reply_body(&long_id, MAX_FRAME_BYTES)).id(),
        "unknown"
    );
}

#[tokio::test]
async fn an_oversized_reply_reaches_the_client_as_a_small_refusal() {
    let mut rig = Rig::new(FollowTimes::DEFAULT).await;
    let (mut client, serving) = rig.connect();
    let request = rig.envelope("req_flood", "echo", serde_json::json!({}));
    let calling = tokio::spawn(async move { call(&mut client, &request).await });

    let submitted = rig.submitted().await;
    // The policy recorded what the listener saw and what the hello said.
    assert_eq!(submitted.origin, Origin::Public);
    assert_eq!(
        submitted.peer,
        Some(PublicPeer {
            identity: PEER,
            relayed: false
        })
    );
    submitted
        .reply
        .send(Response::Result {
            id: "req_flood".to_owned(),
            outcome: Outcome::Solved,
            body: serde_json::json!({ "text": "x".repeat(2 * MAX_FRAME_BYTES) }),
            evidence: Vec::new(),
        })
        .unwrap();

    let response = calling.await.unwrap().expect("a reply frame");
    assert_eq!(refusal(&response), (CAUSE_RESPONSE_BUDGET, false));
    assert_eq!(response.id(), "req_flood");
    serving.await.unwrap();
}

/// A request the core accepted is never answered with a bare end of file,
/// whatever became of its handler.
#[tokio::test]
async fn a_request_whose_handler_vanished_is_still_answered() {
    let mut rig = Rig::new(FollowTimes::DEFAULT).await;

    // The handler dropped its reply while the daemon serves: internal.
    let (mut client, serving) = rig.connect();
    let request = rig.envelope("req_dropped", "echo", serde_json::json!({}));
    let calling = tokio::spawn(async move { call(&mut client, &request).await });
    drop(rig.submitted().await.reply);
    let response = calling.await.unwrap().expect("a reply frame");
    assert_eq!(refusal(&response), (CAUSE_INTERNAL_ERROR, true));
    assert_eq!(response.id(), "req_dropped");
    serving.await.unwrap();

    // The same after the request's own deadline: the deadline is the cause.
    let (mut client, serving) = rig.connect();
    let mut request = rig.envelope("req_overdue", "echo", serde_json::json!({}));
    request.deadline_ms = 20;
    let calling = tokio::spawn(async move { call(&mut client, &request).await });
    let submitted = rig.submitted().await;
    tokio::time::sleep(Duration::from_millis(60)).await;
    drop(submitted.reply);
    let response = calling.await.unwrap().expect("a reply frame");
    assert_eq!(refusal(&response), (CAUSE_DEADLINE_EXCEEDED, true));
    serving.await.unwrap();

    // The listener stops while a reply is still owed: the client is told.
    let (mut client, serving) = rig.connect();
    let request = rig.envelope("req_at_stop", "echo", serde_json::json!({}));
    let calling = tokio::spawn(async move { call(&mut client, &request).await });
    let held = rig.submitted().await;
    rig.stop.send_replace(true);
    let response = calling.await.unwrap().expect("a reply frame");
    assert_eq!(refusal(&response), (CAUSE_DAEMON_SHUTTING_DOWN, true));
    serving.await.unwrap();
    drop(held);
    rig.stop.send_replace(false);

    // Once the daemon is leaving, the answer does not depend on whether
    // the dispatcher is still there: the core is not even asked.
    for (phase, expected) in [
        (LifecyclePhase::Draining, CAUSE_DAEMON_SHUTTING_DOWN),
        (LifecyclePhase::Restarting, CAUSE_DAEMON_OUTDATED),
    ] {
        rig.phase.send_replace(phase);
        let (mut client, serving) = rig.connect();
        let request = rig.envelope("req_leaving", "echo", serde_json::json!({}));
        let response = call(&mut client, &request).await.expect("a reply frame");
        assert_eq!(refusal(&response), (expected, true));
        serving.await.unwrap();
        assert!(rig.core.try_recv().is_err(), "{phase:?} reached the core");
    }
}

/// The subscribe-after-publish race, forced: the ticket ends — durable row,
/// then its terminal event — after the follow was authorised and before it
/// attached. The event is gone by the time the follower's queue exists; the
/// second read of the store is what ends the stream. The backstop is set to
/// an hour, so it cannot be what did.
#[tokio::test]
async fn a_terminal_event_between_authorisation_and_attach_still_ends_the_follow() {
    let mut rig = Rig::new(FollowTimes {
        lifetime: Duration::from_hours(1),
        reconcile: Duration::from_hours(1),
    })
    .await;
    rig.admit("req_raced").await;

    let (mut client, serving) = rig
        .follow("req_raced", async |rig: &Rig| {
            rig.hub.publish("req_raced", Event::Queued).unwrap();
            rig.hub.publish("req_raced", Event::Started).unwrap();
            rig.finish("req_raced").await;
            rig.hub.publish("req_raced", Event::Done).unwrap();
        })
        .await;

    // The query's answer was already stale; `following` says what it said.
    let attached = following(&mut client).await;
    assert_eq!(attached.state, "running");
    assert_eq!(attached.seq, 0, "the terminal event took the ring with it");
    let end = end(&mut client).await;
    assert_eq!(end.event, Some(Event::Done));
    assert_eq!(end.seq, None);
    assert_eq!(end.response.id(), "req_follow");
    assert_eq!(state_of(&end.response), "done");
    serving.await.unwrap();
    assert_eq!(rig.hub.usage().followers, 0);
    assert_eq!(rig.hub.usage().entries, 0);
}

/// A terminal transition whose event is never published (the case the
/// client's reconcile query covers today) is found by the store re-check.
#[tokio::test]
async fn the_store_re_check_ends_a_follow_whose_terminal_event_never_came() {
    let mut rig = Rig::new(FollowTimes {
        lifetime: Duration::from_hours(1),
        reconcile: Duration::from_millis(80),
    })
    .await;
    rig.admit("req_silent").await;
    rig.hub.publish("req_silent", Event::Queued).unwrap();

    let (mut client, serving) = rig.follow("req_silent", async |_: &Rig| {}).await;
    assert_eq!(following(&mut client).await.seq, 1);
    assert!(matches!(frame(&mut client).await, Ok(Frame::Event(_))));

    rig.finish("req_silent").await;
    let end = end(&mut client).await;
    assert_eq!(end.event, Some(Event::Done));
    assert_eq!(end.seq, None, "no terminal event was ever published");
    assert_eq!(state_of(&end.response), "done");
    serving.await.unwrap();
}

/// A terminal event can run ahead of its row (a verdict parked for retry is
/// announced before the store takes it). The stream does not end on the
/// event alone, and ends with the event's sequence number once the row is
/// durable.
#[tokio::test]
async fn a_terminal_event_ahead_of_its_row_waits_for_the_durable_state() {
    let mut rig = Rig::new(FollowTimes {
        lifetime: Duration::from_hours(1),
        reconcile: Duration::from_hours(1),
    })
    .await;
    rig.admit("req_parked").await;

    let (mut client, serving) = rig.follow("req_parked", async |_: &Rig| {}).await;
    following(&mut client).await;
    rig.hub.publish("req_parked", Event::Started).unwrap();
    rig.hub.publish("req_parked", Event::Done).unwrap();
    assert!(matches!(frame(&mut client).await, Ok(Frame::Event(_))));
    // The row is still in flight: no `end` yet.
    let early = tokio::time::timeout(
        Duration::from_millis(600),
        framed::read_daemon_frame(&mut client, MAX_FRAME_BYTES),
    )
    .await;
    assert!(
        early.is_err(),
        "ended before the row was durable: {early:?}"
    );

    rig.finish("req_parked").await;
    let end = end(&mut client).await;
    assert_eq!(end.event, Some(Event::Done));
    assert_eq!(end.seq, Some(2));
    assert_eq!(state_of(&end.response), "done");
    serving.await.unwrap();
}

/// Authorisation is re-checked, not remembered: a follower whose repository
/// stops being approved mid-stream is ended with the refusal a `query` would
/// get, and no terminal event.
#[tokio::test]
async fn a_follow_ends_when_its_authorisation_no_longer_holds() {
    let mut rig = Rig::new(FollowTimes {
        lifetime: Duration::from_hours(1),
        reconcile: Duration::from_millis(80),
    })
    .await;
    rig.admit("req_revoked").await;

    let (mut client, serving) = rig.follow("req_revoked", async |_: &Rig| {}).await;
    following(&mut client).await;
    rig.store
        .set_setting(
            crate::scope_policy::SETTING_SCOPE_POLICY,
            r#"{"version":1,"repositories":[]}"#,
        )
        .await
        .unwrap();

    let end = end(&mut client).await;
    assert_eq!(end.event, None);
    assert_eq!(refusal(&end.response), ("result_unavailable", false));
    assert_eq!(end.response.id(), "req_follow");
    serving.await.unwrap();
    assert_eq!(rig.hub.usage().followers, 0);
}

/// The follow path authorizes under the managed policy too: a policy that
/// drops the follower's repository from the effective scopes ends the follow
/// with the refusal a `query` would get, while the human's stored scopes
/// still name the repository.
#[tokio::test]
async fn a_follow_ends_when_the_managed_policy_drops_its_repository() {
    let source = crate::policy_test::SwitchablePolicy::new(None);
    let mut rig = Rig::under(
        FollowTimes {
            lifetime: Duration::from_hours(1),
            reconcile: Duration::from_millis(80),
        },
        Some(Arc::clone(&source)),
    )
    .await;
    rig.admit("req_managed").await;

    let (mut client, serving) = rig.follow("req_managed", async |_: &Rig| {}).await;
    following(&mut client).await;
    let elsewhere = if cfg!(windows) {
        r"C:\pam-policy-allows-only-this"
    } else {
        "/pam-policy-allows-only-this"
    };
    source.set(Some(
        &serde_json::json!({
            "version": 1,
            "scopes": { "allowed_repository_roots": [elsewhere] },
        })
        .to_string(),
    ));
    rig.policy_reload().await;

    let end = end(&mut client).await;
    assert_eq!(end.event, None);
    assert_eq!(refusal(&end.response), ("result_unavailable", false));
    serving.await.unwrap();
    assert_eq!(rig.hub.usage().followers, 0);
    let stored = rig
        .store
        .get_setting(crate::scope_policy::SETTING_SCOPE_POLICY)
        .await
        .unwrap()
        .unwrap();
    assert!(
        stored.contains(&rig.repo().replace('\\', "\\\\")),
        "the human's scopes are untouched: {stored}"
    );
}

#[tokio::test]
async fn a_follow_expires_at_its_lifetime_and_frees_its_slot() {
    let mut rig = Rig::new(FollowTimes {
        lifetime: Duration::from_millis(250),
        reconcile: Duration::from_hours(1),
    })
    .await;
    rig.admit("req_long").await;

    let (mut client, serving) = rig.follow("req_long", async |_: &Rig| {}).await;
    following(&mut client).await;
    assert_eq!(rig.hub.usage().followers, 1);
    let Err(DialError::Refused(error)) = frame(&mut client).await else {
        panic!("expected error follow_expired");
    };
    assert_eq!(error.cause, cause::FOLLOW_EXPIRED);
    serving.await.unwrap();
    assert_eq!(rig.hub.usage().followers, 0);
    // The ticket was not touched.
    let row = rig.store.get_request("req_long").await.unwrap().unwrap();
    assert_eq!(row.state, RequestState::Running);
}

/// Followers are cut as soon as the daemon leaves `Serving`, and when the
/// hub is closed under them.
#[tokio::test]
async fn a_follow_is_cut_when_the_daemon_leaves_serving() {
    let mut rig = Rig::new(FollowTimes::DEFAULT).await;
    rig.admit("req_cut").await;

    let (mut client, serving) = rig.follow("req_cut", async |_: &Rig| {}).await;
    following(&mut client).await;
    rig.phase.send_replace(LifecyclePhase::Draining);
    let Err(DialError::Refused(error)) = frame(&mut client).await else {
        panic!("expected error daemon_shutting_down");
    };
    assert_eq!(error.cause, cause::DAEMON_SHUTTING_DOWN);
    serving.await.unwrap();
    assert_eq!(rig.hub.usage().followers, 0);
}

/// A follower that stops reading is disconnected when a frame write does not
/// complete within the write timeout: its slot comes back, and neither the
/// publisher nor the ticket ever waited on it. (Real time: the write timeout
/// is five seconds.)
#[tokio::test]
async fn a_follower_that_stops_reading_is_disconnected_at_the_write_timeout() {
    let mut rig = Rig::new(FollowTimes {
        lifetime: Duration::from_hours(1),
        reconcile: Duration::from_hours(1),
    })
    .await;
    // A connection that buffers almost nothing, so an unread stream backs
    // up into the writer after a handful of events.
    rig.buffer = 1024;
    rig.admit("req_unread").await;

    let (mut client, serving) = rig.follow("req_unread", async |_: &Rig| {}).await;
    following(&mut client).await;
    assert_eq!(rig.hub.usage().followers, 1);

    // The client reads nothing from here on.
    let started = std::time::Instant::now();
    for round in 0..8u8 {
        for pct in 0..64u8 {
            rig.hub
                .publish(
                    "req_unread",
                    Event::Progress {
                        pct: Some(pct),
                        note: format!("round {round}"),
                    },
                )
                .expect("publishing never waits on a follower");
        }
        // Let the connection task move what it can into the full buffer.
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "publishing waited on the follower: {:?}",
        started.elapsed()
    );

    tokio::time::timeout(framed::WRITE_TIMEOUT + Duration::from_secs(5), serving)
        .await
        .expect("the follower is disconnected at the write timeout")
        .unwrap();
    assert!(
        started.elapsed() + Duration::from_millis(500) >= framed::WRITE_TIMEOUT,
        "disconnected before the write timeout: {:?}",
        started.elapsed()
    );
    assert_eq!(rig.hub.usage().followers, 0);
    // The ticket was not touched, and what the follower did not read is
    // not owed to it: it reconnects and resumes.
    let row = rig.store.get_request("req_unread").await.unwrap().unwrap();
    assert_eq!(row.state, RequestState::Running);
    let mut delivered = 0usize;
    while let Ok(Frame::Event(_)) = frame(&mut client).await {
        delivered += 1;
    }
    assert!(
        delivered < 8 * 64,
        "a follower that does not read cannot have been sent everything"
    );
}

/// The connection cap, on a real socket with a small limit: a connection
/// over it is told so and closed, and a slot freed by a disconnect is
/// reusable.
#[cfg(unix)]
#[tokio::test]
async fn a_connection_over_the_cap_is_told_and_a_freed_slot_is_reusable() {
    use crate::framed::Listener;
    use crate::framed_unix::UnixAcceptor;

    let rig = Rig::new(FollowTimes::DEFAULT).await;
    let limits = Limits {
        max_connections: 2,
        ..Limits::PUBLIC
    };
    let (incoming, mut core) = mpsc::channel(4);
    let policy = PublicPolicy::with_limits(
        Ingress::new(incoming),
        Arc::clone(&rig.store),
        rig.phase.clone(),
        Arc::clone(&rig.hub),
        ImageWatch::capture(Arc::new(FsProbe)),
        limits,
        FollowTimes::DEFAULT,
        crate::managed_policy_service::PolicyHandle::none(),
    );
    let dir = pam_testkit::short_tempdir();
    let path = dir.path().join("pam.sock");
    let listener = Listener::spawn(UnixAcceptor::bind(&path).expect("the socket binds"), policy);

    // Two connections sitting in their handshake hold both permits.
    let first = crate::framed_unix::connect(&path).await.unwrap();
    let second = crate::framed_unix::connect(&path).await.unwrap();
    tokio::time::timeout(PATIENCE, async {
        while listener.available_connections() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("both connections are being served");

    let mut third = crate::framed_unix::connect(&path).await.unwrap();
    let answer = tokio::time::timeout(
        PATIENCE,
        framed::read_daemon_frame(&mut third, MAX_FRAME_BYTES),
    )
    .await
    .expect("a connection over the cap is answered, not left hanging");
    let Err(DialError::Refused(error)) = answer else {
        panic!("expected error connection_capacity_exhausted, got {answer:?}");
    };
    assert_eq!(error.cause, cause::CONNECTION_CAPACITY_EXHAUSTED);

    // One goes away; the next connection is served to its reply.
    drop(first);
    tokio::time::timeout(PATIENCE, async {
        while listener.available_connections() != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the permit comes back");
    let mut fourth = crate::framed_unix::connect(&path).await.unwrap();
    let request = rig.envelope("req_after_cap", "echo", serde_json::json!({}));
    let calling = tokio::spawn(async move {
        framed::call(
            &mut fourth,
            &framed::client_hello(Via::Relay),
            &request,
            MAX_FRAME_BYTES,
        )
        .await
    });
    let submitted = tokio::time::timeout(PATIENCE, core.recv())
        .await
        .expect("the request reaches the core")
        .unwrap();
    // The kernel's view of this process, and the hello's relay marker.
    let peer = submitted.peer.expect("a framed request carries its peer");
    assert_eq!(peer.identity.pid(), Some(std::process::id()));
    assert_eq!(
        peer.identity.uid(),
        crate::framed_unix::own_identity().unwrap().uid()
    );
    assert!(peer.relayed);
    submitted
        .reply
        .send(Response::refusal("req_after_cap", "scripted", "", ""))
        .unwrap();
    let (_, response) = calling.await.unwrap().expect("a reply frame");
    assert_eq!(refusal(&response), ("scripted", false));

    drop(second);
    listener.shutdown().await;
    assert!(!path.exists(), "the socket file is unlinked at shutdown");
}

// ---------------------------------------------------------------------------
// A real daemon with its queue in reach, dialled over the framed socket.
// ---------------------------------------------------------------------------

mod live {
    use std::sync::Arc;
    use std::time::Duration;

    use pam_proto::wire::{MAX_FRAME_BYTES, Via};
    use pam_proto::{Envelope, Response};
    use pam_store::RequestState;
    use tokio::sync::watch;

    use crate::daemon::{
        ACTION_DEADLINE_REFUSAL, CAUSE_DEADLINE_EXCEEDED, DaemonConfig, DaemonHandle, WORK_SLOTS,
        run_daemon_with,
    };
    use crate::framed::{self, MAX_PUBLIC_CONNECTIONS};
    use crate::runtime_dir::RuntimeDir;
    use crate::secrets::FakeSecretBackend;

    const REPO: &str = "/repo/framed";
    const PATIENCE: Duration = Duration::from_secs(10);

    async fn eventually<F, Fut>(what: &str, mut check: F)
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = bool>,
    {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        while !check().await {
            assert!(
                tokio::time::Instant::now() < deadline,
                "never happened: {what}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// A relaxed daemon on a private base whose handlers are cut off 300 ms
    /// past their deadline.
    async fn start(tmp: &tempfile::TempDir) -> (DaemonHandle, watch::Sender<bool>) {
        pam_testkit::seed_relaxed(tmp).await;
        let (shutdown, shutdown_rx) = watch::channel(false);
        let handle = run_daemon_with(
            DaemonConfig {
                base_dir: Some(pam_testkit::base_of(tmp)),
                secret_backend: Some(Arc::new(FakeSecretBackend::default())),
                handler_grace: Duration::from_millis(300),
                policy_source: Some(crate::daemon_test::no_policy_file()),
                ..DaemonConfig::default()
            },
            shutdown_rx,
        )
        .await
        .expect("the daemon starts");
        (handle, shutdown)
    }

    /// One unary call over the framed public socket.
    async fn call(dirs: RuntimeDir, envelope: Envelope) -> Response {
        let mut stream = framed::connect_public(&dirs).await.expect("connects");
        framed::call(
            &mut stream,
            &framed::client_hello(Via::Direct),
            &envelope,
            MAX_FRAME_BYTES,
        )
        .await
        .expect("the daemon answers")
        .1
    }

    fn echo(id: &str, args: serde_json::Value, wait: bool) -> Envelope {
        pam_testkit::envelope_for_repo(REPO, id, "echo", args, wait)
    }

    /// The hard handler deadline as a framed client sees it: a handler
    /// wedged in its own bookkeeping is cut off at its deadline plus the
    /// grace, the client reads `deadline_exceeded` on the connection it
    /// has open, the slot and the connection permit come back, and the
    /// request still gets its terminal row with one audit row.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_wedged_handler_answers_its_framed_client_at_the_hard_deadline() {
        let test = Box::pin(async {
            let tmp = pam_testkit::short_tempdir();
            let (handle, shutdown) = start(&tmp).await;
            let store = handle.store();
            let queue = handle.queue();
            let dirs = handle.runtime_dir().clone();

            // The lane is busy with a long echo...
            let holder = echo(
                "framed_holder",
                serde_json::json!({ "delay_ms": 8_000 }),
                false,
            );
            assert!(matches!(
                call(dirs.clone(), holder).await,
                Response::Ticket { .. }
            ));
            eventually("the holder is leased", || async {
                queue
                    .leased_ids()
                    .await
                    .contains(&"framed_holder".to_owned())
            })
            .await;

            // ...and a waiting request with a short deadline queues behind.
            let mut waiting = echo("framed_wedged", serde_json::json!({ "n": 2 }), true);
            waiting.deadline_ms = 500;
            let answer = tokio::spawn(call(dirs, waiting));
            eventually("the waiter is queued", || async {
                store
                    .get_request("framed_wedged")
                    .await
                    .unwrap()
                    .is_some_and(|row| row.state == RequestState::Queued)
            })
            .await;

            // The queue wedges: at its deadline the handler blocks in it.
            let stall = queue.stall().await;
            let response = tokio::time::timeout(Duration::from_secs(5), answer)
                .await
                .expect("the client is answered although the handler is wedged")
                .unwrap();
            let Response::Refusal {
                cause, retryable, ..
            } = &response
            else {
                panic!("expected a refusal, got {response:?}");
            };
            assert_eq!(
                (cause.as_str(), *retryable),
                (CAUSE_DEADLINE_EXCEEDED, true)
            );

            // Slot, connection permit and terminal row — all while the
            // queue is still wedged.
            eventually("the slot is released", || async {
                handle.admission_available().work == WORK_SLOTS
            })
            .await;
            eventually("the connection permit is released", || async {
                handle.public_connections_available() == MAX_PUBLIC_CONNECTIONS
            })
            .await;
            eventually("the terminal row is written", || async {
                store
                    .get_request("framed_wedged")
                    .await
                    .unwrap()
                    .is_some_and(|row| row.state == RequestState::Failed)
            })
            .await;
            let row = store.get_request("framed_wedged").await.unwrap().unwrap();
            assert_eq!(row.outcome.as_deref(), Some(CAUSE_DEADLINE_EXCEEDED));
            let audit = store.audit_for_request("framed_wedged").await.unwrap();
            assert_eq!(audit.len(), 1, "{audit:?}");
            assert_eq!(audit[0].action, ACTION_DEADLINE_REFUSAL);
            // The row says which connection asked.
            #[cfg(unix)]
            assert_eq!(row.origin.peer_pid, Some(std::process::id()));

            drop(stall);
            let _ = queue
                .cancel("framed_holder", pam_store::Actor::System)
                .await;
            let _ = shutdown.send(true);
            tokio::time::timeout(Duration::from_secs(30), handle.shutdown())
                .await
                .expect("the daemon drains");
        });
        tokio::time::timeout(Duration::from_secs(60), test)
            .await
            .expect("the test finishes in time");
    }
}
