//! The follow stream of the framed public listener against a real daemon:
//! `follow` in, then `following`, `event`* and `end`, dialled with the client
//! primitives of [`pam_daemon::framed`].
//!
//! Tickets are waiting `echo` requests with a delay; where a test needs more
//! events than an echo publishes it publishes progress into the daemon's hub
//! itself ([`pam_daemon::daemon::DaemonHandle::event_hub`]), which is what a
//! flow step does.

use std::time::Duration;

use pam_daemon::daemon::{DaemonConfig, DaemonHandle};
use pam_daemon::event_hub::{
    FOLLOWER_QUEUE, MAX_FOLLOWERS, MAX_FOLLOWERS_PER_TICKET, PUBLIC_PROGRESS_NOTE,
};
use pam_daemon::framed::{self, DialError, MAX_PUBLIC_CONNECTIONS, PublicStream};
use pam_daemon::queue::ACTION_CANCEL;
use pam_proto::wire::{End, Following, Frame, MAX_FRAME_BYTES, Via, cause};
use pam_proto::{Envelope, Event, Response};
use pam_store::RequestState;
use pam_testkit::{
    TestDaemon, envelope_for_repo, seed_relaxed, seed_repository_scope, short_tempdir,
    with_deadline,
};
use tokio::io::AsyncWriteExt;

/// Every read of a frame in this file is bounded by this, far under the
/// follow's fifteen-second store re-check: a stream that only ends because
/// of that backstop fails the test.
const PATIENCE: Duration = Duration::from_secs(8);

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

    fn handle(&self) -> &DaemonHandle {
        self.daemon.handle()
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

    async fn call(&self, envelope: &Envelope) -> Response {
        let mut stream = framed::connect_public(self.handle().runtime_dir())
            .await
            .expect("the public listener accepts");
        framed::call(
            &mut stream,
            &framed::client_hello(Via::Direct),
            envelope,
            MAX_FRAME_BYTES,
        )
        .await
        .expect("the daemon answers")
        .1
    }

    /// Starts an echo that takes `delay_ms` and returns its ticket. `tag`
    /// keeps two tickets from being one deduplicated request.
    async fn ticket(&self, id: &str, delay_ms: u64) -> String {
        let request = self.envelope(
            id,
            "echo",
            serde_json::json!({ "delay_ms": delay_ms, "tag": id }),
            false,
        );
        let response = self.call(&request).await;
        let Response::Ticket { ticket, .. } = response else {
            panic!("expected a ticket, got {response:?}");
        };
        ticket
    }

    /// Opens a follow of `ticket` under request id `id` and returns the
    /// stream right after the hello was acknowledged.
    async fn follow(
        &self,
        id: &str,
        ticket: &str,
        after_seq: u64,
        epoch: Option<&str>,
    ) -> FollowStream {
        let query = self.envelope(id, "query", serde_json::json!({ "ticket": ticket }), true);
        let mut stream = framed::connect_public(self.handle().runtime_dir())
            .await
            .expect("the public listener accepts");
        let ack = framed::follow(
            &mut stream,
            &framed::client_hello(Via::Direct),
            &query,
            after_seq,
            epoch,
        )
        .await
        .expect("the hello is acknowledged");
        FollowStream {
            stream,
            epoch: ack.epoch,
        }
    }

    async fn wait_for_state(&self, id: &str, state: RequestState) {
        let store = self.daemon.store();
        eventually(&format!("{id} is {state:?}"), || async {
            store
                .get_request(id)
                .await
                .unwrap()
                .is_some_and(|row| row.state == state)
        })
        .await;
    }
}

/// One follow connection, client side.
struct FollowStream {
    stream: PublicStream,
    /// The epoch the hello was acknowledged under.
    epoch: String,
}

impl FollowStream {
    /// The next daemon frame, bounded by [`PATIENCE`].
    async fn frame(&mut self) -> Result<Frame, DialError> {
        tokio::time::timeout(
            PATIENCE,
            framed::read_daemon_frame(&mut self.stream, MAX_FRAME_BYTES),
        )
        .await
        .expect("a frame within the test's patience")
    }

    async fn following(&mut self) -> Following {
        match self.frame().await {
            Ok(Frame::Following(following)) => following,
            other => panic!("expected following, got {other:?}"),
        }
    }

    /// Reads `event` frames until `end`: the events with their sequence
    /// numbers, then the end.
    async fn until_end(&mut self) -> (Vec<(u64, Event)>, End) {
        let mut events = Vec::new();
        loop {
            match self.frame().await {
                Ok(Frame::Event(frame)) => {
                    events.push((frame.seq.expect("a follow event carries seq"), frame.event));
                }
                Ok(Frame::End(end)) => return (events, end),
                other => panic!("expected event or end, got {other:?}"),
            }
        }
    }

    /// The whole stream when it is not known whether the ticket was still
    /// in flight: `following` if there was one, the events, the end.
    async fn whole(&mut self) -> (Option<Following>, Vec<(u64, Event)>, End) {
        let following = match self.frame().await {
            Ok(Frame::Following(following)) => following,
            Ok(Frame::End(end)) => return (None, Vec::new(), end),
            other => panic!("expected following or end, got {other:?}"),
        };
        let (events, end) = self.until_end().await;
        (Some(following), events, end)
    }

    /// The next `event` frame.
    async fn event(&mut self) -> (u64, Event) {
        match self.frame().await {
            Ok(Frame::Event(frame)) => {
                (frame.seq.expect("a follow event carries seq"), frame.event)
            }
            other => panic!("expected an event, got {other:?}"),
        }
    }

    async fn refused(&mut self) -> pam_proto::wire::ErrorFrame {
        match self.frame().await {
            Err(DialError::Refused(error)) => error,
            other => panic!("expected an error frame, got {other:?}"),
        }
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

fn progress(pct: u8) -> Event {
    Event::Progress {
        pct: Some(pct),
        note: "step build: cargo test in /private/repo".to_owned(),
    }
}

fn state_of(response: &Response) -> &str {
    match response {
        Response::Result { body, .. } => body["state"].as_str().expect("a state"),
        other => panic!("expected a result, got {other:?}"),
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

#[tokio::test]
async fn a_follow_streams_the_tickets_events_and_ends_with_the_durable_answer() {
    with_deadline(async {
        let fixture = Fixture::start().await;
        let store = fixture.daemon.store();
        let hub = fixture.handle().event_hub();

        let ticket = fixture.ticket("req_followed", 700).await;
        fixture.wait_for_state(&ticket, RequestState::Running).await;
        // Another ticket's events must never reach this follower.
        let other = fixture.ticket("req_other", 5_000).await;

        let mut follow = fixture.follow("req_follow", &ticket, 0, None).await;
        assert_eq!(follow.epoch, hub.epoch());
        let following = follow.following().await;
        assert_eq!(following.ticket, ticket);
        assert_eq!(following.epoch, hub.epoch());
        assert_eq!(following.state, "running");
        // Late attach: `queued` (and `started`, unless it is still on its
        // way) were published before the follow and come from the ring.
        assert!((1..=2).contains(&following.seq), "{following:?}");
        assert_eq!(follow.event().await, (1, Event::Queued));
        assert_eq!(follow.event().await, (2, Event::Started));

        hub.publish(&other, progress(10)).unwrap();
        hub.publish(&ticket, progress(40)).unwrap();
        let (events, end) = follow.until_end().await;
        assert_eq!(
            events,
            [
                // The public view of progress carries no task prose, and
                // the other ticket's event is not in this stream.
                (
                    3,
                    Event::Progress {
                        pct: Some(40),
                        note: PUBLIC_PROGRESS_NOTE.to_owned()
                    }
                ),
            ]
        );
        assert_eq!(end.seq, Some(4));
        assert_eq!(end.event, Some(Event::Done));
        assert_eq!(end.response.id(), "req_follow");
        assert_eq!(state_of(&end.response), "done");

        // `end` carries what a `query` answers at that moment.
        let query = fixture.envelope(
            "req_query_after",
            "query",
            serde_json::json!({ "ticket": ticket }),
            true,
        );
        let (
            Response::Result { body, outcome, .. },
            Response::Result {
                body: ended,
                outcome: ended_outcome,
                ..
            },
        ) = (fixture.call(&query).await, end.response)
        else {
            panic!("both are results");
        };
        assert_eq!(ended, body);
        assert_eq!(ended_outcome, outcome);

        // The whole follow cost one `query` request: one row, one terminal
        // audit row.
        let row = store.get_request("req_follow").await.unwrap().unwrap();
        assert_eq!(row.capability, "query");
        assert_eq!(row.state, RequestState::Done);
        assert_eq!(
            store.audit_for_request("req_follow").await.unwrap().len(),
            1
        );

        fixture.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn a_follow_of_a_finished_or_unreadable_ticket_ends_at_once() {
    with_deadline(async {
        let fixture = Fixture::start().await;
        let store = fixture.daemon.store();

        let ticket = fixture.ticket("req_finished", 0).await;
        fixture.wait_for_state(&ticket, RequestState::Done).await;

        // Attach after terminal: `end` is the first frame; nothing waits.
        let mut follow = fixture.follow("req_follow_late", &ticket, 0, None).await;
        let (events, end) = follow.until_end().await;
        assert!(events.is_empty());
        assert_eq!(end.event, Some(Event::Done));
        assert_eq!(state_of(&end.response), "done");

        // A ticket that does not exist reads exactly like one the caller may
        // not see: a refusal in `end`, and no event.
        let mut follow = fixture
            .follow("req_follow_missing", "no_such_ticket", 0, None)
            .await;
        let (events, end) = follow.until_end().await;
        assert!(events.is_empty());
        assert_eq!(end.event, None);
        assert_eq!(refusal(&end.response), ("result_unavailable", false));
        // The refused follow is still one audited `query`.
        let row = store
            .get_request("req_follow_missing")
            .await
            .unwrap()
            .unwrap();
        assert!(row.state.is_terminal());

        // A caller in a repository that is not the ticket's is refused the
        // same way.
        let elsewhere = tempfile::tempdir().unwrap();
        let foreign = envelope_for_repo(
            &elsewhere.path().to_string_lossy(),
            "req_follow_foreign",
            "query",
            serde_json::json!({ "ticket": ticket }),
            true,
        );
        let mut stream = framed::connect_public(fixture.handle().runtime_dir())
            .await
            .unwrap();
        framed::follow(
            &mut stream,
            &framed::client_hello(Via::Direct),
            &foreign,
            0,
            None,
        )
        .await
        .unwrap();
        let frame = framed::read_daemon_frame(&mut stream, MAX_FRAME_BYTES)
            .await
            .unwrap();
        let Frame::End(end) = frame else {
            panic!("expected end, got {frame:?}");
        };
        assert_eq!(refusal(&end.response), ("result_unavailable", false));

        // A follow must carry a waiting `query`: anything else is refused
        // before a row exists.
        let not_a_query = fixture.envelope(
            "req_follow_echo",
            "echo",
            serde_json::json!({ "ticket": ticket }),
            true,
        );
        let mut stream = framed::connect_public(fixture.handle().runtime_dir())
            .await
            .unwrap();
        framed::follow(
            &mut stream,
            &framed::client_hello(Via::Direct),
            &not_a_query,
            0,
            None,
        )
        .await
        .unwrap();
        let frame = framed::read_daemon_frame(&mut stream, MAX_FRAME_BYTES)
            .await
            .unwrap();
        let Frame::End(end) = frame else {
            panic!("expected end, got {frame:?}");
        };
        assert_eq!(refusal(&end.response), ("bad_request", false));
        assert!(
            store
                .get_request("req_follow_echo")
                .await
                .unwrap()
                .is_none()
        );

        fixture.daemon.stop().await;
    })
    .await;
}

/// The subscribe-after-publish race: a follow sent just before or just after
/// the ticket's terminal event must end with `end` on its own, from the
/// event or from the second read of the store — never by waiting for the
/// fifteen-second backstop (every read here is bounded well under it).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_follow_racing_the_terminal_event_always_ends() {
    with_deadline(async {
        let fixture = Fixture::start().await;

        // How many follows attached while the ticket was still in flight.
        let mut before_terminal = 0u32;
        for round in 0u64..24 {
            let id = format!("req_race_{round}");
            let ticket = fixture.ticket(&id, 40).await;
            // Spread the follow across the moment the echo finishes.
            tokio::time::sleep(Duration::from_millis(round * 4)).await;
            let mut follow = fixture
                .follow(&format!("req_race_follow_{round}"), &ticket, 0, None)
                .await;
            let (following, events, end) = follow.whole().await;
            assert_eq!(end.event, Some(Event::Done), "round {round}");
            assert_eq!(state_of(&end.response), "done", "round {round}");
            before_terminal += u32::from(following.is_some());
            // Whatever was delivered is in order, without repeats.
            assert!(
                events.windows(2).all(|pair| pair[0].0 < pair[1].0),
                "round {round}: {events:?}"
            );
            if let (Some(seq), Some((last, _))) = (end.seq, events.last()) {
                assert!(seq > *last, "round {round}: end {seq} after {last}");
            }
        }
        // Not asserted: how the rounds split depends on the machine. The
        // case where the terminal event lands exactly between authorisation
        // and attach is forced deterministically in `public_transport_test`.
        println!("{before_terminal} of 24 follows attached before the terminal event");
        // Every follower slot came back.
        eventually("no follower is left attached", || async {
            fixture.handle().event_hub().usage().followers == 0
        })
        .await;

        fixture.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn a_follow_resumes_after_the_last_sequence_number_it_saw() {
    with_deadline(async {
        let fixture = Fixture::start().await;
        let hub = fixture.handle().event_hub();

        let ticket = fixture.ticket("req_resumed", 20_000).await;
        fixture.wait_for_state(&ticket, RequestState::Running).await;

        let mut first = fixture.follow("req_resume_1", &ticket, 0, None).await;
        let epoch = first.epoch.clone();
        first.following().await;
        assert_eq!(first.event().await, (1, Event::Queued));
        assert_eq!(first.event().await, (2, Event::Started));
        hub.publish(&ticket, progress(10)).unwrap();
        assert_eq!(first.event().await.0, 3);
        // The connection is lost after seq 3; more happens meanwhile.
        drop(first);
        hub.publish(&ticket, progress(20)).unwrap();
        hub.publish(&ticket, progress(30)).unwrap();

        // Same epoch: only what came after seq 3.
        let mut resumed = fixture
            .follow("req_resume_2", &ticket, 3, Some(&epoch))
            .await;
        let following = resumed.following().await;
        assert_eq!(following.seq, 5);
        assert_eq!(following.state, "running");
        assert_eq!(resumed.event().await.0, 4);
        assert_eq!(resumed.event().await.0, 5);
        hub.publish(&ticket, progress(60)).unwrap();
        assert_eq!(resumed.event().await.0, 6);

        // Another epoch (the daemon restarted and counts again): the
        // position means nothing and the ring is replayed from the start.
        let mut restarted = fixture
            .follow(
                "req_resume_3",
                &ticket,
                3,
                Some("01JB2M5T8Q0V7K3W9X4Y6Z1ABC"),
            )
            .await;
        assert_eq!(restarted.following().await.seq, 6);
        for expected in 1..=6 {
            assert_eq!(restarted.event().await.0, expected);
        }

        // A disconnecting follower never cancels the work.
        drop(resumed);
        drop(restarted);
        eventually("the followers detached", || async {
            hub.usage().followers == 0
        })
        .await;
        let store = fixture.daemon.store();
        let row = store.get_request(&ticket).await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Running, "{row:?}");
        let audit = store.audit_for_request(&ticket).await.unwrap();
        assert!(audit.iter().all(|row| row.action != ACTION_CANCEL));

        let cancel = fixture.envelope(
            "req_resume_cancel",
            "cancel",
            serde_json::json!({ "ticket": ticket }),
            true,
        );
        let _ = fixture.call(&cancel).await;
        fixture.daemon.stop().await;
    })
    .await;
}

/// A follower that stops reading while thousands of events are published:
/// publishing never waits for it, its queue stays bounded so it sees a gap in
/// the sequence, and its stream still ends with the durable answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_follower_loses_progress_but_not_the_ending() {
    with_deadline(async {
        let fixture = Fixture::start().await;
        let hub = fixture.handle().event_hub();

        let ticket = fixture.ticket("req_slow", 2_500).await;
        fixture.wait_for_state(&ticket, RequestState::Running).await;
        let mut slow = fixture.follow("req_slow_follow", &ticket, 0, None).await;
        slow.following().await;
        let mut prompt = fixture.follow("req_prompt_follow", &ticket, 0, None).await;
        prompt.following().await;

        // The slow follower reads nothing while 20,000 events are published.
        // The other follower keeps reading, so its own queue is not what is
        // being tested.
        let published: u64 = 20_000;
        let reader = tokio::spawn(async move {
            let (events, end) = prompt.until_end().await;
            (events.len(), end)
        });
        let started = std::time::Instant::now();
        for index in 0..published {
            hub.publish(&ticket, progress(u8::try_from(index % 100).unwrap()))
                .unwrap();
        }
        // Nothing in `publish` waited on the follower that is not reading.
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "publishing waited on a slow follower: {:?}",
            started.elapsed()
        );

        // Now it reads: far fewer events than were published, in order, with
        // a gap — and then the ending, which cannot be dropped.
        let (events, end) = slow.until_end().await;
        let delivered = u64::try_from(events.len()).unwrap();
        assert!(
            delivered < published,
            "a slow follower must not be sent everything: {delivered}"
        );
        assert!(events.windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert!(
            events.windows(2).any(|pair| pair[1].0 > pair[0].0 + 1),
            "expected a gap in seq among {delivered} events"
        );
        // What it did get at the end is the tail of the stream: the queue
        // held the most recent events, not the oldest.
        let tail = events.last().expect("some events").0;
        assert!(tail > published - u64::try_from(FOLLOWER_QUEUE).unwrap());
        assert_eq!(end.event, Some(Event::Done));
        assert_eq!(end.seq, Some(published + 3));
        assert_eq!(state_of(&end.response), "done");

        // The follower that kept reading was not held back by the slow one.
        let (_, end) = reader.await.unwrap();
        assert_eq!(end.seq, Some(published + 3));
        assert_eq!(state_of(&end.response), "done");

        fixture.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn follower_slots_are_capped_per_ticket_and_in_total_and_come_back() {
    with_deadline(async {
        let fixture = Fixture::start_with(|config| {
            config.drain_timeout = Duration::from_millis(200);
        })
        .await;
        let hub = fixture.handle().event_hub();

        // Seven tickets in flight: the first runs, the rest queue behind it.
        let tickets_needed = MAX_FOLLOWERS / MAX_FOLLOWERS_PER_TICKET + 1;
        let mut tickets = Vec::new();
        for index in 0..tickets_needed {
            tickets.push(fixture.ticket(&format!("req_cap_{index}"), 30_000).await);
        }

        // Opens one follow, retrying while the control rate window is spent
        // (each follow is a `query`, and 64 are admitted per second).
        let attach = |name: String, ticket: String| {
            let fixture = &fixture;
            async move {
                loop {
                    let mut follow = fixture.follow(&name, &ticket, 0, None).await;
                    match follow.frame().await {
                        Ok(Frame::Following(_)) => return Ok(follow),
                        Ok(Frame::End(end)) => {
                            let (cause, retryable) = refusal(&end.response);
                            if cause == "request_rate_exhausted" {
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                continue;
                            }
                            return Err((cause.to_owned(), retryable));
                        }
                        other => panic!("expected following or end, got {other:?}"),
                    }
                }
            }
        };

        // Sixteen followers of one ticket; the seventeenth is refused with a
        // cause a client retries.
        let mut held = Vec::new();
        for slot in 0..MAX_FOLLOWERS_PER_TICKET {
            held.push(
                attach(format!("req_f0_{slot}"), tickets[0].clone())
                    .await
                    .expect("a follower slot"),
            );
        }
        let refused = attach("req_f0_over".to_owned(), tickets[0].clone())
            .await
            .err()
            .expect("the seventeenth follower of one ticket is refused");
        assert_eq!(
            refused,
            (cause::FOLLOWER_CAPACITY_EXHAUSTED.to_owned(), true)
        );
        // A slot freed by a disconnect is reusable.
        drop(held.pop());
        eventually("the freed slot is seen", || async {
            hub.usage().followers == MAX_FOLLOWERS_PER_TICKET - 1
        })
        .await;
        held.push(
            attach("req_f0_again".to_owned(), tickets[0].clone())
                .await
                .expect("the freed slot is reusable"),
        );

        // Fill the daemon: ninety-six followers across six tickets.
        for (index, ticket) in tickets.iter().enumerate().take(tickets_needed - 1).skip(1) {
            for slot in 0..MAX_FOLLOWERS_PER_TICKET {
                held.push(
                    attach(format!("req_f{index}_{slot}"), ticket.clone())
                        .await
                        .expect("a follower slot"),
                );
            }
        }
        assert_eq!(hub.usage().followers, MAX_FOLLOWERS);
        // The ninety-seventh, on a ticket nobody follows yet.
        let refused = attach(
            "req_f_total".to_owned(),
            tickets[tickets_needed - 1].clone(),
        )
        .await
        .err()
        .expect("the ninety-seventh follower is refused");
        assert_eq!(
            refused,
            (cause::FOLLOWER_CAPACITY_EXHAUSTED.to_owned(), true)
        );
        // Followers hold connections, not request slots: unary calls are
        // still served.
        let echo = fixture.envelope("req_while_full", "status", serde_json::json!({}), true);
        assert!(matches!(fixture.call(&echo).await, Response::Result { .. }));
        eventually("only the followers hold connections", || async {
            fixture.handle().public_connections_available()
                == MAX_PUBLIC_CONNECTIONS - MAX_FOLLOWERS
        })
        .await;

        drop(held);
        eventually("every follower slot comes back", || async {
            hub.usage().followers == 0
        })
        .await;
        fixture.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn a_follower_that_speaks_is_a_protocol_error_and_the_work_goes_on() {
    with_deadline(async {
        let fixture = Fixture::start().await;
        let store = fixture.daemon.store();

        let ticket = fixture.ticket("req_spoken_to", 600).await;
        let mut follow = fixture.follow("req_speaker", &ticket, 0, None).await;
        follow.following().await;
        // After `follow` the client sends nothing.
        follow.stream.write_all(b"\0\0\0\x02{}").await.unwrap();
        let error = loop {
            match follow.frame().await {
                Ok(Frame::Event(_)) => {}
                Err(DialError::Refused(error)) => break error,
                other => panic!("expected events then an error, got {other:?}"),
            }
        };
        assert_eq!(error.cause, cause::BAD_FRAME);

        fixture.wait_for_state(&ticket, RequestState::Done).await;
        let audit = store.audit_for_request(&ticket).await.unwrap();
        assert!(audit.iter().all(|row| row.action != ACTION_CANCEL));

        fixture.daemon.stop().await;
    })
    .await;
}

/// The drain: followers are told the daemon is shutting down as soon as it
/// leaves `Serving`; they are not left to find out from a closed socket.
#[tokio::test]
async fn followers_are_told_when_the_daemon_shuts_down() {
    with_deadline(async {
        let fixture = Fixture::start_with(|config| {
            config.drain_timeout = Duration::from_millis(200);
        })
        .await;
        let dirs = fixture.handle().runtime_dir().clone();

        let ticket = fixture.ticket("req_drained", 30_000).await;
        fixture.wait_for_state(&ticket, RequestState::Running).await;
        let mut follow = fixture.follow("req_drain_follow", &ticket, 0, None).await;
        follow.following().await;
        assert_eq!(follow.event().await, (1, Event::Queued));
        assert_eq!(follow.event().await, (2, Event::Started));

        let Fixture {
            daemon,
            repo: _repo,
        } = fixture;
        let stopping = tokio::spawn(async move { daemon.stop().await });
        let error = follow.refused().await;
        assert_eq!(error.cause, cause::DAEMON_SHUTTING_DOWN);
        stopping.await.unwrap();

        #[cfg(unix)]
        assert!(!dirs.public_socket().exists());
        assert!(framed::connect_public(&dirs).await.is_err());
    })
    .await;
}
