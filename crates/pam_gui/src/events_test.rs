use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::sync::Mutex;
use std::time::Duration;

use pam_daemon::framed::DialError;
use pam_proto::Event;
use pam_proto::wire::{ErrorFrame, EventFrame, Ingress, cause};

use crate::events::{
    BACKOFF_MAX, BACKOFF_MIN, Connect, EventPayload, EventSink, EventSource, Next, PayloadEvent,
    SessionEnd, classify, next_backoff, next_pause, payload_from_frame, run_session,
};

#[test]
fn backoff_doubles_and_caps() {
    let mut pause = BACKOFF_MIN;
    let mut seen = vec![pause];
    for _ in 0..10 {
        pause = next_backoff(pause);
        seen.push(pause);
    }
    assert_eq!(seen[1], BACKOFF_MIN * 2);
    assert_eq!(seen[2], BACKOFF_MIN * 4);
    assert!(seen.iter().all(|pause| *pause <= BACKOFF_MAX));
    assert_eq!(*seen.last().expect("non-empty"), BACKOFF_MAX);
    // The cap is a fixed point: reconnect pauses never grow past it.
    assert_eq!(next_backoff(BACKOFF_MAX), BACKOFF_MAX);
    assert_eq!(next_backoff(Duration::MAX), BACKOFF_MAX);
}

fn frame(n: u64, ticket: &str, event: Event) -> EventFrame {
    EventFrame {
        seq: None,
        n: Some(n),
        ticket: Some(ticket.to_owned()),
        capability: Some("flow.run".to_owned()),
        repo: Some("/work/app".to_owned()),
        agent: Some("claude".to_owned()),
        ingress: Some(Ingress::Public),
        event,
    }
}

#[test]
fn an_all_events_frame_forwards_its_rich_members() {
    let forwarded = payload_from_frame(frame(
        7,
        "req_01ABC",
        Event::Progress {
            pct: Some(40),
            note: "step build: cargo test".to_owned(),
        },
    ))
    .expect("a frame with a ticket forwards");
    assert_eq!(
        serde_json::to_value(&forwarded).expect("serializes"),
        serde_json::json!({
            "ticket": "req_01ABC",
            "event": { "kind": "progress", "pct": 40, "note": "step build: cargo test" },
            "n": 7,
            "capability": "flow.run",
            "repo": "/work/app",
            "agent": "claude",
            "ingress": "public",
        })
    );
}

#[test]
fn members_the_daemon_did_not_send_are_left_out_not_nulled() {
    let bare = EventFrame {
        seq: None,
        n: Some(1),
        ticket: Some("req_1".to_owned()),
        capability: None,
        repo: None,
        agent: None,
        ingress: None,
        event: Event::Done,
    };
    assert_eq!(
        serde_json::to_value(payload_from_frame(bare).expect("forwards")).expect("serializes"),
        serde_json::json!({ "ticket": "req_1", "event": { "kind": "done" }, "n": 1 })
    );
}

#[test]
fn a_frame_without_a_ticket_is_dropped_not_fatal() {
    let mut orphan = frame(1, "ignored", Event::Done);
    orphan.ticket = None;
    assert_eq!(payload_from_frame(orphan), None);
}

#[test]
fn the_resync_marker_is_an_event_kind_with_no_ticket() {
    assert_eq!(
        serde_json::to_value(EventPayload::resync()).expect("serializes"),
        serde_json::json!({ "ticket": "", "event": { "kind": "resync" } })
    );
}

fn refused(cause: &str) -> DialError {
    DialError::Refused(ErrorFrame::new(cause, "detail", "recovery"))
}

#[test]
fn every_end_of_a_stream_has_a_reconnect_policy() {
    for (error, expected) in [
        (refused(cause::SUBSCRIBER_LAGGED), Next::Lagged),
        (refused(cause::SUBSCRIBER_CAPACITY_EXHAUSTED), Next::Backoff),
        (refused(cause::DAEMON_SHUTTING_DOWN), Next::Backoff),
        (refused(cause::DAEMON_OUTDATED), Next::Backoff),
        (refused(cause::CONNECTION_CAPACITY_EXHAUSTED), Next::Backoff),
        (refused(cause::CLIENT_VERSION_MISMATCH), Next::Slow),
        (refused(cause::PROTOCOL_MISMATCH), Next::Slow),
        (DialError::LegacyDaemon, Next::Slow),
        (
            DialError::Io(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Next::Backoff,
        ),
        (
            DialError::Io(io::Error::from(io::ErrorKind::NotFound)),
            Next::Backoff,
        ),
        (DialError::Protocol("odd".to_owned()), Next::Backoff),
    ] {
        assert_eq!(classify(&error), expected, "{error}");
    }
}

#[test]
fn the_pause_follows_how_the_stream_ended() {
    let backoff = BACKOFF_MIN * 4;
    let ended = |delivered, next| SessionEnd { delivered, next };

    // A plain failure waits the running backoff and doubles it.
    assert_eq!(
        next_pause(ended(false, Next::Backoff), backoff),
        (backoff, backoff * 2)
    );
    // A stream that delivered something starts over.
    assert_eq!(
        next_pause(ended(true, Next::Backoff), backoff),
        (BACKOFF_MIN, BACKOFF_MIN * 2)
    );
    // A lagged subscriber comes straight back, never later than the first pause.
    assert_eq!(
        next_pause(ended(false, Next::Lagged), BACKOFF_MAX),
        (BACKOFF_MIN, BACKOFF_MIN * 2)
    );
    // A window that is not the daemon's build waits at the cap and stays there.
    assert_eq!(
        next_pause(ended(false, Next::Slow), BACKOFF_MIN),
        (BACKOFF_MAX, BACKOFF_MAX)
    );
}

/// A source that replays a script: frames, then the error that ends the stream.
struct ScriptedSource {
    items: VecDeque<Result<EventFrame, DialError>>,
}

impl EventSource for ScriptedSource {
    fn next_event(&mut self) -> impl Future<Output = Result<EventFrame, DialError>> + Send {
        std::future::ready(
            self.items.pop_front().unwrap_or_else(|| {
                Err(DialError::Io(io::Error::from(io::ErrorKind::UnexpectedEof)))
            }),
        )
    }
}

/// What one scripted stream yields, in order, before the connection ends.
type Frames = Vec<Result<EventFrame, DialError>>;

/// One scripted connect per session: a stream, or the dial's error.
struct Script {
    sessions: Mutex<VecDeque<Result<Frames, DialError>>>,
}

impl Script {
    fn new(sessions: Vec<Result<Frames, DialError>>) -> Self {
        Self {
            sessions: Mutex::new(sessions.into()),
        }
    }
}

impl Connect for Script {
    type Source = ScriptedSource;

    fn connect(&self) -> impl Future<Output = Result<ScriptedSource, DialError>> + Send {
        std::future::ready(match self.sessions.lock().expect("script").pop_front() {
            Some(Ok(items)) => Ok(ScriptedSource {
                items: items.into(),
            }),
            Some(Err(error)) => Err(error),
            None => Err(DialError::Io(io::Error::from(io::ErrorKind::NotFound))),
        })
    }
}

/// Collects what the webview would receive; refuses after `capacity` when one is set.
#[derive(Default)]
struct Collector {
    seen: Mutex<Vec<EventPayload>>,
    capacity: Option<usize>,
}

impl Collector {
    fn seen(&self) -> Vec<EventPayload> {
        self.seen.lock().expect("collector").clone()
    }

    fn resyncs(&self) -> usize {
        self.seen()
            .iter()
            .filter(|payload| matches!(payload.event, PayloadEvent::Resync { .. }))
            .count()
    }
}

impl EventSink for Collector {
    fn emit(&self, payload: &EventPayload) -> bool {
        let mut seen = self.seen.lock().expect("collector");
        if self.capacity.is_some_and(|capacity| seen.len() >= capacity) {
            return false;
        }
        seen.push(payload.clone());
        true
    }
}

fn tickets(sink: &Collector) -> Vec<String> {
    sink.seen()
        .into_iter()
        .filter(|payload| matches!(payload.event, PayloadEvent::Lifecycle(_)))
        .map(|payload| payload.ticket)
        .collect()
}

/// Every successful connect asks for one refresh, because nothing published before the
/// subscription is replayed; events then follow in order.
#[tokio::test]
async fn a_connect_asks_for_one_refresh_and_events_follow_in_order() {
    let script = Script::new(vec![Ok(vec![
        Ok(frame(1, "req_a", Event::Queued)),
        Ok(frame(2, "req_a", Event::Started)),
        Ok(frame(3, "req_a", Event::Done)),
        Err(refused(cause::DAEMON_SHUTTING_DOWN)),
    ])]);
    let sink = Collector::default();
    let end = run_session(&script, &sink).await;

    assert_eq!(
        end,
        SessionEnd {
            delivered: true,
            next: Next::Backoff
        },
        "a draining daemon is retried with backoff, not alarmed over"
    );
    assert_eq!(sink.resyncs(), 1, "one refresh for the connect");
    assert_eq!(
        sink.seen()[0].event,
        PayloadEvent::Resync { kind: "resync" }
    );
    assert_eq!(tickets(&sink), ["req_a", "req_a", "req_a"]);
}

/// A subscriber that overflowed is closed by the daemon; reconnecting refreshes once, and the
/// refresh is the connect's, not a second one.
#[tokio::test]
async fn a_lagged_stream_ends_in_one_resync_after_the_reconnect() {
    let script = Script::new(vec![
        Ok(vec![
            Ok(frame(10, "req_a", Event::Started)),
            Err(refused(cause::SUBSCRIBER_LAGGED)),
        ]),
        Ok(vec![Ok(frame(500, "req_b", Event::Done))]),
    ]);
    let sink = Collector::default();

    let first = run_session(&script, &sink).await;
    assert_eq!(first.next, Next::Lagged);
    assert_eq!(
        sink.resyncs(),
        1,
        "the lag itself adds no refresh; only the first connect's is there"
    );

    let (pause, _) = next_pause(first, BACKOFF_MAX);
    assert_eq!(
        pause, BACKOFF_MIN,
        "a lagged subscriber comes straight back"
    );

    let _ = run_session(&script, &sink).await;
    assert_eq!(
        sink.resyncs(),
        2,
        "the reconnect is the one refresh that follows the lag"
    );
    // `n` restarts or jumps across a reconnect; the counter is only compared inside one stream.
    assert_eq!(tickets(&sink), ["req_a", "req_b"]);
}

/// A step in `n` means progress was dropped for this subscriber: refresh once, then carry on.
#[tokio::test]
async fn a_gap_in_the_counter_asks_for_a_refresh_before_the_event_that_shows_it() {
    let script = Script::new(vec![Ok(vec![
        Ok(frame(1, "req_a", Event::Queued)),
        Ok(frame(2, "req_a", Event::Started)),
        Ok(frame(9, "req_a", Event::Done)),
        Ok(frame(10, "req_b", Event::Queued)),
    ])]);
    let sink = Collector::default();
    let _ = run_session(&script, &sink).await;

    let kinds: Vec<&str> = sink
        .seen()
        .iter()
        .map(|payload| match payload.event {
            PayloadEvent::Resync { .. } => "resync",
            PayloadEvent::Lifecycle(Event::Queued) => "queued",
            PayloadEvent::Lifecycle(Event::Started) => "started",
            PayloadEvent::Lifecycle(Event::Done) => "done",
            PayloadEvent::Lifecycle(_) => "other",
        })
        .collect();
    assert_eq!(
        kinds,
        ["resync", "queued", "started", "resync", "done", "queued"],
        "one refresh at the connect, one at the skip, none for consecutive events"
    );
}

#[tokio::test]
async fn a_dial_that_fails_forwards_nothing_and_says_why() {
    let sink = Collector::default();
    let down = Script::new(vec![Err(DialError::Io(io::Error::from(
        io::ErrorKind::ConnectionRefused,
    )))]);
    assert_eq!(
        run_session(&down, &sink).await,
        SessionEnd {
            delivered: false,
            next: Next::Backoff
        }
    );
    let full = Script::new(vec![Err(refused(cause::SUBSCRIBER_CAPACITY_EXHAUSTED))]);
    assert_eq!(
        run_session(&full, &sink).await,
        SessionEnd {
            delivered: false,
            next: Next::Backoff
        },
        "a fifth window backs off without a word"
    );
    let mismatch = Script::new(vec![Err(refused(cause::CLIENT_VERSION_MISMATCH))]);
    assert_eq!(run_session(&mismatch, &sink).await.next, Next::Slow);
    assert!(sink.seen().is_empty(), "nothing reaches the webview");
}

/// A webview that is gone ends the session; the pump then waits and tries again like any other
/// end.
#[tokio::test]
async fn a_sink_that_cannot_receive_ends_the_session() {
    let script = Script::new(vec![Ok(vec![Ok(frame(1, "req_a", Event::Queued))])]);
    let sink = Collector {
        capacity: Some(1),
        ..Collector::default()
    };
    let end = run_session(&script, &sink).await;
    assert_eq!(
        end,
        SessionEnd {
            delivered: false,
            next: Next::Backoff
        }
    );
    assert_eq!(sink.seen().len(), 1, "only the connect's refresh was taken");
}
