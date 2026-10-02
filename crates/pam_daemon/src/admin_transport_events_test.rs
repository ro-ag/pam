//! The all-events stream through the administration policy, over in-memory
//! streams: the hub on one side, the client half on the other.

use std::io;

use pam_proto::Event;
use pam_proto::wire::{EventFrame, Frame, Ingress, cause};
use tokio::io::AsyncWriteExt;

use super::events_stream::{AdminEvents, CAUSE_SUBSCRIBER_CAPACITY, subscribe_on};
use super::frame::MAX_REQUEST_BYTES;
use super::frame_test::{OWNER, Plane, bounded, hello, read, read_error, write};
use crate::event_hub::{MAX_SUBSCRIBERS, PUBLIC_PROGRESS_NOTE, SUBSCRIBER_QUEUE, TicketMeta};
use crate::framed::{self, DialError};
use crate::framed_test::eventually;
use crate::ingress::PeerIdentity;
use crate::lifecycle::LifecyclePhase;

const VERSION: &str = env!("CARGO_PKG_VERSION");

async fn subscribe(plane: &Plane, include_probes: bool) -> AdminEvents {
    subscribe_on(plane.connect(), &hello(VERSION), include_probes)
        .await
        .expect("subscribed")
}

fn meta(capability: &str, ingress: Ingress) -> TicketMeta {
    TicketMeta {
        capability: capability.to_owned(),
        repo: "/work/app".to_owned(),
        agent: "claude".to_owned(),
        ingress,
    }
}

fn progress(note: &str) -> Event {
    Event::Progress {
        pct: Some(40),
        note: note.to_owned(),
    }
}

/// The cause of the `error` frame that ended a stream.
fn refused(outcome: Result<EventFrame, DialError>) -> String {
    match outcome {
        Err(DialError::Refused(error)) => {
            assert!(!error.detail.is_empty() && !error.recovery.is_empty());
            error.cause
        }
        other => panic!("expected the stream to end with an error frame, got {other:?}"),
    }
}

/// Reads until the event for `ticket` that is `last`, returning everything
/// up to and including it as `(ticket, event)`.
async fn read_through(events: &mut AdminEvents, ticket: &str, last: &Event) -> Vec<EventFrame> {
    let mut seen = Vec::new();
    loop {
        let frame = events.next().await.expect("an event");
        let done = frame.ticket.as_deref() == Some(ticket) && &frame.event == last;
        seen.push(frame);
        if done {
            return seen;
        }
    }
}

fn pairs(frames: &[EventFrame]) -> Vec<(&str, &Event)> {
    frames
        .iter()
        .map(|frame| (frame.ticket.as_deref().expect("a ticket"), &frame.event))
        .collect()
}

fn assert_gap_free(frames: &[EventFrame]) {
    let numbers: Vec<u64> = frames.iter().map(|frame| frame.n.expect("n")).collect();
    assert!(
        numbers.windows(2).all(|pair| pair[1] == pair[0] + 1),
        "n has a gap: {numbers:?}"
    );
}

/// Every event arrives in the order it was published, with its ticket, the
/// admission metadata the daemon holds, and the real progress note: the
/// private plane is not given the public plane's constant.
#[tokio::test]
async fn the_stream_carries_rich_events_in_publish_order() {
    bounded(async {
        let plane = Plane::new().await;
        let mut events = subscribe(&plane, false).await;
        assert_eq!(events.epoch(), plane.hub.epoch());
        assert_eq!(events.daemon_version(), crate::daemon::DAEMON_VERSION);

        plane
            .hub
            .register("req_a", meta("flow.run", Ingress::Public));
        plane.hub.register("req_b", meta("echo", Ingress::Admin));
        let note = "step build: cargo test";
        let published = [
            ("req_a", Event::Queued),
            ("req_b", Event::Queued),
            ("req_a", Event::Started),
            ("req_c", Event::Started),
            ("req_a", progress(note)),
            ("req_b", Event::Done),
            ("req_a", Event::ApprovalPending),
            ("req_a", Event::Refused),
        ];
        for (ticket, event) in &published {
            plane.hub.publish(ticket, event.clone()).unwrap();
        }

        let frames = read_through(&mut events, "req_a", &Event::Refused).await;
        let expected: Vec<(&str, &Event)> = published
            .iter()
            .map(|(ticket, event)| (*ticket, event))
            .collect();
        assert_eq!(pairs(&frames), expected);
        assert_gap_free(&frames);
        assert_ne!(note, PUBLIC_PROGRESS_NOTE);

        for frame in &frames {
            assert_eq!(frame.seq, None, "seq belongs to the follow stream");
            match frame.ticket.as_deref() {
                Some("req_a") => {
                    assert_eq!(frame.capability.as_deref(), Some("flow.run"));
                    assert_eq!(frame.repo.as_deref(), Some("/work/app"));
                    assert_eq!(frame.agent.as_deref(), Some("claude"));
                    assert_eq!(frame.ingress, Some(Ingress::Public));
                }
                Some("req_b") => {
                    assert_eq!(frame.capability.as_deref(), Some("echo"));
                    assert_eq!(frame.ingress, Some(Ingress::Admin));
                }
                // A ticket nobody registered still streams, without metadata.
                Some("req_c") => {
                    assert_eq!(
                        (&frame.capability, &frame.repo, &frame.agent, frame.ingress),
                        (&None, &None, &None, None)
                    );
                }
                other => panic!("unexpected ticket {other:?}"),
            }
        }
    })
    .await;
}

/// `status` and `query` traffic is left out at the source unless the
/// subscriber asked for it, and either view is numbered without gaps.
#[tokio::test]
async fn probes_are_omitted_by_default_and_included_on_request() {
    bounded(async {
        let plane = Plane::new().await;
        let mut quiet = subscribe(&plane, false).await;
        let mut everything = subscribe(&plane, true).await;

        plane
            .hub
            .register("req_status", meta("status", Ingress::Public));
        plane
            .hub
            .register("req_query", meta("query", Ingress::Public));
        plane
            .hub
            .register("req_work", meta("echo", Ingress::Public));
        let published = [
            ("req_status", Event::Queued),
            ("req_work", Event::Queued),
            ("req_status", Event::Done),
            ("req_query", Event::Started),
            ("req_query", Event::Done),
            ("req_work", Event::Done),
        ];
        for (ticket, event) in &published {
            plane.hub.publish(ticket, event.clone()).unwrap();
        }

        let seen = read_through(&mut quiet, "req_work", &Event::Done).await;
        assert_eq!(
            pairs(&seen),
            [("req_work", &Event::Queued), ("req_work", &Event::Done)]
        );
        assert_gap_free(&seen);

        let seen = read_through(&mut everything, "req_work", &Event::Done).await;
        let expected: Vec<(&str, &Event)> = published
            .iter()
            .map(|(ticket, event)| (*ticket, event))
            .collect();
        assert_eq!(pairs(&seen), expected);
        assert_gap_free(&seen);
    })
    .await;
}

/// At most four subscribers. The fifth is told why and takes no slot; a slot
/// freed by a client that went away is reusable.
#[tokio::test]
async fn the_subscriber_cap_is_enforced_and_a_freed_slot_is_reusable() {
    bounded(async {
        let plane = Plane::new().await;
        let mut held = Vec::new();
        for _ in 0..MAX_SUBSCRIBERS {
            held.push(subscribe(&plane, false).await);
        }
        assert_eq!(plane.hub.usage().subscribers, MAX_SUBSCRIBERS);

        let outcome = subscribe_on(plane.connect(), &hello(VERSION), false).await;
        match outcome {
            Err(DialError::Refused(error)) => {
                assert_eq!(error.cause, CAUSE_SUBSCRIBER_CAPACITY);
            }
            other => panic!("expected a capacity refusal, got {other:?}"),
        }
        assert_eq!(plane.hub.usage().subscribers, MAX_SUBSCRIBERS);

        // The held ones are unaffected.
        plane.hub.publish("req_x", Event::Queued).unwrap();
        for events in &mut held {
            assert_eq!(events.next().await.unwrap().event, Event::Queued);
        }

        // A client that closes ends its stream and frees its slot.
        drop(held.pop());
        eventually(|| plane.hub.usage().subscribers == MAX_SUBSCRIBERS - 1).await;
        let mut again = subscribe(&plane, false).await;
        plane.hub.publish("req_y", Event::Started).unwrap();
        assert_eq!(again.next().await.unwrap().ticket.as_deref(), Some("req_y"));
    })
    .await;
}

/// A subscriber that falls behind loses progress first, and is not closed for
/// it: the gap in `n` is the signal. Publishing never waits for it.
#[tokio::test]
async fn a_slow_subscriber_loses_progress_before_anything_else() {
    bounded(async {
        let plane = Plane::new().await;
        let mut slow = subscribe(&plane, false).await;
        // No await in this loop: the serving task cannot take anything, so
        // the queue overflows three times over.
        for index in 0..3 * SUBSCRIBER_QUEUE {
            plane
                .hub
                .publish("req_busy", progress(&format!("line {index}")))
                .unwrap();
        }
        plane.hub.publish("req_busy", Event::Done).unwrap();

        let frames = read_through(&mut slow, "req_busy", &Event::Done).await;
        assert!(frames.len() <= SUBSCRIBER_QUEUE, "{} frames", frames.len());
        let first = frames[0].n.expect("n");
        assert!(
            first > 1,
            "the oldest progress was dropped; first n = {first}"
        );
        // Still subscribed, still in order.
        plane.hub.publish("req_next", Event::Queued).unwrap();
        assert_eq!(
            slow.next().await.unwrap().ticket.as_deref(),
            Some("req_next")
        );
        assert_eq!(plane.hub.usage().subscribers, 1);
    })
    .await;
}

/// The lag rule: when the bounded queue overflows with events that may not
/// be dropped, the subscriber is closed with `subscriber_lagged`. It
/// reconnects and refetches; nobody else is affected.
#[tokio::test]
async fn a_subscriber_whose_queue_overflows_is_closed_with_subscriber_lagged() {
    bounded(async {
        let plane = Plane::new().await;
        let mut lagging = subscribe(&plane, false).await;
        for index in 0..SUBSCRIBER_QUEUE + 8 {
            plane
                .hub
                .publish(&format!("req_{index}"), Event::Queued)
                .unwrap();
        }
        // Whatever was already on the wire arrives; then the verdict.
        let ended = loop {
            match lagging.next().await {
                Ok(_) => {}
                ended @ Err(_) => break ended,
            }
        };
        assert_eq!(refused(ended), cause::SUBSCRIBER_LAGGED);
        eventually(|| plane.hub.usage().subscribers == 0).await;

        // Publishing was never held up, and a new subscription starts clean.
        let mut fresh = subscribe(&plane, false).await;
        plane.hub.publish("req_after", Event::Started).unwrap();
        let frame = fresh.next().await.unwrap();
        assert_eq!(frame.ticket.as_deref(), Some("req_after"));
    })
    .await;
}

/// A client that stops reading is disconnected at the write timeout and its
/// slot comes back; the hub never waited for it.
#[tokio::test]
async fn a_subscriber_that_does_not_read_is_dropped_at_the_write_timeout() {
    bounded(async {
        let plane = Plane::new().await;
        let mut stuck = subscribe(&plane, false).await;
        tokio::time::pause();
        // More bytes than the connection buffers: the serving task ends up
        // waiting on a write the client never reads.
        let note = "n".repeat(8 * 1024);
        for _ in 0..SUBSCRIBER_QUEUE {
            plane.hub.publish("req_big", progress(&note)).unwrap();
        }
        let started = tokio::time::Instant::now();
        eventually(|| plane.hub.usage().subscribers == 0).await;
        assert!(
            started.elapsed() >= framed::WRITE_TIMEOUT,
            "dropped after {:?}",
            started.elapsed()
        );
        // What was buffered is still readable; then the stream is just gone.
        let ended = loop {
            match stuck.next().await {
                Ok(_) => {}
                Err(error) => break error,
            }
        };
        assert!(
            matches!(&ended, DialError::Io(error) if error.kind() == io::ErrorKind::UnexpectedEof),
            "{ended:?}"
        );
    })
    .await;
}

/// Drain: the stream is cut with `daemon_shutting_down` when the phase leaves
/// `Serving`, when the listener stops, and when the hub closes; and an
/// `events` request that arrives while draining is refused the same way.
#[tokio::test]
async fn the_drain_ends_every_stream_with_daemon_shutting_down() {
    bounded(async {
        for ending in ["phase", "restart", "listener", "hub"] {
            let plane = Plane::new().await;
            let mut events = subscribe(&plane, false).await;
            plane.hub.publish("req_before", Event::Queued).unwrap();
            assert_eq!(events.next().await.unwrap().event, Event::Queued);
            match ending {
                "phase" => {
                    plane.phase.send_replace(LifecyclePhase::Draining);
                }
                "restart" => {
                    plane.phase.send_replace(LifecyclePhase::Restarting);
                }
                "listener" => {
                    plane.stop.send_replace(true);
                }
                _ => plane.hub.close(),
            }
            assert_eq!(
                refused(events.next().await),
                cause::DAEMON_SHUTTING_DOWN,
                "{ending}"
            );
            eventually(|| plane.hub.usage().subscribers == 0).await;
        }

        let plane = Plane::new().await;
        plane.phase.send_replace(LifecyclePhase::Draining);
        let outcome = subscribe_on(plane.connect(), &hello(VERSION), false).await;
        assert!(
            matches!(&outcome, Err(DialError::Refused(error)) if error.cause == cause::DAEMON_SHUTTING_DOWN),
            "{outcome:?}"
        );
        assert_eq!(plane.hub.usage().subscribers, 0);
    })
    .await;
}

/// The wire sequence, frame by frame: `hello_ack`, `subscribed`, then events;
/// and after `events` the client sends nothing.
#[tokio::test]
async fn the_wire_sequence_is_ack_subscribed_events_and_the_client_stays_silent() {
    bounded(async {
        let plane = Plane::new().await;
        let mut client = plane.connect();
        write(&mut client, &Frame::Hello(hello(VERSION))).await;
        write(
            &mut client,
            &Frame::Events {
                include_probes: false,
            },
        )
        .await;
        assert!(matches!(read(&mut client).await, Frame::HelloAck(_)));
        // The marker is exactly this on the wire, and the shared enum names it.
        let body = framed::read_frame(&mut client, MAX_REQUEST_BYTES)
            .await
            .unwrap();
        assert_eq!(body, br#"{"t":"subscribed"}"#);
        assert_eq!(Frame::decode(&body), Ok(Frame::Subscribed));
        assert_eq!(plane.hub.usage().subscribers, 1);

        plane.hub.publish("req_w", Event::Started).unwrap();
        let Frame::Event(event) = read(&mut client).await else {
            panic!("expected an event frame");
        };
        assert_eq!(
            serde_json::to_value(&event).unwrap(),
            serde_json::json!({ "n": 1, "ticket": "req_w", "event": { "kind": "started" } })
        );

        // Any byte from the client now is a protocol error.
        client.write_all(b"x").await.unwrap();
        assert_eq!(read_error(&mut client).await.cause, cause::BAD_FRAME);
        eventually(|| plane.hub.usage().subscribers == 0).await;
    })
    .await;
}

/// The stream is behind the same door as every admin request: the hello's
/// version rule and the owner check both come first.
#[tokio::test]
async fn a_stream_is_refused_to_another_build_and_to_another_peer() {
    bounded(async {
        let plane = Plane::new().await;
        let outcome = subscribe_on(plane.connect(), &hello("9.9.9"), true).await;
        assert!(
            matches!(&outcome, Err(DialError::Refused(error)) if error.cause == cause::CLIENT_VERSION_MISMATCH),
            "{outcome:?}"
        );
        let stranger = PeerIdentity::Unix {
            uid: OWNER + 1,
            gid: 20,
            pid: Some(9),
        };
        let outcome = subscribe_on(plane.connect_as(stranger), &hello(VERSION), true).await;
        assert!(matches!(&outcome, Err(DialError::Io(_))), "{outcome:?}");
        assert_eq!(plane.hub.usage().subscribers, 0);
        assert_eq!(*plane.phase.borrow(), LifecyclePhase::Serving);
    })
    .await;
}

/// `next` under a timeout loses nothing: the caller can poll for quiet and
/// keep reading the same stream.
#[tokio::test]
async fn a_cancelled_next_keeps_the_stream_usable() {
    bounded(async {
        let plane = Plane::new().await;
        let mut events = subscribe(&plane, false).await;
        for round in 0..3 {
            let quiet =
                tokio::time::timeout(std::time::Duration::from_millis(20), events.next()).await;
            assert!(quiet.is_err(), "nothing was published");
            let ticket = format!("req_{round}");
            plane.hub.publish(&ticket, Event::Queued).unwrap();
            assert_eq!(events.next().await.unwrap().ticket, Some(ticket));
        }
    })
    .await;
}
