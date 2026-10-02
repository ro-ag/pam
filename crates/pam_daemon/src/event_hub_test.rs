//! The hub's contract: publish never waits, followers see only their ticket
//! and only sanitised events, the administration view is rich and filterable,
//! and every table and queue is bounded.

use std::sync::Arc;
use std::time::Duration;

use pam_proto::Event;
use pam_proto::wire::{Frame, Ingress};
use tokio::sync::mpsc;

use crate::event_hub::{
    AdminEvent, AttachError, EventHub, FOLLOWER_QUEUE, Followed, Follower, MAX_ENTRIES,
    MAX_FOLLOWERS, MAX_FOLLOWERS_PER_TICKET, MAX_SUBSCRIBERS, PUBLIC_PROGRESS_NOTE, REPLAY_RING,
    SUBSCRIBER_QUEUE, SubscribeError, Subscribed, Subscriber, TicketMeta,
};

const PATIENCE: Duration = Duration::from_secs(5);

fn progress(pct: u8, note: &str) -> Event {
    Event::Progress {
        pct: Some(pct),
        note: note.to_owned(),
    }
}

fn public_progress(pct: u8) -> Event {
    progress(pct, PUBLIC_PROGRESS_NOTE)
}

fn meta(capability: &str) -> TicketMeta {
    TicketMeta {
        capability: capability.to_owned(),
        repo: "/work/app".to_owned(),
        agent: "claude".to_owned(),
        ingress: Ingress::Public,
    }
}

async fn next(follower: &mut Follower) -> Followed {
    tokio::time::timeout(PATIENCE, follower.next())
        .await
        .expect("the follower has something to deliver")
}

async fn next_admin(subscriber: &mut Subscriber) -> Subscribed {
    tokio::time::timeout(PATIENCE, subscriber.next())
        .await
        .expect("the subscriber has something to deliver")
}

async fn admin_event(subscriber: &mut Subscriber) -> AdminEvent {
    match next_admin(subscriber).await {
        Subscribed::Event(event) => event,
        other => panic!("expected an event, got {other:?}"),
    }
}

/// A follower with nothing queued must be waiting, not spinning or ended.
async fn assert_idle(follower: &mut Follower) {
    assert!(
        tokio::time::timeout(Duration::from_millis(50), follower.next())
            .await
            .is_err(),
        "the follower had nothing to deliver"
    );
}

#[tokio::test]
async fn sequence_numbers_start_at_one_per_ticket_and_a_follower_sees_only_its_ticket() {
    let hub = EventHub::new();
    let mut a = hub.attach("req_a", 0).unwrap().follower;
    let mut b = hub.attach("req_b", 0).unwrap().follower;
    hub.publish("req_a", Event::Queued).unwrap();
    hub.publish("req_b", Event::Queued).unwrap();
    hub.publish("req_a", Event::Started).unwrap();
    hub.publish("req_a", progress(40, "step build: cargo test"))
        .unwrap();

    assert_eq!(a.ticket(), "req_a");
    assert_eq!(
        next(&mut a).await,
        Followed::Event {
            seq: 1,
            event: Event::Queued
        }
    );
    assert_eq!(
        next(&mut a).await,
        Followed::Event {
            seq: 2,
            event: Event::Started
        }
    );
    // Public followers never see progress prose.
    assert_eq!(
        next(&mut a).await,
        Followed::Event {
            seq: 3,
            event: public_progress(40)
        }
    );
    assert_idle(&mut a).await;
    // Ticket B counts on its own and never received A's events.
    assert_eq!(
        next(&mut b).await,
        Followed::Event {
            seq: 1,
            event: Event::Queued
        }
    );
    assert_idle(&mut b).await;
}

#[tokio::test]
async fn the_terminal_event_is_a_flag_delivered_after_everything_queued_before_it() {
    let hub = EventHub::new();
    let mut follower = hub.attach("req_a", 0).unwrap().follower;
    hub.publish("req_a", Event::Started).unwrap();
    hub.publish("req_a", Event::Done).unwrap();
    assert_eq!(
        next(&mut follower).await,
        Followed::Event {
            seq: 1,
            event: Event::Started
        }
    );
    assert_eq!(
        next(&mut follower).await,
        Followed::Terminal {
            seq: 2,
            event: Event::Done
        }
    );
    // The flag stays: asking again never blocks a handler that re-checks.
    assert_eq!(
        next(&mut follower).await,
        Followed::Terminal {
            seq: 2,
            event: Event::Done
        }
    );
    // The entry ended with its terminal event; the follower still holds its slot.
    assert_eq!(hub.usage().entries, 0);
    assert_eq!(hub.usage().followers, 1);
    drop(follower);
    assert_eq!(hub.usage().followers, 0);

    let mut refused = hub.attach("req_r", 0).unwrap().follower;
    hub.publish("req_r", Event::Refused).unwrap();
    assert_eq!(
        next(&mut refused).await,
        Followed::Terminal {
            seq: 1,
            event: Event::Refused
        }
    );
}

#[tokio::test]
async fn a_waiting_follower_is_woken_by_a_publish() {
    let hub = EventHub::new();
    let mut follower = hub.attach("req_a", 0).unwrap().follower;
    let waiting = tokio::spawn(async move { follower.next().await });
    tokio::task::yield_now().await;
    hub.publish("req_a", Event::Started).unwrap();
    let delivered = tokio::time::timeout(PATIENCE, waiting)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        delivered,
        Followed::Event {
            seq: 1,
            event: Event::Started
        }
    );
}

#[tokio::test]
async fn the_replay_ring_keeps_the_last_events_and_resumes_after_a_position() {
    let hub = EventHub::new();
    hub.publish("req_a", Event::Queued).unwrap();
    hub.publish("req_a", Event::Started).unwrap();

    // Late attach: `queued` and `started` were published before anyone
    // followed, and are replayed.
    let late = hub.attach("req_a", 0).unwrap();
    assert_eq!(late.seq, 2);
    assert_eq!(late.replay, vec![(1, Event::Queued), (2, Event::Started)]);
    drop(late);

    for pct in 0..38 {
        hub.publish("req_a", progress(pct, "private prose"))
            .unwrap();
    }
    // 40 events published; the ring holds the last 32, sanitised.
    let fresh = hub.attach("req_a", 0).unwrap();
    assert_eq!(fresh.seq, 40);
    assert_eq!(fresh.replay.len(), REPLAY_RING);
    assert_eq!(fresh.replay.first().unwrap().0, 9);
    assert_eq!(fresh.replay.last().unwrap(), &(40, public_progress(37)));
    assert!(
        fresh
            .replay
            .iter()
            .all(|(_, event)| *event == Event::Started
                || matches!(event, Event::Progress { note, .. } if note == PUBLIC_PROGRESS_NOTE))
    );

    // Resume: only what came after the position.
    let resumed = hub.attach("req_a", 38).unwrap();
    assert_eq!(
        resumed
            .replay
            .iter()
            .map(|(seq, _)| *seq)
            .collect::<Vec<_>>(),
        vec![39, 40]
    );
    let caught_up = hub.attach("req_a", 40).unwrap();
    assert!(caught_up.replay.is_empty());
    // A position beyond the ticket's counter belongs to another counter
    // (an evicted entry): replay everything rather than nothing.
    let stale = hub.attach("req_a", 4_000).unwrap();
    assert_eq!(stale.replay.len(), REPLAY_RING);
}

#[tokio::test]
async fn attach_and_replay_are_one_critical_section_with_later_events_on_the_queue() {
    let hub = EventHub::new();
    hub.publish("req_a", Event::Queued).unwrap();
    let mut attached = hub.attach("req_a", 0).unwrap();
    hub.publish("req_a", Event::Started).unwrap();
    // Nothing is delivered twice and nothing is missed across the attach.
    assert_eq!(attached.replay, vec![(1, Event::Queued)]);
    assert_eq!(
        next(&mut attached.follower).await,
        Followed::Event {
            seq: 2,
            event: Event::Started
        }
    );
    assert_idle(&mut attached.follower).await;
}

#[tokio::test]
async fn a_full_follower_queue_drops_the_oldest_progress_and_never_delays_publish() {
    let hub = EventHub::new();
    let mut slow = hub.attach("req_a", 0).unwrap().follower;
    let mut other = hub.attach("req_a", 0).unwrap().follower;
    hub.publish("req_a", Event::Queued).unwrap();
    hub.publish("req_a", Event::Started).unwrap();
    // Thousands of progress events at a follower that never reads: every
    // publish returns at once and the queue never exceeds its bound.
    tokio::time::timeout(PATIENCE, async {
        for index in 0..5_000u32 {
            hub.publish(
                "req_a",
                progress(u8::try_from(index % 100).unwrap(), "prose"),
            )
            .unwrap();
            assert!(slow.queued() <= FOLLOWER_QUEUE);
        }
    })
    .await
    .expect("publish never waits on a follower");
    hub.publish("req_a", Event::Done).unwrap();
    assert_eq!(slow.queued(), FOLLOWER_QUEUE);

    // The lifecycle events survived; the oldest progress events did not.
    assert_eq!(
        next(&mut slow).await,
        Followed::Event {
            seq: 1,
            event: Event::Queued
        }
    );
    assert_eq!(
        next(&mut slow).await,
        Followed::Event {
            seq: 2,
            event: Event::Started
        }
    );
    let mut last = 2;
    let mut delivered = 2;
    let terminal = loop {
        match next(&mut slow).await {
            Followed::Event { seq, event } => {
                assert!(seq > last, "sequence numbers only grow: {last} then {seq}");
                assert!(matches!(event, Event::Progress { .. }));
                last = seq;
                delivered += 1;
            }
            other => break other,
        }
    };
    assert_eq!(delivered, FOLLOWER_QUEUE);
    // The newest progress is the one that was kept.
    assert_eq!(last, 5_002);
    // The terminal condition cannot be dropped, and the gap needs no action.
    assert_eq!(
        terminal,
        Followed::Terminal {
            seq: 5_003,
            event: Event::Done
        }
    );

    // A second follower of the same ticket is independent of the slow one.
    assert_eq!(
        next(&mut other).await,
        Followed::Event {
            seq: 1,
            event: Event::Queued
        }
    );
}

#[tokio::test]
async fn lifecycle_events_are_dropped_only_when_nothing_else_can_be() {
    let hub = EventHub::new();
    let mut follower = hub.attach("req_a", 0).unwrap().follower;
    // A queue holding nothing but lifecycle events.
    for _ in 0..FOLLOWER_QUEUE {
        hub.publish("req_a", Event::ApprovalPending).unwrap();
    }
    assert_eq!(follower.queued(), FOLLOWER_QUEUE);
    // Progress never displaces a lifecycle event: it is the one dropped.
    hub.publish("req_a", progress(1, "prose")).unwrap();
    assert_eq!(follower.queued(), FOLLOWER_QUEUE);
    // A lifecycle event with no progress to displace takes the oldest slot.
    hub.publish("req_a", Event::Started).unwrap();
    assert_eq!(follower.queued(), FOLLOWER_QUEUE);
    assert_eq!(
        next(&mut follower).await,
        Followed::Event {
            seq: 2,
            event: Event::ApprovalPending
        },
        "the oldest lifecycle event (seq 1) made room"
    );
    let mut last = None;
    while follower.queued() > 0 {
        last = Some(next(&mut follower).await);
    }
    let newest = u64::try_from(FOLLOWER_QUEUE).unwrap() + 2;
    assert_eq!(
        last,
        Some(Followed::Event {
            seq: newest,
            event: Event::Started
        })
    );
}

#[tokio::test]
async fn follower_caps_hold_per_ticket_and_in_total_and_a_freed_slot_is_reusable() {
    let hub = EventHub::new();
    let mut held: Vec<Follower> = (0..MAX_FOLLOWERS_PER_TICKET)
        .map(|_| hub.attach("req_busy", 0).unwrap().follower)
        .collect();
    // The seventeenth follower of one ticket.
    assert_eq!(
        hub.attach("req_busy", 0).unwrap_err(),
        AttachError::TicketCapacity
    );
    // Another ticket is unaffected.
    held.push(hub.attach("req_other", 0).unwrap().follower);
    // A disconnect frees the slot.
    held.remove(0);
    held.push(hub.attach("req_busy", 0).unwrap().follower);

    let mut ticket = 0;
    while held.len() < MAX_FOLLOWERS {
        ticket += 1;
        held.push(hub.attach(&format!("req_{ticket}"), 0).unwrap().follower);
    }
    assert_eq!(hub.usage().followers, MAX_FOLLOWERS);
    // The ninety-seventh overall, on a ticket with room of its own.
    assert_eq!(
        hub.attach("req_fresh", 0).unwrap_err(),
        AttachError::TotalCapacity
    );
    held.pop();
    held.push(hub.attach("req_fresh", 0).unwrap().follower);
    assert_eq!(hub.usage().followers, MAX_FOLLOWERS);
    drop(held);
    assert_eq!(hub.usage().followers, 0);
    // Entries that only ever existed for a follower go with it.
    assert_eq!(hub.usage().entries, 0);
}

#[tokio::test]
async fn the_admin_subscription_sees_every_ticket_unsanitised_with_metadata() {
    let hub = EventHub::new();
    let mut subscriber = hub.subscribe_all(false).unwrap();
    let mut follower = hub.attach("req_a", 0).unwrap().follower;
    hub.register("req_a", meta("flow.run"));
    hub.publish("req_a", Event::Queued).unwrap();
    hub.publish("req_unregistered", Event::Started).unwrap();
    hub.publish("req_a", progress(40, "step build: cargo test"))
        .unwrap();

    let first = admin_event(&mut subscriber).await;
    assert_eq!(
        (first.n, first.ticket.as_str(), &first.event),
        (1, "req_a", &Event::Queued)
    );
    assert_eq!(first.meta.as_deref(), Some(&meta("flow.run")));
    let second = admin_event(&mut subscriber).await;
    assert_eq!((second.n, second.ticket.as_str()), (2, "req_unregistered"));
    assert_eq!(second.meta, None);
    let third = admin_event(&mut subscriber).await;
    // The real note, in publish order, with a gap-free counter.
    assert_eq!(third.n, 3);
    assert_eq!(third.event, progress(40, "step build: cargo test"));
    // The public follower of the same ticket got the constant instead.
    assert_eq!(
        next(&mut follower).await,
        Followed::Event {
            seq: 1,
            event: Event::Queued
        }
    );
    assert_eq!(
        next(&mut follower).await,
        Followed::Event {
            seq: 2,
            event: public_progress(40)
        }
    );

    assert_eq!(
        serde_json::to_value(third.into_frame()).unwrap(),
        serde_json::json!({
            "t": "event", "n": 3, "ticket": "req_a", "capability": "flow.run",
            "repo": "/work/app", "agent": "claude", "ingress": "public",
            "event": { "kind": "progress", "pct": 40, "note": "step build: cargo test" }
        })
    );
    let Frame::Event(bare) = second.into_frame() else {
        panic!("expected an event frame");
    };
    assert_eq!(
        (bare.n, bare.seq, bare.capability, bare.ingress),
        (Some(2), None, None, None)
    );
}

#[tokio::test]
async fn probes_are_left_out_unless_asked_and_each_view_counts_without_gaps() {
    let hub = EventHub::new();
    let mut plain = hub.subscribe_all(false).unwrap();
    let mut probing = hub.subscribe_all(true).unwrap();
    hub.register("req_status", meta("status"));
    hub.register("req_query", meta("query"));
    hub.register("req_flow", meta("flow.run"));

    hub.publish("req_flow", Event::Queued).unwrap();
    hub.publish("req_status", Event::Started).unwrap();
    hub.publish("req_status", Event::Done).unwrap();
    hub.publish("req_query", Event::Done).unwrap();
    hub.publish("req_flow", Event::Done).unwrap();

    // Without probes: only the flow, numbered 1, 2 — a status poll does not
    // come back as an event, and it leaves no gap behind.
    let seen: Vec<_> = [admin_event(&mut plain).await, admin_event(&mut plain).await]
        .into_iter()
        .map(|event| (event.n, event.ticket))
        .collect();
    assert_eq!(
        seen,
        vec![(1, "req_flow".to_owned()), (2, "req_flow".to_owned())]
    );
    assert_eq!(plain.queued(), 0);

    // With probes: everything, in publish order, numbered 1..=5.
    let mut all = Vec::new();
    for _ in 0..5 {
        let event = admin_event(&mut probing).await;
        all.push((event.n, event.ticket));
    }
    assert_eq!(
        all,
        vec![
            (1, "req_flow".to_owned()),
            (2, "req_status".to_owned()),
            (3, "req_status".to_owned()),
            (4, "req_query".to_owned()),
            (5, "req_flow".to_owned()),
        ]
    );
}

#[tokio::test]
async fn subscribers_are_capped_and_a_dropped_one_frees_its_slot() {
    let hub = EventHub::new();
    let mut held: Vec<Subscriber> = (0..MAX_SUBSCRIBERS)
        .map(|_| hub.subscribe_all(false).unwrap())
        .collect();
    assert_eq!(
        hub.subscribe_all(false).unwrap_err(),
        SubscribeError::Capacity
    );
    assert_eq!(hub.usage().subscribers, MAX_SUBSCRIBERS);
    held.pop();
    held.push(hub.subscribe_all(true).unwrap());
    drop(held);
    assert_eq!(hub.usage().subscribers, 0);
}

#[tokio::test]
async fn a_subscriber_loses_progress_first_and_lags_only_on_lifecycle_overflow() {
    let hub = EventHub::new();
    let mut slow = hub.subscribe_all(false).unwrap();
    let mut reading = hub.subscribe_all(false).unwrap();
    hub.publish("req_a", Event::Started).unwrap();
    // Twice the queue in progress: the oldest go, the subscriber stays.
    for index in 0..(2 * SUBSCRIBER_QUEUE) {
        hub.publish(
            "req_a",
            progress(u8::try_from(index % 100).unwrap(), "prose"),
        )
        .unwrap();
        assert!(slow.queued() <= SUBSCRIBER_QUEUE);
        // The other subscriber keeps up and is unaffected throughout.
        while reading.queued() > 0 {
            admin_event(&mut reading).await;
        }
    }
    assert_eq!(slow.queued(), SUBSCRIBER_QUEUE);
    assert_eq!(hub.usage().subscribers, 2);
    let first = admin_event(&mut slow).await;
    assert_eq!((first.n, &first.event), (1, &Event::Started));
    // The gap in `n` is what tells the reader it missed events.
    assert!(admin_event(&mut slow).await.n > 2);

    // Lifecycle events with no progress left to displace: the subscriber
    // lags and is detached; the hub and the other subscriber carry on.
    for index in 0..(2 * SUBSCRIBER_QUEUE) {
        hub.publish(&format!("req_{index}"), Event::Queued).unwrap();
        while reading.queued() > 0 {
            admin_event(&mut reading).await;
        }
    }
    assert_eq!(next_admin(&mut slow).await, Subscribed::Lagged);
    assert_eq!(next_admin(&mut slow).await, Subscribed::Lagged);
    assert_eq!(hub.usage().subscribers, 1);
    hub.publish("req_after", Event::Queued).unwrap();
    assert_eq!(admin_event(&mut reading).await.ticket, "req_after");
}

#[tokio::test]
async fn the_table_is_bounded_and_evicts_the_oldest_ticket_nobody_follows() {
    let hub = EventHub::new();
    // The oldest entry has a follower; the second oldest does not.
    let _followed = hub.attach("req_followed", 0).unwrap().follower;
    hub.publish("req_followed", Event::Queued).unwrap();
    hub.publish("req_idle", Event::Queued).unwrap();
    for index in 2..MAX_ENTRIES {
        hub.publish(&format!("req_{index}"), Event::Queued).unwrap();
    }
    assert_eq!(hub.usage().entries, MAX_ENTRIES);

    // A terminal publish that never comes cannot grow the table.
    hub.publish("req_one_more", Event::Queued).unwrap();
    assert_eq!(hub.usage().entries, MAX_ENTRIES);
    // The followed ticket kept its counter; the idle one lost only replay.
    assert_eq!(hub.attach("req_followed", 0).unwrap().seq, 1);
    let evicted = hub.attach("req_idle", 0).unwrap();
    assert_eq!((evicted.seq, evicted.replay.len()), (0, 0));
    assert_eq!(hub.usage().entries, MAX_ENTRIES);

    // A terminal event removes its entry.
    hub.publish("req_one_more", Event::Done).unwrap();
    assert_eq!(hub.usage().entries, MAX_ENTRIES - 1);
}

#[tokio::test]
async fn the_legacy_sink_gets_what_a_public_client_sees_and_never_blocks() {
    let hub = EventHub::new();
    // No sink: publishing is fine.
    hub.publish("req_a", Event::Queued).unwrap();
    let (tx, mut rx) = mpsc::channel(2);
    hub.set_legacy_sink(tx);
    hub.publish("req_a", progress(7, "private prose")).unwrap();
    hub.publish("req_b", Event::Started).unwrap();
    // A full sink drops the notification without an error or a wait.
    hub.publish("req_b", Event::Done).unwrap();
    assert_eq!(
        rx.recv().await.unwrap(),
        ("req_a".to_owned(), public_progress(7))
    );
    assert_eq!(
        rx.recv().await.unwrap(),
        ("req_b".to_owned(), Event::Started)
    );
    assert!(rx.try_recv().is_err());
    // A closed sink is the transport having shut down.
    drop(rx);
    assert!(hub.publish("req_c", Event::Queued).is_err());
}

#[tokio::test]
async fn close_tells_everyone_and_refuses_everything_after() {
    let hub = EventHub::new();
    let mut follower = hub.attach("req_a", 0).unwrap().follower;
    let mut subscriber = hub.subscribe_all(false).unwrap();
    let publisher = hub.publisher();
    assert!(Arc::ptr_eq(publisher.hub(), &hub));
    publisher.publish("req_a", Event::Started).await.unwrap();

    hub.close();
    // What was queued before the close is still delivered, then the close.
    assert_eq!(
        next(&mut follower).await,
        Followed::Event {
            seq: 1,
            event: Event::Started
        }
    );
    assert_eq!(next(&mut follower).await, Followed::Closed);
    assert_eq!(admin_event(&mut subscriber).await.n, 1);
    assert_eq!(next_admin(&mut subscriber).await, Subscribed::Closed);

    assert!(publisher.publish("req_a", Event::Done).await.is_err());
    assert_eq!(hub.attach("req_a", 0).unwrap_err(), AttachError::Closed);
    assert_eq!(
        hub.subscribe_all(false).unwrap_err(),
        SubscribeError::Closed
    );
    hub.register("req_late", meta("flow.run"));
    assert_eq!(hub.usage().entries, 0);
    drop(follower);
    assert_eq!(hub.usage().followers, 0);
}

#[test]
fn every_hub_has_its_own_epoch() {
    let (first, second) = (EventHub::new(), EventHub::new());
    // A ULID: 26 characters, and never the same twice.
    assert_eq!(first.epoch().len(), 26);
    assert_ne!(first.epoch(), second.epoch());
    assert_eq!(EventHub::with_epoch("01TEST".to_owned()).epoch(), "01TEST");
}

/// A ticket that ends without a terminal event (a verdict parked for retry)
/// must not hold a table slot until the table is full.
#[tokio::test]
async fn unregister_forgets_a_ticket_that_ended_without_a_terminal_event() {
    let hub = EventHub::new();

    // Nothing follows it: the entry goes at once, replay ring included.
    hub.register("req_idle", meta("flow.run"));
    hub.publish("req_idle", Event::Started).unwrap();
    assert_eq!(hub.usage().entries, 1);
    hub.unregister("req_idle");
    assert_eq!(hub.usage().entries, 0);

    // A follower is attached: it keeps its queue, and the entry goes with it.
    hub.register("req_followed", meta("flow.run"));
    hub.publish("req_followed", Event::Started).unwrap();
    let mut follower = hub.attach("req_followed", 0).unwrap().follower;
    hub.unregister("req_followed");
    assert_eq!(hub.usage().entries, 1);
    hub.publish("req_followed", public_progress(10)).unwrap();
    assert_eq!(
        next(&mut follower).await,
        Followed::Event {
            seq: 2,
            event: public_progress(10)
        }
    );
    drop(follower);
    assert_eq!(
        hub.usage(),
        crate::event_hub::HubUsage {
            entries: 0,
            followers: 0,
            subscribers: 0
        }
    );

    // A ticket the hub never heard of, or already removed by its terminal
    // event, is a no-op.
    hub.unregister("req_unknown");
    hub.register("req_done", meta("echo"));
    hub.publish("req_done", Event::Done).unwrap();
    hub.unregister("req_done");
    assert_eq!(hub.usage().entries, 0);
}
