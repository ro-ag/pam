//! The administration plane's all-events stream against a real daemon: what
//! the GUI's event pump connects to. The stream is opened through
//! `admin_transport::events`, the requests whose events it carries go in
//! through the public plane, and the daemon is stopped and restarted under it.
#![cfg(any(target_os = "macos", target_os = "linux", windows))]

use pam_daemon::admin_transport::{self, AdminEvents, CAUSE_SUBSCRIBER_CAPACITY};
use pam_daemon::framed::DialError;
use pam_proto::wire::{EventFrame, Ingress, cause};
use pam_proto::{Event, Outcome, Response};
use pam_testkit::{
    TestDaemon, envelope, envelope_for_repo, seed_relaxed, seed_repository_scope, short_tempdir,
    with_deadline,
};
use serde_json::json;

/// Reads the stream until `ticket`'s terminal event, returning every frame
/// seen on the way, in order.
async fn through_terminal(events: &mut AdminEvents, ticket: &str) -> Vec<EventFrame> {
    let mut seen = Vec::new();
    loop {
        let frame = events.next().await.expect("an event frame");
        let last = frame.ticket.as_deref() == Some(ticket)
            && matches!(frame.event, Event::Done | Event::Refused);
        seen.push(frame);
        if last {
            return seen;
        }
    }
}

fn of<'a>(frames: &'a [EventFrame], ticket: &str) -> Vec<&'a EventFrame> {
    frames
        .iter()
        .filter(|frame| frame.ticket.as_deref() == Some(ticket))
        .collect()
}

fn assert_gap_free(frames: &[EventFrame]) {
    let numbers: Vec<u64> = frames.iter().map(|frame| frame.n.expect("n")).collect();
    assert!(
        numbers.windows(2).all(|pair| pair[1] == pair[0] + 1),
        "n has a gap: {numbers:?}"
    );
}

/// A real request's lifecycle arrives on the stream in the order the daemon
/// published it, each frame naming the ticket and what admission knew about
/// it.
///
/// Control requests (`status`, `query`, `cancel`) never appear: the daemon
/// core publishes no lifecycle events for them, so there is no probe traffic
/// to leave out — and none to include. A subscriber that asks for probes
/// (`include_probes: true`) therefore receives exactly the stream one that
/// does not ask receives. That the hub's filter itself honours the flag is
/// proved against the hub in `admin_transport_events_test`.
#[tokio::test]
async fn work_arrives_in_order_and_control_requests_never_appear_even_when_probes_are_asked_for() {
    with_deadline(async {
        // A query is only admitted for a ticket under an approved repository.
        let tmp = short_tempdir();
        seed_relaxed(&tmp).await;
        let repo = tempfile::tempdir().expect("a repository directory");
        seed_repository_scope(&tmp, repo.path(), &[]).await;
        let repo = repo.path().canonicalize().unwrap();
        let repo = repo.to_string_lossy();
        let daemon = TestDaemon::spawn_at(tmp).await;
        let base = daemon.base_dir();
        let mut quiet = admin_transport::events(&base, false).await.unwrap();
        let mut everything = admin_transport::events(&base, true).await.unwrap();
        assert_eq!(quiet.epoch(), everything.epoch());

        // Two work requests with one control request of every kind between
        // them. Each control request is served (the query and the cancel are
        // recorded and audited); none of them is published.
        let mut client = daemon.client().await;
        for (id, capability, args) in [
            ("ev_first", "echo", json!({ "text": "one" })),
            ("ev_probe", "query", json!({ "ticket": "ev_first" })),
            ("ev_status", "status", json!({})),
            ("ev_cancel", "cancel", json!({ "ticket": "ev_first" })),
            ("ev_work", "echo", json!({ "text": "hi" })),
        ] {
            let response = client
                .request(&envelope_for_repo(&repo, id, capability, args, true))
                .await;
            if capability == "cancel" {
                // Cancelling a finished ticket is answered either way; what
                // matters here is that it ran as a control request.
                continue;
            }
            assert!(
                matches!(response, Response::Result { .. }),
                "{id}: {response:?}"
            );
        }
        let store = daemon.store();
        for id in ["ev_probe", "ev_cancel"] {
            assert!(
                store.get_request(id).await.unwrap().is_some(),
                "{id} ran and was recorded"
            );
        }

        // The default stream: both echoes' lifecycles, in publish order.
        let seen = through_terminal(&mut quiet, "ev_work").await;
        assert_gap_free(&seen);
        let work = of(&seen, "ev_work");
        let kinds: Vec<&Event> = work.iter().map(|frame| &frame.event).collect();
        assert_eq!(kinds.last(), Some(&&Event::Done), "{kinds:?}");
        let started = kinds.iter().position(|event| **event == Event::Started);
        assert!(started.is_some(), "started precedes done: {kinds:?}");
        if let Some(queued) = kinds.iter().position(|event| **event == Event::Queued) {
            assert!(Some(queued) < started, "{kinds:?}");
        }
        for frame in &work {
            assert_eq!(frame.capability.as_deref(), Some("echo"), "{frame:?}");
            assert_eq!(frame.ingress, Some(Ingress::Public), "{frame:?}");
            assert!(frame.agent.is_some() && frame.repo.is_some(), "{frame:?}");
            assert_eq!(frame.seq, None);
        }
        let position = |frames: &[EventFrame], ticket: &str| {
            frames
                .iter()
                .position(|frame| frame.ticket.as_deref() == Some(ticket))
        };
        assert!(position(&seen, "ev_first") < position(&seen, "ev_work"));

        // The stream that asked for probes: frame for frame the same. No
        // control request has a frame on either, under its own id or as a
        // capability.
        let with_probes = through_terminal(&mut everything, "ev_work").await;
        assert_gap_free(&with_probes);
        let pairs = |frames: &[EventFrame]| -> Vec<(Option<String>, Event)> {
            frames
                .iter()
                .map(|frame| (frame.ticket.clone(), frame.event.clone()))
                .collect()
        };
        assert_eq!(pairs(&with_probes), pairs(&seen));
        for (stream, frames) in [("default", &seen), ("with probes", &with_probes)] {
            for frame in frames {
                let ticket = frame.ticket.as_deref().expect("a ticket");
                assert!(
                    ["ev_first", "ev_work"].contains(&ticket),
                    "{stream}: a control request was published: {frame:?}"
                );
                assert_eq!(
                    frame.capability.as_deref(),
                    Some("echo"),
                    "{stream}: {frame:?}"
                );
            }
        }

        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}

/// The daemon's drain ends the stream by name; the next daemon is a new
/// epoch, and the caller's reconnect finds it.
#[tokio::test]
async fn the_stream_ends_with_daemon_shutting_down_and_reconnects_to_the_next_daemon() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let base = daemon.base_dir();
        let mut events = admin_transport::events(&base, false).await.unwrap();
        let first_epoch = events.epoch().to_owned();

        let tmp = daemon.stop().await;
        let ended = loop {
            match events.next().await {
                Ok(_) => {}
                Err(error) => break error,
            }
        };
        assert!(
            matches!(&ended, DialError::Refused(error) if error.cause == cause::DAEMON_SHUTTING_DOWN),
            "{ended:?}"
        );
        // No daemon: the caller sees a plain connection failure and backs off.
        let down = admin_transport::events(&base, false).await;
        assert!(matches!(&down, Err(DialError::Io(_))), "{down:?}");

        let restarted = TestDaemon::spawn_at(tmp).await;
        let mut events = admin_transport::events(&base, false).await.unwrap();
        assert_ne!(events.epoch(), first_epoch, "a restarted daemon is a new epoch");
        let mut client = restarted.client().await;
        client
            .request(&envelope("ev_after_restart", "echo", json!({ "text": "x" }), true))
            .await;
        let seen = through_terminal(&mut events, "ev_after_restart").await;
        assert!(!seen.is_empty());
        restarted.stop().await;
    })
    .await;
}

/// Four GUI windows may watch; the fifth is told why it may not, and admin
/// requests keep being served beside the streams.
#[tokio::test]
async fn the_subscriber_cap_holds_on_a_real_daemon_and_requests_are_still_served() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let base = daemon.base_dir();
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(admin_transport::events(&base, false).await.unwrap());
        }
        let fifth = admin_transport::events(&base, false).await;
        assert!(
            matches!(&fifth, Err(DialError::Refused(error)) if error.cause == CAUSE_SUBSCRIBER_CAPACITY),
            "{fifth:?}"
        );
        let mut request = envelope("ev_admin_beside", "admin.profile.get", json!({}), true);
        request.caller.agent = "pam-gui".to_owned();
        let response = admin_transport::exchange(&base, &request).await.unwrap();
        assert!(
            matches!(&response, Response::Result { outcome: Outcome::Verified, .. }),
            "{response:?}"
        );
        drop(held);
        daemon.stop().await;
    })
    .await;
}

/// A GUI process left running across the upgrade speaks the old protocol on
/// the real socket: one bare envelope. It is answered in that shape with
/// `client_outdated`, and its operation is not run.
#[cfg(unix)]
#[tokio::test]
async fn an_old_gui_on_the_real_socket_is_told_client_outdated() {
    use pam_daemon::framed::{read_frame, write_frame};
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let socket = daemon.base_dir().join("admin").join("control.sock");
        let mut request = envelope(
            "ev_old_gui",
            "admin.profile.set",
            json!({ "profile": "strict" }),
            true,
        );
        request.caller.agent = "pam-gui".to_owned();
        request.client_version = "0.4.3".to_owned();

        let mut stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
        let payload = serde_json::to_vec(&request).unwrap();
        write_frame(&mut stream, &payload, 1024 * 1024)
            .await
            .unwrap();
        let reply = read_frame(&mut stream, 16 * 1024 * 1024).await.unwrap();
        let response: Response = serde_json::from_slice(&reply).expect("the old, bare shape");
        match &response {
            Response::Refusal {
                id,
                cause,
                recovery,
                ..
            } => {
                assert_eq!(id, "ev_old_gui");
                assert_eq!(cause, "client_outdated");
                assert!(recovery.contains("Quit PAM and reopen it"), "{recovery}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(
            daemon
                .store()
                .get_request("ev_old_gui")
                .await
                .unwrap()
                .is_none(),
            "the refused operation left no row"
        );
        assert_eq!(
            *daemon.handle().lifecycle().borrow(),
            pam_daemon::lifecycle::LifecyclePhase::Serving
        );
        daemon.stop().await;
    })
    .await;
}
