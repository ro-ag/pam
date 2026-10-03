//! Bridge integration tests: the seams `pam_gui`'s Tauri commands are thin over, driven against a
//! **real daemon** (`pam_testkit`). The Tauri runtime itself never starts here; instead each test
//! replicates exactly what the command bodies do — the same `pam_client` calls with the same
//! parameters, unwrapped through the same [`pam_gui::bridge`] helpers — plus the event pump: the
//! very [`pump`] the Tauri command spawns, dialling the daemon's private all-events stream
//! ([`AdminConnect`]) and delivering to a channel where the webview would be.
//!
//! The commands resolve their base dir from the process environment (`$PAM_BASE_DIR`), which the
//! workspace's `unsafe` denial forbids mutating in-process — so the tests pass the harness base dir
//! to the underlying client calls explicitly, as the commands do one line in.

use std::time::Duration;

use pam_client::client;
use pam_daemon::policy::CAUSE_UNKNOWN_CAPABILITY;
use pam_gui::bridge::{HumanStop, expect_result, is_disconnect, is_known_admin_op, poll_status};
use pam_gui::events::{AdminConnect, EventPayload, EventSink, PayloadEvent, pump};
use pam_proto::wire::Ingress;
use pam_proto::{Event, Response};
use pam_testkit::{TestDaemon, with_deadline};
#[cfg(any(target_os = "macos", windows))]
use serde_json::Value;
use serde_json::json;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

/// The deadlines the bridge commands use (`bridge.rs` constants are
/// private; the values are part of the replicated call).
const STATUS_DEADLINE_MS: u64 = 5_000;
const ADMIN_DEADLINE_MS: u64 = 30_000;

/// `daemon_status`'s happy path: the ordinary read-only `status`
/// request against a live daemon answers a result whose body carries
/// the fields the beacon and the status views read.
#[tokio::test]
async fn daemon_status_call_answers_the_status_body() {
    let daemon = TestDaemon::spawn().await;
    let base = daemon.base_dir();

    let response = with_deadline(client::send_request(
        &base,
        "status",
        json!({}),
        true,
        STATUS_DEADLINE_MS,
        None,
    ))
    .await
    .expect("a live daemon answers the status poll");
    let body = expect_result(response).expect("status answers a result");

    for field in ["daemon_version", "protocol", "uptime_s", "active_requests"] {
        assert!(
            body.get(field).is_some(),
            "status body must carry {field}: {body}"
        );
    }
    daemon.stop().await;
}

/// The human's Stop against a real daemon: while it runs the poll reads it as usual (a raised
/// flag only forbids starting), and once it has stopped the poll reports "stopped by you" and
/// leaves it stopped — the instance lock stays free, no successor appears.
#[tokio::test]
async fn a_stopped_daemon_stays_stopped_while_the_gui_polls() {
    let daemon = TestDaemon::spawn().await;
    let base = daemon.base_dir();
    let stop = HumanStop::new();
    stop.raise();

    let reply = with_deadline(poll_status(&base, &stop))
        .await
        .expect("a live daemon answers the poll");
    assert!(
        reply.connected,
        "a raised flag does not hide a running daemon"
    );
    assert!(!reply.stopped_by_you);

    let tmp = daemon.stop().await;
    for _ in 0..3 {
        let reply = with_deadline(poll_status(&base, &stop))
            .await
            .expect("a stopped daemon is an answer");
        assert!(!reply.connected);
        assert!(reply.stopped_by_you);
        assert_eq!(
            client::probe_daemon(&base).expect("probe"),
            client::DaemonStatus::NotRunning,
            "the poll did not start a successor"
        );
    }
    drop(tmp);
}

/// `admin_call`'s happy path: a whitelisted op goes through
/// `send_admin` and unwraps to its result body.
#[tokio::test]
#[cfg(any(target_os = "macos", windows))]
async fn admin_call_forwards_a_whitelisted_op_to_the_daemon() {
    let daemon = TestDaemon::spawn().await;
    let base = daemon.base_dir();

    let op = "admin.profile.get";
    assert!(is_known_admin_op(op), "the bridge whitelists {op}");
    let response = with_deadline(client::send_admin(&base, op, json!({}), ADMIN_DEADLINE_MS))
        .await
        .expect("a live daemon answers admin ops");
    let body = expect_result(response).expect("profile.get answers a result");
    assert!(
        body.get("profile").is_some(),
        "profile.get body must carry the active profile: {body}"
    );
    daemon.stop().await;
}

/// The Models screen's own poll: `admin.models.status` through the
/// bridge whitelist against a live daemon answers the block the runtime
/// card reads, with an empty runtime on a fresh base dir.
#[tokio::test]
#[cfg(any(target_os = "macos", windows))]
async fn admin_call_reads_the_model_status_block() {
    let daemon = TestDaemon::spawn().await;
    let base = daemon.base_dir();

    let op = pam_daemon::admin_models::OP_MODELS_STATUS;
    assert!(is_known_admin_op(op), "the bridge whitelists {op}");
    let response = with_deadline(client::send_admin(&base, op, json!({}), ADMIN_DEADLINE_MS))
        .await
        .expect("a live daemon answers model admin ops");
    let body = expect_result(response).expect("models.status answers a result");

    assert_eq!(
        body.pointer("/runtime/state/state").and_then(Value::as_str),
        Some("idle"),
        "a daemon that never loaded weights reports an idle runtime: {body}"
    );
    for field in ["jobs", "defaults", "idle_unload_min", "models_dir"] {
        assert!(
            body.get(field).is_some(),
            "models.status body must carry {field}: {body}"
        );
    }
    daemon.stop().await;
}

#[tokio::test]
#[cfg(not(any(target_os = "macos", windows)))]
async fn admin_call_reports_unsupported_native_administration() {
    let daemon = TestDaemon::spawn().await;
    let op = "admin.profile.get";
    assert!(is_known_admin_op(op));
    let error = with_deadline(client::send_admin(
        &daemon.base_dir(),
        op,
        json!({}),
        ADMIN_DEADLINE_MS,
    ))
    .await
    .expect_err("unsupported platforms must not fall back to public administration");
    assert!(matches!(
        &error,
        client::RequestError::AdminTransport { source }
            if source.kind() == std::io::ErrorKind::Unsupported
    ));
    let mapped = pam_gui::bridge::BridgeError::from(error);
    assert_eq!(mapped.cause, "admin_transport_failed");
    assert!(mapped.recovery.contains("supported platform"));
    assert!(mapped.recovery.contains("never falls back"));
    daemon.stop().await;
}

/// A real daemon refusal passes through [`expect_result`] verbatim —
/// the frontend renders the daemon's own cause/detail/recovery, not a
/// bridge paraphrase.
#[tokio::test]
async fn a_real_daemon_refusal_passes_through_verbatim() {
    let daemon = TestDaemon::spawn().await;
    let base = daemon.base_dir();

    let response = with_deadline(client::send_request(
        &base,
        "no_such_capability",
        json!({}),
        true,
        STATUS_DEADLINE_MS,
        None,
    ))
    .await
    .expect("the daemon answers (with a refusal)");
    let err = expect_result(response).expect_err("unknown capability refuses");
    assert_eq!(err.cause, CAUSE_UNKNOWN_CAPABILITY);
    assert!(!err.detail.is_empty(), "refusal detail passes through");
    assert!(!err.recovery.is_empty(), "refusal recovery passes through");
    daemon.stop().await;
}

/// Where the pump delivers in these tests: a channel in place of the webview.
struct Webview(UnboundedSender<EventPayload>);

impl EventSink for Webview {
    fn emit(&self, payload: &EventPayload) -> bool {
        self.0.send(payload.clone()).is_ok()
    }
}

/// The pump the Tauri command spawns, against the daemon at `base`, and what it delivers.
fn start_pump(
    base: &std::path::Path,
) -> (tokio::task::JoinHandle<()>, UnboundedReceiver<EventPayload>) {
    let (tx, rx) = unbounded_channel();
    let task = tokio::spawn(pump(AdminConnect::new(base.to_path_buf()), Webview(tx)));
    (task, rx)
}

fn is_resync(payload: &EventPayload) -> bool {
    matches!(payload.event, PayloadEvent::Resync { .. })
}

/// The next payload, within the test deadline.
async fn next(rx: &mut UnboundedReceiver<EventPayload>) -> EventPayload {
    with_deadline(rx.recv())
        .await
        .expect("the pump keeps delivering")
}

/// Event frames from a real daemon decode to the payload the webview receives: after the
/// connect's one resync, a real request's lifecycle arrives in order under its ticket, carrying
/// what the daemon knows about it, and ends in the terminal `done`.
#[tokio::test]
async fn event_frames_from_a_real_daemon_decode_to_the_payload() {
    let daemon = TestDaemon::spawn().await;
    let base = daemon.base_dir();
    let (pump_task, mut rx) = start_pump(&base);

    // The stream is subscribed once the connect's refresh arrives: from here nothing is missed.
    let first = next(&mut rx).await;
    assert!(
        is_resync(&first),
        "the first payload is the refresh: {first:?}"
    );
    assert_eq!(first.ticket, "", "a resync names no ticket");

    let args = json!({ "msg": "over the bridge" });
    let response = with_deadline(client::send_request(
        &base, "echo", args, true, 10_000, None,
    ))
    .await
    .expect("echo answers");
    let Response::Result { id, .. } = response else {
        panic!("echo with wait=true answers a result, got {response:?}");
    };

    let mut events = Vec::new();
    let mut counters = Vec::new();
    while events.last() != Some(&Event::Done) {
        let payload = next(&mut rx).await;
        assert!(
            !is_resync(&payload),
            "no gap on an idle stream: {payload:?}"
        );
        assert_eq!(payload.ticket, id, "one request, one ticket");
        assert_eq!(payload.capability.as_deref(), Some("echo"));
        assert_eq!(payload.ingress, Some(Ingress::Public));
        assert!(
            payload.agent.is_some(),
            "the agent label travels: {payload:?}"
        );
        assert!(
            payload.repo.is_some(),
            "the repository travels: {payload:?}"
        );
        counters.push(payload.n.expect("the daemon-wide counter travels"));
        let PayloadEvent::Lifecycle(event) = payload.event else {
            unreachable!("resync was excluded above");
        };
        events.push(event);
    }
    assert!(
        events.contains(&Event::Started),
        "the lifecycle reports the worker start before done: {events:?}"
    );
    assert!(
        counters.windows(2).all(|pair| pair[1] == pair[0] + 1),
        "no events were dropped for this subscriber: {counters:?}"
    );

    pump_task.abort();
    daemon.stop().await;
}

/// The acceptance statement for the feedback loop: the GUI's own status polls (and queries) never
/// come back as events, because the daemon publishes none for control requests. The old design
/// filtered them in the webview; there is nothing left to filter.
#[tokio::test]
async fn a_status_poll_does_not_come_back_as_an_event() {
    let daemon = TestDaemon::spawn().await;
    let base = daemon.base_dir();
    let (pump_task, mut rx) = start_pump(&base);
    assert!(is_resync(&next(&mut rx).await));

    for _ in 0..5 {
        let response = with_deadline(client::send_request(
            &base,
            "status",
            json!({}),
            true,
            STATUS_DEADLINE_MS,
            None,
        ))
        .await
        .expect("a live daemon answers the status poll");
        expect_result(response).expect("status answers a result");
    }
    // Real work after the polls, so the stream demonstrably carries traffic and the absence of
    // the polls is not just an idle socket.
    let Response::Result { id: work, .. } = with_deadline(client::send_request(
        &base,
        "echo",
        json!({ "msg": "after the polls" }),
        true,
        10_000,
        None,
    ))
    .await
    .expect("echo answers") else {
        panic!("echo answers a result");
    };
    let mut seen = Vec::new();
    loop {
        let payload = next(&mut rx).await;
        let done = payload.event == PayloadEvent::Lifecycle(Event::Done);
        seen.push(payload);
        if done {
            break;
        }
    }
    assert!(
        seen.iter().all(|payload| payload.ticket == work),
        "only the echo's ticket is on the stream, no status poll: {seen:?}"
    );
    // Nothing trails behind it either.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        rx.try_recv().is_err(),
        "no late event for a poll arrived after the work"
    );

    pump_task.abort();
    daemon.stop().await;
}

/// The reconnect loop against a daemon that goes away and comes back at the same base: the
/// stream ends with the daemon, the pump retries on its own, and the next connect asks for one
/// refresh and carries the new daemon's events.
#[tokio::test]
async fn the_stream_reconnects_when_the_daemon_comes_and_goes() {
    let daemon = TestDaemon::spawn().await;
    let base = daemon.base_dir();
    let (pump_task, mut rx) = start_pump(&base);
    assert!(
        is_resync(&next(&mut rx).await),
        "connected to the first daemon"
    );

    // Keep the temp dir alive past the daemon: the second one starts on the same base.
    let tmp = daemon.stop().await;
    let daemon = TestDaemon::spawn_at(tmp).await;

    let refreshed = next(&mut rx).await;
    assert!(
        is_resync(&refreshed),
        "the reconnect to the new daemon asks for exactly one refresh: {refreshed:?}"
    );

    let Response::Result { id, .. } = with_deadline(client::send_request(
        &base,
        "echo",
        json!({ "msg": "second daemon" }),
        true,
        10_000,
        None,
    ))
    .await
    .expect("the new daemon answers") else {
        panic!("echo answers a result");
    };
    loop {
        let payload = next(&mut rx).await;
        assert!(!is_resync(&payload), "one refresh per connect: {payload:?}");
        assert_eq!(payload.ticket, id);
        if payload.event == PayloadEvent::Lifecycle(Event::Done) {
            break;
        }
    }

    pump_task.abort();
    daemon.stop().await;
}

/// The classification `daemon_status` uses to answer
/// `{ connected: false }` holds for the errors a dead daemon actually
/// produces (unit tests cover the mapping table; this pins one real
/// instance of the enum against the classifier).
#[test]
fn ensure_failures_classify_as_disconnects() {
    let err = client::RequestError::Ensure(client::ClientError::NotReady {
        waited: Duration::from_secs(6),
    });
    assert!(
        is_disconnect(&err),
        "a daemon that never came up is a disconnect"
    );
}
