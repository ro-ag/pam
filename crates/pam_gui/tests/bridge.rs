//! Bridge integration tests: the seams `pam_gui`'s Tauri commands are
//! thin over, driven against a **real daemon** (`pam_testkit`).
//!
//! The Tauri runtime itself never starts here (headless webview testing
//! is out of scope); instead each test replicates exactly what the
//! command bodies do — the same `pam_client` calls with the same
//! parameters, unwrapped through the same [`pam_gui::bridge`] helpers —
//! plus the event subscriber's decode path: a `SubSocket` connected the
//! way `events.rs` connects, decoding `PUB` frames through the very
//! [`decode_event_frames`] the forwarding task uses.
//!
//! The commands resolve their base dir from the process environment
//! (`$PAM_BASE_DIR`), which the workspace's `unsafe` denial forbids
//! mutating in-process — so the tests pass the harness base dir to the
//! underlying client calls explicitly, as the commands do one line in.

use std::time::Duration;

use pam_client::client::{self, DaemonStatus};
use pam_daemon::policy::CAUSE_UNKNOWN_CAPABILITY;
use pam_daemon::runtime_dir::RuntimeDir;
use pam_gui::bridge::{expect_result, is_disconnect, is_known_admin_op};
use pam_gui::events::decode_event_frames;
use pam_proto::{Event, Response};
use pam_testkit::{TestDaemon, with_deadline};
use serde_json::{Value, json};
use zeromq::{Socket, SocketRecv, SubSocket};

/// The deadlines the bridge commands use (`bridge.rs` constants are
/// private; the values are part of the replicated call).
const STATUS_DEADLINE_MS: u64 = 5_000;
const ADMIN_DEADLINE_MS: u64 = 30_000;

/// Settle time for a fresh `SUB` subscription (zmq `PUB` drops frames
/// published before the subscription registers — same reason
/// `pam_testkit` settles its own subscribers).
const SUB_SETTLE: Duration = Duration::from_millis(300);

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

/// `admin_call`'s happy path: a whitelisted op goes through
/// `send_admin` and unwraps to its result body.
#[tokio::test]
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

/// The event subscriber's decode path against real `PUB` traffic: a
/// `SubSocket` connected exactly as `events.rs::stream_events` connects
/// (all topics, empty prefix) decodes a real request's lifecycle into
/// `(ticket, Event)` pairs via [`decode_event_frames`], ending in the
/// terminal `done` for the ticket the daemon answered with.
#[tokio::test]
async fn event_frames_from_a_real_daemon_decode_like_the_subscriber() {
    let daemon = TestDaemon::spawn().await;
    let base = daemon.base_dir();

    // Connect the way events.rs does: SubSocket on events.sock, every topic.
    let dirs = RuntimeDir::at_base(&base).expect("runtime dir resolves");
    let mut sub = SubSocket::new();
    with_deadline(sub.connect(&dirs.events_endpoint()))
        .await
        .expect("sub connects");
    with_deadline(sub.subscribe(""))
        .await
        .expect("subscribes to every topic");
    tokio::time::sleep(SUB_SETTLE).await;

    let args = json!({ "msg": "over the bridge" });
    let response = with_deadline(client::send_request(
        &base, "echo", args, true, 10_000, None,
    ))
    .await
    .expect("echo answers");
    let Response::Result { id, .. } = response else {
        panic!("echo with wait=true answers a result, got {response:?}");
    };

    // Drain PUB frames through the subscriber's own decoder until the
    // ticket's terminal event; undecodable frames drop, as in events.rs.
    let mut events = Vec::new();
    while events.last() != Some(&Event::Done) {
        let message = with_deadline(sub.recv())
            .await
            .expect("event frames arrive");
        let Some(payload) = decode_event_frames(&message.into_vec()) else {
            continue;
        };
        assert_eq!(payload.ticket, id, "one request, one topic");
        events.push(payload.event);
    }
    assert!(
        events.contains(&Event::Started),
        "the lifecycle reports the worker start before done: {events:?}"
    );
    daemon.stop().await;
}

/// The reconnect loop's staleness probe (`events.rs` idle path): a live
/// daemon reads as running; once stopped, the same probe reports it
/// gone so the stream tears down instead of trusting a silent socket.
#[tokio::test]
async fn the_idle_probe_sees_the_daemon_come_and_go() {
    let daemon = TestDaemon::spawn().await;
    let base = daemon.base_dir();

    assert!(
        matches!(
            client::probe_daemon(&base),
            Ok(DaemonStatus::Running { .. })
        ),
        "a live daemon holds the instance lock"
    );

    // Keep the temp dir alive past the daemon so the probe sees an
    // existing-but-empty runtime dir, exactly what a crashed daemon leaves.
    let tmp = daemon.stop().await;
    assert!(
        matches!(client::probe_daemon(&base), Ok(DaemonStatus::NotRunning)),
        "a stopped daemon releases the lock"
    );
    drop(tmp);
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
