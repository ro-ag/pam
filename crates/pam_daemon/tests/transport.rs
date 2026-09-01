//! Real-socket round-trip tests for the transport service.

use std::time::Duration;

use pam_daemon::runtime_dir::RuntimeDir;
use pam_daemon::transport::{IncomingRequest, Transport};
use pam_proto::{Caller, Envelope, Event, Outcome, PROTOCOL_VERSION, Response};
use tokio::sync::mpsc;
use tokio::time::timeout;
use zeromq::{DealerSocket, Socket, SocketRecv, SocketSend, SubSocket, ZmqMessage};

const DEADLINE: Duration = Duration::from_secs(5);

/// Temp dir with a short absolute path: macOS caps unix socket paths at
/// 104 bytes and the default temp root can get close.
fn short_tempdir() -> tempfile::TempDir {
    #[cfg(unix)]
    {
        tempfile::Builder::new()
            .prefix("pam")
            .tempdir_in("/tmp")
            .expect("tempdir under /tmp")
    }
    #[cfg(not(unix))]
    {
        tempfile::tempdir().expect("tempdir")
    }
}

fn envelope(id: &str) -> Envelope {
    Envelope {
        v: PROTOCOL_VERSION,
        id: id.to_owned(),
        capability: "log.summarize".to_owned(),
        client_version: env!("CARGO_PKG_VERSION").to_owned(),
        caller: Caller {
            agent: "claude".to_owned(),
            repo: "/tmp/repo".to_owned(),
            pid: 4242,
        },
        args: serde_json::json!({}),
        idempotency_key: None,
        deadline_ms: 60_000,
        wait: true,
    }
}

async fn bind_transport(dirs: &RuntimeDir) -> (Transport, mpsc::Receiver<IncomingRequest>) {
    let (tx, rx) = mpsc::channel(8);
    let transport = Transport::bind(dirs, tx).await.expect("transport binds");
    (transport, rx)
}

async fn connected_dealer(dirs: &RuntimeDir) -> DealerSocket {
    let mut dealer = DealerSocket::new();
    dealer
        .connect(&dirs.router_endpoint())
        .await
        .expect("dealer connects");
    dealer
}

#[tokio::test]
async fn valid_envelope_round_trips_to_core_and_back() {
    let tmp = short_tempdir();
    let dirs = RuntimeDir::at_base(tmp.path()).expect("runtime dir");
    let (transport, mut incoming) = bind_transport(&dirs).await;
    let mut dealer = connected_dealer(&dirs).await;

    let sent = envelope("req_roundtrip");
    let payload = serde_json::to_vec(&sent).expect("serialize envelope");
    timeout(DEADLINE, dealer.send(ZmqMessage::from(payload)))
        .await
        .expect("send within deadline")
        .expect("send ok");

    let request = timeout(DEADLINE, incoming.recv())
        .await
        .expect("request within deadline")
        .expect("channel open");
    assert_eq!(request.envelope, sent);
    assert!(!request.identity.is_empty());

    let response = Response::Result {
        id: sent.id.clone(),
        outcome: Outcome::Solved,
        body: serde_json::json!({ "answer": 42 }),
        evidence: vec!["ev_1".to_owned()],
    };
    request
        .reply
        .send(response.clone())
        .expect("reply accepted");

    let answer = timeout(DEADLINE, dealer.recv())
        .await
        .expect("response within deadline")
        .expect("recv ok");
    let frames = answer.into_vec();
    assert_eq!(frames.len(), 1, "dealer sees exactly the payload frame");
    let received: Response = serde_json::from_slice(&frames[0]).expect("parse response");
    assert_eq!(received, response);

    timeout(DEADLINE, transport.shutdown())
        .await
        .expect("shutdown within deadline");
}

#[tokio::test]
async fn malformed_payload_is_refused_as_bad_request() {
    let tmp = short_tempdir();
    let dirs = RuntimeDir::at_base(tmp.path()).expect("runtime dir");
    let (transport, mut incoming) = bind_transport(&dirs).await;
    let mut dealer = connected_dealer(&dirs).await;

    timeout(DEADLINE, dealer.send(ZmqMessage::from("this is not json")))
        .await
        .expect("send within deadline")
        .expect("send ok");

    let answer = timeout(DEADLINE, dealer.recv())
        .await
        .expect("refusal within deadline")
        .expect("recv ok");
    let frames = answer.into_vec();
    let received: Response = serde_json::from_slice(&frames[0]).expect("parse refusal");
    let Response::Refusal {
        cause,
        detail,
        recovery,
        ..
    } = received
    else {
        panic!("expected a refusal, got {received:?}");
    };
    assert_eq!(cause, "bad_request");
    assert!(
        detail.contains("cannot parse request envelope"),
        "detail: {detail}"
    );
    assert!(recovery.contains("GUI"), "recovery: {recovery}");

    // Nothing reached the daemon core.
    assert!(incoming.try_recv().is_err());

    timeout(DEADLINE, transport.shutdown())
        .await
        .expect("shutdown within deadline");
}

#[tokio::test]
async fn refusal_salvages_request_id_from_invalid_envelope() {
    let tmp = short_tempdir();
    let dirs = RuntimeDir::at_base(tmp.path()).expect("runtime dir");
    let (transport, _incoming) = bind_transport(&dirs).await;
    let mut dealer = connected_dealer(&dirs).await;

    // Valid JSON with an id, but not a valid envelope (missing fields).
    let payload = serde_json::json!({ "id": "req_partial" }).to_string();
    timeout(DEADLINE, dealer.send(ZmqMessage::from(payload)))
        .await
        .expect("send within deadline")
        .expect("send ok");

    let answer = timeout(DEADLINE, dealer.recv())
        .await
        .expect("refusal within deadline")
        .expect("recv ok");
    let frames = answer.into_vec();
    let received: Response = serde_json::from_slice(&frames[0]).expect("parse refusal");
    let Response::Refusal { id, cause, .. } = received else {
        panic!("expected a refusal, got {received:?}");
    };
    assert_eq!(id, "req_partial");
    assert_eq!(cause, "bad_request");

    timeout(DEADLINE, transport.shutdown())
        .await
        .expect("shutdown within deadline");
}

#[tokio::test]
async fn subscriber_receives_only_its_topic() {
    let tmp = short_tempdir();
    let dirs = RuntimeDir::at_base(tmp.path()).expect("runtime dir");
    let (transport, _incoming) = bind_transport(&dirs).await;
    let publisher = transport.event_publisher();

    let mut sub = SubSocket::new();
    sub.connect(&dirs.events_endpoint())
        .await
        .expect("sub connects");
    sub.subscribe("req_mine").await.expect("subscribe");

    // PUB drops messages sent before the subscription is registered
    // (slow-joiner), so publish repeatedly until one lands. Every round
    // publishes the foreign topic first: if filtering were broken the
    // first message received would be `req_other`.
    let received = timeout(DEADLINE, async {
        loop {
            publisher
                .publish("req_other", Event::Started)
                .await
                .expect("publish other");
            publisher
                .publish(
                    "req_mine",
                    Event::Progress {
                        pct: Some(50),
                        note: "halfway".to_owned(),
                    },
                )
                .await
                .expect("publish mine");
            if let Ok(message) = timeout(Duration::from_millis(200), sub.recv()).await {
                return message.expect("recv ok");
            }
        }
    })
    .await
    .expect("event within deadline");

    let frames = received.into_vec();
    assert_eq!(frames.len(), 2, "topic frame + event frame");
    assert_eq!(frames[0].as_ref(), b"req_mine");
    let event: Event = serde_json::from_slice(&frames[1]).expect("parse event");
    assert_eq!(
        event,
        Event::Progress {
            pct: Some(50),
            note: "halfway".to_owned(),
        }
    );

    timeout(DEADLINE, transport.shutdown())
        .await
        .expect("shutdown within deadline");
}

#[tokio::test]
async fn shutdown_stops_all_tasks_and_publisher_errors_after() {
    let tmp = short_tempdir();
    let dirs = RuntimeDir::at_base(tmp.path()).expect("runtime dir");
    let (transport, _incoming) = bind_transport(&dirs).await;
    let publisher = transport.event_publisher();

    timeout(DEADLINE, transport.shutdown())
        .await
        .expect("shutdown within deadline");

    let err = timeout(DEADLINE, publisher.publish("req_late", Event::Done))
        .await
        .expect("publish returns within deadline");
    assert!(err.is_err(), "publishing after shutdown must fail");
}
