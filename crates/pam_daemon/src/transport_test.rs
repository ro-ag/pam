//! Notification backpressure must never become request backpressure.
use crate::transport::EventPublisher;
use pam_proto::Event;
use std::time::Duration;

#[tokio::test]
async fn a_saturated_event_queue_drops_notifications_without_blocking_and_recovers() {
    let (publisher, mut receiver) = EventPublisher::for_tests();
    let capacity = receiver.max_capacity();
    for _ in 0..capacity {
        publisher.publish("queued", Event::Started).await.unwrap();
    }
    tokio::time::timeout(
        Duration::from_millis(100),
        publisher.publish("dropped", Event::Done),
    )
    .await
    .expect("full queue must not delay a terminal result")
    .unwrap();
    assert_eq!(receiver.len(), capacity);
    for _ in 0..capacity {
        assert_eq!(receiver.recv().await.unwrap().0, "queued");
    }
    publisher.publish("recovered", Event::Done).await.unwrap();
    assert_eq!(
        receiver.recv().await.unwrap(),
        ("recovered".to_owned(), Event::Done)
    );
    drop(receiver);
    assert!(publisher.publish("closed", Event::Done).await.is_err());
}

#[test]
fn oversized_response_and_identity_get_a_small_explicit_refusal() {
    let response = pam_proto::Response::Result {
        id: "x".repeat(2 * 1024 * 1024),
        outcome: pam_proto::Outcome::Verified,
        body: serde_json::json!({ "log": "y".repeat(2 * 1024 * 1024) }),
        evidence: Vec::new(),
    };
    let encoded = crate::transport::bounded_response(&response).unwrap();
    assert!(encoded.len() < 1024);
    let response: pam_proto::Response = serde_json::from_slice(&encoded).unwrap();
    assert!(
        matches!(response, pam_proto::Response::Refusal { id, cause, .. }
        if id == "unknown" && cause == "response_budget_exhausted")
    );
}

#[tokio::test]
async fn public_publisher_strips_prose_before_queueing_and_preserves_lifecycle() {
    let (publisher, mut receiver) = EventPublisher::for_tests();
    for pct in [None, Some(0), Some(52), Some(100)] {
        publisher
            .publish(
                "req_opaque",
                Event::Progress {
                    pct,
                    note: format!(
                        "private-repository publish-secret-artifact FAILED {}",
                        "secret".repeat(100_000)
                    ),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            receiver.recv().await.unwrap(),
            (
                "req_opaque".to_owned(),
                Event::Progress {
                    pct,
                    note: crate::transport::PUBLIC_PROGRESS_NOTE.to_owned(),
                }
            )
        );
    }
    for event in [
        Event::Queued,
        Event::Started,
        Event::ApprovalPending,
        Event::Done,
        Event::Refused,
    ] {
        publisher
            .publish("req_opaque", event.clone())
            .await
            .unwrap();
        assert_eq!(
            receiver.recv().await.unwrap(),
            ("req_opaque".to_owned(), event)
        );
    }
}

#[tokio::test]
async fn wildcard_subscriber_receives_only_generic_progress_across_topics() {
    use crate::runtime_dir::RuntimeDir;
    use crate::transport::{PUBLIC_PROGRESS_NOTE, Transport};
    use zeromq::{Socket, SocketRecv, SubSocket};

    #[cfg(unix)]
    let tmp = tempfile::Builder::new()
        .prefix("pam-events")
        .tempdir_in("/tmp")
        .unwrap();
    #[cfg(not(unix))]
    let tmp = tempfile::tempdir().unwrap();
    let dirs = RuntimeDir::at_base(tmp.path()).unwrap();
    let (incoming, _requests) = tokio::sync::mpsc::channel(1);
    let transport = Transport::bind(&dirs, incoming).await.unwrap();
    let publisher = transport.event_publisher();
    let mut subscriber = SubSocket::new();
    subscriber.connect(&dirs.events_endpoint()).await.unwrap();
    subscriber.subscribe("").await.unwrap();
    // A wildcard is intentionally permitted. Repeat while PUB registers the
    // subscription; no fixed startup sleep and no claim of topic isolation.
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut observed = std::collections::BTreeSet::new();
        while observed.len() < 2 {
            for topic in ["req_first", "req_second"] {
                publisher.publish(topic, Event::Progress {
                    pct: Some(37),
                    note: "private-repo deploy-payroll FAILED Authorization: Bearer sensitive-token".to_owned(),
                }).await.unwrap();
            }
            if let Ok(message) = tokio::time::timeout(Duration::from_millis(200), subscriber.recv()).await {
                let frames = message.unwrap().into_vec();
                assert_eq!(frames.len(), 2);
                let topic = std::str::from_utf8(&frames[0]).unwrap().to_owned();
                assert!(["req_first", "req_second"].contains(&topic.as_str()));
                let event: Event = serde_json::from_slice(&frames[1]).unwrap();
                assert_eq!(event, Event::Progress { pct: Some(37), note: PUBLIC_PROGRESS_NOTE.to_owned() });
                let public = std::str::from_utf8(&frames[1]).unwrap();
                for private in ["private-repo", "deploy-payroll", "FAILED", "Authorization", "sensitive-token"] {
                    assert!(!public.contains(private));
                }
                observed.insert(topic);
            }
        }
    }).await.expect("both topics received before timeout");
    tokio::time::timeout(Duration::from_secs(5), transport.shutdown())
        .await
        .expect("transport shutdown");
}
