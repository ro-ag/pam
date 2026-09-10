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
