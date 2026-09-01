use serde_json::json;

use super::{Caller, Envelope};
use crate::PROTOCOL_VERSION;

fn sample(idempotency_key: Option<&str>) -> Envelope {
    Envelope {
        v: PROTOCOL_VERSION,
        id: "req_01J8ZC4V9K3W6P2Q8R5T7X9Y0Z".to_owned(),
        capability: "log.summarize".to_owned(),
        client_version: "0.10.1".to_owned(),
        caller: Caller {
            agent: "claude".to_owned(),
            repo: "/abs/path".to_owned(),
            pid: 4242,
        },
        args: json!({ "lines": 200 }),
        idempotency_key: idempotency_key.map(str::to_owned),
        deadline_ms: 60_000,
        wait: true,
    }
}

#[test]
fn round_trips_with_idempotency_key() {
    let envelope = sample(Some("retry-1"));
    let wire = serde_json::to_string(&envelope).unwrap();
    let back: Envelope = serde_json::from_str(&wire).unwrap();
    assert_eq!(back, envelope);
}

#[test]
fn round_trips_without_idempotency_key() {
    let envelope = sample(None);
    let wire = serde_json::to_string(&envelope).unwrap();
    assert!(!wire.contains("idempotency_key"));
    let back: Envelope = serde_json::from_str(&wire).unwrap();
    assert_eq!(back, envelope);
}

#[test]
fn ignores_unknown_fields() {
    let mut wire = serde_json::to_value(sample(None)).unwrap();
    wire["from_the_future"] = json!({ "shiny": true });
    let back: Envelope = serde_json::from_value(wire).unwrap();
    assert_eq!(back, sample(None));
}

#[test]
fn wire_format_is_pinned() {
    let envelope = sample(None);
    assert_eq!(
        serde_json::to_value(&envelope).unwrap(),
        json!({
            "v": 1,
            "id": "req_01J8ZC4V9K3W6P2Q8R5T7X9Y0Z",
            "capability": "log.summarize",
            "client_version": "0.10.1",
            "caller": { "agent": "claude", "repo": "/abs/path", "pid": 4242 },
            "args": { "lines": 200 },
            "deadline_ms": 60_000,
            "wait": true
        })
    );
}
