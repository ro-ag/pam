use std::time::Duration;

use pam_proto::Event;

use crate::events::{BACKOFF_MAX, BACKOFF_MIN, decode_event_frames, is_own_event, next_backoff};

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

#[test]
fn pub_frames_decode_into_ticket_and_event() {
    let frames: Vec<&[u8]> = vec![b"req_01ABC", br#"{"kind":"approval_pending"}"#];
    let payload = decode_event_frames(&frames).expect("decodes");
    assert_eq!(payload.ticket, "req_01ABC");
    assert_eq!(payload.event, Event::ApprovalPending);
}

#[test]
fn the_forwarded_payload_serializes_with_the_event_tag() {
    let frames: Vec<&[u8]> = vec![b"req_01ABC", br#"{"kind":"done"}"#];
    let payload = decode_event_frames(&frames).expect("decodes");
    assert_eq!(
        serde_json::to_value(&payload).expect("serializes"),
        serde_json::json!({ "ticket": "req_01ABC", "event": { "kind": "done" } })
    );
}

#[test]
fn malformed_frames_are_dropped_not_fatal() {
    // Too few frames.
    assert_eq!(decode_event_frames::<&[u8]>(&[]), None);
    assert_eq!(decode_event_frames(&[b"req_1".as_slice()]), None);
    // Payload that is not an event.
    let junk: Vec<&[u8]> = vec![b"req_1", b"not json"];
    assert_eq!(decode_event_frames(&junk), None);
    let wrong_shape: Vec<&[u8]> = vec![b"req_1", br#"{"kind":"nope"}"#];
    assert_eq!(decode_event_frames(&wrong_shape), None);
}

/// The feedback-loop guard: the GUI's own control requests are marked before they are sent, and
/// the event pump drops their lifecycle events instead of forwarding them to the webview.
#[test]
fn events_of_the_guis_own_control_requests_are_not_forwarded() {
    crate::own_requests::register("req_gui_status_1");
    let own: Vec<&[u8]> = vec![b"req_gui_status_1", br#"{"kind":"done"}"#];
    let own = decode_event_frames(&own).expect("decodes");
    assert!(
        is_own_event(&own),
        "a status poll's `done` must not wake the poller"
    );

    let foreign: Vec<&[u8]> = vec![b"req_agent_flow_9", br#"{"kind":"done"}"#];
    let foreign = decode_event_frames(&foreign).expect("decodes");
    assert!(
        !is_own_event(&foreign),
        "other callers' events still reach the GUI"
    );
}
