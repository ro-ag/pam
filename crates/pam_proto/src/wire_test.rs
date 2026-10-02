use serde_json::json;

use crate::wire::{
    End, ErrorFrame, EventFrame, FRAME_TYPES, Follow, Following, Frame, FrameError, Hello,
    HelloAck, Ingress, MAX_ADMIN_REPLY_BYTES, MAX_FRAME_BYTES, MAX_HELLO_BYTES, Via, WIRE_PROTOCOL,
    ZMTP_GREETING_FIRST_BYTE, cause, salvage_envelope_id,
};
use crate::{Caller, Envelope, Event, Outcome, Response};

fn envelope(id: &str) -> Envelope {
    Envelope {
        v: 2,
        id: id.to_owned(),
        capability: "echo".to_owned(),
        client_version: "0.5.0".to_owned(),
        caller: Caller {
            agent: "claude".to_owned(),
            repo: "/work/app".to_owned(),
            pid: 4242,
        },
        args: json!({ "text": "hi" }),
        idempotency_key: None,
        deadline_ms: 60_000,
        wait: true,
    }
}

fn result(id: &str) -> Response {
    Response::Result {
        id: id.to_owned(),
        outcome: Outcome::Solved,
        body: json!({ "echo": { "text": "hi" } }),
        evidence: Vec::new(),
    }
}

#[test]
fn the_protocol_number_and_limits_are_the_specified_ones() {
    assert_eq!(WIRE_PROTOCOL, 2);
    assert_eq!(MAX_FRAME_BYTES, 1024 * 1024);
    assert_eq!(MAX_ADMIN_REPLY_BYTES, 16 * 1024 * 1024);
    assert_eq!(MAX_HELLO_BYTES, 4096);
    assert_eq!(ZMTP_GREETING_FIRST_BYTE, 0xFF);
    // Every limit a first frame can have keeps its first length byte 0x00,
    // which is what makes the first byte a discriminator.
    assert_eq!(u32::try_from(MAX_HELLO_BYTES).unwrap().to_be_bytes()[0], 0);
    assert_eq!(u32::try_from(MAX_FRAME_BYTES).unwrap().to_be_bytes()[0], 0);
}

#[test]
fn the_hello_example_encodes_to_the_documented_bytes() {
    let hello = Frame::Hello(Hello {
        proto: WIRE_PROTOCOL,
        version: "0.5.0".to_owned(),
        via: Via::Direct,
    });
    let encoded = hello.encode().unwrap();
    assert_eq!(
        std::str::from_utf8(&encoded).unwrap(),
        r#"{"t":"hello","proto":2,"version":"0.5.0","via":"direct"}"#
    );
    // The specification's worked example: length prefix 00 00 00 38.
    assert_eq!(encoded.len(), 0x38);
    assert_eq!(Frame::decode(&encoded).unwrap(), hello);
}

#[test]
fn a_hello_without_via_is_a_direct_client_and_unknown_members_are_ignored() {
    let frame =
        Frame::decode(br#"{"t":"hello","proto":2,"version":"0.5.0","later":{"x":1}}"#).unwrap();
    assert_eq!(
        frame,
        Frame::Hello(Hello {
            proto: 2,
            version: "0.5.0".to_owned(),
            via: Via::Direct,
        })
    );
    let relayed = Frame::decode(br#"{"t":"hello","proto":2,"version":"0.5.0","via":"relay"}"#);
    assert!(matches!(
        relayed,
        Ok(Frame::Hello(Hello {
            via: Via::Relay,
            ..
        }))
    ));
}

#[test]
fn every_frame_type_round_trips_under_its_documented_name() {
    let frames = vec![
        Frame::Hello(Hello {
            proto: 2,
            version: "0.5.0".to_owned(),
            via: Via::Relay,
        }),
        Frame::HelloAck(HelloAck {
            proto: 2,
            version: "0.5.0".to_owned(),
            epoch: "01JB2M5T8Q0V7K3W9X4Y6Z1ABC".to_owned(),
        }),
        Frame::Request {
            envelope: envelope("req_1"),
        },
        Frame::Reply {
            response: result("req_1"),
        },
        Frame::Follow(Follow {
            envelope: envelope("req_2"),
            after_seq: 3,
            epoch: Some("01JB2M5T8Q0V7K3W9X4Y6Z1ABC".to_owned()),
        }),
        Frame::Following(Following {
            ticket: "req_1".to_owned(),
            epoch: "01JB2M5T8Q0V7K3W9X4Y6Z1ABC".to_owned(),
            state: "running".to_owned(),
            seq: 2,
        }),
        Frame::follow_event(3, Event::Started),
        Frame::End(End {
            seq: Some(5),
            event: Some(Event::Done),
            response: result("req_2"),
        }),
        Frame::Events,
        Frame::Subscribed,
        Frame::error(cause::BAD_FRAME, "not JSON", "Upgrade pam."),
    ];
    let mut seen = Vec::new();
    for frame in frames {
        let encoded = frame.encode().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(value["t"], frame.type_name(), "{value}");
        assert_eq!(Frame::decode(&encoded).unwrap(), frame);
        seen.push(frame.type_name());
    }
    assert_eq!(seen, FRAME_TYPES);
}

#[test]
fn follow_defaults_to_a_fresh_position() {
    let body =
        serde_json::to_vec(&json!({ "t": "follow", "envelope": envelope("req_2") })).unwrap();
    let Frame::Follow(follow) = Frame::decode(&body).unwrap() else {
        panic!("expected a follow frame");
    };
    assert_eq!(follow.after_seq, 0);
    assert_eq!(follow.epoch, None);
    let explicit = serde_json::to_vec(
        &json!({ "t": "follow", "envelope": envelope("req_2"), "after_seq": 0, "epoch": null }),
    )
    .unwrap();
    assert_eq!(Frame::decode(&explicit).unwrap(), Frame::Follow(follow));
}

#[test]
fn a_follow_event_carries_only_its_sequence_number() {
    let encoded = Frame::follow_event(
        3,
        Event::Progress {
            pct: Some(40),
            note: "Task progress updated".to_owned(),
        },
    )
    .encode()
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&encoded).unwrap(),
        json!({ "t": "event", "seq": 3,
                "event": { "kind": "progress", "pct": 40, "note": "Task progress updated" } })
    );
}

#[test]
fn an_all_events_frame_carries_the_counter_and_the_admission_metadata() {
    let body = serde_json::to_vec(&json!({
        "t": "event", "n": 1042, "ticket": "req_01JB2M6A", "capability": "flow.run",
        "repo": "/work/app", "agent": "claude", "ingress": "public",
        "event": { "kind": "progress", "pct": 40, "note": "step build: cargo test" }
    }))
    .unwrap();
    let frame = Frame::decode(&body).unwrap();
    assert_eq!(
        frame,
        Frame::Event(EventFrame {
            seq: None,
            n: Some(1042),
            ticket: Some("req_01JB2M6A".to_owned()),
            capability: Some("flow.run".to_owned()),
            repo: Some("/work/app".to_owned()),
            agent: Some("claude".to_owned()),
            ingress: Some(Ingress::Public),
            event: Event::Progress {
                pct: Some(40),
                note: "step build: cargo test".to_owned(),
            },
        })
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&frame.encode().unwrap()).unwrap(),
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()
    );
}

#[test]
fn a_refused_follow_ends_without_a_sequence_number_or_event() {
    let end = Frame::End(End {
        seq: None,
        event: None,
        response: Response::Refusal {
            id: "req_2".to_owned(),
            cause: "request_unavailable".to_owned(),
            detail: "no such ticket".to_owned(),
            recovery: "Check the ticket id.".to_owned(),
            retryable: false,
        },
    });
    let value: serde_json::Value = serde_json::from_slice(&end.encode().unwrap()).unwrap();
    assert!(
        value.get("seq").is_none() && value.get("event").is_none(),
        "{value}"
    );
    assert_eq!(Frame::decode(&end.encode().unwrap()).unwrap(), end);
}

#[test]
fn events_is_a_bare_marker_and_ignores_unknown_members() {
    assert_eq!(Frame::Events.encode().unwrap(), br#"{"t":"events"}"#);
    assert_eq!(Frame::decode(br#"{"t":"events"}"#).unwrap(), Frame::Events);
    // An earlier build of this protocol sent a selector with it; the frame
    // still reads, and selects nothing.
    assert_eq!(
        Frame::decode(br#"{"t":"events","include_probes":true}"#).unwrap(),
        Frame::Events
    );
}

#[test]
fn subscribed_is_a_bare_marker_and_ignores_unknown_members() {
    assert_eq!(
        Frame::Subscribed.encode().unwrap(),
        br#"{"t":"subscribed"}"#
    );
    assert_eq!(
        Frame::decode(br#"{"t":"subscribed"}"#).unwrap(),
        Frame::Subscribed
    );
    // A newer daemon may say more in it; this build still reads the marker.
    assert_eq!(
        Frame::decode(br#"{"t":"subscribed","replayed":0}"#).unwrap(),
        Frame::Subscribed
    );
}

#[test]
fn decode_tells_the_ways_a_body_can_be_wrong_apart() {
    assert!(matches!(
        Frame::decode(b"not json"),
        Err(FrameError::NotJson(_))
    ));
    assert!(matches!(
        Frame::decode(b"[1,2]"),
        Err(FrameError::NotJson(_))
    ));
    // A pre-migration client's first frame: a bare envelope, no "t".
    let bare = serde_json::to_vec(&envelope("req_old")).unwrap();
    assert_eq!(Frame::decode(&bare), Err(FrameError::Untyped));
    assert_eq!(Frame::decode(br#"{"t":7}"#), Err(FrameError::Untyped));
    assert_eq!(
        Frame::decode(br#"{"t":"subscribe_everything"}"#),
        Err(FrameError::UnknownType("subscribe_everything".to_owned()))
    );
    // A known type whose envelope does not parse keeps its type, so the
    // daemon can answer `bad_request` instead of `bad_frame`.
    let broken = br#"{"t":"request","envelope":{"id":"req_salvage","capability":7}}"#;
    let Err(FrameError::Invalid { t, detail }) = Frame::decode(broken) else {
        panic!("expected an invalid request frame");
    };
    assert_eq!(t, "request");
    assert!(!detail.is_empty());
    assert_eq!(salvage_envelope_id(broken), Some("req_salvage".to_owned()));
    assert_eq!(salvage_envelope_id(br#"{"t":"request"}"#), None);
    assert_eq!(salvage_envelope_id(b"not json"), None);
}

#[test]
fn an_unknown_type_name_is_bounded_in_the_error() {
    let body = format!(r#"{{"t":"{}"}}"#, "x".repeat(10_000));
    let Err(FrameError::UnknownType(name)) = Frame::decode(body.as_bytes()) else {
        panic!("expected an unknown type");
    };
    assert_eq!(name.len(), 64);
}

#[test]
fn an_error_frame_names_cause_detail_and_recovery() {
    let frame = Frame::Error(ErrorFrame::new(
        cause::PROTOCOL_MISMATCH,
        "this daemon speaks pam wire protocol 2; the client sent 3",
        "Use the pam binary that matches the running daemon (0.5.0).",
    ));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&frame.encode().unwrap()).unwrap(),
        json!({ "t": "error", "cause": "protocol_mismatch",
                "detail": "this daemon speaks pam wire protocol 2; the client sent 3",
                "recovery": "Use the pam binary that matches the running daemon (0.5.0)." })
    );
    for name in [
        cause::PROTOCOL_MISMATCH,
        cause::CLIENT_VERSION_MISMATCH,
        cause::DAEMON_OUTDATED,
        cause::BAD_FRAME,
        cause::HANDSHAKE_TIMEOUT,
        cause::CONNECTION_CAPACITY_EXHAUSTED,
        cause::DAEMON_SHUTTING_DOWN,
        cause::FOLLOW_EXPIRED,
        cause::SUBSCRIBER_LAGGED,
        cause::SUBSCRIBER_CAPACITY_EXHAUSTED,
        cause::FOLLOWER_CAPACITY_EXHAUSTED,
    ] {
        assert!(name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
    }
}
