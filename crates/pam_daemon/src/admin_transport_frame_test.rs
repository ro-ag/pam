use std::io;

use pam_proto::{Caller, Envelope, Outcome, PROTOCOL_VERSION, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::frame::{
    CAUSE_RESPONSE_TOO_LARGE, MAX_REQUEST_BYTES, MAX_REQUEST_MS, MAX_RESPONSE_BYTES, encode_reply,
    encode_request, read_frame, validate_envelope, write_frame,
};

fn envelope(capability: &str, wait: bool, deadline_ms: u64) -> Envelope {
    Envelope {
        v: PROTOCOL_VERSION,
        id: "req_frame".to_owned(),
        capability: capability.to_owned(),
        client_version: env!("CARGO_PKG_VERSION").to_owned(),
        caller: Caller {
            agent: "pam-gui".to_owned(),
            repo: "/repo".to_owned(),
            pid: 1,
        },
        args: serde_json::json!({}),
        idempotency_key: None,
        deadline_ms,
        wait,
    }
}

/// The envelope rules every adapter shares, as a table: only a waiting
/// `admin.*` request with a deadline inside `1..=MAX_REQUEST_MS` is carried.
#[test]
fn validate_envelope_limits_table() {
    let cases: [(&str, bool, u64, bool); 8] = [
        ("admin.status", true, 1, true),
        ("admin.status", true, MAX_REQUEST_MS, true),
        ("admin.status", true, 0, false),
        ("admin.status", true, MAX_REQUEST_MS + 1, false),
        ("admin.status", false, 1_000, false),
        ("status", true, 1_000, false),
        ("admin", true, 1_000, false),
        ("", true, 1_000, false),
    ];
    for (capability, wait, deadline_ms, accepted) in cases {
        let verdict = validate_envelope(&envelope(capability, wait, deadline_ms));
        assert_eq!(
            verdict.is_ok(),
            accepted,
            "{capability:?} wait={wait} deadline={deadline_ms}: {verdict:?}"
        );
        if let Err(error) = verdict {
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }
    let oversized = Envelope {
        args: serde_json::json!({ "pad": "x".repeat(MAX_REQUEST_BYTES) }),
        ..envelope("admin.status", true, 1_000)
    };
    assert_eq!(
        encode_request(&oversized).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

/// The framing limits: an empty frame, a frame over the budget, and a
/// length prefix over the budget are all refused before any payload byte
/// is read or written; a frame at the budget passes.
#[tokio::test]
async fn frame_limits_table() {
    let budget = 64;
    let (mut client, mut server) = tokio::io::duplex(budget * 4);

    write_frame(&mut client, &[7u8; 64], budget).await.unwrap();
    assert_eq!(
        read_frame(&mut server, budget).await.unwrap(),
        vec![7u8; 64]
    );

    for (payload, accepted) in [
        (vec![1u8; 1], true),
        (Vec::new(), false),
        (vec![1u8; 65], false),
    ] {
        let (mut sink, _keep) = tokio::io::duplex(budget * 4);
        let verdict = write_frame(&mut sink, &payload, budget).await;
        assert_eq!(verdict.is_ok(), accepted, "writing {} bytes", payload.len());
    }

    for (length, accepted) in [(0u32, false), (65, false), (64, true)] {
        let (mut client, mut server) = tokio::io::duplex(budget * 4);
        client.write_u32(length).await.unwrap();
        client.write_all(&[0u8; 64]).await.unwrap();
        let verdict = read_frame(&mut server, budget).await;
        assert_eq!(verdict.is_ok(), accepted, "length prefix {length}");
        if !accepted {
            assert_eq!(verdict.unwrap_err().kind(), io::ErrorKind::InvalidData);
            // Nothing past the prefix was consumed.
            let mut rest = vec![0u8; 64];
            server.read_exact(&mut rest).await.unwrap();
        }
    }
}

/// A reply that outgrew the response budget is replaced by a small refusal
/// carrying the request id: the op already ran and was audited, and the
/// client must learn that rather than see a transport failure.
#[test]
fn an_oversized_reply_becomes_a_small_refusal_naming_the_request() {
    let small = Response::Result {
        id: "req_small".to_owned(),
        outcome: Outcome::Verified,
        body: serde_json::json!({ "ok": true }),
        evidence: Vec::new(),
    };
    let encoded = encode_reply("req_small", &small).unwrap();
    assert_eq!(serde_json::from_slice::<Response>(&encoded).unwrap(), small);

    let huge = Response::Result {
        id: "req_huge".to_owned(),
        outcome: Outcome::Verified,
        body: serde_json::json!({ "text": "x".repeat(MAX_RESPONSE_BYTES) }),
        evidence: Vec::new(),
    };
    let encoded = encode_reply("req_huge", &huge).unwrap();
    assert!(
        encoded.len() < 4096,
        "the substitute is small: {} bytes",
        encoded.len()
    );
    match serde_json::from_slice::<Response>(&encoded).unwrap() {
        Response::Refusal {
            id, cause, detail, ..
        } => {
            assert_eq!(id, "req_huge");
            assert_eq!(cause, CAUSE_RESPONSE_TOO_LARGE);
            assert!(detail.contains("completed"), "{detail}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}
