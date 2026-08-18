use pam_core::{CallerId, IdempotencyKey, ProjectId, RequestId};
use serde::Serialize;

use super::{
    CodecError, Event, EventEnvelope, Failure, FailureCode, MAX_FRAME_SIZE, PROTOCOL_VERSION,
    RequestEnvelope, RequestPayload, ResultBody, ResultEnvelope, ServerMessage, decode_request,
    decode_server_message, encode,
};

fn status_request() -> RequestEnvelope {
    RequestEnvelope::status(
        RequestId::from("request-1"),
        CallerId::from("cli-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("status-1"),
    )
}

#[test]
fn request_round_trips_through_named_messagepack() {
    let expected = status_request();
    let bytes = encode(&expected).unwrap();

    assert_eq!(decode_request(&bytes).unwrap(), expected);
}

#[test]
fn server_message_round_trips_with_sequence_and_correlation() {
    let expected = ServerMessage::Event(EventEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: RequestId::from("request-1"),
        project_id: ProjectId::from("project-1"),
        sequence: 2,
        event: Event::Started,
    });
    let bytes = encode(&expected).unwrap();

    assert_eq!(decode_server_message(&bytes).unwrap(), expected);
}

#[test]
fn oversized_frames_are_rejected_before_decode() {
    let bytes = vec![0; MAX_FRAME_SIZE + 1];

    assert!(matches!(
        decode_request(&bytes),
        Err(CodecError::FrameTooLarge { .. })
    ));
}

#[test]
fn unsupported_protocol_versions_are_rejected() {
    let mut request = status_request();
    request.protocol_version += 1;
    let bytes = encode(&request).unwrap();

    assert!(matches!(
        decode_request(&bytes),
        Err(CodecError::UnsupportedProtocolVersion { .. })
    ));
}

#[test]
fn unsupported_version_failures_are_decodable_across_versions() {
    let expected = ServerMessage::Result(ResultEnvelope {
        protocol_version: PROTOCOL_VERSION + 1,
        request_id: RequestId::from("request-1"),
        project_id: ProjectId::from("project-1"),
        body: ResultBody::Failure(Failure {
            code: FailureCode::UnsupportedProtocolVersion,
            message: "supported protocol version is 1".to_owned(),
            recovery: None,
        }),
    });

    assert_eq!(
        decode_server_message(&encode(&expected).unwrap()).unwrap(),
        expected
    );
}

#[derive(Serialize)]
struct ExtendedRequest {
    protocol_version: u16,
    request_id: RequestId,
    caller_id: CallerId,
    project_id: ProjectId,
    capability: super::Capability,
    idempotency_key: IdempotencyKey,
    deadline_unix_ms: Option<u64>,
    payload: RequestPayload,
    future_optional_field: String,
}

#[test]
fn unknown_named_fields_are_ignored_for_compatible_evolution() {
    let request = status_request();
    let extended = ExtendedRequest {
        protocol_version: request.protocol_version,
        request_id: request.request_id.clone(),
        caller_id: request.caller_id.clone(),
        project_id: request.project_id.clone(),
        capability: request.capability.clone(),
        idempotency_key: request.idempotency_key.clone(),
        deadline_unix_ms: request.deadline_unix_ms,
        payload: request.payload.clone(),
        future_optional_field: "ignored by v1".to_owned(),
    };

    assert_eq!(
        decode_request(&encode(&extended).unwrap()).unwrap(),
        request
    );
}

#[test]
fn status_request_matches_the_v1_golden_fixture() {
    let bytes = encode(&status_request()).unwrap();
    let actual = bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut hex, byte| {
            write!(hex, "{byte:02x}").unwrap();
            hex
        });

    assert_eq!(
        actual,
        include_str!("../fixtures/status_request_v1.msgpack.hex").trim()
    );
}
use std::fmt::Write;
