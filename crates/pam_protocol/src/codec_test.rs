use pam_core::{
    CallerCredential, CallerId, ContentDigest, EvidenceHandle, IdempotencyKey, ProjectId, RequestId,
};
use serde::Serialize;

use super::{
    BriefItem, BriefProvenance, BriefResult, CancellationDisposition, CancellationResult,
    Capability, CodecError, ConfigurationPresence, Event, EventEnvelope, EvidenceChunk,
    EvidenceMetadata, EvidenceRedaction, EvidenceRetention, Failure, FailureCode,
    MAX_EVIDENCE_CHUNK_SIZE, MAX_FRAME_SIZE, NetworkDiagnosticsResult, OperationTruth,
    PROTOCOL_VERSION, PacState, ReplayResult, RequestEnvelope, RequestPayload, ResultBody,
    ResultEnvelope, ResultPayload, ServerMessage, SourceAvailability, decode_request,
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

fn evidence_handle() -> EvidenceHandle {
    EvidenceHandle::parse("evidence://ci/1842/failure").unwrap()
}

fn brief_result() -> BriefResult {
    let handle = evidence_handle();
    let item = |text: &str, truth| BriefItem {
        text: text.to_owned(),
        truth,
        evidence: vec![handle.clone()],
    };
    BriefResult {
        goal: Some(item("Ship durable continuity", OperationTruth::Observed)),
        decisions: vec![item("Use SQLite", OperationTruth::Observed)],
        verified: vec![item("Protocol tests pass", OperationTruth::Verified)],
        next: vec![item("Wire the daemon", OperationTruth::Unresolved)],
        provenance: vec![
            BriefProvenance {
                source: "pam".to_owned(),
                availability: SourceAvailability::Available,
                truth: OperationTruth::Verified,
                evidence: Some(handle.clone()),
                detail: None,
            },
            BriefProvenance {
                source: "ptrack".to_owned(),
                availability: SourceAvailability::Partial,
                truth: OperationTruth::Observed,
                evidence: Some(handle),
                detail: Some("bounded context snapshot".to_owned()),
            },
            BriefProvenance {
                source: "connector".to_owned(),
                availability: SourceAvailability::Unavailable,
                truth: OperationTruth::Unresolved,
                evidence: None,
                detail: Some("source is not configured".to_owned()),
            },
        ],
    }
}

#[test]
fn request_round_trips_through_named_messagepack() {
    let expected = status_request();
    let bytes = encode(&expected).unwrap();

    assert_eq!(decode_request(&bytes).unwrap(), expected);
}

#[test]
fn authenticated_request_round_trips_without_debug_disclosure() {
    let secret = "caller-secret-that-must-not-appear";
    let expected = status_request().authenticated(CallerCredential::new(secret));
    let bytes = encode(&expected).unwrap();
    let actual = decode_request(&bytes).unwrap();

    assert_eq!(actual, expected);
    assert!(!format!("{actual:?}").contains(secret));
}

#[test]
fn approval_receipt_round_trips_as_an_additive_request_field() {
    let expected = status_request().with_approval(pam_core::ApprovalId::from("approval-1"));

    assert_eq!(
        decode_request(&encode(&expected).unwrap()).unwrap(),
        expected
    );
}

#[test]
fn cancel_target_round_trips_without_replacing_observer_correlation() {
    let expected = RequestEnvelope::cancel(
        RequestId::from("cancel-observer-1"),
        CallerId::from("cli-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("cancel-1"),
        RequestId::from("target-1"),
    );

    let actual = decode_request(&encode(&expected).unwrap()).unwrap();

    assert_eq!(actual.request_id.as_str(), "cancel-observer-1");
    assert_eq!(actual.payload, expected.payload);
}

#[test]
fn replay_after_sequence_round_trips_through_named_messagepack() {
    let expected = RequestEnvelope::replay(
        RequestId::from("replay-observer-1"),
        CallerId::from("cli-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("replay-1"),
        RequestId::from("target-1"),
        12,
    );

    assert_eq!(
        decode_request(&encode(&expected).unwrap()).unwrap(),
        expected
    );
}

#[test]
fn read_only_request_variants_round_trip_through_named_messagepack() {
    let handle = evidence_handle();
    let requests = [
        RequestEnvelope::brief(
            RequestId::from("brief-observer-1"),
            CallerId::from("cli-1"),
            ProjectId::from("project-1"),
            IdempotencyKey::from("brief-1"),
        ),
        RequestEnvelope::network_diagnostics(
            RequestId::from("network-observer-1"),
            CallerId::from("cli-1"),
            ProjectId::from("project-1"),
            IdempotencyKey::from("network-1"),
        )
        .authenticated(CallerCredential::new("network-credential")),
        RequestEnvelope::wait_for_result(
            RequestId::from("wait-observer-1"),
            CallerId::from("cli-1"),
            ProjectId::from("project-1"),
            IdempotencyKey::from("wait-1"),
            RequestId::from("target-1"),
            12,
        ),
        RequestEnvelope::get_result(
            RequestId::from("result-observer-1"),
            CallerId::from("cli-1"),
            ProjectId::from("project-1"),
            IdempotencyKey::from("result-1"),
            RequestId::from("target-1"),
        ),
        RequestEnvelope::inspect_evidence(
            RequestId::from("inspect-observer-1"),
            CallerId::from("cli-1"),
            ProjectId::from("project-1"),
            IdempotencyKey::from("inspect-1"),
            handle.clone(),
        ),
        RequestEnvelope::read_evidence(
            RequestId::from("read-observer-1"),
            CallerId::from("cli-1"),
            ProjectId::from("project-1"),
            IdempotencyKey::from("read-1"),
            handle,
            512,
            1024,
        )
        .unwrap(),
    ];

    for expected in requests {
        assert_eq!(
            decode_request(&encode(&expected).unwrap()).unwrap(),
            expected
        );
    }
}

#[test]
fn invalid_evidence_read_lengths_are_rejected_during_decode() {
    for length in [0, MAX_EVIDENCE_CHUNK_SIZE as u64 + 1] {
        let request = RequestEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: RequestId::from("read-observer-1"),
            caller_id: CallerId::from("cli-1"),
            authentication: None,
            approval_id: None,
            project_id: ProjectId::from("project-1"),
            capability: Capability::ReadEvidence,
            idempotency_key: IdempotencyKey::from("read-1"),
            deadline_unix_ms: None,
            payload: RequestPayload::ReadEvidence {
                handle: evidence_handle(),
                offset: 0,
                length,
            },
        };

        assert!(matches!(
            decode_request(&encode(&request).unwrap()),
            Err(CodecError::Decode(_))
        ));
    }
}

#[test]
fn durable_result_payloads_round_trip_through_named_messagepack() {
    let results = [
        ServerMessage::Result(ResultEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: RequestId::from("cancel-observer-1"),
            project_id: ProjectId::from("project-1"),
            body: ResultBody::Success {
                truth: OperationTruth::Changed,
                payload: ResultPayload::Cancellation(CancellationResult {
                    target_request_id: RequestId::from("target-1"),
                    disposition: CancellationDisposition::Requested,
                }),
            },
        }),
        ServerMessage::Result(ResultEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: RequestId::from("replay-observer-1"),
            project_id: ProjectId::from("project-1"),
            body: ResultBody::Success {
                truth: OperationTruth::Observed,
                payload: ResultPayload::Replay(ReplayResult {
                    target_request_id: RequestId::from("target-1"),
                    through_sequence: 12,
                    pending: true,
                }),
            },
        }),
    ];

    for expected in results {
        assert_eq!(
            decode_server_message(&encode(&expected).unwrap()).unwrap(),
            expected
        );
    }
}

#[test]
fn read_only_result_variants_round_trip_through_named_messagepack() {
    let mut results = vec![ServerMessage::Result(ResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: RequestId::from("brief-observer-1"),
        project_id: ProjectId::from("project-1"),
        body: ResultBody::Success {
            truth: OperationTruth::Observed,
            payload: ResultPayload::Brief(brief_result()),
        },
    })];
    results.push(ServerMessage::Result(ResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: RequestId::from("network-observer-1"),
        project_id: ProjectId::from("project-1"),
        body: ResultBody::Success {
            truth: OperationTruth::Observed,
            payload: ResultPayload::NetworkDiagnostics(NetworkDiagnosticsResult {
                platform_roots_enabled: true,
                system_proxy_discovery_enabled: true,
                proxy_environment_presence: ConfigurationPresence::Configured,
                no_proxy_presence: ConfigurationPresence::NotConfigured,
                pac_state: PacState::DetectedUnsupported,
            }),
        },
    }));
    for retention in [
        EvidenceRetention::Session,
        EvidenceRetention::Project,
        EvidenceRetention::Persistent,
    ] {
        for redaction in [EvidenceRedaction::Unredacted, EvidenceRedaction::Redacted] {
            results.push(ServerMessage::Result(ResultEnvelope {
                protocol_version: PROTOCOL_VERSION,
                request_id: RequestId::from("inspect-observer-1"),
                project_id: ProjectId::from("project-1"),
                body: ResultBody::Success {
                    truth: OperationTruth::Observed,
                    payload: ResultPayload::EvidenceMetadata(EvidenceMetadata {
                        handle: evidence_handle(),
                        digest: ContentDigest::from_sha256([0xab; 32]),
                        size_bytes: 3,
                        media_type: "text/plain".to_owned(),
                        retention: retention.clone(),
                        redaction,
                        created_at_unix_ms: 1_700_000_000_000,
                    }),
                },
            }));
        }
    }
    results.push(ServerMessage::Result(ResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: RequestId::from("read-observer-1"),
        project_id: ProjectId::from("project-1"),
        body: ResultBody::Success {
            truth: OperationTruth::Observed,
            payload: ResultPayload::EvidenceChunk(
                EvidenceChunk::new(evidence_handle(), 512, vec![1, 2, 3], true).unwrap(),
            ),
        },
    }));

    for expected in results {
        assert_eq!(
            decode_server_message(&encode(&expected).unwrap()).unwrap(),
            expected
        );
    }
}

#[test]
fn brief_named_fields_preserve_presentation_order() {
    let bytes = encode(&brief_result()).unwrap();
    let positions = ["goal", "decisions", "verified", "next", "provenance"].map(|field| {
        bytes
            .windows(field.len())
            .position(|window| window == field.as_bytes())
            .unwrap()
    });

    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
}

#[derive(Serialize)]
struct UnboundedEvidenceChunk {
    handle: EvidenceHandle,
    offset: u64,
    bytes: Vec<u8>,
    eof: bool,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum UnboundedResultPayload {
    EvidenceChunk(UnboundedEvidenceChunk),
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum UnboundedResultBody {
    Success {
        truth: OperationTruth,
        payload: UnboundedResultPayload,
    },
}

#[derive(Serialize)]
struct UnboundedResultEnvelope {
    protocol_version: u16,
    request_id: RequestId,
    project_id: ProjectId,
    body: UnboundedResultBody,
}

#[derive(Serialize)]
#[serde(tag = "message_type", rename_all = "snake_case")]
enum UnboundedServerMessage {
    Result(UnboundedResultEnvelope),
}

#[test]
fn oversized_evidence_chunks_are_rejected_during_decode() {
    let message = UnboundedServerMessage::Result(UnboundedResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: RequestId::from("read-observer-1"),
        project_id: ProjectId::from("project-1"),
        body: UnboundedResultBody::Success {
            truth: OperationTruth::Observed,
            payload: UnboundedResultPayload::EvidenceChunk(UnboundedEvidenceChunk {
                handle: evidence_handle(),
                offset: 0,
                bytes: vec![0; MAX_EVIDENCE_CHUNK_SIZE + 1],
                eof: true,
            }),
        },
    });

    assert!(matches!(
        decode_server_message(&encode(&message).unwrap()),
        Err(CodecError::Decode(_))
    ));
}

#[test]
fn maximum_evidence_chunk_fits_the_protocol_frame_and_round_trips() {
    let expected = ServerMessage::Result(ResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: RequestId::from("read-observer-1"),
        project_id: ProjectId::from("project-1"),
        body: ResultBody::Success {
            truth: OperationTruth::Observed,
            payload: ResultPayload::EvidenceChunk(
                EvidenceChunk::new(
                    evidence_handle(),
                    0,
                    vec![u8::MAX; MAX_EVIDENCE_CHUNK_SIZE],
                    true,
                )
                .unwrap(),
            ),
        },
    });

    let bytes = encode(&expected).unwrap();
    assert!(bytes.len() < MAX_FRAME_SIZE);
    assert_eq!(decode_server_message(&bytes).unwrap(), expected);
}

#[test]
fn durable_failures_round_trip_as_distinct_typed_codes() {
    for code in [
        FailureCode::NotFound,
        FailureCode::Pending,
        FailureCode::IdempotencyConflict,
        FailureCode::Cancelled,
        FailureCode::LeaseConflict,
    ] {
        let expected = ServerMessage::Result(ResultEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: RequestId::from("observer-1"),
            project_id: ProjectId::from("project-1"),
            body: ResultBody::Failure(Failure {
                message: format!("{code:?}"),
                code,
                recovery: None,
                approval: None,
            }),
        });

        assert_eq!(
            decode_server_message(&encode(&expected).unwrap()).unwrap(),
            expected
        );
    }
}

#[test]
fn durable_lifecycle_events_round_trip_through_named_messagepack() {
    for (sequence, event) in [
        Event::LeaseExpired,
        Event::CancellationRequested,
        Event::Cancelled,
        Event::Failed,
    ]
    .into_iter()
    .enumerate()
    {
        let expected = ServerMessage::Event(EventEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: RequestId::from("target-1"),
            project_id: ProjectId::from("project-1"),
            sequence: sequence as u64 + 1,
            event,
        });

        assert_eq!(
            decode_server_message(&encode(&expected).unwrap()).unwrap(),
            expected
        );
    }
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
            approval: None,
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
    authentication: Option<CallerCredential>,
    approval_id: Option<pam_core::ApprovalId>,
    project_id: ProjectId,
    capability: Capability,
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
        authentication: request.authentication.clone(),
        approval_id: request.approval_id.clone(),
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
