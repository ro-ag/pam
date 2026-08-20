use std::fmt::Write;

use pam_core::{
    CallerCredential, CallerId, ContentDigest, EvidenceHandle, IdempotencyKey, ProjectId, RequestId,
};
use pam_flow::{
    EffectResult, EvidenceHandle as FlowEvidenceHandle, FlowDefinition, FlowRun, FlowRunResult,
    MAX_EFFECT_SUMMARY_BYTES, MAX_EVIDENCE_HANDLE_BYTES, MAX_EVIDENCE_HANDLES,
    MAX_FLOW_DOCUMENT_BYTES, MAX_FLOW_ID_BYTES, MAX_FLOW_STEPS, MAX_RUN_ID_BYTES, RunDecision,
    RunId, RunTransition,
};
use serde::Serialize;

use super::{
    BriefItem, BriefProvenance, BriefResult, CancellationDisposition, CancellationResult,
    Capability, CodecError, ConfigurationPresence, Event, EventEnvelope, EvidenceChunk,
    EvidenceMetadata, EvidenceRedaction, EvidenceRetention, ExpectedTargetKind, Failure,
    FailureCode, MAX_EVIDENCE_CHUNK_SIZE, MAX_FRAME_SIZE, MAX_MODEL_MESSAGE_BYTES,
    MAX_MODEL_OUTPUT_BYTES, ModelFinishReason, ModelGenerationResult, ModelMessage, ModelRole,
    ModelUsage, NetworkDiagnosticsResult, OperationTruth, PROTOCOL_VERSION, PacState, ReplayResult,
    RequestEnvelope, RequestPayload, ResultBody, ResultEnvelope, ResultPayload, ServerMessage,
    SourceAvailability, decode_request, decode_request_envelope, decode_server_message,
    decode_server_message_envelope, encode,
};

const PROJECT_ROOT: &str = "/canonical/project";

const FLOW_RESULT_FRAME_MARGIN: usize = 64 * 1024;

const FLOW_DEFINITION: &str = r#"
schema_version = 2
id = "protocol-flow"
name = "Protocol flow"
description = "Exercise flow protocol codecs."
revision = 1

[outcome]
solved = "Report solved work."
changed = "Report changed state."
verified = "Report verified evidence."
unresolved = "Report unresolved work."
blocked = "Report blockers."

[[steps]]
id = "inspect"
description = "Inspect repository state."
timeout_seconds = 30
effect = "read_only"
semantic = "verify"
action = { type = "command", program = "git", args = ["diff", "--quiet"], working_directory = "." }
"#;

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

fn flow_artifacts() -> (RunTransition, FlowRunResult) {
    let definition = FlowDefinition::parse_toml(FLOW_DEFINITION).unwrap();
    let mut run = FlowRun::start(RunId::parse("protocol-run-1").unwrap(), definition).unwrap();
    let scheduled = run.next_decision(1).unwrap();
    let RunDecision::EvaluateEffect { effect, .. } = scheduled.decision() else {
        panic!("expected effect evaluation")
    };
    let effect = effect.clone();
    run.prepare_effect(&effect, 2).unwrap();
    let recorded = run
        .record_effect_result(
            &effect,
            EffectResult::succeeded(
                "repository verified",
                vec![FlowEvidenceHandle::parse("evidence:protocol").unwrap()],
            )
            .unwrap(),
            3,
        )
        .unwrap();
    let terminal = run.next_decision(4).unwrap();
    let RunDecision::Terminal { result } = terminal.decision() else {
        panic!("expected terminal flow result")
    };
    (recorded.transition().unwrap().clone(), result.clone())
}

fn maximum_flow_result() -> FlowRunResult {
    let mut source = String::from(
        r#"
schema_version = 1
id = "maximum-protocol-flow"
name = "Maximum protocol flow"
description = "Exercise the maximum valid terminal flow result."
revision = 1

[outcome]
solved = "Report solved work."
changed = "Report changed state."
verified = "Report verified evidence."
unresolved = "Report unresolved work."
blocked = "Report blockers."
"#,
    );
    for index in 0..MAX_FLOW_STEPS {
        let prefix = format!("step-{index:03}-");
        let step_id = format!("{prefix}{}", "s".repeat(MAX_FLOW_ID_BYTES - prefix.len()));
        writeln!(
            source,
            r#"
[[steps]]
id = "{step_id}"
description = "Exercise one maximum result step."
timeout_seconds = 30
effect = "read_only"
action = {{ type = "command", program = "git", args = ["status"], working_directory = "." }}"#
        )
        .unwrap();
    }

    let definition = FlowDefinition::parse_toml(&source).unwrap();
    let mut run = FlowRun::start(
        RunId::parse("r".repeat(MAX_RUN_ID_BYTES)).unwrap(),
        definition,
    )
    .unwrap();
    let evidence = (0..MAX_EVIDENCE_HANDLES)
        .map(|index| {
            let prefix = format!("evidence:{index}:");
            FlowEvidenceHandle::parse(format!(
                "{prefix}{}",
                "e".repeat(MAX_EVIDENCE_HANDLE_BYTES - prefix.len())
            ))
            .unwrap()
        })
        .collect::<Vec<_>>();

    let maximum_steps = u64::try_from(MAX_FLOW_STEPS).unwrap();
    for now_ms in 0..maximum_steps {
        let scheduled = run.next_decision(now_ms).unwrap();
        let RunDecision::EvaluateEffect { effect, .. } = scheduled.decision() else {
            panic!("expected effect evaluation")
        };
        let effect = effect.clone();
        run.prepare_effect(&effect, now_ms).unwrap();
        run.record_effect_result(
            &effect,
            EffectResult::succeeded("s".repeat(MAX_EFFECT_SUMMARY_BYTES), evidence.clone())
                .unwrap(),
            now_ms,
        )
        .unwrap();
    }

    let terminal = run.next_decision(maximum_steps).unwrap();
    let RunDecision::Terminal { result } = terminal.decision() else {
        panic!("expected terminal flow result")
    };
    result.clone()
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
fn direct_model_request_round_trips_with_bounded_messages() {
    let secret_prompt = "Return exactly PRIVATE-CONTENT.";
    let expected = RequestEnvelope::model_infer(
        RequestId::from("model-observer-1"),
        CallerId::from("cli-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("model-1"),
        "vendor/model",
        vec![ModelMessage::new(ModelRole::User, secret_prompt).unwrap()],
        16,
        42,
    )
    .unwrap()
    .authenticated(CallerCredential::new("model-credential"));

    let decoded = decode_request(&encode(&expected).unwrap()).unwrap();
    assert_eq!(decoded, expected);
    assert!(!format!("{decoded:?}").contains(secret_prompt));
}

#[test]
fn flow_run_request_round_trips_through_named_messagepack() {
    let expected = RequestEnvelope::flow_run(
        RequestId::from("flow-observer-1"),
        CallerId::from("cli-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("flow-1"),
        FLOW_DEFINITION,
        PROJECT_ROOT,
    )
    .unwrap()
    .authenticated(CallerCredential::new("flow-credential"));

    assert_eq!(
        decode_request(&encode(&expected).unwrap()).unwrap(),
        expected
    );
}

#[derive(Serialize)]
struct RawFlowRequest {
    protocol_version: u16,
    request_id: RequestId,
    caller_id: CallerId,
    authentication: Option<CallerCredential>,
    approval_id: Option<pam_core::ApprovalId>,
    project_id: ProjectId,
    capability: Capability,
    idempotency_key: IdempotencyKey,
    deadline_unix_ms: Option<u64>,
    payload: RawFlowPayload,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum RawFlowPayload {
    FlowRun {
        definition: String,
        project_root: String,
    },
}

fn raw_flow_request(definition: String) -> RawFlowRequest {
    RawFlowRequest {
        protocol_version: PROTOCOL_VERSION,
        request_id: RequestId::from("flow-observer-1"),
        caller_id: CallerId::from("cli-1"),
        authentication: None,
        approval_id: None,
        project_id: ProjectId::from("project-1"),
        capability: Capability::FlowRun,
        idempotency_key: IdempotencyKey::from("flow-1"),
        deadline_unix_ms: None,
        payload: RawFlowPayload::FlowRun {
            definition,
            project_root: PROJECT_ROOT.to_owned(),
        },
    }
}

#[test]
fn malformed_flow_definitions_are_rejected_after_decode() {
    let bytes = encode(&raw_flow_request("not valid TOML =".to_owned())).unwrap();

    assert!(matches!(
        decode_request(&bytes),
        Err(CodecError::Contract(
            super::ProtocolContractError::InvalidFlowDefinition
        ))
    ));
}

#[test]
fn invalid_flow_run_ids_are_rejected_after_decode_without_disclosure() {
    let invalid = "flow run with spaces";
    let mut request = raw_flow_request(FLOW_DEFINITION.to_owned());
    request.request_id = RequestId::from(invalid);
    let bytes = encode(&request).unwrap();

    let error = decode_request(&bytes).unwrap_err();
    assert!(matches!(
        error,
        CodecError::Contract(super::ProtocolContractError::InvalidFlowRunId)
    ));
    assert!(!format!("{error:?}").contains(invalid));
    assert!(!error.to_string().contains(invalid));
}

#[test]
fn invalid_flow_project_roots_are_rejected_during_decode_without_disclosure() {
    let invalid = "/secret/project/../other";
    let mut request = raw_flow_request(FLOW_DEFINITION.to_owned());
    request.payload = RawFlowPayload::FlowRun {
        definition: FLOW_DEFINITION.to_owned(),
        project_root: invalid.to_owned(),
    };
    let bytes = encode(&request).unwrap();

    let error = decode_request(&bytes).unwrap_err();
    assert!(matches!(error, CodecError::Decode(_)));
    assert!(!format!("{error:?}").contains(invalid));
    assert!(!error.to_string().contains(invalid));
}

#[test]
fn oversized_flow_definitions_are_rejected_before_decode() {
    let bytes = rmp_serde::to_vec_named(&raw_flow_request("x".repeat(MAX_FLOW_DOCUMENT_BYTES + 1)))
        .unwrap();
    assert!(bytes.len() > MAX_FRAME_SIZE);

    assert!(matches!(
        decode_request(&bytes),
        Err(CodecError::FrameTooLarge { .. })
    ));
}

#[test]
fn aggregate_model_prompt_budget_is_enforced_by_the_canonical_decoder() {
    let request = RequestEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: RequestId::from("model-observer-1"),
        caller_id: CallerId::from("cli-1"),
        authentication: None,
        approval_id: None,
        project_id: ProjectId::from("project-1"),
        capability: Capability::ModelInfer,
        idempotency_key: IdempotencyKey::from("model-1"),
        deadline_unix_ms: None,
        payload: RequestPayload::ModelInfer {
            model: "vendor/model".to_owned(),
            messages: (0..5)
                .map(|_| {
                    ModelMessage::new(ModelRole::User, "x".repeat(MAX_MODEL_MESSAGE_BYTES)).unwrap()
                })
                .collect(),
            max_output_tokens: 16,
        },
    };

    assert!(matches!(
        decode_request(&encode(&request).unwrap()),
        Err(CodecError::Contract(_))
    ));
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
fn flow_only_target_expectations_round_trip_through_named_messagepack() {
    let caller = CallerId::from("cli-1");
    let project = ProjectId::from("project-1");
    let target = RequestId::from("flow-run-1");
    let requests = [
        RequestEnvelope::cancel_with_expected_target(
            RequestId::from("cancel-observer"),
            caller.clone(),
            project.clone(),
            IdempotencyKey::from("cancel-key"),
            target.clone(),
            ExpectedTargetKind::FlowRun,
        ),
        RequestEnvelope::replay_with_expected_target(
            RequestId::from("logs-observer"),
            caller.clone(),
            project.clone(),
            IdempotencyKey::from("logs-key"),
            target.clone(),
            1,
            ExpectedTargetKind::FlowRun,
        ),
        RequestEnvelope::wait_for_result_with_expected_target(
            RequestId::from("wait-observer"),
            caller.clone(),
            project.clone(),
            IdempotencyKey::from("wait-key"),
            target.clone(),
            2,
            ExpectedTargetKind::FlowRun,
        ),
        RequestEnvelope::get_result_with_expected_target(
            RequestId::from("result-observer"),
            caller,
            project,
            IdempotencyKey::from("result-key"),
            target,
            ExpectedTargetKind::FlowRun,
        ),
    ];

    for expected in requests {
        assert_eq!(
            decode_request(&encode(&expected).unwrap()).unwrap(),
            expected
        );
    }
}

#[test]
fn v3_cannot_treat_the_flow_only_target_field_as_ignorable_authority() {
    let mut request = RequestEnvelope::cancel_with_expected_target(
        RequestId::from("legacy-cancel-observer"),
        CallerId::from("cli-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("legacy-cancel-key"),
        RequestId::from("flow-run-1"),
        ExpectedTargetKind::FlowRun,
    );
    request.protocol_version = 3;
    let bytes = encode(&request).unwrap();
    let correlatable = decode_request_envelope(&bytes).unwrap();
    assert_eq!(correlatable.request_id, request.request_id);
    assert_eq!(correlatable.payload, request.payload);
    assert!(matches!(
        decode_request(&bytes),
        Err(CodecError::UnsupportedProtocolVersion {
            actual: 3,
            supported: 5
        })
    ));
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
fn flow_transition_event_round_trips_through_named_messagepack() {
    let (transition, _) = flow_artifacts();
    assert!(matches!(
        transition.semantic_events(),
        [
            pam_flow::FlowSemanticEvent::EvidenceFound { .. },
            pam_flow::FlowSemanticEvent::VerificationPassed { .. },
        ]
    ));
    let expected = ServerMessage::Event(EventEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: RequestId::from("flow-observer-1"),
        project_id: ProjectId::from("project-1"),
        sequence: 1,
        event: Event::FlowTransition(transition),
    });

    assert_eq!(
        decode_server_message(&encode(&expected).unwrap()).unwrap(),
        expected
    );
}

#[test]
fn flow_terminal_result_round_trips_through_named_messagepack() {
    let (_, result) = flow_artifacts();
    assert!(result.report().solved().satisfied());
    assert!(result.report().verified().satisfied());
    assert_eq!(
        result.report().verified().evidence()[0].as_str(),
        "evidence:protocol"
    );
    let expected = ServerMessage::Result(ResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: RequestId::from("flow-observer-1"),
        project_id: ProjectId::from("project-1"),
        body: ResultBody::Success {
            truth: OperationTruth::Verified,
            payload: ResultPayload::FlowRun(result),
        },
    });

    assert_eq!(
        decode_server_message(&encode(&expected).unwrap()).unwrap(),
        expected
    );
}

#[test]
fn durable_v4_server_results_are_decodable_before_current_reenveloping() {
    let (_, result) = flow_artifacts();
    let expected = ServerMessage::Result(ResultEnvelope {
        protocol_version: 4,
        request_id: RequestId::from("legacy-flow-observer"),
        project_id: ProjectId::from("project-1"),
        body: ResultBody::Success {
            truth: OperationTruth::Verified,
            payload: ResultPayload::FlowRun(result),
        },
    });
    let bytes = encode(&expected).unwrap();

    assert!(matches!(
        decode_server_message(&bytes),
        Err(CodecError::UnsupportedProtocolVersion {
            actual: 4,
            supported: 5,
        })
    ));
    assert_eq!(decode_server_message_envelope(&bytes).unwrap(), expected);
}

#[test]
fn maximum_valid_flow_terminal_result_fits_one_frame_with_margin() {
    let expected = ServerMessage::Result(ResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: RequestId::from("r".repeat(MAX_RUN_ID_BYTES)),
        project_id: ProjectId::from("project-1"),
        body: ResultBody::Success {
            truth: OperationTruth::Verified,
            payload: ResultPayload::FlowRun(maximum_flow_result()),
        },
    });

    let bytes = encode(&expected).unwrap();
    let remaining = MAX_FRAME_SIZE - bytes.len();
    assert!(
        remaining >= FLOW_RESULT_FRAME_MARGIN,
        "maximum flow result encoded to {} bytes, leaving only {remaining} bytes",
        bytes.len()
    );
    assert_eq!(decode_server_message(&bytes).unwrap(), expected);
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
    ModelGeneration(UnboundedModelGenerationResult),
}

#[derive(Serialize)]
struct UnboundedModelGenerationResult {
    model: String,
    text: String,
    finish_reason: ModelFinishReason,
    usage: ModelUsage,
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
fn oversized_model_generation_is_rejected_by_the_canonical_decoder() {
    let message = UnboundedServerMessage::Result(UnboundedResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: RequestId::from("model-observer-1"),
        project_id: ProjectId::from("project-1"),
        body: UnboundedResultBody::Success {
            truth: OperationTruth::Observed,
            payload: UnboundedResultPayload::ModelGeneration(UnboundedModelGenerationResult {
                model: "vendor/model".to_owned(),
                text: "x".repeat(MAX_MODEL_OUTPUT_BYTES + 1),
                finish_reason: ModelFinishReason::Stop,
                usage: ModelUsage {
                    input_tokens: 1,
                    sampled_output_tokens: 1,
                    emitted_output_tokens: 1,
                },
            }),
        },
    });

    assert!(matches!(
        decode_server_message(&encode(&message).unwrap()),
        Err(CodecError::Decode(_))
    ));
}

#[test]
fn bounded_model_generation_still_round_trips_after_decode_validation() {
    let expected = ServerMessage::Result(ResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: RequestId::from("model-observer-1"),
        project_id: ProjectId::from("project-1"),
        body: ResultBody::Success {
            truth: OperationTruth::Observed,
            payload: ResultPayload::ModelGeneration(
                ModelGenerationResult::new(
                    "vendor/model",
                    "answer",
                    ModelFinishReason::Stop,
                    ModelUsage {
                        input_tokens: 2,
                        sampled_output_tokens: 1,
                        emitted_output_tokens: 1,
                    },
                )
                .unwrap(),
            ),
        },
    });

    assert_eq!(
        decode_server_message(&encode(&expected).unwrap()).unwrap(),
        expected
    );
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
fn older_version_failures_are_decodable_by_the_current_protocol() {
    let expected = ServerMessage::Result(ResultEnvelope {
        protocol_version: 2,
        request_id: RequestId::from("request-1"),
        project_id: ProjectId::from("project-1"),
        body: ResultBody::Failure(Failure {
            code: FailureCode::UnsupportedProtocolVersion,
            message: format!("supported protocol version is {PROTOCOL_VERSION}"),
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

fn status_request_for_version(protocol_version: u16) -> RequestEnvelope {
    let mut request = status_request();
    request.protocol_version = protocol_version;
    request
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut hex, byte| {
            write!(hex, "{byte:02x}").unwrap();
            hex
        })
}

fn decode_hex(hex: &str) -> Vec<u8> {
    hex.trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).unwrap()
        })
        .collect()
}

#[test]
fn legacy_status_request_matches_the_exact_v2_golden_fixture() {
    let bytes = encode(&status_request_for_version(2)).unwrap();

    assert_eq!(
        encode_hex(&bytes),
        include_str!("../fixtures/status_request_v2.msgpack.hex").trim()
    );
}

#[test]
fn legacy_status_request_matches_the_exact_v3_golden_fixture() {
    let bytes = encode(&status_request_for_version(3)).unwrap();

    assert_eq!(
        encode_hex(&bytes),
        include_str!("../fixtures/status_request_v3.msgpack.hex").trim()
    );
}

#[test]
fn legacy_status_request_matches_the_exact_v4_golden_fixture() {
    let bytes = encode(&status_request_for_version(4)).unwrap();

    assert_eq!(
        encode_hex(&bytes),
        include_str!("../fixtures/status_request_v4.msgpack.hex").trim()
    );
}

#[test]
fn status_request_matches_the_current_v5_golden_fixture() {
    assert_eq!(PROTOCOL_VERSION, 5);
    let bytes = encode(&status_request()).unwrap();

    assert_eq!(
        encode_hex(&bytes),
        include_str!("../fixtures/status_request_v5.msgpack.hex").trim()
    );
}

#[test]
fn v2_v3_and_v4_requests_are_correlatable_but_rejected_by_the_current_decoder() {
    for (actual, fixture) in [
        (2, include_str!("../fixtures/status_request_v2.msgpack.hex")),
        (3, include_str!("../fixtures/status_request_v3.msgpack.hex")),
        (4, include_str!("../fixtures/status_request_v4.msgpack.hex")),
    ] {
        let bytes = decode_hex(fixture);
        let envelope = decode_request_envelope(&bytes).unwrap();

        assert_eq!(envelope.protocol_version, actual);
        assert_eq!(envelope.request_id.as_str(), "request-1");
        assert_eq!(envelope.project_id.as_str(), "project-1");
        let failure = envelope.unsupported_version_failure().unwrap();
        assert_eq!(failure.request_id, envelope.request_id);
        assert_eq!(failure.project_id, envelope.project_id);
        assert!(matches!(
            decode_request(&bytes),
            Err(CodecError::UnsupportedProtocolVersion {
                actual: rejected,
                supported: 5
            }) if rejected == actual
        ));
    }
}
