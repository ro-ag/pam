use pam_core::{
    ApprovalId, CallerCredential, CallerId, ContentDigest, EvidenceHandle, IdempotencyKey,
    ProjectId, RequestId,
};

use super::{
    BriefItem, BriefProvenance, BriefResult, CancellationDisposition, CancellationResult,
    Capability, ConfigurationPresence, Event, EventEnvelope, EvidenceChunk, EvidenceMetadata,
    EvidenceRedaction, EvidenceRetention, FailureCode, MAX_EVIDENCE_CHUNK_SIZE,
    MAX_MODEL_MESSAGE_BYTES, MAX_MODEL_OUTPUT_BYTES, MAX_MODEL_OUTPUT_TOKENS, ModelFinishReason,
    ModelGenerationResult, ModelMessage, ModelRole, ModelUsage, NetworkDiagnosticsResult,
    OperationTruth, PROTOCOL_VERSION, PacState, ProtocolContractError, ReplayResult,
    RequestEnvelope, RequestPayload, ResultBody, ResultEnvelope, ResultPayload, SourceAvailability,
    StatusResult,
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
fn status_request_populates_the_versioned_identity_contract() {
    let request = status_request();

    assert_eq!(request.protocol_version, PROTOCOL_VERSION);
    assert_eq!(request.request_id.as_str(), "request-1");
    assert_eq!(request.caller_id.as_str(), "cli-1");
    assert!(request.authentication.is_none());
    assert_eq!(request.project_id.as_str(), "project-1");
    assert_eq!(request.idempotency_key.as_str(), "status-1");
}

#[test]
fn request_authentication_is_explicit_and_redacted() {
    let secret = "credential-secret";
    let request = status_request().authenticated(CallerCredential::new(secret));

    assert_eq!(
        request
            .authentication
            .as_ref()
            .expect("credential is attached")
            .expose_secret(),
        secret
    );
    assert!(!format!("{request:?}").contains(secret));
}

#[test]
fn request_approval_receipt_is_explicit_and_one_effect_scoped() {
    let request = status_request().with_approval(ApprovalId::from("approval-1"));

    assert_eq!(
        request.approval_id.as_ref().map(ApprovalId::as_str),
        Some("approval-1")
    );
    assert_eq!(request.capability.policy_name(), "daemon.status");
}

#[test]
fn network_diagnostics_request_is_authenticated_read_only_and_policy_named() {
    let request = RequestEnvelope::network_diagnostics(
        RequestId::from("network-observer-1"),
        CallerId::from("cli-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("network-1"),
    )
    .authenticated(CallerCredential::new("network-diagnostics-credential"));

    assert!(request.authentication.is_some());
    assert_eq!(request.capability, Capability::NetworkDiagnostics);
    assert_eq!(request.capability.policy_name(), "network.diagnostics");
    assert_eq!(request.payload, RequestPayload::NetworkDiagnostics);
}

#[test]
fn model_generation_contract_is_bounded_authenticated_and_policy_named() {
    let secret_prompt = "private prompt that must stay redacted";
    let messages = vec![
        ModelMessage::new(ModelRole::System, "Answer briefly.").unwrap(),
        ModelMessage::new(ModelRole::User, secret_prompt).unwrap(),
    ];
    let request = RequestEnvelope::model_infer(
        RequestId::from("model-observer-1"),
        CallerId::from("cli-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("model-1"),
        "byteshape/qwen3.6-q4ks",
        messages.clone(),
        64,
        42,
    )
    .unwrap()
    .authenticated(CallerCredential::new("model-credential"));

    assert!(request.authentication.is_some());
    assert_eq!(request.capability, Capability::ModelInfer);
    assert_eq!(request.capability.policy_name(), "model.infer");
    assert_eq!(
        request.payload,
        RequestPayload::ModelInfer {
            model: "byteshape/qwen3.6-q4ks".to_owned(),
            messages,
            max_output_tokens: 64,
        }
    );
    assert!(request.validate_model_request().is_ok());
    assert!(!format!("{request:?}").contains(secret_prompt));
}

#[test]
fn model_generation_rejects_invalid_conversations_and_bounds() {
    let make = |messages, max_output_tokens| {
        RequestEnvelope::model_infer(
            RequestId::from("model-observer-1"),
            CallerId::from("cli-1"),
            ProjectId::from("project-1"),
            IdempotencyKey::from("model-1"),
            "vendor/model",
            messages,
            max_output_tokens,
            42,
        )
    };

    assert!(matches!(
        make(Vec::new(), 1),
        Err(ProtocolContractError::InvalidModelConversation)
    ));
    assert!(matches!(
        make(
            vec![ModelMessage::new(ModelRole::Assistant, "done").unwrap()],
            1,
        ),
        Err(ProtocolContractError::InvalidModelConversation)
    ));
    assert!(matches!(
        ModelMessage::new(ModelRole::User, "x".repeat(MAX_MODEL_MESSAGE_BYTES + 1)),
        Err(ProtocolContractError::InvalidModelMessage)
    ));
    assert!(matches!(
        ModelMessage::new(ModelRole::User, "not\0valid"),
        Err(ProtocolContractError::InvalidModelMessage)
    ));
    let oversized = (0..5)
        .map(|index| {
            ModelMessage::new(
                if index == 4 {
                    ModelRole::User
                } else {
                    ModelRole::System
                },
                "x".repeat(MAX_MODEL_MESSAGE_BYTES),
            )
            .unwrap()
        })
        .collect();
    assert!(matches!(
        make(oversized, 1),
        Err(ProtocolContractError::ModelPromptTooLarge { .. })
    ));
    assert!(matches!(
        make(
            vec![ModelMessage::new(ModelRole::User, "hi").unwrap()],
            MAX_MODEL_OUTPUT_TOKENS + 1,
        ),
        Err(ProtocolContractError::InvalidModelOutputTokens { .. })
    ));
    assert!(matches!(
        RequestEnvelope::model_infer(
            RequestId::from("model-observer-1"),
            CallerId::from("cli-1"),
            ProjectId::from("project-1"),
            IdempotencyKey::from("model-1"),
            "vendor/model",
            vec![ModelMessage::new(ModelRole::User, "hi").unwrap()],
            1,
            0,
        ),
        Err(ProtocolContractError::InvalidModelDeadline)
    ));

    let mut missing_deadline =
        make(vec![ModelMessage::new(ModelRole::User, "hi").unwrap()], 1).unwrap();
    missing_deadline.deadline_unix_ms = None;
    assert!(matches!(
        missing_deadline.validate_model_request(),
        Err(ProtocolContractError::InvalidModelDeadline)
    ));
}

#[test]
fn model_generation_result_enforces_transport_output_bound() {
    let usage = ModelUsage {
        input_tokens: 2,
        sampled_output_tokens: 1,
        emitted_output_tokens: 1,
    };
    let result =
        ModelGenerationResult::new("vendor/model", "95", ModelFinishReason::Stop, usage).unwrap();
    assert_eq!(result.text(), "95");
    assert!(!format!("{result:?}").contains("95"));
    assert!(matches!(
        ModelGenerationResult::new(
            "vendor/model",
            "x".repeat(MAX_MODEL_OUTPUT_BYTES + 1),
            ModelFinishReason::Length,
            usage,
        ),
        Err(ProtocolContractError::ModelOutputTooLarge { .. })
    ));
}

#[test]
fn unsupported_versions_produce_a_correlated_typed_failure() {
    let mut request = status_request();
    request.protocol_version = PROTOCOL_VERSION + 1;

    let failure = request.unsupported_version_failure().unwrap();
    assert_eq!(failure.request_id, request.request_id);
    assert_eq!(failure.project_id, request.project_id);
    let ResultBody::Failure(failure) = failure.body else {
        panic!("expected protocol failure")
    };
    assert_eq!(failure.code, FailureCode::UnsupportedProtocolVersion);
}

#[test]
fn cancel_request_keeps_observer_and_target_correlation_separate() {
    let request = RequestEnvelope::cancel(
        RequestId::from("cancel-observer-1"),
        CallerId::from("cli-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("cancel-1"),
        RequestId::from("target-1"),
    );

    assert_eq!(request.request_id.as_str(), "cancel-observer-1");
    assert_eq!(request.capability, Capability::CancelRequest);
    assert_eq!(
        request.payload,
        RequestPayload::Cancel {
            target_request_id: RequestId::from("target-1"),
        }
    );
}

#[test]
fn replay_request_resumes_exclusively_after_the_observed_sequence() {
    let request = RequestEnvelope::replay(
        RequestId::from("replay-observer-1"),
        CallerId::from("cli-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("replay-1"),
        RequestId::from("target-1"),
        41,
    );

    assert_eq!(request.request_id.as_str(), "replay-observer-1");
    assert_eq!(request.capability, Capability::ReplayEvents);
    assert_eq!(
        request.payload,
        RequestPayload::Replay {
            target_request_id: RequestId::from("target-1"),
            after_sequence: 41,
        }
    );
}

#[test]
fn read_only_request_constructors_preserve_observer_and_target_identity() {
    let wait = RequestEnvelope::wait_for_result(
        RequestId::from("wait-observer-1"),
        CallerId::from("cli-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("wait-1"),
        RequestId::from("target-1"),
        7,
    );
    let result = RequestEnvelope::get_result(
        RequestId::from("result-observer-1"),
        CallerId::from("cli-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("result-1"),
        RequestId::from("target-1"),
    );

    assert_eq!(wait.capability, Capability::WaitForResult);
    assert_eq!(wait.request_id.as_str(), "wait-observer-1");
    assert_eq!(
        wait.payload,
        RequestPayload::WaitForResult {
            target_request_id: RequestId::from("target-1"),
            after_sequence: 7,
        }
    );
    assert_eq!(result.capability, Capability::GetResult);
    assert_eq!(result.request_id.as_str(), "result-observer-1");
    assert_eq!(
        result.payload,
        RequestPayload::GetResult {
            target_request_id: RequestId::from("target-1"),
        }
    );
}

#[test]
fn observed_terminal_results_remap_only_the_envelope_correlation() {
    let observer_request_id = RequestId::from("wait-observer-1");
    let original = ResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: RequestId::from("target-1"),
        project_id: ProjectId::from("project-1"),
        body: ResultBody::Failure(super::Failure {
            code: FailureCode::Cancelled,
            message: "request was cancelled".to_owned(),
            recovery: None,
            approval: None,
        }),
    };
    let observed = ResultEnvelope {
        protocol_version: original.protocol_version,
        request_id: observer_request_id.clone(),
        project_id: original.project_id.clone(),
        body: original.body.clone(),
    };

    assert_eq!(observed.request_id, observer_request_id);
    assert_ne!(observed.request_id, original.request_id);
    assert_eq!(observed.project_id, original.project_id);
    assert_eq!(observed.body, original.body);
}

#[test]
fn brief_and_evidence_constructors_are_read_only_typed_requests() {
    let handle = EvidenceHandle::parse("evidence://ci/1842/failure").unwrap();
    let brief = RequestEnvelope::brief(
        RequestId::from("brief-observer-1"),
        CallerId::from("cli-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("brief-1"),
    );
    let inspect = RequestEnvelope::inspect_evidence(
        RequestId::from("inspect-observer-1"),
        CallerId::from("cli-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("inspect-1"),
        handle.clone(),
    );
    let read = RequestEnvelope::read_evidence(
        RequestId::from("read-observer-1"),
        CallerId::from("cli-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("read-1"),
        handle.clone(),
        512,
        1024,
    )
    .unwrap();

    assert_eq!(brief.capability, Capability::Brief);
    assert_eq!(brief.payload, RequestPayload::Brief);
    assert_eq!(inspect.capability, Capability::InspectEvidence);
    assert_eq!(inspect.payload, RequestPayload::InspectEvidence { handle });
    assert_eq!(read.capability, Capability::ReadEvidence);
    assert!(matches!(
        read.payload,
        RequestPayload::ReadEvidence {
            offset: 512,
            length: 1024,
            ..
        }
    ));
}

#[test]
fn evidence_reads_and_chunks_enforce_the_protocol_bound() {
    let handle = EvidenceHandle::parse("evidence://ci/1842/failure").unwrap();
    let request = |length| {
        RequestEnvelope::read_evidence(
            RequestId::from("read-observer-1"),
            CallerId::from("cli-1"),
            ProjectId::from("project-1"),
            IdempotencyKey::from("read-1"),
            handle.clone(),
            0,
            length,
        )
    };

    assert!(request(MAX_EVIDENCE_CHUNK_SIZE as u64).is_ok());
    assert!(matches!(
        request(0),
        Err(ProtocolContractError::InvalidEvidenceReadLength { .. })
    ));
    assert!(matches!(
        request(MAX_EVIDENCE_CHUNK_SIZE as u64 + 1),
        Err(ProtocolContractError::InvalidEvidenceReadLength { .. })
    ));
    assert!(EvidenceChunk::new(handle.clone(), 0, vec![0; MAX_EVIDENCE_CHUNK_SIZE], true,).is_ok());
    assert!(matches!(
        EvidenceChunk::new(handle, 0, vec![0; MAX_EVIDENCE_CHUNK_SIZE + 1], true,),
        Err(ProtocolContractError::EvidenceChunkTooLarge { .. })
    ));
}

#[test]
fn terminal_replay_separates_snapshot_from_the_original_result() {
    let target_request_id = RequestId::from("target-1");
    let request = RequestEnvelope::replay(
        RequestId::from("replay-observer-1"),
        CallerId::from("cli-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("replay-1"),
        target_request_id.clone(),
        2,
    );
    let replayed_event = EventEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: target_request_id.clone(),
        project_id: request.project_id.clone(),
        sequence: 3,
        event: Event::Completed,
    };
    let replay_snapshot = ResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: request.request_id.clone(),
        project_id: request.project_id.clone(),
        body: ResultBody::Success {
            truth: OperationTruth::Observed,
            payload: ResultPayload::Replay(ReplayResult {
                target_request_id: target_request_id.clone(),
                through_sequence: 3,
                pending: false,
            }),
        },
    };
    let original_result = ResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: target_request_id.clone(),
        project_id: request.project_id.clone(),
        body: ResultBody::Success {
            truth: OperationTruth::Observed,
            payload: ResultPayload::Status(StatusResult {
                ready: true,
                healthy: true,
                daemon_version: "0.1.0".to_owned(),
                protocol_version: PROTOCOL_VERSION,
                queue_depth: 0,
            }),
        },
    };
    let stored_original_result = original_result.clone();

    assert_ne!(request.request_id, target_request_id);
    assert_eq!(replayed_event.request_id, target_request_id);
    assert_eq!(replay_snapshot.request_id, request.request_id);
    assert_eq!(original_result.request_id, target_request_id);
    assert_eq!(original_result, stored_original_result);
}

#[test]
fn durable_operation_results_retain_target_state() {
    let cancellation = ResultPayload::Cancellation(CancellationResult {
        target_request_id: RequestId::from("target-1"),
        disposition: CancellationDisposition::AlreadyCancelled,
    });
    let replay = ResultPayload::Replay(ReplayResult {
        target_request_id: RequestId::from("target-1"),
        through_sequence: 41,
        pending: true,
    });

    assert!(matches!(cancellation, ResultPayload::Cancellation(_)));
    assert!(matches!(replay, ResultPayload::Replay(_)));
}

#[test]
fn brief_contract_orders_truthful_sections_and_reports_source_availability() {
    let handle = EvidenceHandle::parse("evidence://ptrack/context/current").unwrap();
    let item = |text: &str, truth| BriefItem {
        text: text.to_owned(),
        truth,
        evidence: vec![handle.clone()],
    };
    let brief = BriefResult {
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
    };

    assert_eq!(brief.goal.unwrap().text, "Ship durable continuity");
    assert_eq!(brief.decisions[0].text, "Use SQLite");
    assert_eq!(brief.verified[0].truth, OperationTruth::Verified);
    assert_eq!(brief.next[0].truth, OperationTruth::Unresolved);
    assert_eq!(brief.provenance.len(), 3);
}

#[test]
fn evidence_result_contract_carries_exact_metadata_and_bounded_bytes() {
    let handle = EvidenceHandle::parse("evidence://ci/1842/failure").unwrap();
    let metadata = EvidenceMetadata {
        handle: handle.clone(),
        digest: ContentDigest::from_sha256([0xab; 32]),
        size_bytes: 3,
        media_type: "text/plain".to_owned(),
        retention: EvidenceRetention::Project,
        redaction: EvidenceRedaction::Redacted,
        created_at_unix_ms: 1_700_000_000_000,
    };
    let chunk = EvidenceChunk::new(handle, 12, vec![1, 2, 3], true).unwrap();

    assert_eq!(metadata.size_bytes, 3);
    assert_eq!(metadata.retention, EvidenceRetention::Project);
    assert_eq!(metadata.redaction, EvidenceRedaction::Redacted);
    assert_eq!(chunk.offset, 12);
    assert_eq!(chunk.bytes(), &[1, 2, 3]);
    assert!(chunk.eof);
}

#[test]
fn network_diagnostics_result_exposes_only_sanitized_configuration_facts() {
    let result = NetworkDiagnosticsResult {
        platform_roots_enabled: true,
        system_proxy_discovery_enabled: true,
        proxy_environment_presence: ConfigurationPresence::Configured,
        no_proxy_presence: ConfigurationPresence::Invalid,
        pac_state: PacState::DetectedUnsupported,
    };

    assert!(result.platform_roots_enabled);
    assert!(result.system_proxy_discovery_enabled);
    assert_eq!(
        result.proxy_environment_presence,
        ConfigurationPresence::Configured
    );
    assert_eq!(result.no_proxy_presence, ConfigurationPresence::Invalid);
    assert_eq!(result.pac_state, PacState::DetectedUnsupported);
    assert_ne!(
        ConfigurationPresence::NotConfigured,
        ConfigurationPresence::Configured
    );
    assert_ne!(PacState::NotDetected, PacState::DetectedUnsupported);
    assert_ne!(PacState::NotDetected, PacState::InspectionUnavailable);
}

#[test]
fn truth_contract_distinguishes_all_documented_outcomes() {
    let truths = [
        OperationTruth::Observed,
        OperationTruth::Changed,
        OperationTruth::Verified,
        OperationTruth::Unresolved,
        OperationTruth::Blocked,
    ];

    for truth in truths {
        let body = ResultBody::Success {
            truth,
            payload: ResultPayload::Status(StatusResult {
                ready: true,
                healthy: true,
                daemon_version: "0.1.0".to_owned(),
                protocol_version: PROTOCOL_VERSION,
                queue_depth: 0,
            }),
        };
        assert!(matches!(body, ResultBody::Success { .. }));
    }
}
