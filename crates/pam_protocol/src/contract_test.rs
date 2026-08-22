use pam_core::{
    ApprovalId, CallerCredential, CallerId, ContentDigest, EvidenceHandle, IdempotencyKey,
    MAX_CALLER_CREDENTIAL_LENGTH, ProjectId, RequestId,
};
use pam_flow::{MAX_FLOW_DOCUMENT_BYTES, MAX_RUN_ID_BYTES};

use super::{
    ApprovalDecision, ApprovalDecisionDisposition, ApprovalDecisionResult, BriefItem,
    BriefProvenance, BriefResult, CallerListResult, CallerSummary, CancellationDisposition,
    CancellationResult, Capability, ConfigurationPresence, DaemonLifecycleResult, Event,
    EventEnvelope, EvidenceChunk, EvidenceMetadata, EvidenceRedaction, EvidenceRetention,
    ExpectedTargetKind, FailureCode, MAX_EVIDENCE_CHUNK_SIZE, MAX_FLOW_PROJECT_ROOT_BYTES,
    MAX_FRAME_SIZE, MAX_MODEL_MESSAGE_BYTES, MAX_MODEL_OUTPUT_BYTES, MAX_MODEL_OUTPUT_TOKENS,
    MAX_PROJECT_CURRENT_QUEUED, MAX_PROJECT_OPERATION_KIND_BYTES, ModelFinishReason,
    ModelGenerationResult, ModelMessage, ModelRole, ModelUsage, NetworkDiagnosticsResult,
    OperationTruth, PROTOCOL_VERSION, PacState, ProjectCurrentResult, ProjectRequestState,
    ProjectRequestSummary, ProtocolContractError, ReplayResult, RequestEnvelope, RequestPayload,
    ResultBody, ResultEnvelope, ResultPayload, SourceAvailability, StatusResult,
};

const PROJECT_ROOT: &str = "/canonical/project";

const FLOW_DEFINITION: &str = r#"
schema_version = 1
id = "protocol-flow"
name = "Protocol flow"
description = "Debug must not reveal this flow description."
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
action = { type = "command", program = "git", args = ["status"], working_directory = "." }
"#;

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
fn daemon_stop_is_an_authenticated_lifecycle_operation_without_process_identity() {
    let request = RequestEnvelope::stop(
        RequestId::from("stop-1"),
        CallerId::from("control-center-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("stop-key-1"),
    )
    .authenticated(CallerCredential::new("stop-credential"));

    assert!(request.authentication.is_some());
    assert_eq!(request.capability, Capability::DaemonStop);
    assert_eq!(request.capability.policy_name(), "daemon.stop");
    assert_eq!(request.payload, RequestPayload::Stop);

    let result = ResultPayload::DaemonLifecycle(DaemonLifecycleResult { stopping: true });
    let encoded = rmp_serde::to_vec_named(&result).unwrap();
    assert!(matches!(
        result,
        ResultPayload::DaemonLifecycle(DaemonLifecycleResult { stopping: true })
    ));
    assert!(!String::from_utf8_lossy(&encoded).contains("pid"));
}

#[test]
fn project_current_is_authenticated_policy_gated_and_bound_by_the_envelope() {
    let request = RequestEnvelope::project_current(
        RequestId::from("current-1"),
        CallerId::from("control-center-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("current-key-1"),
    )
    .authenticated(CallerCredential::new("current-credential"));

    assert!(request.authentication.is_some());
    assert_eq!(request.caller_id.as_str(), "control-center-1");
    assert_eq!(request.project_id.as_str(), "project-1");
    assert_eq!(request.capability, Capability::ProjectCurrent);
    assert_eq!(request.capability.policy_name(), "project.current");
    assert_eq!(request.payload, RequestPayload::ProjectCurrent);
}

#[test]
fn daemon_activity_is_an_authenticated_bounded_read_and_policy_named() {
    let request = RequestEnvelope::daemon_activity(
        RequestId::from("activity-1"),
        CallerId::from("control-center-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("activity-key-1"),
        25,
    )
    .authenticated(CallerCredential::new("activity-credential"));

    assert!(request.authentication.is_some());
    assert_eq!(request.capability, Capability::DaemonActivity);
    assert_eq!(request.capability.policy_name(), "daemon.activity");
    assert_eq!(
        request.payload,
        RequestPayload::DaemonActivity { limit: 25 }
    );
}

#[test]
fn caller_list_is_authenticated_policy_named_and_free_of_credential_fields() {
    let request = RequestEnvelope::caller_list(
        RequestId::from("callers-1"),
        CallerId::from("control-center-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("callers-key-1"),
    )
    .authenticated(CallerCredential::new("callers-credential"));

    assert!(request.authentication.is_some());
    assert_eq!(request.capability, Capability::CallerList);
    assert_eq!(request.capability.policy_name(), "caller.list");
    assert_eq!(request.payload, RequestPayload::CallerList);

    let result = ResultPayload::CallerList(CallerListResult {
        callers: vec![CallerSummary {
            caller_id: CallerId::from("caller-1"),
            registered_at_ms: 1,
            revoked_at_ms: None,
        }],
    });
    let encoded = rmp_serde::to_vec_named(&result).unwrap();
    let rendered = String::from_utf8_lossy(&encoded).into_owned();
    assert!(!rendered.contains("credential"));
    assert!(!rendered.contains("digest"));
}

#[test]
fn approval_decision_is_authenticated_and_contains_no_receipt_or_secret_field() {
    let request = RequestEnvelope::approval_decide(
        RequestId::from("approval-decision-1"),
        CallerId::from("control-center-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("approval-decision-key-1"),
        ApprovalId::from("approval-1"),
        ApprovalDecision::Approve,
    )
    .authenticated(CallerCredential::new("decision-credential"));

    assert!(request.authentication.is_some());
    assert!(request.approval_id.is_none());
    assert_eq!(request.caller_id.as_str(), "control-center-1");
    assert_eq!(request.project_id.as_str(), "project-1");
    assert_eq!(request.capability, Capability::ApprovalDecide);
    assert_eq!(request.capability.policy_name(), "approval.decide");
    assert_eq!(
        request.payload,
        RequestPayload::ApprovalDecide {
            approval_id: ApprovalId::from("approval-1"),
            decision: ApprovalDecision::Approve,
        }
    );

    let payload = rmp_serde::to_vec_named(&request.payload).unwrap();
    let field_names = String::from_utf8_lossy(&payload);
    assert!(!field_names.contains("credential"));
    assert!(!field_names.contains("secret"));
    assert!(!field_names.contains("token"));

    let result = ResultPayload::ApprovalDecision(ApprovalDecisionResult {
        approval_id: ApprovalId::from("approval-1"),
        disposition: ApprovalDecisionDisposition::Approved,
    });
    assert!(matches!(result, ResultPayload::ApprovalDecision(_)));
}

fn project_request_summary(operation_kind: impl Into<String>) -> ProjectRequestSummary {
    ProjectRequestSummary::new(
        RequestId::from("work-1"),
        operation_kind,
        ProjectRequestState::Queued,
        7,
        100,
        None,
    )
    .unwrap()
}

#[test]
fn project_current_result_bounds_queue_and_operation_kind_without_operation_payloads() {
    let maximum_kind = "k".repeat(MAX_PROJECT_OPERATION_KIND_BYTES);
    let maximum = project_request_summary(maximum_kind);
    assert_eq!(
        maximum.operation_kind().len(),
        MAX_PROJECT_OPERATION_KIND_BYTES
    );
    assert_eq!(maximum.completed_at_ms, None);

    assert_eq!(
        ProjectRequestSummary::new(
            RequestId::from("work-2"),
            "k".repeat(MAX_PROJECT_OPERATION_KIND_BYTES + 1),
            ProjectRequestState::Succeeded,
            8,
            101,
            Some(102),
        )
        .unwrap_err(),
        ProtocolContractError::InvalidProjectOperationKind
    );

    let queued = (0..MAX_PROJECT_CURRENT_QUEUED)
        .map(|_| project_request_summary("flow_run"))
        .collect::<Vec<_>>();
    assert!(ProjectCurrentResult::new(queued.clone(), None, None, false).is_ok());
    let error = ProjectCurrentResult::new(
        queued
            .into_iter()
            .chain(std::iter::once(project_request_summary("model.infer")))
            .collect(),
        None,
        None,
        true,
    )
    .unwrap_err();
    assert_eq!(
        error,
        ProtocolContractError::ProjectCurrentQueueTooLarge {
            actual: MAX_PROJECT_CURRENT_QUEUED + 1,
            maximum: MAX_PROJECT_CURRENT_QUEUED,
        }
    );

    let encoded = rmp_serde::to_vec_named(&maximum).unwrap();
    let fields = String::from_utf8_lossy(&encoded);
    assert!(!fields.contains("operation_blob"));
    assert!(!fields.contains("operation_payload"));
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
fn flow_run_constructor_is_bounded_authenticated_and_policy_named() {
    let request = RequestEnvelope::flow_run(
        RequestId::from("flow-observer-1"),
        CallerId::from("cli-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("flow-1"),
        FLOW_DEFINITION,
        PROJECT_ROOT,
    )
    .unwrap()
    .authenticated(CallerCredential::new("flow-credential"));

    assert!(request.authentication.is_some());
    assert_eq!(request.capability, Capability::FlowRun);
    assert_eq!(request.capability.policy_name(), "flow.run");
    let RequestPayload::FlowRun {
        definition,
        project_root,
    } = &request.payload
    else {
        panic!("expected flow-run payload")
    };
    assert_eq!(definition.as_str(), FLOW_DEFINITION);
    assert_eq!(project_root.as_str(), PROJECT_ROOT);
    assert!(request.validate_flow_request().is_ok());
    assert!(!format!("{request:?}").contains("Debug must not reveal"));
    assert!(!format!("{request:?}").contains(PROJECT_ROOT));
}

#[test]
fn flow_run_constructor_rejects_malformed_and_oversized_definitions() {
    let request = |definition| {
        RequestEnvelope::flow_run(
            RequestId::from("flow-observer-1"),
            CallerId::from("cli-1"),
            ProjectId::from("project-1"),
            IdempotencyKey::from("flow-1"),
            definition,
            PROJECT_ROOT,
        )
    };

    assert!(matches!(
        request("not valid TOML =".to_owned()),
        Err(ProtocolContractError::InvalidFlowDefinition)
    ));
    assert!(matches!(
        request("x".repeat(MAX_FLOW_DOCUMENT_BYTES + 1)),
        Err(ProtocolContractError::FlowDefinitionTooLarge { .. })
    ));
}

#[test]
fn flow_run_constructor_rejects_request_ids_outside_the_run_id_contract() {
    for invalid in [
        "run id".to_owned(),
        "rún".to_owned(),
        "r".repeat(MAX_RUN_ID_BYTES + 1),
    ] {
        let error = RequestEnvelope::flow_run(
            RequestId::from(invalid.clone()),
            CallerId::from("cli-1"),
            ProjectId::from("project-1"),
            IdempotencyKey::from("flow-1"),
            FLOW_DEFINITION,
            PROJECT_ROOT,
        )
        .unwrap_err();

        assert_eq!(error, ProtocolContractError::InvalidFlowRunId);
        assert!(!format!("{error:?}").contains(&invalid));
        assert!(!error.to_string().contains(&invalid));
    }
}

#[test]
fn flow_run_constructor_rejects_a_valid_document_that_cannot_fit_one_frame() {
    let comment_bytes = MAX_FRAME_SIZE - FLOW_DEFINITION.len() - 2;
    let definition = format!("{FLOW_DEFINITION}#{}", "x".repeat(comment_bytes));
    assert_eq!(definition.len(), MAX_FRAME_SIZE - 1);

    assert!(matches!(
        RequestEnvelope::flow_run(
            RequestId::from("flow-observer-1"),
            CallerId::from("cli-1"),
            ProjectId::from("project-1"),
            IdempotencyKey::from("flow-1"),
            definition,
            PROJECT_ROOT,
        ),
        Err(ProtocolContractError::FlowRequestTooLarge { .. })
    ));
}

#[test]
fn flow_run_constructor_reserves_authenticated_approval_frame_space() {
    let target_bytes = MAX_FRAME_SIZE - 512;
    let definition = format!(
        "{FLOW_DEFINITION}#{}",
        "x".repeat(target_bytes - FLOW_DEFINITION.len() - 1)
    );
    assert_eq!(definition.len(), target_bytes);
    let bare = RequestEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: RequestId::from("flow-observer-1"),
        caller_id: CallerId::from("cli-1"),
        authentication: None,
        approval_id: None,
        project_id: ProjectId::from("project-1"),
        capability: Capability::FlowRun,
        idempotency_key: IdempotencyKey::from("flow-1"),
        deadline_unix_ms: None,
        payload: RequestPayload::FlowRun {
            definition: super::FlowDefinitionDocument::new(definition.clone()).unwrap(),
            project_root: super::FlowProjectRoot::new(PROJECT_ROOT).unwrap(),
        },
    };
    let bare_bytes = rmp_serde::to_vec_named(&bare).unwrap();
    assert!(bare_bytes.len() <= MAX_FRAME_SIZE);
    let attached = bare
        .authenticated(CallerCredential::new(
            "x".repeat(MAX_CALLER_CREDENTIAL_LENGTH),
        ))
        .with_approval(ApprovalId::from("a".repeat(256)));
    assert!(rmp_serde::to_vec_named(&attached).unwrap().len() > MAX_FRAME_SIZE);

    assert!(matches!(
        RequestEnvelope::flow_run(
            RequestId::from("flow-observer-1"),
            CallerId::from("cli-1"),
            ProjectId::from("project-1"),
            IdempotencyKey::from("flow-1"),
            definition,
            PROJECT_ROOT,
        ),
        Err(ProtocolContractError::FlowRequestTooLarge { .. })
    ));
}

#[test]
fn flow_run_constructor_rejects_noncanonical_or_unbounded_project_roots_without_disclosure() {
    let invalid_roots = [
        "relative/project".to_owned(),
        "/canonical/../project".to_owned(),
        "/canonical//project".to_owned(),
        "/canonical/project/".to_owned(),
    ];
    for invalid in invalid_roots {
        let error = RequestEnvelope::flow_run(
            RequestId::from("flow-observer-1"),
            CallerId::from("cli-1"),
            ProjectId::from("project-1"),
            IdempotencyKey::from("flow-1"),
            FLOW_DEFINITION,
            invalid.clone(),
        )
        .unwrap_err();

        assert_eq!(error, ProtocolContractError::InvalidFlowProjectRoot);
        assert!(!format!("{error:?}").contains(&invalid));
        assert!(!error.to_string().contains(&invalid));
    }

    let oversized = format!("/{}", "x".repeat(MAX_FLOW_PROJECT_ROOT_BYTES));
    let error = RequestEnvelope::flow_run(
        RequestId::from("flow-observer-1"),
        CallerId::from("cli-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("flow-1"),
        FLOW_DEFINITION,
        oversized.clone(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ProtocolContractError::FlowProjectRootTooLarge { .. }
    ));
    assert!(!format!("{error:?}").contains(&oversized));
    assert!(!error.to_string().contains(&oversized));
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
            expected_target_kind: None,
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
            expected_target_kind: None,
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
            expected_target_kind: None,
        }
    );
    assert_eq!(result.capability, Capability::GetResult);
    assert_eq!(result.request_id.as_str(), "result-observer-1");
    assert_eq!(
        result.payload,
        RequestPayload::GetResult {
            target_request_id: RequestId::from("target-1"),
            expected_target_kind: None,
        }
    );
}

#[test]
fn typed_target_constructors_always_bind_flow_run() {
    let cancel = RequestEnvelope::cancel_with_expected_target(
        RequestId::from("cancel-observer"),
        CallerId::from("cli"),
        ProjectId::from("project"),
        IdempotencyKey::from("cancel-key"),
        RequestId::from("target"),
        ExpectedTargetKind::FlowRun,
    );
    let replay = RequestEnvelope::replay_with_expected_target(
        RequestId::from("logs-observer"),
        CallerId::from("cli"),
        ProjectId::from("project"),
        IdempotencyKey::from("logs-key"),
        RequestId::from("target"),
        3,
        ExpectedTargetKind::FlowRun,
    );
    let wait = RequestEnvelope::wait_for_result_with_expected_target(
        RequestId::from("wait-observer"),
        CallerId::from("cli"),
        ProjectId::from("project"),
        IdempotencyKey::from("wait-key"),
        RequestId::from("target"),
        4,
        ExpectedTargetKind::FlowRun,
    );
    let result = RequestEnvelope::get_result_with_expected_target(
        RequestId::from("result-observer"),
        CallerId::from("cli"),
        ProjectId::from("project"),
        IdempotencyKey::from("result-key"),
        RequestId::from("target"),
        ExpectedTargetKind::FlowRun,
    );

    for payload in [cancel.payload, replay.payload, wait.payload, result.payload] {
        let (RequestPayload::Cancel {
            expected_target_kind: expected,
            ..
        }
        | RequestPayload::Replay {
            expected_target_kind: expected,
            ..
        }
        | RequestPayload::WaitForResult {
            expected_target_kind: expected,
            ..
        }
        | RequestPayload::GetResult {
            expected_target_kind: expected,
            ..
        }) = payload
        else {
            panic!("expected a target-scoped payload")
        };
        assert_eq!(expected, Some(ExpectedTargetKind::FlowRun));
    }
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
