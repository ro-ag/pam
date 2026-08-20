use pam_core::{
    ApprovalId, CallerCredential, CallerId, EvidenceHandle, IdempotencyKey, ProjectId, RequestId,
};
use pam_protocol::{
    ApprovalChallenge, ConfigurationPresence, FailureCode, NetworkDiagnosticsResult,
    OperationTruth, PacState, RequestEnvelope,
};

use super::{
    access_config::{AccessConfigState, map_diagnostics_for_test},
    current::{CurrentState, EvidencePreview, pending_approval_for_test},
    desktop::{
        AccessConfigDto, CommandFence, CurrentDto, EvidenceHandleDto, FailureKindDto, GenerationId,
        OperationId, ProjectHandle, access_dto_for_test, active_core_for_test,
        bounded_detail_for_test, current_dto_for_test, evidence_dto_for_test,
        failure_kind_for_test, reserve_for_test, switch_authority_for_test,
    },
};

#[test]
fn desktop_detail_is_bounded_on_a_utf8_boundary() {
    let bounded = bounded_detail_for_test("é".repeat(3_000));

    assert!(bounded.len() <= 4 * 1024);
    assert!(bounded.ends_with("..."));
}

#[test]
fn desktop_failure_mapping_blocks_only_policy_failures() {
    for code in [FailureCode::Forbidden, FailureCode::ApprovalRequired] {
        assert_eq!(failure_kind_for_test(&code), FailureKindDto::Blocked);
    }
    for code in [
        FailureCode::Unauthenticated,
        FailureCode::ApprovalDenied,
        FailureCode::ApprovalExpired,
        FailureCode::UnsupportedProtocolVersion,
        FailureCode::InvalidRequest,
        FailureCode::FrameTooLarge,
        FailureCode::NotFound,
        FailureCode::Pending,
        FailureCode::IdempotencyConflict,
        FailureCode::Cancelled,
        FailureCode::LeaseConflict,
        FailureCode::Busy,
        FailureCode::Internal,
    ] {
        assert_eq!(failure_kind_for_test(&code), FailureKindDto::Unavailable);
    }
}

#[tokio::test]
async fn operation_generation_and_project_switches_are_fenced() {
    let project = ProjectHandle::new();
    let generation = GenerationId::new();
    let operation = OperationId::new();
    let core = active_core_for_test(&project, generation.clone());
    let fence = CommandFence::new(project.clone(), generation.clone(), operation.clone());

    reserve_for_test(&core, &fence).await.unwrap();
    assert!(reserve_for_test(&core, &fence).await.is_err());

    let new_generation = GenerationId::new();
    switch_authority_for_test(&core, project.clone(), new_generation.clone()).await;
    let stale_generation = CommandFence::new(project.clone(), generation, OperationId::new());
    assert!(reserve_for_test(&core, &stale_generation).await.is_err());

    let other_project = ProjectHandle::new();
    switch_authority_for_test(&core, other_project, new_generation.clone()).await;
    let stale_project = CommandFence::new(project, new_generation, OperationId::new());
    assert!(reserve_for_test(&core, &stale_project).await.is_err());
}

#[test]
fn approval_dto_exposes_no_credential_envelope_or_project_authority() {
    let request = RequestEnvelope::project_current(
        RequestId::new("request-raw"),
        CallerId::new("caller-raw"),
        ProjectId::new("project-raw-authority"),
        IdempotencyKey::new("idempotency-raw"),
    )
    .authenticated(CallerCredential::new("credential-secret"));
    let pending = pending_approval_for_test(
        request,
        ApprovalChallenge {
            approval_id: ApprovalId::new("approval-raw"),
            expires_at_unix_ms: 42,
        },
    );

    let dto = current_dto_for_test(CurrentState::ApprovalRequired(pending));
    let json = serde_json::to_string(&dto).unwrap();

    assert!(matches!(dto, CurrentDto::ApprovalRequired { .. }));
    assert!(!json.contains("credential-secret"));
    assert!(!json.contains("project-raw-authority"));
    assert!(!json.contains("request-raw"));
    assert!(!json.contains("caller-raw"));
}

#[test]
fn current_access_and_evidence_conversions_remain_bounded_and_truthful() {
    let access = access_dto_for_test(AccessConfigState::Available(map_diagnostics_for_test(
        OperationTruth::Observed,
        &NetworkDiagnosticsResult {
            platform_roots_enabled: true,
            system_proxy_discovery_enabled: false,
            proxy_environment_presence: ConfigurationPresence::Configured,
            no_proxy_presence: ConfigurationPresence::NotConfigured,
            pac_state: PacState::DetectedUnsupported,
        },
    )));
    assert!(matches!(
        access,
        AccessConfigDto::Available {
            platform_roots_enabled: true,
            system_proxy_discovery_enabled: false,
            ..
        }
    ));

    let protocol_handle = EvidenceHandle::parse("evidence://test/result").unwrap();
    let body = "x".repeat(8 * 1024);
    let dto = evidence_dto_for_test(
        EvidenceHandleDto::new(),
        EvidencePreview {
            handle: protocol_handle,
            digest: "sha256:test".to_owned(),
            size_bytes: 8 * 1024,
            media_type: "text/plain".to_owned(),
            body: Some(body),
            truncated: true,
            truth: OperationTruth::Observed,
        },
    );
    assert!(dto.body.as_ref().unwrap().len() <= 4 * 1024);
    assert!(dto.truncated);
    assert_eq!(dto.truth, "observed");
}
