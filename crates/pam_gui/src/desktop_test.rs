use pam_core::{
    ApprovalId, CallerCredential, CallerId, EvidenceHandle, IdempotencyKey, ProjectId, RequestId,
};
use pam_protocol::{
    ApprovalChallenge, ConfigurationPresence, FailureCode, NetworkDiagnosticsResult,
    OperationTruth, PacState, RequestEnvelope,
};
use std::sync::atomic::AtomicUsize;

use super::{
    access_config::{AccessConfigState, map_diagnostics_for_test},
    current::{CurrentState, EvidencePreview, pending_approval_for_test},
    desktop::{
        AccessConfigDto, ApprovalDecisionDispositionDto, CommandFence, CurrentDto,
        EvidenceHandleDto, FailureDto, FailureKindDto, GenerationId, HealthDto, OperationId,
        ProjectHandle, TimelineKindDto, access_dto_for_test, active_core_for_test,
        approval_current_for_test, approval_failure_retains_handle_for_test,
        bounded_detail_for_test, current_dto_for_test, evidence_dto_for_test,
        failure_kind_for_test, gui_registration_current_for_test, post_save_reload_error_for_test,
        registration_contract_for_test, reserve_for_test, switch_authority_for_test,
    },
    flow_editor::FlowEditorError,
};

#[test]
fn timeline_kinds_have_stable_exhaustive_wire_names() {
    let kinds = [
        TimelineKindDto::Request,
        TimelineKindDto::Evidence,
        TimelineKindDto::Change,
        TimelineKindDto::Verification,
        TimelineKindDto::Failure,
    ];

    assert_eq!(
        serde_json::to_value(kinds).unwrap(),
        serde_json::json!(["request", "evidence", "change", "verification", "failure"])
    );
}

#[test]
fn approval_dispositions_have_stable_truthful_wire_names() {
    assert_eq!(
        serde_json::to_value([
            ApprovalDecisionDispositionDto::Approved,
            ApprovalDecisionDispositionDto::Denied,
            ApprovalDecisionDispositionDto::Expired,
        ])
        .unwrap(),
        serde_json::json!(["approved", "denied", "expired"])
    );
}

#[test]
fn gui_registration_recovery_uses_a_stable_typed_current_code() {
    let current = gui_registration_current_for_test("Native credential is unavailable.".to_owned());

    assert_eq!(
        serde_json::to_value(current).unwrap(),
        serde_json::json!({
            "status": "unavailable",
            "failure": {
                "kind": "unavailable",
                "code": "gui_registration_required",
                "detail": "Native credential is unavailable.",
                "recovery": "Use Register GUI caller in PAM."
            }
        })
    );
}

#[test]
fn tagged_desktop_dtos_serialize_variant_fields_in_the_frontend_contract() {
    assert_eq!(
        serde_json::to_value(HealthDto::Healthy {
            daemon_version: "0.1.0".to_owned(),
            queue_depth: 3,
        })
        .unwrap(),
        serde_json::json!({
            "status": "healthy",
            "daemonVersion": "0.1.0",
            "queueDepth": 3
        })
    );

    let available = access_dto_for_test(AccessConfigState::Available(map_diagnostics_for_test(
        OperationTruth::Observed,
        &NetworkDiagnosticsResult {
            platform_roots_enabled: true,
            system_proxy_discovery_enabled: false,
            proxy_environment_presence: ConfigurationPresence::Configured,
            no_proxy_presence: ConfigurationPresence::NotConfigured,
            pac_state: PacState::DetectedUnsupported,
        },
    )));
    assert_eq!(
        serde_json::to_value(available).unwrap(),
        serde_json::json!({
            "status": "available",
            "truth": "observed",
            "platformRootsEnabled": true,
            "systemProxyDiscoveryEnabled": false,
            "proxyEnvironment": "configured",
            "noProxy": "not configured",
            "pac": "detected but unsupported"
        })
    );

    assert_eq!(
        serde_json::to_value(AccessConfigDto::Blocked {
            failure: FailureDto {
                kind: FailureKindDto::Blocked,
                code: Some("forbidden".to_owned()),
                detail: "Blocked by policy.".to_owned(),
                recovery: None,
            },
            approval_id: Some("approval-1".to_owned()),
            expires_at_ms: Some(42),
        })
        .unwrap(),
        serde_json::json!({
            "status": "blocked",
            "failure": {
                "kind": "blocked",
                "code": "forbidden",
                "detail": "Blocked by policy.",
                "recovery": null
            },
            "approvalId": "approval-1",
            "expiresAtMs": 42
        })
    );
}

#[test]
fn post_save_refresh_failure_truthfully_reports_that_publication_succeeded() {
    let error = post_save_reload_error_for_test(&FlowEditorError::TooManyRecoveryArtifacts);

    assert_eq!(error.kind, super::desktop::DesktopErrorKind::Unavailable);
    assert!(error.message.starts_with("The flow was saved, but "));
    assert_eq!(
        error.recovery.as_deref(),
        Some("Reload the flow workspace before opening or saving another definition.")
    );
}

#[test]
fn desktop_detail_is_bounded_on_a_utf8_boundary() {
    let bounded = bounded_detail_for_test("é".repeat(3_000));

    assert!(bounded.len() <= 4 * 1024);
    assert!(bounded.ends_with("..."));
}

#[test]
fn gui_registration_uses_only_the_bundled_helper_and_fixed_bounded_contract() {
    let executable = std::path::Path::new("/Applications/PAM.app/Contents/MacOS/pam");
    let root = std::path::Path::new("/projects/pam");

    let (program, args, current_dir, kill_on_drop, timeout) =
        registration_contract_for_test(executable, root);

    assert_eq!(program, executable);
    assert_eq!(
        args,
        ["caller", "register", "--kind", "gui"]
            .map(std::ffi::OsString::from)
            .to_vec()
    );
    assert_eq!(current_dir.as_deref(), Some(root));
    assert!(kill_on_drop);
    assert_eq!(timeout, std::time::Duration::from_secs(15));
}

#[tokio::test]
async fn approved_current_is_preserved_without_a_second_project_current_load() {
    let calls = AtomicUsize::new(0);
    let approved = CurrentState::Available(super::current::CurrentView {
        queued: Vec::new(),
        truncated: false,
        run: None,
    });

    let refreshed = approval_current_for_test(approved.clone(), &calls).await;

    assert_eq!(refreshed, approved);
    assert_eq!(calls.into_inner(), 1);
}

#[tokio::test]
async fn denied_current_is_preserved_without_a_second_project_current_load() {
    let calls = AtomicUsize::new(0);
    let denied = CurrentState::Degraded {
        code: None,
        detail: "This exact project-current request was denied.".to_owned(),
        recovery: None,
    };

    let refreshed = approval_current_for_test(denied.clone(), &calls).await;

    assert_eq!(refreshed, denied);
    assert_eq!(calls.into_inner(), 1);
}

#[tokio::test]
async fn indeterminate_approval_failure_retains_the_exact_retry_handle() {
    let project = ProjectHandle::new();
    let generation = GenerationId::new();
    let core = active_core_for_test(&project, generation.clone());
    let fence = CommandFence::new(project, generation, OperationId::new());
    let approval = super::desktop::ApprovalHandle::new();
    let pending = pending_approval_for_test(
        RequestEnvelope::project_current(
            RequestId::new("current-retry"),
            CallerId::new("gui-retry"),
            ProjectId::new("internal-project-authority"),
            IdempotencyKey::new("current-retry"),
        )
        .authenticated(CallerCredential::new("credential-secret")),
        ApprovalChallenge {
            approval_id: ApprovalId::new("approval-retry"),
            expires_at_unix_ms: 100,
        },
    );

    let (error, retained, retry_authorized) =
        approval_failure_retains_handle_for_test(&core, fence, approval, pending).await;

    assert!(retained);
    assert!(retry_authorized);
    assert_eq!(error.kind, super::desktop::DesktopErrorKind::Unavailable);
    assert_eq!(error.message, "The approval response was not observed.");
    assert!(!format!("{error:?}").contains("credential-secret"));
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

#[tokio::test]
async fn skill_inventory_rejects_a_stale_project_before_scanning() {
    let project = ProjectHandle::new();
    let generation = GenerationId::new();
    let core = active_core_for_test(&project, generation.clone());
    let stale = CommandFence::new(project.clone(), generation, OperationId::new());
    switch_authority_for_test(&core, ProjectHandle::new(), GenerationId::new()).await;

    let error = core.skill_inventory(stale).await.unwrap_err();

    assert_eq!(error.kind, super::desktop::DesktopErrorKind::Stale);
}

#[tokio::test]
async fn skill_audit_commands_reject_a_stale_project_before_storage_or_scan_work() {
    let project = ProjectHandle::new();
    let generation = GenerationId::new();
    let core = active_core_for_test(&project, generation.clone());
    switch_authority_for_test(&core, ProjectHandle::new(), GenerationId::new()).await;

    let load_error = core
        .load_skill_audit(CommandFence::new(
            project.clone(),
            generation.clone(),
            OperationId::new(),
        ))
        .await
        .unwrap_err();
    let run_error = core
        .run_skill_audit(CommandFence::new(project, generation, OperationId::new()))
        .await
        .unwrap_err();

    assert_eq!(load_error.kind, super::desktop::DesktopErrorKind::Stale);
    assert_eq!(run_error.kind, super::desktop::DesktopErrorKind::Stale);
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
    assert_eq!(
        serde_json::to_value(&dto).unwrap(),
        serde_json::json!({
            "status": "approval_required",
            "approval": serde_json::to_value(match &dto {
                CurrentDto::ApprovalRequired { approval, .. } => approval,
                _ => unreachable!(),
            }).unwrap(),
            "expiresAtMs": 42
        })
    );
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
