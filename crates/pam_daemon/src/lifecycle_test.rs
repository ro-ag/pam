use std::{
    fs,
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use pam_core::{
    ApprovalId, CallerCredential, CallerId, ContentDigest, EvidenceHandle, GrantId, IdempotencyKey,
    ProjectId, RequestId,
};
use pam_model::{RuntimeFinishReason, RuntimeResponse, RuntimeUsage};
use pam_platform::{ClientTransport, LocalEndpoint};
use pam_policy::{
    ApprovalRequirement, CapabilityName, Effect, Grant, MAX_RESOURCE_NAME_BYTES, ResourceName,
    ResourceScope,
};
use pam_protocol::{
    BriefProvenance, BriefResult, CancellationDisposition, Event, EvidenceRedaction,
    EvidenceRetention, ExpectedTargetKind, FailureCode, MAX_EVIDENCE_CHUNK_SIZE, MAX_FRAME_SIZE,
    ModelMessage, ModelRole, OperationTruth, ProjectRequestState, RequestEnvelope, RequestPayload,
    ResultBody, ResultPayload, ServerMessage, SourceAvailability, decode_server_message, encode,
};
use pam_store::{
    AcceptRequest, ApprovalDecision, AuditEventRecord, CallerRegistration, CancelOutcome,
    EvidenceRedaction as StoreEvidenceRedaction, EvidenceRetention as StoreEvidenceRetention,
    ProjectCurrent as StoreProjectCurrent, ProjectRequestSummary as StoreProjectRequestSummary,
    PutEvidence, PutGrant, RequestState, Store, StoreError,
};
use tokio::sync::oneshot;

use super::lifecycle::{
    BriefProvider, DaemonConfig, Ownership, approval_recovery, cancellation_presentation,
    clamp_activity_limit, grant_recovery, model_runtime_result, policy_resource, prepare_endpoint,
    protocol_activity_event, protocol_caller_summary, protocol_project_current,
    request_audit_event_id, request_preflight, serve_until_with_delay,
};
use crate::{
    DaemonError, ExchangeError, request_exchange, request_exchange_streaming, request_status,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const TEST_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[test]
fn repeated_running_cancellation_is_observed_not_changed() {
    assert_eq!(
        cancellation_presentation(CancelOutcome::CancellationRequested),
        (CancellationDisposition::Requested, OperationTruth::Changed)
    );
    assert_eq!(
        cancellation_presentation(CancelOutcome::AlreadyRequested),
        (
            CancellationDisposition::AlreadyRequested,
            OperationTruth::Observed,
        )
    );
}

fn test_runtime(name: &str) -> PathBuf {
    let base = if cfg!(unix) {
        PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    };
    base.join(format!("pam-test-{name}-{}", std::process::id()))
}

#[derive(Debug)]
struct PartialBriefProvider;

impl BriefProvider for PartialBriefProvider {
    fn brief<'a>(
        &'a self,
        _project_id: &'a ProjectId,
        _store: &'a Store,
    ) -> Pin<Box<dyn Future<Output = BriefResult> + Send + 'a>> {
        Box::pin(async {
            BriefResult {
                goal: None,
                decisions: Vec::new(),
                verified: Vec::new(),
                next: Vec::new(),
                provenance: vec![BriefProvenance {
                    source: "test-provider".to_owned(),
                    availability: SourceAvailability::Partial,
                    truth: OperationTruth::Unresolved,
                    evidence: None,
                    detail: Some("provider returned bounded partial context".to_owned()),
                }],
            }
        })
    }
}

#[derive(Debug)]
struct NeverBriefProvider;

impl BriefProvider for NeverBriefProvider {
    fn brief<'a>(
        &'a self,
        _project_id: &'a ProjectId,
        _store: &'a Store,
    ) -> Pin<Box<dyn Future<Output = BriefResult> + Send + 'a>> {
        Box::pin(std::future::pending())
    }
}

#[derive(Debug)]
struct OversizedBriefProvider;

impl BriefProvider for OversizedBriefProvider {
    fn brief<'a>(
        &'a self,
        _project_id: &'a ProjectId,
        _store: &'a Store,
    ) -> Pin<Box<dyn Future<Output = BriefResult> + Send + 'a>> {
        Box::pin(async {
            BriefResult {
                goal: None,
                decisions: Vec::new(),
                verified: Vec::new(),
                next: Vec::new(),
                provenance: vec![BriefProvenance {
                    source: "oversized-provider".to_owned(),
                    availability: SourceAvailability::Partial,
                    truth: OperationTruth::Unresolved,
                    evidence: None,
                    detail: Some("x".repeat(MAX_FRAME_SIZE)),
                }],
            }
        })
    }
}

#[test]
fn ownership_rejects_a_second_daemon() {
    let runtime = test_runtime("ownership");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let first = Ownership::acquire(&endpoint).unwrap();

    assert!(matches!(
        Ownership::acquire(&endpoint),
        Err(DaemonError::AlreadyRunning)
    ));

    drop(first);
    let _ = fs::remove_dir_all(runtime);
}

#[cfg(unix)]
#[test]
fn ownership_hardens_runtime_directory_permissions() {
    use std::os::unix::fs::PermissionsExt as _;

    let runtime = test_runtime("ownership-permissions");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o777)).unwrap();
    let endpoint = LocalEndpoint::ipc(runtime.clone());

    let ownership = Ownership::acquire(&endpoint).unwrap();

    assert_eq!(
        fs::metadata(&runtime).unwrap().permissions().mode() & 0o777,
        0o700
    );
    drop(ownership);
    let _ = fs::remove_dir_all(runtime);
}

#[cfg(unix)]
#[test]
fn ownership_rejects_a_symlink_without_truncating_its_target() {
    use std::os::unix::fs::symlink;

    let runtime = test_runtime("ownership-symlink");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let target = runtime.join("must-not-be-truncated");
    fs::write(&target, b"preserve these bytes").unwrap();
    symlink(&target, endpoint.ownership_path()).unwrap();

    assert!(matches!(
        Ownership::acquire(&endpoint),
        Err(DaemonError::Io(_))
    ));
    assert_eq!(fs::read(&target).unwrap(), b"preserve these bytes");

    let _ = fs::remove_dir_all(runtime);
}

#[test]
fn model_policy_resource_binds_the_exact_redacted_runtime_effect() {
    let make = |request_id: &str,
                model: &str,
                first_role: ModelRole,
                prompt: &str,
                max_output_tokens: u32,
                deadline_unix_ms: u64| {
        RequestEnvelope::model_infer(
            RequestId::from(request_id),
            CallerId::from("model-caller"),
            ProjectId::from("model-project"),
            IdempotencyKey::new(format!("{request_id}-key")),
            model,
            vec![
                ModelMessage::new(first_role, "private setup").unwrap(),
                ModelMessage::new(ModelRole::User, prompt).unwrap(),
            ],
            max_output_tokens,
            deadline_unix_ms,
        )
        .unwrap()
    };
    let secret = "private prompt bytes must never enter the policy resource";
    let baseline = make(
        "model-effect-1",
        "vendor/model",
        ModelRole::System,
        secret,
        64,
        10_000,
    );
    let baseline_resource = policy_resource(&baseline).unwrap();
    assert!(
        baseline_resource
            .as_str()
            .contains("model:vendor/model:effect=sha256:")
    );
    assert!(!baseline_resource.as_str().contains(secret));
    assert!(!baseline_resource.as_str().contains("private setup"));
    assert_eq!(
        baseline_resource,
        policy_resource(&make(
            "model-effect-2",
            "vendor/model",
            ModelRole::System,
            secret,
            64,
            10_000,
        ))
        .unwrap(),
        "observer identity and execution deadline are outside the approved semantic effect"
    );
    assert_eq!(
        baseline_resource,
        policy_resource(&make(
            "model-effect-new-deadline",
            "vendor/model",
            ModelRole::System,
            secret,
            64,
            10_001,
        ))
        .unwrap(),
        "approval retries may refresh the execution deadline"
    );

    for changed in [
        make(
            "changed-model",
            "vendor/other",
            ModelRole::System,
            secret,
            64,
            10_000,
        ),
        make(
            "changed-role",
            "vendor/model",
            ModelRole::Assistant,
            secret,
            64,
            10_000,
        ),
        make(
            "changed-prompt",
            "vendor/model",
            ModelRole::System,
            "private prompt bytes must never enter the policy resource!",
            64,
            10_000,
        ),
        make(
            "changed-tokens",
            "vendor/model",
            ModelRole::System,
            secret,
            65,
            10_000,
        ),
    ] {
        assert_ne!(baseline_resource, policy_resource(&changed).unwrap());
    }
}

#[test]
fn invalid_runtime_generation_becomes_a_bounded_internal_request_failure() {
    let request = RequestEnvelope::model_infer(
        RequestId::from("invalid-model-result"),
        CallerId::from("model-caller"),
        ProjectId::from("model-project"),
        IdempotencyKey::from("invalid-model-result-key"),
        "vendor/model",
        vec![ModelMessage::new(ModelRole::User, "bounded request").unwrap()],
        16,
        10_000,
    )
    .unwrap();
    let (response, outcome, detail) = model_runtime_result(
        &request,
        "vendor/model",
        RuntimeResponse {
            text: "x".repeat(pam_protocol::MAX_MODEL_OUTPUT_BYTES + 1),
            finish_reason: RuntimeFinishReason::Stop,
            usage: RuntimeUsage {
                input_tokens: 2,
                sampled_output_tokens: 1,
                emitted_output_tokens: 1,
            },
        },
    );

    assert!(matches!(
        response.body,
        ResultBody::Failure(ref failure)
            if failure.code == FailureCode::Internal
                && failure.message == "embedded model returned an invalid result"
    ));
    assert_eq!(outcome, "failed");
    assert_eq!(detail, "model=vendor/model outcome=invalid_result");
}

#[test]
fn an_unlocked_persistent_lock_file_is_reclaimed_normally() {
    let runtime = test_runtime("persistent-lock");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    fs::create_dir_all(&runtime).unwrap();
    fs::write(endpoint.ownership_path(), b"stopped-daemon\n").unwrap();

    let ownership = Ownership::acquire(&endpoint).unwrap();
    assert_eq!(
        fs::read_to_string(endpoint.ownership_path()).unwrap(),
        format!("{}\n", std::process::id())
    );

    drop(ownership);
    let _ = fs::remove_dir_all(runtime);
}

#[test]
fn stale_socket_reports_recovery_command() {
    let runtime = test_runtime("stale");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    fs::write(endpoint.socket_path().unwrap(), b"stale").unwrap();

    let error = prepare_endpoint(&DaemonConfig {
        endpoint,
        recover: false,
        model: None,
        state_path: Some(runtime.join("state.sqlite3")),
        brief_provider: None,
        bypass_authentication: true,
        bypass_policy: true,
        flow_preflight_capacity: super::lifecycle::FLOW_PREFLIGHT_CAPACITY,
        flow_preflight_delay: Duration::ZERO,
        status_dispatch: super::lifecycle::TestStatusDispatch::Immediate,
    })
    .unwrap_err();
    assert!(matches!(error, DaemonError::StaleState(_)));
    assert_eq!(error.recovery_action(), Some("pam gui"));

    let _ = fs::remove_dir_all(runtime);
}

fn request(project: &str, suffix: &str) -> RequestEnvelope {
    RequestEnvelope::status(
        RequestId::new(format!("request-{suffix}")),
        CallerId::from("queue-test"),
        ProjectId::new(project),
        IdempotencyKey::new(format!("status-{suffix}")),
    )
}

fn network_request(project: &str, suffix: &str) -> RequestEnvelope {
    RequestEnvelope::network_diagnostics(
        RequestId::new(format!("network-{suffix}")),
        CallerId::from("queue-test"),
        ProjectId::new(project),
        IdempotencyKey::new(format!("network-{suffix}")),
    )
}

#[test]
fn audit_event_ids_are_unique_for_same_millisecond_retries() {
    let request = network_request("audit-nonce-project", "same-request");
    let first = request_audit_event_id(&request, "policy", 42);
    let second = request_audit_event_id(&request, "policy", 42);
    assert_ne!(first, second);
}

#[test]
fn project_current_mapping_is_bounded_and_contains_only_scheduler_metadata() {
    let summary =
        |request_id: &str, operation_kind: &str, state: RequestState| StoreProjectRequestSummary {
            request_id: RequestId::from(request_id),
            operation_kind: operation_kind.to_owned(),
            state,
            queue_sequence: 7,
            accepted_at_ms: 11,
            completed_at_ms: (state == RequestState::Succeeded).then_some(19),
        };
    let mapped = protocol_project_current(StoreProjectCurrent {
        queued: vec![summary("queued", "flow_run", RequestState::Queued)],
        queued_truncated: true,
        active: Some(summary(
            "active",
            "model.infer",
            RequestState::CancellationRequested,
        )),
        latest_terminal: Some(summary("latest", "flow_run", RequestState::Succeeded)),
    })
    .unwrap();

    assert_eq!(mapped.queued().len(), 1);
    assert_eq!(mapped.queued()[0].request_id.as_str(), "queued");
    assert_eq!(mapped.queued()[0].operation_kind(), "flow_run");
    assert_eq!(mapped.queued()[0].state, ProjectRequestState::Queued);
    assert_eq!(
        mapped.active.as_ref().unwrap().state,
        ProjectRequestState::CancellationRequested
    );
    assert_eq!(
        mapped.latest.as_ref().unwrap().state,
        ProjectRequestState::Succeeded
    );
    assert!(mapped.truncated);

    let unbounded_kind = "x".repeat(pam_protocol::MAX_PROJECT_OPERATION_KIND_BYTES + 1);
    assert!(
        protocol_project_current(StoreProjectCurrent {
            queued: vec![summary("oversized", &unbounded_kind, RequestState::Queued)],
            queued_truncated: false,
            active: None,
            latest_terminal: None,
        })
        .is_err()
    );
}

#[test]
fn denial_recovery_is_executable_only_for_shell_safe_exact_resources() {
    let caller = CallerId::from("recovery-caller");
    let project = ProjectId::from("recovery-project");
    let handle = EvidenceHandle::parse("evidence://ci/1842/failure").unwrap();
    let requests = [
        (
            RequestEnvelope::status(
                RequestId::from("recovery-status"),
                caller.clone(),
                project.clone(),
                IdempotencyKey::from("recovery-status"),
            ),
            "pam access grant daemon.status --resource daemon".to_owned(),
        ),
        (
            RequestEnvelope::stop(
                RequestId::from("recovery-stop"),
                caller.clone(),
                project.clone(),
                IdempotencyKey::from("recovery-stop"),
            ),
            "pam access grant daemon.stop --resource daemon".to_owned(),
        ),
        (
            RequestEnvelope::project_current(
                RequestId::from("recovery-project-current"),
                caller.clone(),
                project.clone(),
                IdempotencyKey::from("recovery-project-current"),
            ),
            "pam access grant project.current --resource project".to_owned(),
        ),
        (
            RequestEnvelope::inspect_evidence(
                RequestId::from("recovery-inspect"),
                caller.clone(),
                project.clone(),
                IdempotencyKey::from("recovery-inspect"),
                handle.clone(),
            ),
            "pam access grant evidence.inspect --resource evidence:evidence://ci/1842/failure"
                .to_owned(),
        ),
        (
            RequestEnvelope::read_evidence(
                RequestId::from("recovery-read"),
                caller.clone(),
                project.clone(),
                IdempotencyKey::from("recovery-read"),
                handle,
                5,
                8,
            )
            .unwrap(),
            "pam access grant evidence.read --resource evidence:evidence://ci/1842/failure:offset=5:length=8"
                .to_owned(),
        ),
        (
            RequestEnvelope::replay(
                RequestId::from("recovery-replay"),
                caller.clone(),
                project.clone(),
                IdempotencyKey::from("recovery-replay"),
                RequestId::from("target"),
                7,
            ),
            "pam access grant request.replay --resource request:target:after=7"
                .to_owned(),
        ),
    ];
    for (request, expected) in requests {
        assert_eq!(
            grant_recovery(&request.capability, &policy_resource(&request)),
            expected
        );
    }

    let hostile = RequestEnvelope::brief(
        RequestId::from("recovery-hostile"),
        caller,
        ProjectId::from("$(touch_bad)"),
        IdempotencyKey::from("recovery-hostile"),
    );
    assert_eq!(
        grant_recovery(&hostile.capability, &policy_resource(&hostile)),
        "run pam access grant with the denied capability and exact resource, quoted for your shell"
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Covers every public retry surface in one contract table.
fn approval_recovery_matches_each_capability_retry_surface() {
    let approval_id = ApprovalId::from("approval-1");
    let caller = CallerId::from("approval-recovery-caller");
    let project = ProjectId::from("approval-recovery-project");
    let cli_recovery = "pam approval approve approval-1, then retry the original command with --approval-id approval-1";
    for request in [
        RequestEnvelope::status(
            RequestId::from("status"),
            caller.clone(),
            project.clone(),
            IdempotencyKey::from("status"),
        ),
        RequestEnvelope::brief(
            RequestId::from("brief"),
            caller.clone(),
            project.clone(),
            IdempotencyKey::from("brief"),
        ),
        RequestEnvelope::get_result(
            RequestId::from("result"),
            caller.clone(),
            project.clone(),
            IdempotencyKey::from("result"),
            RequestId::from("target"),
        ),
    ] {
        assert_eq!(approval_recovery(&request, &approval_id), cli_recovery);
    }

    let evidence_recovery = "pam approval approve approval-1; pam evidence show spans inspection and range reads, so this one-request receipt must be retried by a protocol client against the exact challenged request";
    let evidence = RequestEnvelope::inspect_evidence(
        RequestId::from("evidence"),
        caller.clone(),
        project.clone(),
        IdempotencyKey::from("evidence"),
        EvidenceHandle::parse("evidence://flow/test").unwrap(),
    );
    assert_eq!(
        approval_recovery(&evidence, &approval_id),
        evidence_recovery
    );

    let protocol_recovery = "pam approval approve approval-1; PAM has no CLI retry surface for this capability, so a protocol client must attach this one-request receipt to the exact challenged request";
    let stop = RequestEnvelope::stop(
        RequestId::from("stop"),
        caller.clone(),
        project.clone(),
        IdempotencyKey::from("stop"),
    );
    assert_eq!(approval_recovery(&stop, &approval_id), protocol_recovery);
    let generic_cancel = RequestEnvelope::cancel(
        RequestId::from("cancel"),
        caller.clone(),
        project.clone(),
        IdempotencyKey::from("cancel"),
        RequestId::from("run-1"),
    );
    assert_eq!(
        approval_recovery(&generic_cancel, &approval_id),
        protocol_recovery
    );

    let target = RequestId::from("run-1");
    let typed = [
        (
            RequestEnvelope::cancel_with_expected_target(
                RequestId::from("typed-cancel"),
                caller.clone(),
                project.clone(),
                IdempotencyKey::from("typed-cancel"),
                target.clone(),
                ExpectedTargetKind::FlowRun,
            ),
            "pam approval approve approval-1, then run pam flow cancel run-1 --approval-id approval-1",
        ),
        (
            RequestEnvelope::replay_with_expected_target(
                RequestId::from("typed-logs"),
                caller.clone(),
                project.clone(),
                IdempotencyKey::from("typed-logs"),
                target.clone(),
                7,
                ExpectedTargetKind::FlowRun,
            ),
            "pam approval approve approval-1, then run pam flow logs run-1 --after 7 --approval-id approval-1",
        ),
        (
            RequestEnvelope::wait_for_result_with_expected_target(
                RequestId::from("typed-wait"),
                caller.clone(),
                project.clone(),
                IdempotencyKey::from("typed-wait"),
                target.clone(),
                8,
                ExpectedTargetKind::FlowRun,
            ),
            "pam approval approve approval-1, then run pam flow wait run-1 --after 8 --approval-id approval-1",
        ),
        (
            RequestEnvelope::get_result_with_expected_target(
                RequestId::from("typed-result"),
                caller,
                project,
                IdempotencyKey::from("typed-result"),
                target,
                ExpectedTargetKind::FlowRun,
            ),
            "pam approval approve approval-1, then run pam flow result run-1 --approval-id approval-1",
        ),
    ];
    for (request, expected) in typed {
        assert_eq!(approval_recovery(&request, &approval_id), expected);
    }
    assert_eq!(
        approval_recovery(&generic_cancel, &ApprovalId::from("-unsafe-option")),
        "approve the exact request using a shell-quoted approval ID, then retry without changing its effect"
    );
}

#[tokio::test]
async fn authenticated_policy_preflight_appends_a_redacted_project_audit_event() {
    let runtime = test_runtime("preflight-audit");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let store = Store::open(runtime.join("state.sqlite3")).unwrap();
    let caller = CallerId::from("audit-caller");
    let project = ProjectId::from("audit-project");
    let credential = CallerCredential::new("audit-credential");
    store
        .register_caller(caller.clone(), credential.clone(), 1)
        .await
        .unwrap();
    store
        .put_grant(PutGrant {
            grant: Grant {
                id: GrantId::from("audit-status-grant"),
                caller: caller.clone(),
                project: project.clone(),
                capability: CapabilityName::parse("daemon.status").unwrap(),
                resource: ResourceScope::Exact(ResourceName::parse("daemon").unwrap()),
                effect: Effect::Allow,
                approval: ApprovalRequirement::None,
                expires_at_ms: None,
                revoked_at_ms: None,
            },
            created_at_ms: 2,
        })
        .await
        .unwrap();
    let request = RequestEnvelope::status(
        RequestId::from("audit-request"),
        caller,
        project.clone(),
        IdempotencyKey::from("audit-idempotency"),
    )
    .authenticated(credential);

    assert!(
        request_preflight(&request, &store, true, true)
            .await
            .unwrap()
            .is_none()
    );
    let export = store
        .export_audit_events(project, 0, None, 10)
        .await
        .unwrap();
    assert_eq!(export.events.len(), 1);
    let event = &export.events[0];
    assert_eq!(event.action, "request.preflight");
    assert_eq!(event.decision, "allow");
    assert_eq!(event.outcome, "authorized");
    assert_eq!(
        event.redacted_detail,
        "capability=daemon.status resource=daemon detail=project policy evaluated"
    );
    assert!(!event.redacted_detail.contains("audit-credential"));

    store.shutdown().await.unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

async fn wait_until_ready(endpoint: &LocalEndpoint) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        if endpoint.socket_path().is_some_and(std::path::Path::exists) {
            return;
        }

        let now = Instant::now();
        assert!(
            now < deadline,
            "daemon did not create endpoint {} within {TEST_TIMEOUT:?}; runtime_dir={} ownership_exists={}",
            endpoint.address(),
            endpoint.runtime_dir().display(),
            endpoint.ownership_path().exists(),
        );
        tokio::time::sleep(TEST_POLL_INTERVAL.min(deadline - now)).await;
    }
}

fn start_daemon(
    endpoint: LocalEndpoint,
    state_path: PathBuf,
    delay: Duration,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), DaemonError>>,
) {
    start_daemon_with_provider(endpoint, state_path, delay, None)
}

fn start_daemon_with_provider(
    endpoint: LocalEndpoint,
    state_path: PathBuf,
    delay: Duration,
    brief_provider: Option<Arc<dyn BriefProvider>>,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), DaemonError>>,
) {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let daemon = tokio::spawn(serve_until_with_delay(
        DaemonConfig {
            endpoint,
            recover: false,
            model: None,
            state_path: Some(state_path),
            brief_provider,
            bypass_authentication: true,
            bypass_policy: true,
            flow_preflight_capacity: super::lifecycle::FLOW_PREFLIGHT_CAPACITY,
            flow_preflight_delay: Duration::ZERO,
            status_dispatch: super::lifecycle::TestStatusDispatch::Durable,
        },
        async {
            let _ = shutdown_rx.await;
        },
        delay,
    ));
    (shutdown_tx, daemon)
}

fn start_secure_daemon(
    endpoint: LocalEndpoint,
    state_path: PathBuf,
    delay: Duration,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), DaemonError>>,
) {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let daemon = tokio::spawn(serve_until_with_delay(
        DaemonConfig {
            endpoint,
            recover: false,
            model: None,
            state_path: Some(state_path),
            brief_provider: None,
            bypass_authentication: false,
            bypass_policy: false,
            flow_preflight_capacity: super::lifecycle::FLOW_PREFLIGHT_CAPACITY,
            flow_preflight_delay: Duration::ZERO,
            status_dispatch: super::lifecycle::TestStatusDispatch::Durable,
        },
        async {
            let _ = shutdown_rx.await;
        },
        delay,
    ));
    (shutdown_tx, daemon)
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn max_length_evidence_handle(final_byte: char) -> EvidenceHandle {
    let prefix = "evidence://ci/";
    assert!(final_byte.is_ascii_lowercase());
    let path_bytes = 512 - prefix.len();
    let handle = EvidenceHandle::parse(format!(
        "{prefix}{}{final_byte}",
        "a".repeat(path_bytes - 1)
    ))
    .unwrap();
    assert_eq!(handle.as_str().len(), 512);
    handle
}

fn evidence_byte_request(
    request_id: &str,
    caller: &CallerId,
    project: &ProjectId,
    handle: EvidenceHandle,
    offset: u64,
) -> RequestEnvelope {
    RequestEnvelope::read_evidence(
        RequestId::from(request_id),
        caller.clone(),
        project.clone(),
        IdempotencyKey::from(request_id),
        handle,
        offset,
        1,
    )
    .unwrap()
}

async fn accept_pending_request(store: &Store, request: &RequestEnvelope, now_ms: u64) {
    store
        .accept(
            AcceptRequest {
                request_id: request.request_id.clone(),
                caller_id: request.caller_id.clone(),
                project_id: request.project_id.clone(),
                idempotency_key: request.idempotency_key.clone(),
                operation_kind: request.capability.policy_name().to_owned(),
                operation: encode(request).unwrap(),
            },
            now_ms,
        )
        .await
        .unwrap();
}

async fn put_test_grant(
    store: &Store,
    grant_id: &str,
    caller: &CallerId,
    project: &ProjectId,
    capability: &str,
    resource: ResourceScope,
    approval: ApprovalRequirement,
) {
    store
        .put_grant(PutGrant {
            grant: Grant {
                id: GrantId::from(grant_id),
                caller: caller.clone(),
                project: project.clone(),
                capability: CapabilityName::parse(capability).unwrap(),
                resource,
                effect: Effect::Allow,
                approval,
                expires_at_ms: None,
                revoked_at_ms: None,
            },
            created_at_ms: 2,
        })
        .await
        .unwrap();
}

async fn approve_required_request(
    endpoint: &LocalEndpoint,
    store: &Store,
    approver: &CallerId,
    request: &RequestEnvelope,
) -> ApprovalId {
    let exchange = request_exchange(endpoint, request, TEST_TIMEOUT)
        .await
        .unwrap();
    let ResultBody::Failure(failure) = exchange.result.body else {
        panic!("request should require approval")
    };
    assert_eq!(failure.code, FailureCode::ApprovalRequired);
    let approval_id = failure.approval.unwrap().approval_id;
    let expected_recovery = approval_recovery(request, &approval_id);
    assert_eq!(
        failure.recovery.as_deref(),
        Some(expected_recovery.as_str())
    );
    store
        .decide_approval(
            approval_id.clone(),
            approver.clone(),
            ApprovalDecision::Approve,
            unix_time_ms(),
        )
        .await
        .unwrap();
    approval_id
}

async fn assert_forbidden(endpoint: &LocalEndpoint, request: &RequestEnvelope) {
    assert!(matches!(
        request_exchange(endpoint, request, TEST_TIMEOUT)
            .await
            .unwrap()
            .result
            .body,
        ResultBody::Failure(ref failure) if failure.code == FailureCode::Forbidden
    ));
}

async fn seed_max_evidence_policy_state(
    state_path: &std::path::Path,
    caller: &CallerId,
    credential: &CallerCredential,
    project: &ProjectId,
    handle: &EvidenceHandle,
    allowed_resource: ResourceName,
) {
    let seed = Store::open(state_path).unwrap();
    seed.register_caller(caller.clone(), credential.clone(), 1)
        .await
        .unwrap();
    put_test_grant(
        &seed,
        "max-evidence-status",
        caller,
        project,
        "daemon.status",
        ResourceScope::Exact(ResourceName::parse("daemon").unwrap()),
        ApprovalRequirement::None,
    )
    .await;
    put_test_grant(
        &seed,
        "max-evidence-read",
        caller,
        project,
        "evidence.read",
        ResourceScope::Exact(allowed_resource),
        ApprovalRequirement::None,
    )
    .await;
    seed.put_evidence(
        PutEvidence {
            handle: handle.clone(),
            project_id: project.clone(),
            media_type: "application/octet-stream".to_owned(),
            retention: StoreEvidenceRetention::Project,
            redaction: StoreEvidenceRedaction::Unredacted,
            bytes: vec![7, 8],
        },
        4,
    )
    .await
    .unwrap();
    seed.shutdown().await.unwrap();
}

async fn wait_for_state(store: &Store, request_id: &RequestId, expected: RequestState) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        let snapshot = store.snapshot(request_id.clone()).await;
        if snapshot
            .as_ref()
            .is_ok_and(|snapshot| snapshot.state == expected)
        {
            return;
        }

        let now = Instant::now();
        assert!(
            now < deadline,
            "request {request_id} did not reach {expected:?} within {TEST_TIMEOUT:?}; last_snapshot={snapshot:?}",
        );
        tokio::time::sleep(TEST_POLL_INTERVAL.min(deadline - now)).await;
    }
}

async fn request_once(endpoint: &LocalEndpoint, request: &RequestEnvelope) -> Vec<ServerMessage> {
    let mut client = ClientTransport::connect(endpoint, TEST_TIMEOUT)
        .await
        .unwrap();
    client.send(encode(request).unwrap()).await.unwrap();
    let mut messages = Vec::new();
    loop {
        let message =
            decode_server_message(&client.receive(Duration::from_secs(2)).await.unwrap()).unwrap();
        let terminal = matches!(message, ServerMessage::Result(_));
        messages.push(message);
        if terminal {
            return messages;
        }
    }
}

async fn assert_status_healthy(endpoint: &LocalEndpoint, suffix: &str) {
    let exchange = request_status(endpoint, &request("health-project", suffix), TEST_TIMEOUT)
        .await
        .unwrap();
    assert!(matches!(exchange.result.body, ResultBody::Success { .. }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brief_baseline_is_honest_read_only_and_provider_neutral() {
    let runtime = test_runtime("brief-baseline");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let (shutdown, daemon) = start_daemon(endpoint.clone(), state_path.clone(), Duration::ZERO);
    wait_until_ready(&endpoint).await;
    let request = RequestEnvelope::brief(
        RequestId::from("brief-observer"),
        CallerId::from("brief-test"),
        ProjectId::from("brief-project"),
        IdempotencyKey::from("brief-read"),
    );

    let exchange = request_exchange(&endpoint, &request, TEST_TIMEOUT)
        .await
        .unwrap();
    assert!(exchange.events.is_empty());
    let ResultBody::Success {
        truth,
        payload: ResultPayload::Brief(brief),
    } = exchange.result.body
    else {
        panic!("brief should return a typed success")
    };
    assert_eq!(truth, OperationTruth::Unresolved);
    assert_eq!(
        brief,
        BriefResult {
            goal: None,
            decisions: Vec::new(),
            verified: Vec::new(),
            next: Vec::new(),
            provenance: vec![BriefProvenance {
                source: "planning-context".to_owned(),
                availability: SourceAvailability::Unavailable,
                truth: OperationTruth::Unresolved,
                evidence: None,
                detail: Some("No planning-context provider is configured.".to_owned()),
            }],
        }
    );
    let observer = Store::open(&state_path).unwrap();
    assert!(matches!(
        observer.snapshot(request.request_id).await,
        Err(StoreError::RequestNotFound(_))
    ));
    observer.shutdown().await.unwrap();

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn network_diagnostics_are_typed_read_only_and_sanitized() {
    let runtime = test_runtime("network-diagnostics");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let (shutdown, daemon) = start_daemon(endpoint.clone(), state_path.clone(), Duration::ZERO);
    wait_until_ready(&endpoint).await;
    let request = network_request("network-project", "observer");

    let exchange = request_exchange(&endpoint, &request, Duration::from_secs(5))
        .await
        .unwrap();
    assert!(exchange.events.is_empty());
    let ResultBody::Success {
        truth,
        payload: ResultPayload::NetworkDiagnostics(diagnostics),
    } = exchange.result.body
    else {
        panic!("network diagnostics should return a typed success")
    };
    assert!(matches!(
        truth,
        OperationTruth::Observed | OperationTruth::Unresolved
    ));
    assert!(diagnostics.platform_roots_enabled);
    assert!(diagnostics.system_proxy_discovery_enabled);

    let observer = Store::open(&state_path).unwrap();
    assert!(matches!(
        observer.snapshot(request.request_id.clone()).await,
        Err(StoreError::RequestNotFound(_))
    ));
    let audit = observer
        .export_audit_events(request.project_id.clone(), 0, None, 10)
        .await
        .unwrap();
    assert_eq!(audit.events.len(), 1);
    let observation = &audit.events[0];
    assert_eq!(observation.action, "network.diagnostics");
    assert_eq!(observation.decision, "observe");
    assert!(matches!(
        observation.outcome.as_str(),
        "observed" | "unresolved"
    ));
    assert!(observation.redacted_detail.contains("platform_roots=true"));
    assert!(observation.redacted_detail.contains("system_proxy=true"));
    assert!(!observation.redacted_detail.contains("http://"));
    assert!(!observation.redacted_detail.contains("https://"));
    assert!(!observation.redacted_detail.contains('@'));
    observer.shutdown().await.unwrap();

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn brief_provider_can_report_partial_source_failure_explicitly() {
    let runtime = test_runtime("brief-partial");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let (shutdown, daemon) = start_daemon_with_provider(
        endpoint.clone(),
        runtime.join("state.sqlite3"),
        Duration::ZERO,
        Some(Arc::new(PartialBriefProvider)),
    );
    wait_until_ready(&endpoint).await;
    let request = RequestEnvelope::brief(
        RequestId::from("partial-brief-observer"),
        CallerId::from("brief-test"),
        ProjectId::from("brief-project"),
        IdempotencyKey::from("partial-brief"),
    );

    let exchange = request_exchange(&endpoint, &request, TEST_TIMEOUT)
        .await
        .unwrap();
    let ResultBody::Success {
        truth,
        payload: ResultPayload::Brief(brief),
    } = exchange.result.body
    else {
        panic!("brief should return provider context")
    };
    assert_eq!(brief.provenance.len(), 1);
    assert_eq!(
        brief.provenance[0].availability,
        SourceAvailability::Partial
    );
    assert_eq!(brief.provenance[0].truth, OperationTruth::Unresolved);
    assert!(brief.provenance[0].detail.is_some());
    assert_eq!(truth, OperationTruth::Unresolved);

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_deadline_is_not_reported_as_daemon_unavailable() {
    let runtime = test_runtime("client-deadline");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let (shutdown, daemon) = start_daemon_with_provider(
        endpoint.clone(),
        runtime.join("state.sqlite3"),
        Duration::ZERO,
        Some(Arc::new(NeverBriefProvider)),
    );
    wait_until_ready(&endpoint).await;
    let request = RequestEnvelope::brief(
        RequestId::from("deadline-observer"),
        CallerId::from("brief-test"),
        ProjectId::from("brief-project"),
        IdempotencyKey::from("deadline-brief"),
    );

    let error = request_exchange(&endpoint, &request, Duration::from_millis(100))
        .await
        .unwrap_err();
    assert!(matches!(error, ExchangeError::DeadlineExceeded));
    assert!(!error.is_unavailable());
    assert_eq!(error.recovery_action(), None);

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_brief_provider_result_isolated_and_daemon_stays_healthy() {
    let runtime = test_runtime("oversized-brief");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let (shutdown, daemon) = start_daemon_with_provider(
        endpoint.clone(),
        runtime.join("state.sqlite3"),
        Duration::ZERO,
        Some(Arc::new(OversizedBriefProvider)),
    );
    wait_until_ready(&endpoint).await;
    let request = RequestEnvelope::brief(
        RequestId::from("oversized-brief-observer"),
        CallerId::from("brief-test"),
        ProjectId::from("brief-project"),
        IdempotencyKey::from("oversized-brief"),
    );

    let exchange = request_exchange(&endpoint, &request, TEST_TIMEOUT)
        .await
        .unwrap();
    let ResultBody::Failure(failure) = exchange.result.body else {
        panic!("oversized provider output should fail")
    };
    assert_eq!(failure.code, FailureCode::FrameTooLarge);
    assert_status_healthy(&endpoint, "after-oversized-brief").await;

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wait_resumes_live_and_terminal_work_with_split_correlation() {
    let runtime = test_runtime("wait-result");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let target = request("wait-project", "wait-target");
    let (shutdown, daemon) = start_daemon(
        endpoint.clone(),
        state_path.clone(),
        Duration::from_millis(400),
    );
    wait_until_ready(&endpoint).await;

    let target_observer = tokio::spawn({
        let endpoint = endpoint.clone();
        let target = target.clone();
        async move { request_status(&endpoint, &target, Duration::from_secs(2)).await }
    });
    let observer = Store::open(&state_path).unwrap();
    wait_for_state(&observer, &target.request_id, RequestState::Leased).await;

    let pending_request = RequestEnvelope::get_result(
        RequestId::from("pending-observer"),
        target.caller_id.clone(),
        target.project_id.clone(),
        IdempotencyKey::from("pending-result"),
        target.request_id.clone(),
    );
    let pending = request_exchange(&endpoint, &pending_request, TEST_TIMEOUT)
        .await
        .unwrap();
    let ResultBody::Failure(pending_failure) = pending.result.body else {
        panic!("running target should be pending")
    };
    assert_eq!(pending_failure.code, FailureCode::Pending);

    let wait_request = RequestEnvelope::wait_for_result(
        RequestId::from("live-wait-observer"),
        target.caller_id.clone(),
        target.project_id.clone(),
        IdempotencyKey::from("live-wait"),
        target.request_id.clone(),
        1,
    );
    let live = request_exchange(&endpoint, &wait_request, Duration::from_secs(2))
        .await
        .unwrap();
    let target_exchange = target_observer.await.unwrap().unwrap();
    assert_eq!(
        live.events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert!(
        live.events
            .iter()
            .all(|event| event.request_id == target.request_id)
    );
    assert_eq!(live.result.request_id, wait_request.request_id);
    assert_eq!(live.result.body, target_exchange.result.body);

    assert_terminal_reads(&endpoint, &target, &target_exchange.result.body).await;
    assert!(matches!(
        observer.snapshot(wait_request.request_id).await,
        Err(StoreError::RequestNotFound(_))
    ));

    observer.shutdown().await.unwrap();
    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

async fn assert_terminal_reads(
    endpoint: &LocalEndpoint,
    target: &RequestEnvelope,
    target_body: &ResultBody,
) {
    let resumed_request = RequestEnvelope::wait_for_result(
        RequestId::from("terminal-wait-observer"),
        target.caller_id.clone(),
        target.project_id.clone(),
        IdempotencyKey::from("terminal-wait"),
        target.request_id.clone(),
        2,
    );
    let resumed = request_exchange(endpoint, &resumed_request, TEST_TIMEOUT)
        .await
        .unwrap();
    assert_eq!(resumed.events.len(), 1);
    assert_eq!(resumed.events[0].sequence, 3);
    assert_eq!(resumed.events[0].request_id, target.request_id);
    assert_eq!(resumed.result.request_id, resumed_request.request_id);
    assert_eq!(&resumed.result.body, target_body);

    let result_request = RequestEnvelope::get_result(
        RequestId::from("terminal-result-observer"),
        target.caller_id.clone(),
        target.project_id.clone(),
        IdempotencyKey::from("terminal-result"),
        target.request_id.clone(),
    );
    let terminal = request_exchange(endpoint, &result_request, TEST_TIMEOUT)
        .await
        .unwrap();
    assert!(terminal.events.is_empty());
    assert_eq!(terminal.result.request_id, result_request.request_id);
    assert_eq!(&terminal.result.body, target_body);

    let wrong_project = RequestEnvelope::get_result(
        RequestId::from("wrong-project-observer"),
        target.caller_id.clone(),
        ProjectId::from("other-project"),
        IdempotencyKey::from("wrong-project-result"),
        target.request_id.clone(),
    );
    let hidden = request_exchange(endpoint, &wrong_project, TEST_TIMEOUT)
        .await
        .unwrap();
    let ResultBody::Failure(hidden_failure) = hidden.result.body else {
        panic!("cross-project target should be hidden")
    };
    assert_eq!(hidden_failure.code, FailureCode::NotFound);

    let wrong_wait = RequestEnvelope::wait_for_result(
        RequestId::from("wrong-project-wait"),
        target.caller_id.clone(),
        ProjectId::from("other-project"),
        IdempotencyKey::from("wrong-project-wait"),
        target.request_id.clone(),
        0,
    );
    let hidden_wait = request_exchange(endpoint, &wrong_wait, TEST_TIMEOUT)
        .await
        .unwrap();
    let ResultBody::Failure(hidden_wait_failure) = hidden_wait.result.body else {
        panic!("cross-project wait target should be hidden")
    };
    assert_eq!(hidden_wait_failure.code, FailureCode::NotFound);

    let missing = RequestEnvelope::get_result(
        RequestId::from("missing-observer"),
        target.caller_id.clone(),
        target.project_id.clone(),
        IdempotencyKey::from("missing-result"),
        RequestId::from("missing-target"),
    );
    let missing_exchange = request_exchange(endpoint, &missing, TEST_TIMEOUT)
        .await
        .unwrap();
    let ResultBody::Failure(missing_failure) = missing_exchange.result.body else {
        panic!("missing target should fail")
    };
    assert_eq!(missing_failure.code, FailureCode::NotFound);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_wait_observer_does_not_cancel_target_work() {
    let runtime = test_runtime("wait-disconnect");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let target = request("disconnect-project", "disconnect-target");
    let (shutdown, daemon) = start_daemon(
        endpoint.clone(),
        state_path.clone(),
        Duration::from_millis(250),
    );
    wait_until_ready(&endpoint).await;
    let target_observer = tokio::spawn({
        let endpoint = endpoint.clone();
        let target = target.clone();
        async move { request_status(&endpoint, &target, Duration::from_secs(2)).await }
    });
    let observer = Store::open(&state_path).unwrap();
    wait_for_state(&observer, &target.request_id, RequestState::Leased).await;
    let wait_request = RequestEnvelope::wait_for_result(
        RequestId::from("abandoned-wait"),
        target.caller_id.clone(),
        target.project_id.clone(),
        IdempotencyKey::from("abandoned-wait"),
        target.request_id.clone(),
        0,
    );
    let mut client = ClientTransport::connect(&endpoint, TEST_TIMEOUT)
        .await
        .unwrap();
    client.send(encode(&wait_request).unwrap()).await.unwrap();
    drop(client);

    let completed = target_observer.await.unwrap().unwrap();
    assert!(matches!(completed.result.body, ResultBody::Success { .. }));
    wait_for_state(&observer, &target.request_id, RequestState::Succeeded).await;

    observer.shutdown().await.unwrap();
    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streaming_wait_timeout_retains_progress_and_does_not_cancel_target_work() {
    let runtime = test_runtime("streaming-wait-timeout");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let target = request("streaming-project", "streaming-target");
    let (shutdown, daemon) = start_daemon(
        endpoint.clone(),
        state_path.clone(),
        Duration::from_millis(500),
    );
    wait_until_ready(&endpoint).await;
    let target_observer = tokio::spawn({
        let endpoint = endpoint.clone();
        let target = target.clone();
        async move { request_status(&endpoint, &target, Duration::from_secs(2)).await }
    });
    let observer = Store::open(&state_path).unwrap();
    wait_for_state(&observer, &target.request_id, RequestState::Leased).await;
    let wait = RequestEnvelope::wait_for_result(
        RequestId::from("streaming-wait-observer"),
        target.caller_id.clone(),
        target.project_id.clone(),
        IdempotencyKey::from("streaming-wait-observer"),
        target.request_id.clone(),
        0,
    );
    let mut delivered = Vec::new();
    let error = request_exchange_streaming(&endpoint, &wait, Duration::from_millis(100), |event| {
        delivered.push((event.sequence, event.event.clone()));
    })
    .await
    .unwrap_err();
    assert!(matches!(error.error(), ExchangeError::DeadlineExceeded));
    assert_eq!(error.last_sequence(), 2);
    assert!(error.request_sent());
    assert_eq!(delivered, vec![(1, Event::Accepted), (2, Event::Started)]);

    let resumed_wait = RequestEnvelope::wait_for_result(
        RequestId::from("streaming-zero-event-observer"),
        target.caller_id.clone(),
        target.project_id.clone(),
        IdempotencyKey::from("streaming-zero-event-observer"),
        target.request_id.clone(),
        2,
    );
    let mut resumed_delivered = Vec::new();
    let resumed_error = request_exchange_streaming(
        &endpoint,
        &resumed_wait,
        Duration::from_millis(100),
        |event| resumed_delivered.push(event.sequence),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        resumed_error.error(),
        ExchangeError::DeadlineExceeded
    ));
    assert!(resumed_error.request_sent());
    assert_eq!(resumed_error.last_sequence(), 2);
    assert!(resumed_delivered.is_empty());

    let completed = target_observer.await.unwrap().unwrap();
    assert!(matches!(completed.result.body, ResultBody::Success { .. }));
    wait_for_state(&observer, &target.request_id, RequestState::Succeeded).await;

    observer.shutdown().await.unwrap();
    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn max_length_evidence_handles_are_safe_and_exactly_policy_bound() {
    let runtime = test_runtime("max-evidence-policy-resource");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let caller = CallerId::from("max-evidence-caller");
    let credential = CallerCredential::new("max-evidence-credential");
    let project = ProjectId::from("max-evidence-project");
    let handle = max_length_evidence_handle('a');
    let adjacent_handle = max_length_evidence_handle('b');
    let allowed_read =
        evidence_byte_request("max-evidence-read", &caller, &project, handle.clone(), 0)
            .authenticated(credential.clone());
    let allowed_resource = policy_resource(&allowed_read).unwrap();
    assert!(allowed_resource.as_str().len() < MAX_RESOURCE_NAME_BYTES);
    assert_ne!(
        allowed_resource,
        policy_resource(&evidence_byte_request(
            "adjacent-resource",
            &caller,
            &project,
            adjacent_handle.clone(),
            0,
        ))
        .unwrap(),
    );

    seed_max_evidence_policy_state(
        &state_path,
        &caller,
        &credential,
        &project,
        &handle,
        allowed_resource,
    )
    .await;

    let (shutdown, daemon) = start_secure_daemon(endpoint.clone(), state_path, Duration::ZERO);
    wait_until_ready(&endpoint).await;

    let unauthenticated = RequestEnvelope::inspect_evidence(
        RequestId::from("max-evidence-unauthenticated"),
        caller.clone(),
        project.clone(),
        IdempotencyKey::from("max-evidence-unauthenticated"),
        handle.clone(),
    );
    let denied = request_exchange(&endpoint, &unauthenticated, TEST_TIMEOUT)
        .await
        .unwrap();
    assert_eq!(denied.result.request_id, unauthenticated.request_id);
    assert!(matches!(
        denied.result.body,
        ResultBody::Failure(ref failure) if failure.code == FailureCode::Unauthenticated
    ));

    let allowed = request_exchange(&endpoint, &allowed_read, TEST_TIMEOUT)
        .await
        .unwrap();
    assert!(matches!(
        allowed.result.body,
        ResultBody::Success {
            payload: ResultPayload::EvidenceChunk(ref chunk),
            ..
        } if chunk.bytes() == [7]
    ));

    for denied_read in [
        evidence_byte_request(
            "max-evidence-adjacent",
            &caller,
            &project,
            adjacent_handle,
            0,
        )
        .authenticated(credential.clone()),
        evidence_byte_request("max-evidence-range", &caller, &project, handle, 1)
            .authenticated(credential.clone()),
    ] {
        assert_forbidden(&endpoint, &denied_read).await;
    }

    let health = RequestEnvelope::status(
        RequestId::from("max-evidence-health"),
        caller,
        project,
        IdempotencyKey::from("max-evidence-health"),
    )
    .authenticated(credential);
    assert!(matches!(
        request_status(&endpoint, &health, TEST_TIMEOUT)
            .await
            .unwrap()
            .result
            .body,
        ResultBody::Success { .. }
    ));

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_request_shape_cannot_consume_a_cancel_approval() {
    let runtime = test_runtime("malformed-shape-approval");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let caller = CallerId::from("shape-caller");
    let credential = CallerCredential::new("shape-credential");
    let project = ProjectId::from("shape-project");
    let target = RequestEnvelope::status(
        RequestId::from("shape-target"),
        caller.clone(),
        project.clone(),
        IdempotencyKey::from("shape-target"),
    );
    let cancel = |request_id: &str| {
        RequestEnvelope::cancel(
            RequestId::from(request_id),
            caller.clone(),
            project.clone(),
            IdempotencyKey::new(format!("{request_id}-key")),
            target.request_id.clone(),
        )
        .authenticated(credential.clone())
    };
    let cancel_resource = policy_resource(&cancel("shape-resource")).unwrap();

    let seed = Store::open(&state_path).unwrap();
    seed.register_caller(caller.clone(), credential.clone(), 1)
        .await
        .unwrap();
    put_test_grant(
        &seed,
        "shape-cancel-grant",
        &caller,
        &project,
        "request.cancel",
        ResourceScope::Exact(cancel_resource),
        ApprovalRequirement::Once,
    )
    .await;
    accept_pending_request(&seed, &target, 3).await;
    seed.shutdown().await.unwrap();

    let (shutdown, daemon) =
        start_secure_daemon(endpoint.clone(), state_path.clone(), Duration::from_secs(5));
    wait_until_ready(&endpoint).await;
    let observer = Store::open(&state_path).unwrap();
    wait_for_state(&observer, &target.request_id, RequestState::Leased).await;

    let approval_id =
        approve_required_request(&endpoint, &observer, &caller, &cancel("shape-challenge")).await;

    let mut malformed = cancel("shape-malformed").with_approval(approval_id.clone());
    malformed.payload = RequestPayload::GetResult {
        target_request_id: target.request_id.clone(),
        expected_target_kind: None,
    };
    let malformed_exchange = request_exchange(&endpoint, &malformed, TEST_TIMEOUT)
        .await
        .unwrap();
    assert_eq!(malformed_exchange.result.request_id, malformed.request_id);
    assert!(matches!(
        malformed_exchange.result.body,
        ResultBody::Failure(ref failure) if failure.code == FailureCode::InvalidRequest
    ));

    let valid = cancel("shape-valid").with_approval(approval_id.clone());
    let valid_exchange = request_exchange(&endpoint, &valid, TEST_TIMEOUT)
        .await
        .unwrap();
    assert!(matches!(
        valid_exchange.result.body,
        ResultBody::Success {
            payload: ResultPayload::Cancellation(ref result),
            ..
        } if result.target_request_id == target.request_id
    ));
    let replayed_receipt = cancel("shape-consumed").with_approval(approval_id);
    assert_forbidden(&endpoint, &replayed_receipt).await;

    assert!(!daemon.is_finished());

    observer.shutdown().await.unwrap();
    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_approval_is_bound_to_the_exact_after_sequence() {
    let runtime = test_runtime("replay-cursor-approval");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let caller = CallerId::from("cursor-caller");
    let credential = CallerCredential::new("cursor-credential");
    let project = ProjectId::from("cursor-project");
    let target = RequestEnvelope::status(
        RequestId::from("cursor-target"),
        caller.clone(),
        project.clone(),
        IdempotencyKey::from("cursor-target"),
    );
    let replay = |request_id: &str, after_sequence| {
        RequestEnvelope::replay(
            RequestId::from(request_id),
            caller.clone(),
            project.clone(),
            IdempotencyKey::new(format!("{request_id}-key")),
            target.request_id.clone(),
            after_sequence,
        )
        .authenticated(credential.clone())
    };
    assert_ne!(
        policy_resource(&replay("cursor-zero-resource", 0)).unwrap(),
        policy_resource(&replay("cursor-hundred-resource", 100)).unwrap()
    );

    let seed = Store::open(&state_path).unwrap();
    seed.register_caller(caller.clone(), credential.clone(), 1)
        .await
        .unwrap();
    put_test_grant(
        &seed,
        "cursor-replay-grant",
        &caller,
        &project,
        "request.replay",
        ResourceScope::Any,
        ApprovalRequirement::Once,
    )
    .await;
    accept_pending_request(&seed, &target, 3).await;
    seed.shutdown().await.unwrap();

    let (shutdown, daemon) =
        start_secure_daemon(endpoint.clone(), state_path.clone(), Duration::from_secs(5));
    wait_until_ready(&endpoint).await;
    let observer = Store::open(&state_path).unwrap();
    wait_for_state(&observer, &target.request_id, RequestState::Leased).await;

    let approval_id = approve_required_request(
        &endpoint,
        &observer,
        &caller,
        &replay("cursor-challenge", 100),
    )
    .await;

    let wrong_cursor = replay("cursor-wrong", 0).with_approval(approval_id.clone());
    assert_forbidden(&endpoint, &wrong_cursor).await;

    let exact_cursor = replay("cursor-exact", 100).with_approval(approval_id.clone());
    assert!(matches!(
        request_exchange(&endpoint, &exact_cursor, TEST_TIMEOUT)
            .await
            .unwrap()
            .result
            .body,
        ResultBody::Success {
            payload: ResultPayload::Replay(_),
            ..
        }
    ));
    let consumed = replay("cursor-consumed", 100).with_approval(approval_id);
    assert_forbidden(&endpoint, &consumed).await;

    assert!(!daemon.is_finished());

    observer.shutdown().await.unwrap();
    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[test]
fn target_policy_resource_is_unambiguous_and_binds_the_expected_kind() {
    let caller = CallerId::from("resource-caller");
    let project = ProjectId::from("resource-project");
    let typed = RequestEnvelope::cancel_with_expected_target(
        RequestId::from("typed-observer"),
        caller.clone(),
        project.clone(),
        IdempotencyKey::from("typed-key"),
        RequestId::from("target"),
        ExpectedTargetKind::FlowRun,
    );
    let generic_same_id = RequestEnvelope::cancel(
        RequestId::from("generic-observer"),
        caller.clone(),
        project.clone(),
        IdempotencyKey::from("generic-key"),
        RequestId::from("target"),
    );
    let hostile_generic = RequestEnvelope::cancel(
        RequestId::from("hostile-observer"),
        caller.clone(),
        project.clone(),
        IdempotencyKey::from("hostile-key"),
        RequestId::from("target:kind=flow_run"),
    );
    assert_ne!(
        policy_resource(&typed).unwrap(),
        policy_resource(&generic_same_id).unwrap()
    );
    assert_ne!(
        policy_resource(&typed).unwrap(),
        policy_resource(&hostile_generic).unwrap()
    );
    assert_eq!(
        policy_resource(&generic_same_id).unwrap().as_str(),
        "request:target"
    );

    let typed_replay = RequestEnvelope::replay_with_expected_target(
        RequestId::from("typed-replay"),
        caller.clone(),
        project.clone(),
        IdempotencyKey::from("typed-replay"),
        RequestId::from("target"),
        7,
        ExpectedTargetKind::FlowRun,
    );
    let hostile_replay = RequestEnvelope::replay(
        RequestId::from("hostile-replay"),
        caller,
        project,
        IdempotencyKey::from("hostile-replay"),
        RequestId::from("target:kind=flow_run:after=7"),
        0,
    );
    assert_ne!(
        policy_resource(&typed_replay).unwrap(),
        policy_resource(&hostile_replay).unwrap()
    );
    let generic_replay = RequestEnvelope::replay(
        RequestId::from("generic-replay"),
        CallerId::from("resource-caller"),
        ProjectId::from("resource-project"),
        IdempotencyKey::from("generic-replay"),
        RequestId::from("target"),
        7,
    );
    assert_eq!(
        policy_resource(&generic_replay).unwrap().as_str(),
        "request:target:after=7"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn model_approval_retry_refreshes_deadline_but_not_the_semantic_effect() {
    let runtime = test_runtime("model-effect-approval");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let caller = CallerId::from("model-approval-caller");
    let credential = CallerCredential::new("model-approval-credential");
    let project = ProjectId::from("model-approval-project");
    let model_request = |request_id: &str, prompt: &str, deadline_unix_ms: u64| {
        RequestEnvelope::model_infer(
            RequestId::from(request_id),
            caller.clone(),
            project.clone(),
            IdempotencyKey::new(format!("{request_id}-key")),
            "vendor/model",
            vec![ModelMessage::new(ModelRole::User, prompt).unwrap()],
            64,
            deadline_unix_ms,
        )
        .unwrap()
        .authenticated(credential.clone())
    };

    let seed = Store::open(&state_path).unwrap();
    seed.register_caller(caller.clone(), credential.clone(), 1)
        .await
        .unwrap();
    put_test_grant(
        &seed,
        "model-approval-grant",
        &caller,
        &project,
        "model.infer",
        ResourceScope::Any,
        ApprovalRequirement::Once,
    )
    .await;
    seed.shutdown().await.unwrap();

    let (shutdown, daemon) =
        start_secure_daemon(endpoint.clone(), state_path.clone(), Duration::ZERO);
    wait_until_ready(&endpoint).await;
    let observer = Store::open(&state_path).unwrap();
    let first_deadline = unix_time_ms().saturating_add(60_000);
    let approval_id = approve_required_request(
        &endpoint,
        &observer,
        &caller,
        &model_request("model-approval-challenge", "exact prompt", first_deadline),
    )
    .await;

    let wrong_prompt = model_request("model-approval-wrong", "different prompt", first_deadline)
        .with_approval(approval_id.clone());
    assert_forbidden(&endpoint, &wrong_prompt).await;

    let refreshed_deadline = unix_time_ms().saturating_add(120_000);
    let exact_retry = model_request("model-approval-exact", "exact prompt", refreshed_deadline)
        .with_approval(approval_id.clone());
    assert!(matches!(
        request_exchange(&endpoint, &exact_retry, TEST_TIMEOUT)
            .await
            .unwrap()
            .result
            .body,
        ResultBody::Failure(ref failure) if failure.code == FailureCode::NotFound
    ));

    let consumed = model_request(
        "model-approval-consumed",
        "exact prompt",
        refreshed_deadline,
    )
    .with_approval(approval_id);
    assert_forbidden(&endpoint, &consumed).await;
    assert!(!daemon.is_finished());

    observer.shutdown().await.unwrap();
    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn evidence_inspection_and_chunk_reads_are_bounded_and_project_scoped() {
    let runtime = test_runtime("evidence-read");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let project_id = ProjectId::from("evidence-project");
    let handle = EvidenceHandle::parse("evidence://ci/1842/failure").unwrap();
    let bytes = (0..(MAX_EVIDENCE_CHUNK_SIZE + 17))
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect::<Vec<_>>();
    let seed = Store::open(&state_path).unwrap();
    let stored = seed
        .put_evidence(
            PutEvidence {
                handle: handle.clone(),
                project_id: project_id.clone(),
                media_type: "application/octet-stream".to_owned(),
                retention: StoreEvidenceRetention::Project,
                redaction: StoreEvidenceRedaction::Unredacted,
                bytes: bytes.clone(),
            },
            1,
        )
        .await
        .unwrap();
    seed.shutdown().await.unwrap();
    let (shutdown, daemon) = start_daemon(endpoint.clone(), state_path.clone(), Duration::ZERO);
    wait_until_ready(&endpoint).await;

    let inspect_id =
        assert_evidence_metadata(&endpoint, &project_id, &handle, &stored.digest, bytes.len())
            .await;
    assert_evidence_chunks(&endpoint, &project_id, &handle, &bytes).await;
    assert_evidence_failures(&endpoint, project_id, handle, bytes.len()).await;
    let observer = Store::open(&state_path).unwrap();
    assert!(matches!(
        observer.snapshot(inspect_id).await,
        Err(StoreError::RequestNotFound(_))
    ));
    observer.shutdown().await.unwrap();

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_evidence_observer_is_rejected_and_daemon_stays_healthy() {
    let runtime = test_runtime("oversized-evidence-observer");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let project_id = ProjectId::from("evidence-project");
    let handle = EvidenceHandle::parse("evidence://ci/oversized/observer").unwrap();
    let seed = Store::open(&state_path).unwrap();
    seed.put_evidence(
        PutEvidence {
            handle: handle.clone(),
            project_id: project_id.clone(),
            media_type: "application/octet-stream".to_owned(),
            retention: StoreEvidenceRetention::Project,
            redaction: StoreEvidenceRedaction::Unredacted,
            bytes: vec![7; MAX_EVIDENCE_CHUNK_SIZE],
        },
        1,
    )
    .await
    .unwrap();
    seed.shutdown().await.unwrap();
    let (shutdown, daemon) = start_daemon(endpoint.clone(), state_path, Duration::ZERO);
    wait_until_ready(&endpoint).await;
    let oversized = RequestEnvelope::read_evidence(
        RequestId::new("r".repeat(800 * 1024)),
        CallerId::from("evidence-test"),
        project_id,
        IdempotencyKey::from("oversized-observer"),
        handle,
        0,
        MAX_EVIDENCE_CHUNK_SIZE as u64,
    )
    .unwrap();

    let exchange = request_exchange(&endpoint, &oversized, Duration::from_secs(2))
        .await
        .unwrap();
    let ResultBody::Failure(failure) = exchange.result.body else {
        panic!("oversized observer identifier should fail")
    };
    assert_eq!(failure.code, FailureCode::InvalidRequest);
    assert_status_healthy(&endpoint, "after-oversized-evidence").await;

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

async fn assert_evidence_metadata(
    endpoint: &LocalEndpoint,
    project_id: &ProjectId,
    handle: &EvidenceHandle,
    digest: &ContentDigest,
    size_bytes: usize,
) -> RequestId {
    let request = RequestEnvelope::inspect_evidence(
        RequestId::from("inspect-observer"),
        CallerId::from("evidence-test"),
        project_id.clone(),
        IdempotencyKey::from("inspect-evidence"),
        handle.clone(),
    );
    let inspected = request_exchange(endpoint, &request, TEST_TIMEOUT)
        .await
        .unwrap();
    let ResultBody::Success {
        truth: OperationTruth::Observed,
        payload: ResultPayload::EvidenceMetadata(metadata),
    } = inspected.result.body
    else {
        panic!("inspect should return evidence metadata")
    };
    assert_eq!(&metadata.handle, handle);
    assert_eq!(&metadata.digest, digest);
    assert_eq!(metadata.size_bytes, size_bytes as u64);
    assert_eq!(metadata.retention, EvidenceRetention::Project);
    assert_eq!(metadata.redaction, EvidenceRedaction::Unredacted);
    request.request_id
}

async fn assert_evidence_chunks(
    endpoint: &LocalEndpoint,
    project_id: &ProjectId,
    handle: &EvidenceHandle,
    bytes: &[u8],
) {
    let first_read = RequestEnvelope::read_evidence(
        RequestId::from("read-first-observer"),
        CallerId::from("evidence-test"),
        project_id.clone(),
        IdempotencyKey::from("read-first"),
        handle.clone(),
        0,
        MAX_EVIDENCE_CHUNK_SIZE as u64,
    )
    .unwrap();
    let first = request_exchange(endpoint, &first_read, TEST_TIMEOUT)
        .await
        .unwrap();
    let ResultBody::Success {
        payload: ResultPayload::EvidenceChunk(first_chunk),
        ..
    } = first.result.body
    else {
        panic!("read should return an evidence chunk")
    };
    assert_eq!(first_chunk.offset, 0);
    assert!(!first_chunk.eof);
    assert_eq!(first_chunk.bytes(), &bytes[..MAX_EVIDENCE_CHUNK_SIZE]);

    let final_read = RequestEnvelope::read_evidence(
        RequestId::from("read-final-observer"),
        CallerId::from("evidence-test"),
        project_id.clone(),
        IdempotencyKey::from("read-final"),
        handle.clone(),
        MAX_EVIDENCE_CHUNK_SIZE as u64,
        17,
    )
    .unwrap();
    let final_exchange = request_exchange(endpoint, &final_read, TEST_TIMEOUT)
        .await
        .unwrap();
    let ResultBody::Success {
        payload: ResultPayload::EvidenceChunk(final_chunk),
        ..
    } = final_exchange.result.body
    else {
        panic!("final read should return an evidence chunk")
    };
    assert!(final_chunk.eof);
    assert_eq!(final_chunk.bytes(), &bytes[MAX_EVIDENCE_CHUNK_SIZE..]);
}

async fn assert_evidence_failures(
    endpoint: &LocalEndpoint,
    project_id: ProjectId,
    handle: EvidenceHandle,
    size_bytes: usize,
) {
    let wrong_project = RequestEnvelope::inspect_evidence(
        RequestId::from("inspect-wrong-project"),
        CallerId::from("evidence-test"),
        ProjectId::from("other-project"),
        IdempotencyKey::from("inspect-wrong-project"),
        handle.clone(),
    );
    let hidden = request_exchange(endpoint, &wrong_project, TEST_TIMEOUT)
        .await
        .unwrap();
    let ResultBody::Failure(hidden_failure) = hidden.result.body else {
        panic!("wrong-project evidence should be hidden")
    };
    assert_eq!(hidden_failure.code, FailureCode::NotFound);

    let wrong_read = RequestEnvelope::read_evidence(
        RequestId::from("read-wrong-project"),
        CallerId::from("evidence-test"),
        ProjectId::from("other-project"),
        IdempotencyKey::from("read-wrong-project"),
        handle.clone(),
        0,
        1,
    )
    .unwrap();
    let hidden_read = request_exchange(endpoint, &wrong_read, TEST_TIMEOUT)
        .await
        .unwrap();
    let ResultBody::Failure(hidden_read_failure) = hidden_read.result.body else {
        panic!("wrong-project evidence read should be hidden")
    };
    assert_eq!(hidden_read_failure.code, FailureCode::NotFound);

    let invalid_range = RequestEnvelope::read_evidence(
        RequestId::from("read-invalid-range"),
        CallerId::from("evidence-test"),
        project_id,
        IdempotencyKey::from("read-invalid-range"),
        handle,
        size_bytes as u64 + 1,
        1,
    )
    .unwrap();
    let invalid = request_exchange(endpoint, &invalid_range, TEST_TIMEOUT)
        .await
        .unwrap();
    let ResultBody::Failure(range_failure) = invalid.result.body else {
        panic!("out-of-bounds evidence range should fail")
    };
    assert_eq!(range_failure.code, FailureCode::InvalidRequest);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn status_reports_only_queued_project_work_without_waiting_for_active_work() {
    let runtime = test_runtime("honest-status-workload");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let first = network_request("honest-project", "active");
    let second = network_request("honest-project", "queued");
    let seed = Store::open(&state_path).unwrap();
    accept_pending_request(&seed, &first, 1).await;
    accept_pending_request(&seed, &second, 2).await;
    seed.shutdown().await.unwrap();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let daemon = tokio::spawn(serve_until_with_delay(
        DaemonConfig {
            endpoint: endpoint.clone(),
            recover: false,
            model: None,
            state_path: Some(state_path.clone()),
            brief_provider: None,
            bypass_authentication: true,
            bypass_policy: true,
            flow_preflight_capacity: super::lifecycle::FLOW_PREFLIGHT_CAPACITY,
            flow_preflight_delay: Duration::ZERO,
            status_dispatch: super::lifecycle::TestStatusDispatch::Immediate,
        },
        async {
            let _ = shutdown_rx.await;
        },
        Duration::from_secs(1),
    ));
    wait_until_ready(&endpoint).await;
    let observer = Store::open(&state_path).unwrap();
    wait_for_state(&observer, &first.request_id, RequestState::Leased).await;
    wait_for_state(&observer, &second.request_id, RequestState::Queued).await;

    let started = Instant::now();
    let exchange = request_status(
        &endpoint,
        &request("honest-project", "status"),
        Duration::from_millis(250),
    )
    .await
    .unwrap();
    assert!(started.elapsed() < Duration::from_millis(250));
    assert!(exchange.events.is_empty());
    assert_eq!(status_queue_depth(&exchange), 1);

    observer.shutdown().await.unwrap();
    shutdown_tx.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_parallelizes_projects_but_serializes_each_project() {
    let runtime = test_runtime("concurrency");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let delay = Duration::from_millis(300);
    let daemon = tokio::spawn(serve_until_with_delay(
        DaemonConfig {
            endpoint: endpoint.clone(),
            recover: false,
            model: None,
            state_path: Some(runtime.join("state.sqlite3")),
            brief_provider: None,
            bypass_authentication: true,
            bypass_policy: true,
            flow_preflight_capacity: super::lifecycle::FLOW_PREFLIGHT_CAPACITY,
            flow_preflight_delay: Duration::ZERO,
            status_dispatch: super::lifecycle::TestStatusDispatch::Durable,
        },
        async {
            let _ = shutdown_rx.await;
        },
        delay,
    ));
    wait_until_ready(&endpoint).await;

    let different_a = request("project-a", "different-a");
    let different_b = request("project-b", "different-b");
    let different_started = Instant::now();
    let different = tokio::join!(
        request_status(&endpoint, &different_a, Duration::from_secs(3)),
        request_status(&endpoint, &different_b, Duration::from_secs(3))
    );
    assert!(different.0.is_ok());
    assert!(different.1.is_ok());
    let different_elapsed = different_started.elapsed();

    let same_a = request("project-c", "same-a");
    let same_b = request("project-c", "same-b");
    let same_started = Instant::now();
    let same = tokio::join!(
        request_status(&endpoint, &same_a, Duration::from_secs(3)),
        request_status(&endpoint, &same_b, Duration::from_secs(3))
    );
    let first_same_project = same.0.unwrap();
    let second_same_project = same.1.unwrap();
    let mut queue_depths = [
        status_queue_depth(&first_same_project),
        status_queue_depth(&second_same_project),
    ];
    queue_depths.sort_unstable();
    assert_eq!(queue_depths, [0, 1]);
    let same_elapsed = same_started.elapsed();

    assert!(
        same_elapsed >= different_elapsed + Duration::from_millis(150),
        "same-project elapsed {same_elapsed:?}, different-project elapsed {different_elapsed:?}"
    );

    let abandoned = request("project-abandoned", "abandoned");
    let mut abandoned_client = ClientTransport::connect(&endpoint, TEST_TIMEOUT)
        .await
        .unwrap();
    abandoned_client
        .send(encode(&abandoned).unwrap())
        .await
        .unwrap();
    drop(abandoned_client);
    tokio::time::sleep(delay + Duration::from_millis(50)).await;
    assert!(
        request_status(
            &endpoint,
            &request("project-after-disconnect", "after-disconnect"),
            Duration::from_secs(2)
        )
        .await
        .is_ok()
    );

    shutdown_tx.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accepted_work_survives_restart_and_replays_the_original_result() {
    let runtime = test_runtime("durable-restart");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let durable_request = request("project-durable", "durable");
    let (shutdown, daemon) =
        start_daemon(endpoint.clone(), state_path.clone(), Duration::from_secs(5));
    wait_until_ready(&endpoint).await;

    let pending = tokio::spawn({
        let endpoint = endpoint.clone();
        let request = durable_request.clone();
        async move { request_status(&endpoint, &request, Duration::from_secs(10)).await }
    });
    let observer = Store::open(&state_path).unwrap();
    wait_for_state(&observer, &durable_request.request_id, RequestState::Leased).await;
    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    pending.abort();
    let _ = pending.await;
    observer.shutdown().await.unwrap();

    let (second_shutdown, second_daemon) =
        start_daemon(endpoint.clone(), state_path, Duration::ZERO);
    wait_until_ready(&endpoint).await;
    let exchange = request_status(&endpoint, &durable_request, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        exchange
            .events
            .iter()
            .map(|event| event.event.clone())
            .collect::<Vec<_>>(),
        vec![
            Event::Accepted,
            Event::Started,
            Event::LeaseExpired,
            Event::Started,
            Event::Completed,
        ]
    );
    assert!(matches!(exchange.result.body, ResultBody::Success { .. }));

    second_shutdown.send(()).unwrap();
    second_daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_running_work_is_terminal_and_notifies_the_original_observer() {
    let runtime = test_runtime("durable-cancel");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let target = request("project-cancel", "target");
    let (shutdown, daemon) =
        start_daemon(endpoint.clone(), state_path.clone(), Duration::from_secs(5));
    wait_until_ready(&endpoint).await;

    let target_exchange = tokio::spawn({
        let endpoint = endpoint.clone();
        let target = target.clone();
        async move { request_status(&endpoint, &target, Duration::from_secs(3)).await }
    });
    let observer = Store::open(&state_path).unwrap();
    wait_for_state(&observer, &target.request_id, RequestState::Leased).await;
    let cancellation = RequestEnvelope::cancel(
        RequestId::from("cancel-observer"),
        target.caller_id.clone(),
        target.project_id.clone(),
        IdempotencyKey::from("cancel-target"),
        target.request_id.clone(),
    );
    let cancellation_messages = request_once(&endpoint, &cancellation).await;
    let ServerMessage::Result(cancellation_result) = cancellation_messages.last().unwrap() else {
        panic!("cancellation should return a result")
    };
    let ResultBody::Success {
        payload: ResultPayload::Cancellation(result),
        ..
    } = &cancellation_result.body
    else {
        panic!("cancellation should return a typed success")
    };
    assert_eq!(result.disposition, CancellationDisposition::Requested);

    let exchange = target_exchange.await.unwrap().unwrap();
    assert_eq!(
        exchange
            .events
            .iter()
            .map(|event| event.event.clone())
            .collect::<Vec<_>>(),
        vec![
            Event::Accepted,
            Event::Started,
            Event::CancellationRequested,
            Event::Cancelled,
        ]
    );
    let ResultBody::Failure(failure) = exchange.result.body else {
        panic!("cancelled target should return failure truth")
    };
    assert_eq!(failure.code, FailureCode::Cancelled);

    observer.shutdown().await.unwrap();
    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flow_only_observers_hide_generic_work_and_cancel_does_not_mutate_it() {
    let runtime = test_runtime("flow-only-target-kind");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let target = request("flow-only-project", "generic-target");
    let seed = Store::open(&state_path).unwrap();
    accept_pending_request(&seed, &target, 1).await;
    seed.shutdown().await.unwrap();

    let (shutdown, daemon) =
        start_daemon(endpoint.clone(), state_path.clone(), Duration::from_secs(5));
    wait_until_ready(&endpoint).await;
    let observer = Store::open(&state_path).unwrap();
    wait_for_state(&observer, &target.request_id, RequestState::Leased).await;
    let before_snapshot = observer.snapshot(target.request_id.clone()).await.unwrap();
    let before_replay = observer.replay(target.request_id.clone(), 0).await.unwrap();

    let mut legacy_cancel = RequestEnvelope::cancel_with_expected_target(
        RequestId::from("legacy-flow-cancel"),
        target.caller_id.clone(),
        target.project_id.clone(),
        IdempotencyKey::from("legacy-flow-cancel"),
        target.request_id.clone(),
        ExpectedTargetKind::FlowRun,
    );
    legacy_cancel.protocol_version = 3;
    let legacy = request_exchange(&endpoint, &legacy_cancel, TEST_TIMEOUT)
        .await
        .unwrap();
    assert!(matches!(
        legacy.result.body,
        ResultBody::Failure(ref failure)
            if failure.code == FailureCode::UnsupportedProtocolVersion
    ));
    assert_eq!(
        observer.snapshot(target.request_id.clone()).await.unwrap(),
        before_snapshot
    );
    assert_eq!(
        observer.replay(target.request_id.clone(), 0).await.unwrap(),
        before_replay
    );

    let requests = [
        RequestEnvelope::cancel_with_expected_target(
            RequestId::from("flow-cancel-generic"),
            target.caller_id.clone(),
            target.project_id.clone(),
            IdempotencyKey::from("flow-cancel-generic"),
            target.request_id.clone(),
            ExpectedTargetKind::FlowRun,
        ),
        RequestEnvelope::replay_with_expected_target(
            RequestId::from("flow-logs-generic"),
            target.caller_id.clone(),
            target.project_id.clone(),
            IdempotencyKey::from("flow-logs-generic"),
            target.request_id.clone(),
            0,
            ExpectedTargetKind::FlowRun,
        ),
        RequestEnvelope::wait_for_result_with_expected_target(
            RequestId::from("flow-wait-generic"),
            target.caller_id.clone(),
            target.project_id.clone(),
            IdempotencyKey::from("flow-wait-generic"),
            target.request_id.clone(),
            0,
            ExpectedTargetKind::FlowRun,
        ),
        RequestEnvelope::get_result_with_expected_target(
            RequestId::from("flow-result-generic"),
            target.caller_id.clone(),
            target.project_id.clone(),
            IdempotencyKey::from("flow-result-generic"),
            target.request_id.clone(),
            ExpectedTargetKind::FlowRun,
        ),
    ];
    for typed in requests {
        let exchange = request_exchange(&endpoint, &typed, TEST_TIMEOUT)
            .await
            .unwrap();
        assert!(exchange.events.is_empty());
        assert!(matches!(
            exchange.result.body,
            ResultBody::Failure(ref failure) if failure.code == FailureCode::NotFound
        ));
    }

    assert_eq!(
        observer.snapshot(target.request_id.clone()).await.unwrap(),
        before_snapshot
    );
    assert_eq!(
        observer.replay(target.request_id.clone(), 0).await.unwrap(),
        before_replay
    );

    observer.shutdown().await.unwrap();
    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

fn status_queue_depth(exchange: &crate::StatusExchange) -> u64 {
    let ResultBody::Success {
        payload: ResultPayload::Status(status),
        ..
    } = &exchange.result.body
    else {
        panic!("status request should return a status result")
    };
    status.queue_depth
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idempotent_retry_keeps_both_observers_correlated_without_duplicate_events() {
    let runtime = test_runtime("durable-observers");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = runtime.join("state.sqlite3");
    let first = request("project-observers", "first");
    let mut retry = request("project-observers", "retry");
    retry.idempotency_key = first.idempotency_key.clone();
    let (shutdown, daemon) = start_daemon(
        endpoint.clone(),
        state_path.clone(),
        Duration::from_millis(300),
    );
    wait_until_ready(&endpoint).await;

    let first_observer = tokio::spawn({
        let endpoint = endpoint.clone();
        let first = first.clone();
        async move { request_status(&endpoint, &first, Duration::from_secs(2)).await }
    });
    let observer = Store::open(&state_path).unwrap();
    wait_for_state(&observer, &first.request_id, RequestState::Leased).await;
    let retry_observer = tokio::spawn({
        let endpoint = endpoint.clone();
        let retry = retry.clone();
        async move { request_status(&endpoint, &retry, Duration::from_secs(2)).await }
    });

    let first_exchange = first_observer.await.unwrap().unwrap();
    let retry_exchange = retry_observer.await.unwrap().unwrap();
    assert_eq!(first_exchange.result.request_id, first.request_id);
    assert_eq!(retry_exchange.result.request_id, retry.request_id);
    for exchange in [&first_exchange, &retry_exchange] {
        assert_eq!(
            exchange
                .events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    observer.shutdown().await.unwrap();
    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_replay_cursor_is_correlated_and_does_not_stop_the_daemon() {
    let runtime = test_runtime("invalid-replay");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let (shutdown, daemon) = start_daemon(
        endpoint.clone(),
        runtime.join("state.sqlite3"),
        Duration::ZERO,
    );
    wait_until_ready(&endpoint).await;
    let status = request("project-replay", "status");
    let replay = RequestEnvelope::replay(
        RequestId::from("replay-observer"),
        status.caller_id.clone(),
        status.project_id.clone(),
        IdempotencyKey::from("invalid-replay"),
        status.request_id.clone(),
        u64::MAX,
    );

    let messages = request_once(&endpoint, &replay).await;
    let ServerMessage::Result(result) = messages.last().unwrap() else {
        panic!("invalid replay should return a result")
    };
    let ResultBody::Failure(failure) = &result.body else {
        panic!("invalid replay should return a typed failure")
    };
    assert_eq!(failure.code, FailureCode::InvalidRequest);
    let invalid_wait = RequestEnvelope::wait_for_result(
        RequestId::from("invalid-wait-observer"),
        status.caller_id.clone(),
        status.project_id.clone(),
        IdempotencyKey::from("invalid-wait"),
        status.request_id.clone(),
        u64::MAX,
    );
    let wait_messages = request_once(&endpoint, &invalid_wait).await;
    let ServerMessage::Result(wait_result) = wait_messages.last().unwrap() else {
        panic!("invalid wait should return a result")
    };
    let ResultBody::Failure(wait_failure) = &wait_result.body else {
        panic!("invalid wait should return a typed failure")
    };
    assert_eq!(wait_failure.code, FailureCode::InvalidRequest);
    assert!(
        request_status(&endpoint, &status, TEST_TIMEOUT)
            .await
            .is_ok()
    );

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn long_running_work_renews_its_lease_without_duplicate_execution() {
    let runtime = test_runtime("lease-heartbeat");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let (shutdown, daemon) = start_daemon(
        endpoint.clone(),
        runtime.join("state.sqlite3"),
        Duration::from_millis(3_500),
    );
    wait_until_ready(&endpoint).await;

    let exchange = request_status(
        &endpoint,
        &request("project-heartbeat", "long"),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(
        exchange
            .events
            .iter()
            .map(|event| event.event.clone())
            .collect::<Vec<_>>(),
        vec![Event::Accepted, Event::Started, Event::Completed]
    );

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[test]
fn activity_limits_are_clamped_with_a_default_for_zero() {
    assert_eq!(clamp_activity_limit(0), 50);
    assert_eq!(clamp_activity_limit(1), 1);
    assert_eq!(clamp_activity_limit(100), 100);
    assert_eq!(clamp_activity_limit(101), 100);
    assert_eq!(clamp_activity_limit(u32::MAX), 100);
}

#[test]
fn activity_event_summaries_drop_redacted_detail_and_retention() {
    let summary = protocol_activity_event(AuditEventRecord {
        sequence: 7,
        event_id: "event-7".to_owned(),
        project_id: ProjectId::from("project-a"),
        caller_id: CallerId::from("caller-a"),
        action: "request.preflight".to_owned(),
        decision: "allow".to_owned(),
        outcome: "completed".to_owned(),
        redacted_detail: "detail-must-not-cross".to_owned(),
        occurred_at_ms: 11,
        retain_until_ms: 99,
    });
    assert_eq!(summary.sequence, 7);
    assert_eq!(summary.project_id, ProjectId::from("project-a"));
    assert_eq!(summary.caller_id, CallerId::from("caller-a"));
    assert_eq!(summary.action, "request.preflight");
    assert_eq!(summary.decision, "allow");
    assert_eq!(summary.outcome, "completed");
    assert_eq!(summary.occurred_at_ms, 11);
    let encoded = encode(&summary).unwrap();
    assert!(
        !encoded
            .windows(b"detail-must-not-cross".len())
            .any(|window| window == b"detail-must-not-cross")
    );
}

#[test]
fn caller_summaries_preserve_registration_and_revocation() {
    let summary = protocol_caller_summary(CallerRegistration {
        caller_id: CallerId::from("caller-a"),
        registered_at_ms: 5,
        revoked_at_ms: Some(9),
    });
    assert_eq!(summary.caller_id, CallerId::from("caller-a"));
    assert_eq!(summary.registered_at_ms, 5);
    assert_eq!(summary.revoked_at_ms, Some(9));
}
