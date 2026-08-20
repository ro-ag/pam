use std::{fs, path::Path};

use pam_core::{
    ApprovalId, CallerCredential, CallerId, ContentDigest, GrantId, IdempotencyKey, ProjectId,
    RequestId,
};
use pam_flow::{
    ApprovalDecision as FlowApprovalDecision, EffectReport, EffectResult, EngineUpdate,
    FlowDefinition, FlowRun, ReconciliationResult, RunDecision, RunId, RunOutcome, RunTransition,
    TransitionKind,
};
use pam_model::{
    GgufMetadata, LicenseSnapshot, ModelDescriptor, ModelKey, ModelSource, RegisteredModel,
};
use pam_policy::{ApprovalRequirement, CapabilityName, Effect, Grant, ResourceName, ResourceScope};
use rusqlite::Connection;

use super::{
    AUDIT_EXPORT_VERSION, AcceptOutcome, AcceptRequest, AppendAuditEvent, ApprovalDecision,
    ApprovalDecisionOutcome, AuditPruneOutcome, AuthorizationAudit, AuthorizationOutcome,
    AuthorizationRequest, AuthorizeFlowRun, CallerAuthentication, CallerRevocation, CancelOutcome,
    ExpectedOperationKind, FlowAuthorizationOutcome, FlowAuthorizationRecoveryOutcome,
    FlowCheckpointDisposition, FlowEffectAuthorization, FlowTerminalResult, GrantRevocation,
    MAX_AUDIT_ACTION_BYTES, MAX_AUDIT_BATCH_SIZE, MAX_AUDIT_CALLER_ID_BYTES,
    MAX_AUDIT_DECISION_BYTES, MAX_AUDIT_EVENT_ID_BYTES, MAX_AUDIT_OUTCOME_BYTES,
    MAX_AUDIT_PROJECT_ID_BYTES, MAX_FLOW_TERMINAL_RESULT_BYTES, MAX_PROJECT_CURRENT_QUEUED,
    ProjectWorkload, PutGrant, RequestState, SaveFlowCheckpoint, Store, StoreError, TerminalState,
};
use crate::store::database_path;

fn request(
    request_id: &str,
    caller_id: &str,
    project_id: &str,
    idempotency_key: &str,
    operation: &[u8],
) -> AcceptRequest {
    AcceptRequest {
        request_id: RequestId::from(request_id),
        caller_id: CallerId::from(caller_id),
        project_id: ProjectId::from(project_id),
        idempotency_key: IdempotencyKey::from(idempotency_key),
        operation_kind: "test.operation".to_owned(),
        operation: operation.to_vec(),
    }
}

fn request_with_kind(request_id: &str, operation_kind: &str, operation: &[u8]) -> AcceptRequest {
    let mut accepted = request(request_id, "caller", "project-a", request_id, operation);
    accepted.operation_kind = operation_kind.to_owned();
    accepted
}

fn capability(value: &str) -> CapabilityName {
    CapabilityName::parse(value).unwrap()
}

fn resource(value: &str) -> ResourceName {
    ResourceName::parse(value).unwrap()
}

fn grant(
    grant_id: &str,
    caller_id: &str,
    project_id: &str,
    capability_name: &str,
    resource_scope: ResourceScope,
) -> Grant {
    Grant {
        id: GrantId::from(grant_id),
        caller: CallerId::from(caller_id),
        project: ProjectId::from(project_id),
        capability: capability(capability_name),
        resource: resource_scope,
        effect: Effect::Allow,
        approval: ApprovalRequirement::None,
        expires_at_ms: None,
        revoked_at_ms: None,
    }
}

fn authorization(
    caller_id: &str,
    project_id: &str,
    capability_name: &str,
    resource_name: &str,
    approval_id: Option<ApprovalId>,
) -> AuthorizationRequest {
    AuthorizationRequest {
        caller_id: CallerId::from(caller_id),
        project_id: ProjectId::from(project_id),
        capability: capability(capability_name),
        resource: resource(resource_name),
        approval_id,
    }
}

fn audit_event(
    event_id: &str,
    project_id: &str,
    caller_id: &str,
    occurred_at_ms: u64,
    retain_until_ms: u64,
) -> AppendAuditEvent {
    AppendAuditEvent {
        event_id: event_id.to_owned(),
        project_id: ProjectId::from(project_id),
        caller_id: CallerId::from(caller_id),
        action: "policy.authorize".to_owned(),
        decision: "allow".to_owned(),
        outcome: "completed".to_owned(),
        redacted_detail: format!("event={event_id}"),
        occurred_at_ms,
        retain_until_ms,
    }
}

fn authorization_audit(event_id: &str, retain_until_ms: u64) -> AuthorizationAudit {
    AuthorizationAudit {
        event_id: event_id.to_owned(),
        action: "policy.authorize".to_owned(),
        redacted_detail: "bounded redacted policy detail".to_owned(),
        retain_until_ms,
    }
}

fn registered_model(path: &Path) -> RegisteredModel {
    RegisteredModel {
        key: ModelKey::new("qwen", "qwen3.6-35b").unwrap(),
        path: path.to_path_buf(),
        digest: ContentDigest::from_sha256([1; 32]),
        size_bytes: 32,
        gguf: GgufMetadata {
            version: 3,
            tensor_count: 17,
            metadata_kv_count: 29,
        },
        license: LicenseSnapshot::new(
            "Apache-2.0",
            "https://example.test/license",
            ContentDigest::from_sha256([2; 32]),
        )
        .unwrap(),
        source: ModelSource::https("https://models.example/model.gguf").unwrap(),
        registered_at_ms: 42,
    }
}

async fn open_approval_store(name: &str) -> (std::path::PathBuf, std::path::PathBuf, Store) {
    let (directory, path) = database_path(name);
    let store = Store::open(&path).unwrap();
    for (caller_id, credential) in [
        ("approval-subject", "subject credential"),
        ("approval-reviewer", "reviewer credential"),
    ] {
        store
            .register_caller(
                CallerId::from(caller_id),
                CallerCredential::new(credential),
                1,
            )
            .await
            .unwrap();
    }
    let mut approval_grant = grant(
        "approval-grant",
        "approval-subject",
        "approval-project",
        "deploy",
        ResourceScope::Any,
    );
    approval_grant.approval = ApprovalRequirement::Once;
    store
        .put_grant(PutGrant {
            grant: approval_grant,
            created_at_ms: 10,
        })
        .await
        .unwrap();
    (directory, path, store)
}

async fn open_flow_authorization_store(
    name: &str,
    approval: ApprovalRequirement,
) -> (std::path::PathBuf, std::path::PathBuf, Store, ResourceName) {
    let (directory, path) = database_path(name);
    let store = Store::open(&path).unwrap();
    for (caller_id, credential) in [
        ("flow-auth-subject", "flow auth subject credential"),
        ("flow-auth-reviewer", "flow auth reviewer credential"),
    ] {
        store
            .register_caller(
                CallerId::from(caller_id),
                CallerCredential::new(credential),
                1,
            )
            .await
            .unwrap();
    }
    let flow_resource = resource("flow:test-authority");
    let mut flow_grant = grant(
        "flow-auth-grant",
        "flow-auth-subject",
        "flow-auth-project",
        "flow.run",
        ResourceScope::Exact(flow_resource.clone()),
    );
    flow_grant.approval = approval;
    store
        .put_grant(PutGrant {
            grant: flow_grant,
            created_at_ms: 10,
        })
        .await
        .unwrap();
    (directory, path, store, flow_resource)
}

fn flow_authorization_request(
    request_id: &str,
    flow_resource: ResourceName,
    approval_id: Option<ApprovalId>,
    schema_approval_required: bool,
    audit_id: &str,
) -> AuthorizeFlowRun {
    let mut accept = request(
        request_id,
        "flow-auth-subject",
        "flow-auth-project",
        request_id,
        format!("flow operation {request_id}").as_bytes(),
    );
    accept.operation_kind = "flow_run".to_owned();
    AuthorizeFlowRun {
        accept,
        resource: flow_resource,
        approval_id,
        audit: AuthorizationAudit {
            event_id: audit_id.to_owned(),
            action: "flow.authorize".to_owned(),
            redacted_detail: "exact flow authorization decision".to_owned(),
            retain_until_ms: 10_000,
        },
        schema_approval_required,
    }
}

async fn close(store: Store, directory: &Path) {
    store.shutdown().await.unwrap();
    fs::remove_dir_all(directory).unwrap();
}

async fn assert_project_workload(store: &Store, project_id: &str, queued: u64, active: bool) {
    assert_eq!(
        store
            .project_workload(ProjectId::from(project_id))
            .await
            .unwrap(),
        ProjectWorkload { queued, active }
    );
}

async fn seed_project_current_history(store: &Store) {
    let status = request_with_kind("status-a", "status", b"status-secret");
    let legacy_status =
        request_with_kind("legacy-status-a", "daemon_status", b"legacy-status-secret");
    for (accepted, now_ms) in [
        (status, 1),
        (legacy_status, 2),
        (
            request(
                "terminal-a-1",
                "caller",
                "project-a",
                "terminal-a-1",
                b"first-result-secret",
            ),
            3,
        ),
        (
            request(
                "terminal-a-2",
                "caller",
                "project-a",
                "terminal-a-2",
                b"second-result-secret",
            ),
            4,
        ),
        (
            request(
                "active-a",
                "caller",
                "project-a",
                "active-a",
                b"active-operation-secret",
            ),
            5,
        ),
    ] {
        store.accept(accepted, now_ms).await.unwrap();
    }

    let status = store.claim("worker", 10, 1_000).await.unwrap().unwrap();
    store
        .finish(
            status.lease,
            20,
            TerminalState::Succeeded,
            b"status-result-secret".to_vec(),
        )
        .await
        .unwrap();
    let legacy_status = store.claim("worker", 21, 1_000).await.unwrap().unwrap();
    store
        .finish(
            legacy_status.lease,
            101,
            TerminalState::Succeeded,
            b"legacy-status-result-secret".to_vec(),
        )
        .await
        .unwrap();
    let first = store.claim("worker", 22, 1_000).await.unwrap().unwrap();
    store
        .finish(
            first.lease,
            100,
            TerminalState::Failed,
            b"failed-secret".to_vec(),
        )
        .await
        .unwrap();
    let second = store.claim("worker", 23, 1_000).await.unwrap().unwrap();
    store
        .finish(
            second.lease,
            100,
            TerminalState::Succeeded,
            b"solved-secret".to_vec(),
        )
        .await
        .unwrap();
    let active = store.claim("worker", 24, 1_000).await.unwrap().unwrap();
    assert_eq!(active.lease.request_id, RequestId::from("active-a"));
    assert_eq!(
        store
            .cancel(active.lease.request_id, 25, b"cancel-secret".to_vec())
            .await
            .unwrap(),
        CancelOutcome::CancellationRequested
    );
}

async fn seed_project_current_queue(store: &Store) {
    for index in 0_u64..66 {
        let request_id = format!("queued-a-{index:02}");
        store
            .accept(
                request(
                    &request_id,
                    "caller",
                    "project-a",
                    &request_id,
                    b"queued-operation-secret",
                ),
                200 + index,
            )
            .await
            .unwrap();
    }
    store
        .accept(
            request(
                "queued-b",
                "caller",
                "project-b",
                "queued-b",
                b"other-project-secret",
            ),
            300,
        )
        .await
        .unwrap();
}

fn flow_definition(revision: u64) -> FlowDefinition {
    flow_definition_with_step(revision, "inspect")
}

fn flow_definition_with_step(revision: u64, step_id: &str) -> FlowDefinition {
    FlowDefinition::parse_toml(&format!(
        r#"
schema_version = 1
id = "store-flow"
name = "Store flow"
description = "Exercise durable flow checkpoints."
revision = {revision}

[outcome]
solved = "Report solved work."
changed = "Report changed state."
verified = "Report verified evidence."
unresolved = "Report unresolved work."
blocked = "Report the exact blocker."

[[steps]]
id = "{step_id}"
description = "Inspect durable state."
timeout_seconds = 30
effect = "read_only"
action = {{ type = "command", program = "git", args = ["status"], working_directory = "." }}
"#
    ))
    .unwrap()
}

fn approval_flow_definition() -> FlowDefinition {
    let source = flow_definition(1)
        .to_normalized_toml()
        .unwrap()
        .replace("approval = \"none\"", "approval = \"required\"");
    FlowDefinition::parse_toml(&source).unwrap()
}

fn stateful_approval_flow_definition() -> FlowDefinition {
    FlowDefinition::parse_toml(
        r#"
schema_version = 1
id = "store-stateful-flow"
name = "Store stateful flow"
description = "Exercise uncertain stateful cancellation recovery."
revision = 1

[outcome]
solved = "Report solved work."
changed = "Report changed state."
verified = "Report verified evidence."
unresolved = "Report unresolved work."
blocked = "Report the exact blocker."

[[steps]]
id = "apply"
description = "Apply one exact approved effect."
approval = "required"
idempotency_key = "store-stateful:apply"
timeout_seconds = 30
effect = "stateful"
action = { type = "connector", connector = "github.actions", capability = "runs.rerun", resource = { kind = "workflow_run", id = "github:ro-ag/pam/runs/42" } }
"#,
    )
    .unwrap()
}

async fn leased_flow(store: &Store, request_id: &str) -> (super::Lease, FlowRun) {
    leased_flow_with_definition(store, request_id, flow_definition(1)).await
}

async fn leased_flow_with_definition(
    store: &Store,
    request_id: &str,
    definition: FlowDefinition,
) -> (super::Lease, FlowRun) {
    let mut accepted = request(
        request_id,
        "flow-caller",
        "flow-project",
        request_id,
        b"flow",
    );
    accepted.operation_kind = "flow_run".to_owned();
    match store
        .register_caller(
            CallerId::from("flow-caller"),
            CallerCredential::new("flow-test-credential"),
            1,
        )
        .await
    {
        Ok(_) | Err(StoreError::CallerAlreadyRegistered(_)) => {}
        Err(error) => panic!("flow test caller registration failed: {error}"),
    }
    let flow_resource = resource(&format!("flow-test:{request_id}"));
    store
        .put_grant(PutGrant {
            grant: grant(
                &format!("flow-grant-{request_id}"),
                "flow-caller",
                "flow-project",
                "flow.run",
                ResourceScope::Exact(flow_resource.clone()),
            ),
            created_at_ms: 2,
        })
        .await
        .unwrap();
    assert!(matches!(
        store
            .authorize_flow_run(
                AuthorizeFlowRun {
                    accept: accepted,
                    resource: flow_resource,
                    approval_id: None,
                    audit: AuthorizationAudit {
                        event_id: format!("flow-auth-{request_id}"),
                        action: "flow.authorize".to_owned(),
                        redacted_detail: "store flow fixture authorized".to_owned(),
                        retain_until_ms: 1_000,
                    },
                    schema_approval_required: false,
                },
                10,
                100,
            )
            .await
            .unwrap(),
        FlowAuthorizationOutcome::Accepted(AcceptOutcome::Created { .. })
    ));
    let lease = store
        .claim("flow-worker", 20, 1_000)
        .await
        .unwrap()
        .unwrap()
        .lease;
    let run = FlowRun::start(RunId::parse(request_id).unwrap(), definition).unwrap();
    (lease, run)
}

async fn checkpointed_flow(
    store: &Store,
    request_id: &str,
) -> (super::Lease, FlowRun, EngineUpdate) {
    let (lease, mut run) = leased_flow(store, request_id).await;
    store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease: lease.clone(),
            expected_revision: 0,
            snapshot: run.snapshot().clone(),
            transition: None,
            terminal_result: None,
            updated_at_ms: 21,
        })
        .await
        .unwrap();
    let update = run.next_decision(22).unwrap();
    store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease: lease.clone(),
            expected_revision: 1,
            snapshot: update.snapshot().clone(),
            transition: update.transition().cloned(),
            terminal_result: None,
            updated_at_ms: 22,
        })
        .await
        .unwrap();
    (lease, run, update)
}

async fn cancelled_flow_with_terminal_checkpoint(
    store: &Store,
    request_id: &str,
    terminal_result: Vec<u8>,
) -> super::Lease {
    let (lease, mut run) = leased_flow(store, request_id).await;
    store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease: lease.clone(),
            expected_revision: 0,
            snapshot: run.snapshot().clone(),
            transition: None,
            terminal_result: None,
            updated_at_ms: 21,
        })
        .await
        .unwrap();
    assert_eq!(
        store
            .cancel(
                lease.request_id.clone(),
                22,
                b"generic cancellation".to_vec(),
            )
            .await
            .unwrap(),
        CancelOutcome::CancellationRequested
    );
    let terminal = run.cancel().unwrap();
    let RunDecision::Terminal { result } = terminal.decision() else {
        panic!("cancelled flow must become terminal");
    };
    assert_eq!(result.outcome(), RunOutcome::Cancelled);
    store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease: lease.clone(),
            expected_revision: 1,
            snapshot: terminal.snapshot().clone(),
            transition: terminal.transition().cloned(),
            terminal_result: Some(FlowTerminalResult {
                outcome: RunOutcome::Cancelled,
                encoded_result: terminal_result,
            }),
            updated_at_ms: 23,
        })
        .await
        .unwrap();
    lease
}

#[allow(clippy::too_many_lines)] // Every persisted real-engine boundary is part of this fixture.
async fn reconciliation_unknown_after_cancellation(
    store: &Store,
    request_id: &str,
    terminal_result: &[u8],
) -> super::Lease {
    let (lease, mut run) =
        leased_flow_with_definition(store, request_id, stateful_approval_flow_definition()).await;
    let initial = store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease: lease.clone(),
            expected_revision: 0,
            snapshot: run.snapshot().clone(),
            transition: None,
            terminal_result: None,
            updated_at_ms: 21,
        })
        .await
        .unwrap();
    let mut revision = initial.checkpoint.checkpoint_revision;

    let approval = run.next_decision(22).unwrap();
    let token = match approval.decision() {
        RunDecision::AwaitApproval { token, .. } => *token,
        other => panic!("expected approval request, got {other:?}"),
    };
    (_, revision) = save_test_flow_update(store, &lease, revision, approval, terminal_result).await;

    let approved = run
        .resolve_approval(token, FlowApprovalDecision::Approve)
        .unwrap();
    (_, revision) = save_test_flow_update(store, &lease, revision, approved, terminal_result).await;

    let evaluated = run.next_decision(23).unwrap();
    let effect = match evaluated.decision() {
        RunDecision::EvaluateEffect { effect, .. } => effect.clone(),
        other => panic!("expected effect evaluation, got {other:?}"),
    };
    (_, revision) =
        save_test_flow_update(store, &lease, revision, evaluated, terminal_result).await;

    let started = run.prepare_effect(&effect, 24).unwrap();
    assert!(matches!(started.decision(), RunDecision::Execute { .. }));
    (_, revision) = save_test_flow_update(store, &lease, revision, started, terminal_result).await;

    assert_eq!(
        store
            .cancel(
                lease.request_id.clone(),
                25,
                b"generic cancellation".to_vec(),
            )
            .await
            .unwrap(),
        CancelOutcome::CancellationRequested
    );
    let cancelling = run.cancel().unwrap();
    assert!(matches!(
        cancelling.decision(),
        RunDecision::Reconcile { .. }
    ));
    assert!(matches!(
        cancelling.transition().map(RunTransition::kind),
        Some(TransitionKind::CancellationRequested)
    ));
    (_, revision) =
        save_test_flow_update(store, &lease, revision, cancelling, terminal_result).await;

    let blocked = run
        .record_reconciliation(
            &effect,
            ReconciliationResult::Unknown(
                EffectReport::new("application cannot be determined", Vec::new()).unwrap(),
            ),
            26,
        )
        .unwrap();
    assert!(matches!(
        blocked.transition().map(RunTransition::kind),
        Some(TransitionKind::ReconciliationUnknown { .. })
    ));
    let (decision, _) =
        save_test_flow_update(store, &lease, revision, blocked, terminal_result).await;
    assert!(matches!(
        decision,
        RunDecision::Terminal { result } if result.outcome() == RunOutcome::Blocked
    ));
    let checkpoint = store
        .load_flow_checkpoint(lease.clone(), 27)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        checkpoint.terminal_result,
        Some(FlowTerminalResult {
            outcome: RunOutcome::Blocked,
            encoded_result: terminal_result.to_vec(),
        })
    );
    lease
}

async fn save_test_flow_update(
    store: &Store,
    lease: &super::Lease,
    revision: u64,
    update: EngineUpdate,
    encoded_terminal_result: &[u8],
) -> (RunDecision, u64) {
    let decision = update.decision().clone();
    let terminal_result = match &decision {
        RunDecision::Terminal { result } => Some(FlowTerminalResult {
            outcome: result.outcome(),
            encoded_result: encoded_terminal_result.to_vec(),
        }),
        _ => None,
    };
    let saved = store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease: lease.clone(),
            expected_revision: revision,
            snapshot: update.snapshot().clone(),
            transition: update.transition().cloned(),
            terminal_result,
            updated_at_ms: 30 + revision,
        })
        .await
        .unwrap();
    (decision, saved.checkpoint.checkpoint_revision)
}

async fn assert_terminal_flow_update_rejected(
    store: &Store,
    lease: &super::Lease,
    revision: u64,
    update: EngineUpdate,
    encoded_terminal_result: &[u8],
) {
    let RunDecision::Terminal { result } = update.decision() else {
        panic!("expected terminal flow update");
    };
    let error = store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease: lease.clone(),
            expected_revision: revision,
            snapshot: update.snapshot().clone(),
            transition: update.transition().cloned(),
            terminal_result: Some(FlowTerminalResult {
                outcome: result.outcome(),
                encoded_result: encoded_terminal_result.to_vec(),
            }),
            updated_at_ms: 30 + revision,
        })
        .await
        .unwrap_err();
    assert!(matches!(
        &error,
        StoreError::FlowTerminalOutcomeConflict(request_id) if request_id == &lease.request_id
    ));
    assert_eq!(
        error.to_string(),
        format!(
            "flow terminal outcome for {} conflicts with durable request state",
            lease.request_id
        )
    );
}

#[allow(clippy::too_many_lines)] // Keep each real engine outcome explicit in the race fixture.
async fn terminal_flow_with_checkpoint(
    store: &Store,
    request_id: &str,
    outcome: RunOutcome,
    encoded_terminal_result: &[u8],
    cancel_before_terminal: bool,
) -> super::Lease {
    let definition = if outcome == RunOutcome::Blocked {
        approval_flow_definition()
    } else {
        flow_definition(1)
    };
    let (lease, mut run) = leased_flow_with_definition(store, request_id, definition).await;
    let initial = store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease: lease.clone(),
            expected_revision: 0,
            snapshot: run.snapshot().clone(),
            transition: None,
            terminal_result: None,
            updated_at_ms: 21,
        })
        .await
        .unwrap();
    let mut revision = initial.checkpoint.checkpoint_revision;

    match outcome {
        RunOutcome::Cancelled => {
            assert_eq!(
                store
                    .cancel(
                        lease.request_id.clone(),
                        22,
                        b"generic cancellation".to_vec(),
                    )
                    .await
                    .unwrap(),
                CancelOutcome::CancellationRequested
            );
            let terminal = run.cancel().unwrap();
            let (decision, _) =
                save_test_flow_update(store, &lease, revision, terminal, encoded_terminal_result)
                    .await;
            assert!(matches!(
                decision,
                RunDecision::Terminal { result } if result.outcome() == outcome
            ));
        }
        RunOutcome::Blocked => {
            let requested = run.next_decision(22).unwrap();
            let token = match requested.decision() {
                RunDecision::AwaitApproval { token, .. } => *token,
                other => panic!("expected approval request, got {other:?}"),
            };
            (_, revision) =
                save_test_flow_update(store, &lease, revision, requested, encoded_terminal_result)
                    .await;
            if cancel_before_terminal {
                assert_eq!(
                    store
                        .cancel(
                            lease.request_id.clone(),
                            24,
                            b"earlier cancellation".to_vec(),
                        )
                        .await
                        .unwrap(),
                    CancelOutcome::CancellationRequested
                );
            }
            let denied = run
                .resolve_approval(token, FlowApprovalDecision::Deny)
                .unwrap();
            if cancel_before_terminal {
                assert_terminal_flow_update_rejected(
                    store,
                    &lease,
                    revision,
                    denied,
                    encoded_terminal_result,
                )
                .await;
            } else {
                let (decision, _) =
                    save_test_flow_update(store, &lease, revision, denied, encoded_terminal_result)
                        .await;
                assert!(matches!(
                    decision,
                    RunDecision::Terminal { result } if result.outcome() == outcome
                ));
            }
        }
        RunOutcome::Solved | RunOutcome::Unresolved => {
            let evaluation = run.next_decision(22).unwrap();
            let effect = match evaluation.decision() {
                RunDecision::EvaluateEffect { effect, .. } => effect.clone(),
                other => panic!("expected effect evaluation, got {other:?}"),
            };
            (_, revision) =
                save_test_flow_update(store, &lease, revision, evaluation, encoded_terminal_result)
                    .await;
            let started = run.prepare_effect(&effect, 23).unwrap();
            (_, revision) =
                save_test_flow_update(store, &lease, revision, started, encoded_terminal_result)
                    .await;
            let effect_result = if outcome == RunOutcome::Solved {
                EffectResult::succeeded("completed", Vec::new()).unwrap()
            } else {
                EffectResult::failed("failed", false, Vec::new()).unwrap()
            };
            let recorded = run
                .record_effect_result(&effect, effect_result, 24)
                .unwrap();
            (_, revision) =
                save_test_flow_update(store, &lease, revision, recorded, encoded_terminal_result)
                    .await;
            if cancel_before_terminal {
                assert_eq!(
                    store
                        .cancel(
                            lease.request_id.clone(),
                            25,
                            b"earlier cancellation".to_vec(),
                        )
                        .await
                        .unwrap(),
                    CancelOutcome::CancellationRequested
                );
            }
            let terminal = run.next_decision(25).unwrap();
            if cancel_before_terminal {
                assert_terminal_flow_update_rejected(
                    store,
                    &lease,
                    revision,
                    terminal,
                    encoded_terminal_result,
                )
                .await;
            } else {
                let (decision, _) = save_test_flow_update(
                    store,
                    &lease,
                    revision,
                    terminal,
                    encoded_terminal_result,
                )
                .await;
                assert!(matches!(
                    decision,
                    RunDecision::Terminal { result } if result.outcome() == outcome
                ));
            }
        }
    }
    lease
}

#[tokio::test]
async fn caller_authentication_rejects_wrong_unknown_and_duplicate_credentials() {
    let (directory, path) = database_path("caller-authentication");
    let store = Store::open(&path).unwrap();
    let caller_id = CallerId::from("registered-caller");
    let credential = CallerCredential::new("correct credential");

    let registration = store
        .register_caller(caller_id.clone(), credential.clone(), 10)
        .await
        .unwrap();
    assert_eq!(registration.caller_id, caller_id);
    assert_eq!(registration.registered_at_ms, 10);
    assert_eq!(registration.revoked_at_ms, None);
    assert_eq!(
        store
            .authenticate_caller(caller_id.clone(), credential.clone())
            .await
            .unwrap(),
        CallerAuthentication::Authenticated
    );
    assert_eq!(
        store
            .authenticate_caller(caller_id.clone(), CallerCredential::new("wrong credential"))
            .await
            .unwrap(),
        CallerAuthentication::InvalidCredential
    );
    assert_eq!(
        store
            .authenticate_caller(CallerId::from("unknown-caller"), credential.clone())
            .await
            .unwrap(),
        CallerAuthentication::UnknownCaller
    );

    assert!(matches!(
        store
            .register_caller(
                caller_id.clone(),
                CallerCredential::new("replacement credential"),
                11
            )
            .await,
        Err(StoreError::CallerAlreadyRegistered(existing)) if existing == caller_id
    ));
    assert_eq!(
        store
            .authenticate_caller(
                CallerId::from("registered-caller"),
                CallerCredential::new("replacement credential")
            )
            .await
            .unwrap(),
        CallerAuthentication::InvalidCredential
    );
    assert_eq!(
        store
            .authenticate_caller(CallerId::from("registered-caller"), credential)
            .await
            .unwrap(),
        CallerAuthentication::Authenticated
    );

    close(store, &directory).await;
}

#[tokio::test]
async fn empty_and_oversized_caller_credentials_are_rejected() {
    let (directory, path) = database_path("invalid-caller-credentials");
    let store = Store::open(&path).unwrap();

    for (caller_id, credential) in [
        ("empty-credential", CallerCredential::new("")),
        (
            "oversized-credential",
            CallerCredential::new("x".repeat(257)),
        ),
    ] {
        assert!(matches!(
            store
                .register_caller(CallerId::from(caller_id), credential.clone(), 10)
                .await,
            Err(StoreError::InvalidCallerCredential)
        ));
        assert_eq!(
            store
                .authenticate_caller(CallerId::from(caller_id), credential)
                .await
                .unwrap(),
            CallerAuthentication::InvalidCredential
        );
    }

    close(store, &directory).await;
}

#[tokio::test]
async fn caller_revocation_is_immediate_idempotent_and_persistent() {
    let (directory, path) = database_path("caller-revocation");
    let store = Store::open(&path).unwrap();
    let caller_id = CallerId::from("revoked-caller");
    let credential = CallerCredential::new("credential to revoke");
    store
        .register_caller(caller_id.clone(), credential.clone(), 100)
        .await
        .unwrap();

    assert!(matches!(
        store.revoke_caller(caller_id.clone(), 99).await,
        Err(StoreError::InvalidState(state))
            if state == "caller revocation predates registration"
    ));
    assert_eq!(
        store
            .authenticate_caller(caller_id.clone(), credential.clone())
            .await
            .unwrap(),
        CallerAuthentication::Authenticated
    );
    assert_eq!(
        store.revoke_caller(caller_id.clone(), 101).await.unwrap(),
        CallerRevocation::Revoked
    );
    assert_eq!(
        store
            .authenticate_caller(caller_id.clone(), credential.clone())
            .await
            .unwrap(),
        CallerAuthentication::Revoked
    );
    assert_eq!(
        store.revoke_caller(caller_id.clone(), 102).await.unwrap(),
        CallerRevocation::AlreadyRevoked
    );
    assert_eq!(
        store
            .revoke_caller(CallerId::from("unknown-caller"), 102)
            .await
            .unwrap(),
        CallerRevocation::UnknownCaller
    );
    store.shutdown().await.unwrap();

    let reopened = Store::open(&path).unwrap();
    assert_eq!(
        reopened
            .authenticate_caller(caller_id.clone(), credential)
            .await
            .unwrap(),
        CallerAuthentication::Revoked
    );
    assert_eq!(
        reopened.revoke_caller(caller_id, 103).await.unwrap(),
        CallerRevocation::AlreadyRevoked
    );

    let replacement = CallerCredential::new("replacement after revocation");
    reopened
        .register_caller(CallerId::from("revoked-caller"), replacement.clone(), 104)
        .await
        .unwrap();
    assert_eq!(
        reopened
            .authenticate_caller(CallerId::from("revoked-caller"), replacement)
            .await
            .unwrap(),
        CallerAuthentication::Authenticated
    );

    close(reopened, &directory).await;
}

#[tokio::test]
async fn caller_secret_is_absent_from_storage_and_diagnostics() {
    let (directory, path) = database_path("caller-secret-redaction");
    let store = Store::open(&path).unwrap();
    let caller_id = CallerId::from("secret-redaction-caller");
    let secret = "raw-caller-secret-90827-must-never-be-persisted";
    let credential = CallerCredential::new(secret);

    assert!(!format!("{credential:?}").contains(secret));
    let registration = store
        .register_caller(caller_id.clone(), credential.clone(), 10)
        .await
        .unwrap();
    assert!(!format!("{registration:?}").contains(secret));
    let duplicate_error = store
        .register_caller(caller_id, credential, 11)
        .await
        .unwrap_err();
    assert!(!duplicate_error.to_string().contains(secret));
    assert!(!format!("{duplicate_error:?}").contains(secret));

    let mut wal_path = path.as_os_str().to_os_string();
    wal_path.push("-wal");
    let wal_path = std::path::PathBuf::from(wal_path);
    for storage_path in [&path, &wal_path] {
        let bytes = fs::read(storage_path).unwrap();
        assert!(
            !bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()),
            "raw caller secret found in {}",
            storage_path.display()
        );
    }

    close(store, &directory).await;
}

#[tokio::test]
async fn acceptance_is_idempotent_and_rejects_changed_operations_or_request_ids() {
    let (directory, path) = database_path("idempotency");
    let store = Store::open(&path).unwrap();
    let first = request("request-1", "caller-1", "project-1", "key-1", b"same");

    assert_eq!(
        store.accept(first.clone(), 10).await.unwrap(),
        AcceptOutcome::Created {
            request_id: RequestId::from("request-1"),
            queue_sequence: 1
        }
    );
    assert_eq!(
        store
            .accept(
                request("request-2", "caller-1", "project-1", "key-1", b"same"),
                11
            )
            .await
            .unwrap(),
        AcceptOutcome::Existing {
            request_id: RequestId::from("request-1"),
            state: RequestState::Queued
        }
    );
    assert!(matches!(
        store
            .accept(
                request(
                    "request-3",
                    "caller-1",
                    "project-1",
                    "key-1",
                    b"changed"
                ),
                12
            )
            .await,
        Err(StoreError::IdempotencyConflict { canonical_request_id })
            if canonical_request_id == RequestId::from("request-1")
    ));
    assert!(matches!(
        store
            .accept(
                request("request-1", "caller-1", "project-1", "key-2", b"same"),
                13
            )
            .await,
        Err(StoreError::RequestIdConflict(request_id))
            if request_id == RequestId::from("request-1")
    ));

    let replay = store.replay(RequestId::from("request-1"), 0).await.unwrap();
    assert_eq!(replay.events.len(), 1);
    assert_eq!(replay.events[0].kind, "accepted");
    close(store, &directory).await;
}

#[tokio::test]
async fn claims_preserve_project_fifo_while_other_projects_make_progress() {
    let (directory, path) = database_path("fifo");
    let store = Store::open(&path).unwrap();
    for (id, project, key, now) in [
        ("a-1", "project-a", "a-1", 10),
        ("a-2", "project-a", "a-2", 11),
        ("b-1", "project-b", "b-1", 12),
    ] {
        store
            .accept(request(id, "caller", project, key, id.as_bytes()), now)
            .await
            .unwrap();
    }

    let first = store.claim("worker-1", 20, 100).await.unwrap().unwrap();
    let second = store.claim("worker-2", 20, 100).await.unwrap().unwrap();
    assert_eq!(first.lease.request_id, RequestId::from("a-1"));
    assert_eq!(second.lease.request_id, RequestId::from("b-1"));
    assert!(store.claim("worker-3", 20, 100).await.unwrap().is_none());

    store
        .finish(
            first.lease,
            21,
            TerminalState::Succeeded,
            b"a-1 result".to_vec(),
        )
        .await
        .unwrap();
    let third = store.claim("worker-3", 22, 100).await.unwrap().unwrap();
    assert_eq!(third.lease.request_id, RequestId::from("a-2"));
    assert_eq!(third.queue_sequence, 2);

    close(store, &directory).await;
}

#[tokio::test]
async fn expired_lease_is_recovered_after_reopen_and_old_token_is_fenced() {
    let (directory, path) = database_path("recovery");
    let store = Store::open(&path).unwrap();
    store
        .accept(
            request("request-1", "caller", "project", "key", b"operation"),
            10,
        )
        .await
        .unwrap();
    let old = store.claim("worker-old", 20, 10).await.unwrap().unwrap();
    store.shutdown().await.unwrap();

    let reopened = Store::open(&path).unwrap();
    assert_eq!(reopened.recover_expired(29).await.unwrap(), 0);
    assert_eq!(reopened.recover_expired(30).await.unwrap(), 1);
    let current = reopened.claim("worker-new", 31, 20).await.unwrap().unwrap();
    assert_eq!(current.lease.attempt, 2);
    assert_ne!(current.lease.token, old.lease.token);
    assert!(matches!(
        reopened
            .finish(old.lease, 32, TerminalState::Succeeded, b"stale".to_vec())
            .await,
        Err(StoreError::StaleLease(_))
    ));

    let renewed = reopened.renew(current.lease, 32, 30).await.unwrap();
    assert_eq!(renewed.expires_at_ms, 62);
    let replay = reopened
        .replay(RequestId::from("request-1"), 0)
        .await
        .unwrap();
    assert_eq!(
        replay
            .events
            .iter()
            .map(|event| (event.sequence, event.kind.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (1, "accepted"),
            (2, "started"),
            (3, "lease_expired"),
            (4, "started")
        ]
    );

    close(reopened, &directory).await;
}

#[tokio::test]
async fn startup_recovery_requeues_all_leases_once_in_original_project_order() {
    let (directory, path) = database_path("startup-recovery");
    let store = Store::open(&path).unwrap();
    for (id, project, key, now) in [
        ("a-1", "project-a", "a-1", 10),
        ("a-2", "project-a", "a-2", 11),
        ("b-1", "project-b", "b-1", 12),
    ] {
        store
            .accept(request(id, "caller", project, key, id.as_bytes()), now)
            .await
            .unwrap();
    }
    let old_a = store.claim("old-a", 20, 100).await.unwrap().unwrap();
    let old_b = store.claim("old-b", 20, 100).await.unwrap().unwrap();
    assert_eq!(old_a.lease.request_id, RequestId::from("a-1"));
    assert_eq!(old_b.lease.request_id, RequestId::from("b-1"));
    store.shutdown().await.unwrap();

    let reopened = Store::open(&path).unwrap();
    assert_eq!(reopened.recover_all_leases(21).await.unwrap(), 2);
    assert_eq!(reopened.recover_all_leases(22).await.unwrap(), 0);
    assert!(matches!(
        reopened
            .finish(
                old_a.lease.clone(),
                22,
                TerminalState::Succeeded,
                b"stale".to_vec()
            )
            .await,
        Err(StoreError::StaleLease(_))
    ));

    let recovered_a = reopened.claim("new-a", 22, 100).await.unwrap().unwrap();
    let recovered_b = reopened.claim("new-b", 22, 100).await.unwrap().unwrap();
    assert_eq!(recovered_a.lease.request_id, RequestId::from("a-1"));
    assert_eq!(recovered_b.lease.request_id, RequestId::from("b-1"));
    assert_ne!(recovered_a.lease.token, old_a.lease.token);
    assert_ne!(recovered_b.lease.token, old_b.lease.token);

    let before_finish = reopened.replay(RequestId::from("a-1"), 0).await.unwrap();
    assert_eq!(
        before_finish
            .events
            .iter()
            .map(|event| (event.sequence, event.kind.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (1, "accepted"),
            (2, "started"),
            (3, "lease_expired"),
            (4, "started")
        ]
    );

    reopened
        .finish(
            recovered_a.lease,
            23,
            TerminalState::Succeeded,
            b"done".to_vec(),
        )
        .await
        .unwrap();
    let next_a = reopened.claim("new-a", 24, 100).await.unwrap().unwrap();
    assert_eq!(next_a.lease.request_id, RequestId::from("a-2"));
    assert_eq!(next_a.queue_sequence, 2);

    close(reopened, &directory).await;
}

#[tokio::test]
async fn queued_cancellation_is_terminal_idempotent_and_replayable() {
    let (directory, path) = database_path("queued-cancel");
    let store = Store::open(&path).unwrap();
    store
        .accept(
            request("request-1", "caller", "project", "key", b"operation"),
            10,
        )
        .await
        .unwrap();

    assert_eq!(
        store
            .cancel(RequestId::from("request-1"), 11, b"cancelled".to_vec())
            .await
            .unwrap(),
        CancelOutcome::Cancelled
    );
    assert_eq!(
        store
            .cancel(RequestId::from("request-1"), 12, b"not stored".to_vec())
            .await
            .unwrap(),
        CancelOutcome::AlreadyTerminal(RequestState::Cancelled)
    );
    let replay = store.replay(RequestId::from("request-1"), 0).await.unwrap();
    assert_eq!(
        replay
            .events
            .iter()
            .map(|event| (event.sequence, event.kind.as_str()))
            .collect::<Vec<_>>(),
        vec![(1, "accepted"), (2, "cancelled")]
    );
    assert_eq!(replay.result.unwrap().payload, b"cancelled");

    close(store, &directory).await;
}

#[tokio::test]
async fn cancellation_and_completion_race_has_exactly_one_terminal_outcome() {
    let (directory, path) = database_path("cancel-race");
    let store = Store::open(&path).unwrap();
    store
        .accept(
            request("request-1", "caller", "project", "key", b"operation"),
            10,
        )
        .await
        .unwrap();
    let leased = store.claim("worker", 20, 100).await.unwrap().unwrap();
    let cancel_store = store.clone();
    let finish_store = store.clone();
    let request_id = leased.lease.request_id.clone();
    let (cancelled, finished) = tokio::join!(
        cancel_store.cancel(request_id.clone(), 21, b"cancel result".to_vec()),
        finish_store.finish(
            leased.lease,
            21,
            TerminalState::Succeeded,
            b"finish result".to_vec()
        )
    );

    match (&cancelled, &finished) {
        (Ok(CancelOutcome::CancellationRequested), Ok(result))
            if result.state == RequestState::Cancelled => {}
        (Ok(CancelOutcome::AlreadyTerminal(RequestState::Succeeded)), Ok(_)) => {}
        outcome => panic!("unexpected race outcome: {outcome:?}"),
    }
    let replay = store.replay(request_id, 0).await.unwrap();
    let terminal_events = replay
        .events
        .iter()
        .filter(|event| matches!(event.kind.as_str(), "completed" | "cancelled"))
        .count();
    assert_eq!(terminal_events, 1);
    assert!(matches!(
        replay.result.unwrap().state,
        RequestState::Succeeded | RequestState::Cancelled
    ));

    close(store, &directory).await;
}

#[tokio::test]
async fn running_cancellation_retains_lease_until_worker_acknowledges_it() {
    let (directory, path) = database_path("running-cancel");
    let store = Store::open(&path).unwrap();
    store
        .accept(request("a-1", "caller", "project-a", "a-1", b"first"), 10)
        .await
        .unwrap();
    store
        .accept(request("a-2", "caller", "project-a", "a-2", b"second"), 11)
        .await
        .unwrap();
    let leased = store.claim("worker", 20, 100).await.unwrap().unwrap();

    assert_eq!(
        store
            .cancel(
                leased.lease.request_id.clone(),
                21,
                b"persisted cancellation".to_vec()
            )
            .await
            .unwrap(),
        CancelOutcome::CancellationRequested
    );
    assert_eq!(
        store
            .cancel(
                leased.lease.request_id.clone(),
                22,
                b"must not replace first result".to_vec()
            )
            .await
            .unwrap(),
        CancelOutcome::AlreadyRequested
    );
    assert_eq!(
        store
            .snapshot(leased.lease.request_id.clone())
            .await
            .unwrap()
            .state,
        RequestState::CancellationRequested
    );
    assert!(store.claim("other", 22, 100).await.unwrap().is_none());

    let renewed = store.renew(leased.lease, 23, 100).await.unwrap();
    let result = store
        .finish(
            renewed,
            24,
            TerminalState::Succeeded,
            b"success cannot win".to_vec(),
        )
        .await
        .unwrap();
    assert_eq!(result.state, RequestState::Cancelled);
    assert_eq!(result.payload, b"persisted cancellation");
    let replay = store.replay(RequestId::from("a-1"), 0).await.unwrap();
    assert_eq!(
        replay
            .events
            .iter()
            .map(|event| (event.sequence, event.kind.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (1, "accepted"),
            (2, "started"),
            (3, "cancellation_requested"),
            (4, "cancelled")
        ]
    );
    assert_eq!(replay.result.unwrap().payload, b"persisted cancellation");
    let next = store.claim("other", 25, 100).await.unwrap().unwrap();
    assert_eq!(next.lease.request_id, RequestId::from("a-2"));

    close(store, &directory).await;
}

#[tokio::test]
async fn cancelled_flow_finish_replaces_the_placeholder_and_replays_once() {
    let (directory, path) = database_path("cancelled-flow-finish");
    let store = Store::open(&path).unwrap();
    let truthful_result = b"typed cancelled flow result".to_vec();
    let lease =
        cancelled_flow_with_terminal_checkpoint(&store, "flow-cancel-1", truthful_result.clone())
            .await;
    let request_id = lease.request_id.clone();

    assert!(matches!(
        store
            .finish_terminal_flow(lease.clone(), 25, b"different result".to_vec())
            .await,
        Err(StoreError::InvalidState(_))
    ));
    let completed = store
        .finish_terminal_flow(lease.clone(), 25, truthful_result.clone())
        .await
        .unwrap();
    assert_eq!(completed.state, RequestState::Cancelled);
    assert_eq!(completed.payload, truthful_result);
    assert_eq!(completed.completed_at_ms, 25);
    assert!(matches!(
        store
            .finish_terminal_flow(lease, 26, b"duplicate".to_vec())
            .await,
        Err(StoreError::StaleLease(_))
    ));

    let replay = store.replay(request_id, 0).await.unwrap();
    assert_eq!(
        replay
            .events
            .iter()
            .map(|event| (event.sequence, event.kind.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (1, "accepted"),
            (2, "started"),
            (3, "cancellation_requested"),
            (4, "flow_completed"),
            (5, "cancelled")
        ]
    );
    assert_eq!(replay.result.unwrap().payload, truthful_result);

    close(store, &directory).await;
}

#[tokio::test]
async fn cancelled_flow_recovery_uses_the_cached_terminal_result_after_a_crash() {
    let (directory, path) = database_path("cancelled-flow-recovery");
    let store = Store::open(&path).unwrap();
    let truthful_result = b"durable typed cancellation".to_vec();
    let lease = cancelled_flow_with_terminal_checkpoint(
        &store,
        "flow-cancel-recovery",
        truthful_result.clone(),
    )
    .await;
    let request_id = lease.request_id.clone();
    store.shutdown().await.unwrap();

    let reopened = Store::open(&path).unwrap();
    assert_eq!(reopened.recover_all_leases(25).await.unwrap(), 1);
    assert_eq!(reopened.recover_all_leases(26).await.unwrap(), 0);
    let replay = reopened.replay(request_id, 0).await.unwrap();
    assert_eq!(replay.events.len(), 5);
    let result = replay.result.unwrap();
    assert_eq!(result.state, RequestState::Cancelled);
    assert_eq!(result.payload, truthful_result);
    assert_eq!(result.completed_at_ms, 25);

    close(reopened, &directory).await;
}

async fn assert_reconciliation_unknown_replay(
    store: &Store,
    request_id: &str,
    terminal_result: &[u8],
    completed_at_ms: u64,
) {
    let replay = store.replay(RequestId::from(request_id), 0).await.unwrap();
    assert_eq!(
        replay
            .events
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>(),
        vec![
            "accepted",
            "started",
            "flow_approval_required",
            "flow_approval_granted",
            "flow_effect_evaluation_required",
            "flow_effect_started",
            "cancellation_requested",
            "flow_cancellation_requested",
            "flow_reconciliation_unknown",
            "failed",
        ]
    );
    let result = replay.result.unwrap();
    assert_eq!(result.state, RequestState::Failed);
    assert_eq!(result.payload, terminal_result);
    assert_eq!(result.completed_at_ms, completed_at_ms);
}

#[tokio::test]
async fn reconciliation_unknown_after_cancellation_finishes_with_exact_blocked_truth() {
    let (directory, path) = database_path("cancelled-stateful-unknown-finish");
    let store = Store::open(&path).unwrap();
    let terminal_result = b"typed blocked reconciliation result".to_vec();
    let lease = reconciliation_unknown_after_cancellation(
        &store,
        "cancel-stateful-unknown-finish",
        &terminal_result,
    )
    .await;

    assert!(matches!(
        store
            .finish_terminal_flow(lease.clone(), 40, b"wrong terminal bytes".to_vec())
            .await,
        Err(StoreError::InvalidState(_))
    ));
    let finished = store
        .finish_terminal_flow(lease.clone(), 40, terminal_result.clone())
        .await
        .unwrap();
    assert_eq!(finished.state, RequestState::Failed);
    assert_eq!(finished.payload, terminal_result);
    assert!(matches!(
        store
            .finish_terminal_flow(lease, 41, b"duplicate".to_vec())
            .await,
        Err(StoreError::StaleLease(_))
    ));
    assert_reconciliation_unknown_replay(
        &store,
        "cancel-stateful-unknown-finish",
        &terminal_result,
        40,
    )
    .await;

    close(store, &directory).await;
}

#[tokio::test]
async fn duplicate_cancel_finalizes_cached_reconciliation_unknown_as_failed() {
    let (directory, path) = database_path("cancelled-stateful-unknown-duplicate");
    let store = Store::open(&path).unwrap();
    let request_id = "cancel-stateful-unknown-duplicate";
    let terminal_result = b"durable blocked reconciliation result".to_vec();
    reconciliation_unknown_after_cancellation(&store, request_id, &terminal_result).await;

    assert_eq!(
        store
            .cancel(
                RequestId::from(request_id),
                40,
                b"second generic cancellation".to_vec(),
            )
            .await
            .unwrap(),
        CancelOutcome::AlreadyTerminal(RequestState::Failed)
    );
    assert_eq!(
        store
            .cancel(
                RequestId::from(request_id),
                41,
                b"third generic cancellation".to_vec(),
            )
            .await
            .unwrap(),
        CancelOutcome::AlreadyTerminal(RequestState::Failed)
    );
    assert_reconciliation_unknown_replay(&store, request_id, &terminal_result, 40).await;

    close(store, &directory).await;
}

#[tokio::test]
async fn recovery_finalizes_cached_reconciliation_unknown_as_failed_before_requeue() {
    let (directory, path) = database_path("cancelled-stateful-unknown-recovery");
    let store = Store::open(&path).unwrap();
    let request_id = "cancel-stateful-unknown-recovery";
    let terminal_result = b"recovered blocked reconciliation result".to_vec();
    reconciliation_unknown_after_cancellation(&store, request_id, &terminal_result).await;
    store.shutdown().await.unwrap();

    let reopened = Store::open(&path).unwrap();
    assert_eq!(reopened.recover_all_leases(40).await.unwrap(), 1);
    assert_eq!(reopened.recover_all_leases(41).await.unwrap(), 0);
    assert!(
        reopened
            .claim("other-worker", 41, 100)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        reopened
            .cancel(
                RequestId::from(request_id),
                42,
                b"late generic cancellation".to_vec(),
            )
            .await
            .unwrap(),
        CancelOutcome::AlreadyTerminal(RequestState::Failed)
    );
    assert_reconciliation_unknown_replay(&reopened, request_id, &terminal_result, 40).await;

    close(reopened, &directory).await;
}

#[tokio::test]
async fn expired_recovery_finalizes_cached_reconciliation_unknown_as_failed() {
    let (directory, path) = database_path("cancelled-stateful-unknown-expired");
    let store = Store::open(&path).unwrap();
    let request_id = "cancel-stateful-unknown-expired";
    let terminal_result = b"expired blocked reconciliation result".to_vec();
    reconciliation_unknown_after_cancellation(&store, request_id, &terminal_result).await;

    assert_eq!(
        store.recover_expired_requests(1_020).await.unwrap(),
        vec![RequestId::from(request_id)]
    );
    assert!(
        store
            .recover_expired_requests(1_020)
            .await
            .unwrap()
            .is_empty()
    );
    assert_reconciliation_unknown_replay(&store, request_id, &terminal_result, 1_020).await;

    close(store, &directory).await;
}

#[tokio::test]
async fn terminal_flow_checkpoint_requires_a_bounded_encoded_result() {
    let (directory, path) = database_path("terminal-flow-result-bound");
    let store = Store::open(&path).unwrap();
    let lease = cancelled_flow_with_terminal_checkpoint(
        &store,
        "flow-terminal-bound",
        b"cached result".to_vec(),
    )
    .await;
    let checkpoint = store
        .load_flow_checkpoint(lease.clone(), 25)
        .await
        .unwrap()
        .unwrap();
    let cached = FlowTerminalResult {
        outcome: RunOutcome::Cancelled,
        encoded_result: b"cached result".to_vec(),
    };
    assert_eq!(checkpoint.terminal_result.as_ref(), Some(&cached));
    let unchanged = store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease: lease.clone(),
            expected_revision: checkpoint.checkpoint_revision,
            snapshot: checkpoint.snapshot.clone(),
            transition: None,
            terminal_result: Some(cached.clone()),
            updated_at_ms: 25,
        })
        .await
        .unwrap();
    assert_eq!(unchanged.disposition, FlowCheckpointDisposition::Unchanged);
    assert!(matches!(
        store
            .save_flow_checkpoint(SaveFlowCheckpoint {
                lease: lease.clone(),
                expected_revision: checkpoint.checkpoint_revision,
                snapshot: checkpoint.snapshot.clone(),
                transition: None,
                terminal_result: Some(FlowTerminalResult {
                    outcome: RunOutcome::Cancelled,
                    encoded_result: b"different result".to_vec(),
                }),
                updated_at_ms: 25,
            })
            .await,
        Err(StoreError::FlowCheckpointConflict(_))
    ));

    assert!(matches!(
        store
            .save_flow_checkpoint(SaveFlowCheckpoint {
                lease: lease.clone(),
                expected_revision: checkpoint.checkpoint_revision,
                snapshot: checkpoint.snapshot.clone(),
                transition: None,
                terminal_result: None,
                updated_at_ms: 25,
            })
            .await,
        Err(StoreError::InvalidFlowCheckpoint(_))
    ));
    assert!(matches!(
        store
            .save_flow_checkpoint(SaveFlowCheckpoint {
                lease,
                expected_revision: checkpoint.checkpoint_revision,
                snapshot: checkpoint.snapshot,
                transition: None,
                terminal_result: Some(FlowTerminalResult {
                    outcome: RunOutcome::Cancelled,
                    encoded_result: vec![0; MAX_FLOW_TERMINAL_RESULT_BYTES + 1],
                }),
                updated_at_ms: 25,
            })
            .await,
        Err(StoreError::FlowTerminalResultTooLarge {
            size_bytes,
            maximum_bytes: MAX_FLOW_TERMINAL_RESULT_BYTES,
        }) if size_bytes == MAX_FLOW_TERMINAL_RESULT_BYTES + 1
    ));

    close(store, &directory).await;
}

#[tokio::test]
async fn cancelled_flow_finish_rejects_a_live_non_cancellation_state_and_stale_lease() {
    let (directory, path) = database_path("cancelled-flow-state");
    let store = Store::open(&path).unwrap();
    let (lease, _) = leased_flow(&store, "flow-cancel-state").await;
    let request_id = lease.request_id.clone();
    let mut stale = lease.clone();
    stale.token = "stale-token".to_owned();

    assert!(matches!(
        store
            .finish_terminal_flow(lease.clone(), 21, b"premature".to_vec())
            .await,
        Err(StoreError::InvalidState(_))
    ));
    assert!(matches!(
        store
            .finish_terminal_flow(stale, 21, b"stale".to_vec())
            .await,
        Err(StoreError::StaleLease(_))
    ));
    let replay = store.replay(request_id.clone(), 0).await.unwrap();
    assert_eq!(replay.events.len(), 2);
    assert!(replay.result.is_none());

    store
        .cancel(request_id, 22, b"placeholder".to_vec())
        .await
        .unwrap();
    assert!(matches!(
        store
            .finish_terminal_flow(lease, 23, b"cancelled flow".to_vec())
            .await,
        Err(StoreError::InvalidState(_))
    ));

    close(store, &directory).await;
}

#[tokio::test]
async fn cancelled_flow_finish_rejects_non_flow_work_and_generic_finish_retains_its_result() {
    let (directory, path) = database_path("cancelled-non-flow");
    let store = Store::open(&path).unwrap();
    store
        .accept(
            request("ordinary-1", "caller", "project", "ordinary-1", b"work"),
            10,
        )
        .await
        .unwrap();
    let leased = store.claim("worker", 20, 100).await.unwrap().unwrap();
    store
        .cancel(
            leased.lease.request_id.clone(),
            21,
            b"ordinary cancellation".to_vec(),
        )
        .await
        .unwrap();

    assert!(matches!(
        store
            .finish_terminal_flow(leased.lease.clone(), 22, b"replacement".to_vec())
            .await,
        Err(StoreError::InvalidState(_))
    ));
    let completed = store
        .finish(
            leased.lease,
            23,
            TerminalState::Succeeded,
            b"success cannot win".to_vec(),
        )
        .await
        .unwrap();
    assert_eq!(completed.state, RequestState::Cancelled);
    assert_eq!(completed.payload, b"ordinary cancellation");
    let replay = store
        .replay(RequestId::from("ordinary-1"), 0)
        .await
        .unwrap();
    assert_eq!(replay.events.len(), 4);
    assert_eq!(replay.result.unwrap().payload, b"ordinary cancellation");

    close(store, &directory).await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Exact per-outcome event streams are the regression contract.
async fn cancellation_after_each_terminal_flow_checkpoint_preserves_cached_truth() {
    for (label, flow_outcome) in [
        ("solved", RunOutcome::Solved),
        ("unresolved", RunOutcome::Unresolved),
        ("blocked", RunOutcome::Blocked),
        ("cancelled", RunOutcome::Cancelled),
    ] {
        let (directory, path) = database_path(&format!("terminal-cancel-race-{label}"));
        let store = Store::open(&path).unwrap();
        let request_id = format!("terminal-cancel-race-{label}");
        let encoded_result = format!("encoded terminal {label}").into_bytes();
        let lease = terminal_flow_with_checkpoint(
            &store,
            &request_id,
            flow_outcome,
            &encoded_result,
            false,
        )
        .await;

        let (expected_state, expected_cancel, expected_events) = match flow_outcome {
            RunOutcome::Solved => (
                RequestState::Succeeded,
                CancelOutcome::AlreadyTerminal(RequestState::Succeeded),
                vec![
                    "accepted",
                    "started",
                    "flow_effect_evaluation_required",
                    "flow_effect_started",
                    "flow_effect_succeeded",
                    "flow_completed",
                    "completed",
                ],
            ),
            RunOutcome::Unresolved => (
                RequestState::Failed,
                CancelOutcome::AlreadyTerminal(RequestState::Failed),
                vec![
                    "accepted",
                    "started",
                    "flow_effect_evaluation_required",
                    "flow_effect_started",
                    "flow_effect_failed",
                    "flow_completed",
                    "failed",
                ],
            ),
            RunOutcome::Blocked => (
                RequestState::Failed,
                CancelOutcome::AlreadyTerminal(RequestState::Failed),
                vec![
                    "accepted",
                    "started",
                    "flow_approval_required",
                    "flow_approval_denied",
                    "failed",
                ],
            ),
            RunOutcome::Cancelled => (
                RequestState::Cancelled,
                CancelOutcome::Cancelled,
                vec![
                    "accepted",
                    "started",
                    "cancellation_requested",
                    "flow_completed",
                    "cancelled",
                ],
            ),
        };
        let cancellation = store
            .cancel(
                lease.request_id.clone(),
                90,
                b"late generic cancellation".to_vec(),
            )
            .await
            .unwrap();
        assert_eq!(cancellation, expected_cancel, "{label}");
        assert_eq!(
            store
                .cancel(
                    lease.request_id.clone(),
                    91,
                    b"duplicate cancellation".to_vec(),
                )
                .await
                .unwrap(),
            CancelOutcome::AlreadyTerminal(expected_state),
            "{label}"
        );

        let replay = store.replay(lease.request_id.clone(), 0).await.unwrap();
        assert_eq!(
            replay
                .events
                .iter()
                .map(|event| event.kind.as_str())
                .collect::<Vec<_>>(),
            expected_events,
            "{label}"
        );
        let result = replay.result.unwrap();
        assert_eq!(result.state, expected_state, "{label}");
        assert_eq!(result.payload, encoded_result, "{label}");
        assert_eq!(result.completed_at_ms, 90, "{label}");
        assert!(matches!(
            store
                .finish(
                    lease,
                    92,
                    TerminalState::Succeeded,
                    b"worker result".to_vec(),
                )
                .await,
            Err(StoreError::StaleLease(_))
        ));

        close(store, &directory).await;
    }
}

#[tokio::test]
async fn cancellation_before_a_non_cancelled_terminal_checkpoint_remains_authoritative() {
    for (label, flow_outcome, expected_events) in [
        (
            "solved",
            RunOutcome::Solved,
            vec![
                "accepted",
                "started",
                "flow_effect_evaluation_required",
                "flow_effect_started",
                "flow_effect_succeeded",
                "cancellation_requested",
                "cancelled",
            ],
        ),
        (
            "unresolved",
            RunOutcome::Unresolved,
            vec![
                "accepted",
                "started",
                "flow_effect_evaluation_required",
                "flow_effect_started",
                "flow_effect_failed",
                "cancellation_requested",
                "cancelled",
            ],
        ),
        (
            "blocked",
            RunOutcome::Blocked,
            vec![
                "accepted",
                "started",
                "flow_approval_required",
                "cancellation_requested",
                "cancelled",
            ],
        ),
    ] {
        let (directory, path) = database_path(&format!("cancel-first-race-{label}"));
        let store = Store::open(&path).unwrap();
        let request_id = format!("cancel-first-race-{label}");
        let lease = terminal_flow_with_checkpoint(
            &store,
            &request_id,
            flow_outcome,
            format!("later terminal {label}").as_bytes(),
            true,
        )
        .await;

        assert_eq!(
            store
                .cancel(
                    lease.request_id.clone(),
                    90,
                    b"duplicate cancellation".to_vec(),
                )
                .await
                .unwrap(),
            CancelOutcome::AlreadyRequested,
            "{label}"
        );
        let before_finish = store.replay(lease.request_id.clone(), 0).await.unwrap();
        assert!(before_finish.result.is_none(), "{label}");
        let completed = store
            .finish(
                lease.clone(),
                91,
                TerminalState::Succeeded,
                b"worker terminal result".to_vec(),
            )
            .await
            .unwrap();
        assert_eq!(completed.state, RequestState::Cancelled, "{label}");
        assert_eq!(completed.payload, b"earlier cancellation", "{label}");
        let replay = store.replay(lease.request_id, 0).await.unwrap();
        assert_eq!(
            replay
                .events
                .iter()
                .map(|event| event.kind.as_str())
                .collect::<Vec<_>>(),
            expected_events,
            "{label}"
        );
        assert_eq!(replay.result.unwrap().payload, b"earlier cancellation");

        close(store, &directory).await;
    }
}

#[tokio::test]
async fn lease_recovery_finalizes_each_cached_terminal_flow_without_requeueing() {
    for (label, flow_outcome, expected_state, expected_events) in [
        (
            "solved",
            RunOutcome::Solved,
            RequestState::Succeeded,
            vec![
                "accepted",
                "started",
                "flow_effect_evaluation_required",
                "flow_effect_started",
                "flow_effect_succeeded",
                "flow_completed",
                "completed",
            ],
        ),
        (
            "unresolved",
            RunOutcome::Unresolved,
            RequestState::Failed,
            vec![
                "accepted",
                "started",
                "flow_effect_evaluation_required",
                "flow_effect_started",
                "flow_effect_failed",
                "flow_completed",
                "failed",
            ],
        ),
        (
            "blocked",
            RunOutcome::Blocked,
            RequestState::Failed,
            vec![
                "accepted",
                "started",
                "flow_approval_required",
                "flow_approval_denied",
                "failed",
            ],
        ),
        (
            "cancelled",
            RunOutcome::Cancelled,
            RequestState::Cancelled,
            vec![
                "accepted",
                "started",
                "cancellation_requested",
                "flow_completed",
                "cancelled",
            ],
        ),
    ] {
        let (directory, path) = database_path(&format!("terminal-recovery-{label}"));
        let store = Store::open(&path).unwrap();
        let request_id = format!("terminal-recovery-{label}");
        let encoded_result = format!("recovered terminal {label}").into_bytes();
        let lease = terminal_flow_with_checkpoint(
            &store,
            &request_id,
            flow_outcome,
            &encoded_result,
            false,
        )
        .await;

        assert_eq!(store.recover_all_leases(90).await.unwrap(), 1, "{label}");
        assert_eq!(store.recover_all_leases(91).await.unwrap(), 0, "{label}");
        assert!(store.claim("other", 92, 100).await.unwrap().is_none());
        assert_eq!(
            store
                .cancel(lease.request_id.clone(), 93, b"late cancellation".to_vec(),)
                .await
                .unwrap(),
            CancelOutcome::AlreadyTerminal(expected_state),
            "{label}"
        );
        let replay = store.replay(lease.request_id, 0).await.unwrap();
        assert_eq!(
            replay
                .events
                .iter()
                .map(|event| event.kind.as_str())
                .collect::<Vec<_>>(),
            expected_events,
            "{label}"
        );
        let result = replay.result.unwrap();
        assert_eq!(result.state, expected_state, "{label}");
        assert_eq!(result.payload, encoded_result, "{label}");
        assert_eq!(result.completed_at_ms, 90, "{label}");

        close(store, &directory).await;
    }
}

#[tokio::test]
async fn cancellation_requests_finalize_during_expired_and_startup_recovery() {
    let (directory, path) = database_path("cancel-recovery");
    let store = Store::open(&path).unwrap();
    for (id, project, key, now) in [
        ("a-1", "project-a", "a-1", 10),
        ("a-2", "project-a", "a-2", 11),
        ("b-1", "project-b", "b-1", 12),
        ("b-2", "project-b", "b-2", 13),
    ] {
        store
            .accept(request(id, "caller", project, key, id.as_bytes()), now)
            .await
            .unwrap();
    }
    let old_a = store.claim("old-a", 20, 10).await.unwrap().unwrap();
    let old_b = store.claim("old-b", 20, 100).await.unwrap().unwrap();
    store
        .cancel(old_a.lease.request_id.clone(), 21, b"cancel-a".to_vec())
        .await
        .unwrap();
    store
        .cancel(old_b.lease.request_id.clone(), 21, b"cancel-b".to_vec())
        .await
        .unwrap();
    store.shutdown().await.unwrap();

    let reopened = Store::open(&path).unwrap();
    assert_eq!(reopened.recover_expired(30).await.unwrap(), 1);
    assert_eq!(reopened.recover_expired(30).await.unwrap(), 0);
    assert_eq!(
        reopened
            .snapshot(RequestId::from("a-1"))
            .await
            .unwrap()
            .state,
        RequestState::Cancelled
    );
    assert_eq!(
        reopened
            .snapshot(RequestId::from("b-1"))
            .await
            .unwrap()
            .state,
        RequestState::CancellationRequested
    );
    assert_eq!(reopened.recover_all_leases(31).await.unwrap(), 1);
    assert_eq!(reopened.recover_all_leases(31).await.unwrap(), 0);
    assert!(matches!(
        reopened
            .finish(
                old_a.lease,
                32,
                TerminalState::Succeeded,
                b"stale-a".to_vec()
            )
            .await,
        Err(StoreError::StaleLease(_))
    ));
    assert!(matches!(
        reopened
            .finish(
                old_b.lease,
                32,
                TerminalState::Succeeded,
                b"stale-b".to_vec()
            )
            .await,
        Err(StoreError::StaleLease(_))
    ));

    let replay_a = reopened.replay(RequestId::from("a-1"), 0).await.unwrap();
    assert_eq!(
        replay_a
            .events
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>(),
        vec!["accepted", "started", "cancellation_requested", "cancelled"]
    );
    assert_eq!(replay_a.result.unwrap().payload, b"cancel-a");
    let replay_b = reopened.replay(RequestId::from("b-1"), 0).await.unwrap();
    assert_eq!(replay_b.result.unwrap().payload, b"cancel-b");
    let next_a = reopened.claim("new-a", 33, 100).await.unwrap().unwrap();
    let next_b = reopened.claim("new-b", 33, 100).await.unwrap().unwrap();
    assert_eq!(next_a.lease.request_id, RequestId::from("a-2"));
    assert_eq!(next_b.lease.request_id, RequestId::from("b-2"));

    close(reopened, &directory).await;
}

#[tokio::test]
async fn expired_recovery_returns_requeued_and_cancelled_request_ids_once() {
    let (directory, path) = database_path("recovery-details");
    let store = Store::open(&path).unwrap();
    store
        .accept(
            request("a-1", "caller", "project-a", "a-1", b"ordinary"),
            10,
        )
        .await
        .unwrap();
    store
        .accept(
            request("b-1", "caller", "project-b", "b-1", b"cancelled"),
            11,
        )
        .await
        .unwrap();
    store.claim("worker-a", 20, 10).await.unwrap().unwrap();
    let cancelled = store.claim("worker-b", 20, 10).await.unwrap().unwrap();
    store
        .cancel(
            cancelled.lease.request_id,
            21,
            b"persisted cancellation".to_vec(),
        )
        .await
        .unwrap();
    store.shutdown().await.unwrap();

    let reopened = Store::open(&path).unwrap();
    assert_eq!(
        reopened.recover_expired_requests(30).await.unwrap(),
        vec![RequestId::from("a-1"), RequestId::from("b-1")]
    );
    assert!(
        reopened
            .recover_expired_requests(30)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(reopened.recover_expired(30).await.unwrap(), 0);
    assert_eq!(
        reopened
            .snapshot(RequestId::from("a-1"))
            .await
            .unwrap()
            .state,
        RequestState::Queued
    );
    assert_eq!(
        reopened
            .snapshot(RequestId::from("b-1"))
            .await
            .unwrap()
            .state,
        RequestState::Cancelled
    );
    let cancelled_replay = reopened.replay(RequestId::from("b-1"), 0).await.unwrap();
    assert_eq!(
        cancelled_replay
            .events
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>(),
        vec!["accepted", "started", "cancellation_requested", "cancelled"]
    );
    assert_eq!(
        cancelled_replay.result.unwrap().payload,
        b"persisted cancellation"
    );

    close(reopened, &directory).await;
}

#[tokio::test]
async fn queued_behind_counts_only_later_nonterminal_project_work() {
    let (directory, path) = database_path("queued-behind");
    let store = Store::open(&path).unwrap();
    for (id, project, key, now) in [
        ("a-1", "project-a", "a-1", 10),
        ("a-2", "project-a", "a-2", 11),
        ("a-3", "project-a", "a-3", 12),
        ("b-1", "project-b", "b-1", 13),
    ] {
        store
            .accept(request(id, "caller", project, key, id.as_bytes()), now)
            .await
            .unwrap();
    }
    assert_eq!(
        store.queued_behind(RequestId::from("a-1")).await.unwrap(),
        2
    );
    assert_eq!(
        store.queued_behind(RequestId::from("a-2")).await.unwrap(),
        1
    );
    assert_eq!(
        store.queued_behind(RequestId::from("a-3")).await.unwrap(),
        0
    );
    assert_eq!(
        store.queued_behind(RequestId::from("b-1")).await.unwrap(),
        0
    );
    store
        .cancel(RequestId::from("a-2"), 14, b"cancelled".to_vec())
        .await
        .unwrap();
    assert_eq!(
        store.queued_behind(RequestId::from("a-1")).await.unwrap(),
        1
    );
    assert!(matches!(
        store.queued_behind(RequestId::from("missing")).await,
        Err(StoreError::RequestNotFound(_))
    ));

    close(store, &directory).await;
}

#[tokio::test]
async fn project_workload_reports_only_non_status_queued_and_active_work() {
    let (directory, path) = database_path("project-workload");
    let store = Store::open(&path).unwrap();

    let status = request_with_kind("status-a", "status", b"status");
    let legacy_status = request_with_kind("legacy-status-a", "daemon_status", b"legacy-status");
    for (accepted, now_ms) in [
        (status, 10),
        (legacy_status, 11),
        (
            request("work-a-1", "caller", "project-a", "work-a-1", b"first"),
            12,
        ),
        (
            request("work-a-2", "caller", "project-a", "work-a-2", b"second"),
            13,
        ),
        (
            request("work-b-1", "caller", "project-b", "work-b-1", b"other"),
            14,
        ),
    ] {
        store.accept(accepted, now_ms).await.unwrap();
    }

    assert_project_workload(&store, "project-a", 2, false).await;
    assert_project_workload(&store, "project-b", 1, false).await;
    assert_project_workload(&store, "missing-project", 0, false).await;

    let status = store.claim("worker", 20, 100).await.unwrap().unwrap();
    assert_eq!(status.lease.request_id, RequestId::from("status-a"));
    assert_project_workload(&store, "project-a", 2, false).await;
    store
        .finish(status.lease, 21, TerminalState::Succeeded, Vec::new())
        .await
        .unwrap();

    let legacy_status = store.claim("worker", 22, 100).await.unwrap().unwrap();
    assert_eq!(
        legacy_status.lease.request_id,
        RequestId::from("legacy-status-a")
    );
    assert_project_workload(&store, "project-a", 2, false).await;
    store
        .finish(
            legacy_status.lease,
            23,
            TerminalState::Succeeded,
            Vec::new(),
        )
        .await
        .unwrap();

    let work = store.claim("worker", 24, 100).await.unwrap().unwrap();
    assert_eq!(work.lease.request_id, RequestId::from("work-a-1"));
    assert_project_workload(&store, "project-a", 1, true).await;
    assert_eq!(
        store
            .cancel(work.lease.request_id.clone(), 25, b"cancelled".to_vec())
            .await
            .unwrap(),
        CancelOutcome::CancellationRequested
    );
    assert_project_workload(&store, "project-a", 1, true).await;
    store
        .finish(work.lease, 26, TerminalState::Succeeded, Vec::new())
        .await
        .unwrap();
    assert_project_workload(&store, "project-a", 1, false).await;

    close(store, &directory).await;
}

#[tokio::test]
async fn project_current_is_bounded_fifo_project_scoped_and_excludes_status() {
    let (directory, path) = database_path("project-current");
    let store = Store::open(&path).unwrap();
    seed_project_current_history(&store).await;
    seed_project_current_queue(&store).await;

    let current = store
        .project_current(ProjectId::from("project-a"))
        .await
        .unwrap();
    assert_eq!(current.queued.len(), MAX_PROJECT_CURRENT_QUEUED);
    assert!(current.queued_truncated);
    assert_eq!(current.queued[0].request_id, RequestId::from("queued-a-00"));
    assert_eq!(current.queued[0].queue_sequence, 6);
    assert_eq!(current.queued[0].accepted_at_ms, 200);
    assert_eq!(current.queued[0].completed_at_ms, None);
    assert_eq!(
        current.queued[MAX_PROJECT_CURRENT_QUEUED - 1].request_id,
        RequestId::from("queued-a-63")
    );
    let active = current.active.unwrap();
    assert_eq!(active.request_id, RequestId::from("active-a"));
    assert_eq!(active.state, RequestState::CancellationRequested);
    assert_eq!(active.completed_at_ms, None);
    let latest_terminal = current.latest_terminal.unwrap();
    assert_eq!(latest_terminal.request_id, RequestId::from("terminal-a-2"));
    assert_eq!(latest_terminal.state, RequestState::Succeeded);
    assert_eq!(latest_terminal.completed_at_ms, Some(100));

    let other = store
        .project_current(ProjectId::from("project-b"))
        .await
        .unwrap();
    assert_eq!(other.queued.len(), 1);
    assert_eq!(other.queued[0].request_id, RequestId::from("queued-b"));
    assert!(!other.queued_truncated);
    assert_eq!(other.active, None);
    assert_eq!(other.latest_terminal, None);

    let missing = store
        .project_current(ProjectId::from("missing-project"))
        .await
        .unwrap();
    assert!(missing.queued.is_empty());
    assert!(!missing.queued_truncated);
    assert_eq!(missing.active, None);
    assert_eq!(missing.latest_terminal, None);

    close(store, &directory).await;
}

#[tokio::test]
async fn terminal_result_and_gap_free_events_replay_atomically_after_reopen() {
    let (directory, path) = database_path("result-replay");
    let store = Store::open(&path).unwrap();
    store
        .accept(
            request("request-1", "caller", "project", "key", b"operation"),
            10,
        )
        .await
        .unwrap();
    let leased = store.claim("worker", 20, 100).await.unwrap().unwrap();
    let evidence = store
        .append_event(
            leased.lease.clone(),
            21,
            "evidence",
            b"event payload".to_vec(),
        )
        .await
        .unwrap();
    assert_eq!(evidence.sequence, 3);
    store
        .finish(
            leased.lease,
            22,
            TerminalState::Failed,
            b"terminal result".to_vec(),
        )
        .await
        .unwrap();

    let replay = store.replay(RequestId::from("request-1"), 2).await.unwrap();
    assert_eq!(
        replay
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![3, 4]
    );
    assert_eq!(replay.events[0].payload, b"event payload");
    assert_eq!(replay.result.as_ref().unwrap().state, RequestState::Failed);
    assert_eq!(replay.result.unwrap().payload, b"terminal result");
    store.shutdown().await.unwrap();

    let reopened = Store::open(&path).unwrap();
    let replay = reopened
        .replay(RequestId::from("request-1"), 0)
        .await
        .unwrap();
    assert_eq!(
        replay
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    assert_eq!(replay.result.unwrap().payload, b"terminal result");

    close(reopened, &directory).await;
}

#[tokio::test]
async fn flow_only_target_operations_hide_and_never_mutate_generic_work() {
    let (directory, path) = database_path("flow-only-target-mismatch");
    let store = Store::open(&path).unwrap();
    let request_id = RequestId::from("generic-request");
    store
        .accept(
            request(
                request_id.as_str(),
                "caller",
                "project",
                "key",
                b"generic operation",
            ),
            10,
        )
        .await
        .unwrap();
    let before_snapshot = store.snapshot(request_id.clone()).await.unwrap();
    let before_replay = store.replay(request_id.clone(), 0).await.unwrap();

    assert!(matches!(
        store
            .snapshot_with_expected_target(
                request_id.clone(),
                ExpectedOperationKind::FlowRun,
            )
            .await,
        Err(StoreError::RequestNotFound(found)) if found == request_id
    ));
    assert!(matches!(
        store
            .replay_with_expected_target(
                request_id.clone(),
                0,
                ExpectedOperationKind::FlowRun,
            )
            .await,
        Err(StoreError::RequestNotFound(found)) if found == request_id
    ));
    assert!(matches!(
        store
            .cancel_with_expected_target(
                request_id.clone(),
                11,
                b"must not persist".to_vec(),
                ExpectedOperationKind::FlowRun,
            )
            .await,
        Err(StoreError::RequestNotFound(found)) if found == request_id
    ));

    assert_eq!(
        store.snapshot(request_id.clone()).await.unwrap(),
        before_snapshot
    );
    assert_eq!(store.replay(request_id, 0).await.unwrap(), before_replay);
    close(store, &directory).await;
}

#[tokio::test]
async fn explicit_cancelled_finish_requires_durable_cancellation_and_then_fences_the_lease() {
    let (directory, path) = database_path("explicit-cancelled-finish");
    let store = Store::open(&path).unwrap();
    store
        .accept(
            request("request-1", "caller", "project", "key", b"operation"),
            10,
        )
        .await
        .unwrap();
    let leased = store.claim("worker", 20, 100).await.unwrap().unwrap();
    let consumed = leased.lease.clone();
    assert!(matches!(
        store
            .finish(
                leased.lease.clone(),
                21,
                TerminalState::Cancelled,
                b"truthful cancelled result".to_vec(),
            )
            .await,
        Err(StoreError::InvalidState(_))
    ));
    let unchanged = store.snapshot(RequestId::from("request-1")).await.unwrap();
    assert_eq!(unchanged.state, RequestState::Leased);
    let unchanged_replay = store.replay(RequestId::from("request-1"), 0).await.unwrap();
    assert!(unchanged_replay.result.is_none());
    assert_eq!(
        unchanged_replay
            .events
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>(),
        vec!["accepted", "started"]
    );

    assert_eq!(
        store
            .cancel(
                RequestId::from("request-1"),
                22,
                b"truthful cancelled result".to_vec(),
            )
            .await
            .unwrap(),
        CancelOutcome::CancellationRequested
    );
    let finished = store
        .finish(
            leased.lease,
            23,
            TerminalState::Cancelled,
            b"ignored worker result".to_vec(),
        )
        .await
        .unwrap();
    assert_eq!(finished.state, RequestState::Cancelled);
    assert_eq!(finished.payload, b"truthful cancelled result");

    let replay = store.replay(RequestId::from("request-1"), 0).await.unwrap();
    assert_eq!(
        replay
            .events
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>(),
        vec!["accepted", "started", "cancellation_requested", "cancelled"]
    );
    assert_eq!(replay.result.unwrap().state, RequestState::Cancelled);
    assert!(matches!(
        store
            .finish(
                consumed,
                24,
                TerminalState::Cancelled,
                b"replacement".to_vec(),
            )
            .await,
        Err(StoreError::StaleLease(_))
    ));

    close(store, &directory).await;
}

#[tokio::test]
async fn failed_terminal_event_insert_rolls_back_the_result_transition() {
    let (directory, path) = database_path("result-rollback");
    let store = Store::open(&path).unwrap();
    store
        .accept(
            request("request-1", "caller", "project", "key", b"operation"),
            10,
        )
        .await
        .unwrap();
    let leased = store.claim("worker", 20, 100).await.unwrap().unwrap();
    store.shutdown().await.unwrap();

    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER reject_completed_event
             BEFORE INSERT ON events
             WHEN NEW.kind = 'completed'
             BEGIN
                 SELECT RAISE(ABORT, 'injected terminal event failure');
             END;",
        )
        .unwrap();
    drop(connection);

    let reopened = Store::open(&path).unwrap();
    assert!(matches!(
        reopened
            .finish(
                leased.lease,
                21,
                TerminalState::Succeeded,
                b"must roll back".to_vec()
            )
            .await,
        Err(StoreError::Sqlite(_))
    ));
    let snapshot = reopened
        .snapshot(RequestId::from("request-1"))
        .await
        .unwrap();
    assert_eq!(snapshot.state, RequestState::Leased);
    let replay = reopened
        .replay(RequestId::from("request-1"), 0)
        .await
        .unwrap();
    assert_eq!(
        replay
            .events
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>(),
        vec!["accepted", "started"]
    );
    assert!(replay.result.is_none());

    close(reopened, &directory).await;
}

#[tokio::test]
async fn policy_versions_and_grant_revocation_are_durable_and_idempotent() {
    let (directory, path) = database_path("policy-version");
    let store = Store::open(&path).unwrap();
    store
        .register_caller(
            CallerId::from("policy-caller"),
            CallerCredential::new("policy credential"),
            1,
        )
        .await
        .unwrap();

    let first = store
        .put_grant(PutGrant {
            grant: grant(
                "grant-1",
                "policy-caller",
                "project-a",
                "read",
                ResourceScope::Any,
            ),
            created_at_ms: 10,
        })
        .await
        .unwrap();
    assert_eq!(first.project_id, ProjectId::from("project-a"));
    assert_eq!(first.version, 1);
    assert_eq!(first.updated_at_ms, 10);

    let second = store
        .put_grant(PutGrant {
            grant: grant(
                "grant-2",
                "policy-caller",
                "project-a",
                "write",
                ResourceScope::Any,
            ),
            created_at_ms: 11,
        })
        .await
        .unwrap();
    assert_eq!(second.version, 2);
    let other_project = store
        .put_grant(PutGrant {
            grant: grant(
                "grant-other-project",
                "policy-caller",
                "project-b",
                "read",
                ResourceScope::Any,
            ),
            created_at_ms: 12,
        })
        .await
        .unwrap();
    assert_eq!(other_project.version, 1);
    store.shutdown().await.unwrap();

    let reopened = Store::open(&path).unwrap();
    assert_eq!(
        reopened
            .revoke_grant(GrantId::from("grant-1"), 13)
            .await
            .unwrap(),
        GrantRevocation::Revoked
    );
    assert_eq!(
        reopened
            .revoke_grant(GrantId::from("grant-1"), 14)
            .await
            .unwrap(),
        GrantRevocation::AlreadyRevoked
    );
    assert_eq!(
        reopened
            .revoke_grant(GrantId::from("missing-grant"), 14)
            .await
            .unwrap(),
        GrantRevocation::UnknownGrant
    );
    let after_revocation = reopened
        .put_grant(PutGrant {
            grant: grant(
                "grant-3",
                "policy-caller",
                "project-a",
                "admin",
                ResourceScope::Any,
            ),
            created_at_ms: 15,
        })
        .await
        .unwrap();
    assert_eq!(after_revocation.version, 4);
    assert_eq!(after_revocation.updated_at_ms, 15);

    close(reopened, &directory).await;
}

#[tokio::test]
async fn authorization_is_default_deny_and_matches_exact_policy_dimensions() {
    let (directory, path) = database_path("policy-matching");
    let store = Store::open(&path).unwrap();
    for (caller_id, credential) in [
        ("scope-caller", "scope credential"),
        ("other-caller", "other credential"),
    ] {
        store
            .register_caller(
                CallerId::from(caller_id),
                CallerCredential::new(credential),
                1,
            )
            .await
            .unwrap();
    }
    store
        .put_grant(PutGrant {
            grant: grant(
                "exact-read",
                "scope-caller",
                "scope-project",
                "read",
                ResourceScope::Exact(resource("document-1")),
            ),
            created_at_ms: 10,
        })
        .await
        .unwrap();

    assert_eq!(
        store
            .authorize(
                authorization("scope-caller", "scope-project", "read", "document-1", None,),
                20,
                100,
            )
            .await
            .unwrap(),
        AuthorizationOutcome::Allowed
    );
    for denied in [
        authorization("other-caller", "scope-project", "read", "document-1", None),
        authorization("scope-caller", "other-project", "read", "document-1", None),
        authorization("scope-caller", "scope-project", "write", "document-1", None),
        authorization("scope-caller", "scope-project", "read", "document-2", None),
    ] {
        assert_eq!(
            store.authorize(denied, 20, 100).await.unwrap(),
            AuthorizationOutcome::Denied
        );
    }

    close(store, &directory).await;
}

#[tokio::test]
async fn any_scope_allows_every_resource_while_exact_deny_takes_precedence() {
    let (directory, path) = database_path("policy-any-and-deny");
    let store = Store::open(&path).unwrap();
    store
        .register_caller(
            CallerId::from("scope-caller"),
            CallerCredential::new("scope credential"),
            1,
        )
        .await
        .unwrap();
    for (grant_id, capability_name, created_at_ms) in [
        ("any-export", "export", 10),
        ("allow-delete-any", "delete", 11),
    ] {
        store
            .put_grant(PutGrant {
                grant: grant(
                    grant_id,
                    "scope-caller",
                    "scope-project",
                    capability_name,
                    ResourceScope::Any,
                ),
                created_at_ms,
            })
            .await
            .unwrap();
    }
    assert_eq!(
        store
            .authorize(
                authorization(
                    "scope-caller",
                    "scope-project",
                    "export",
                    "arbitrary-resource",
                    None,
                ),
                20,
                100,
            )
            .await
            .unwrap(),
        AuthorizationOutcome::Allowed
    );

    let mut deny_exact = grant(
        "deny-delete-protected",
        "scope-caller",
        "scope-project",
        "delete",
        ResourceScope::Exact(resource("protected")),
    );
    deny_exact.effect = Effect::Deny;
    store
        .put_grant(PutGrant {
            grant: deny_exact,
            created_at_ms: 12,
        })
        .await
        .unwrap();
    assert_eq!(
        store
            .authorize(
                authorization("scope-caller", "scope-project", "delete", "protected", None,),
                20,
                100,
            )
            .await
            .unwrap(),
        AuthorizationOutcome::Denied
    );
    assert_eq!(
        store
            .authorize(
                authorization("scope-caller", "scope-project", "delete", "ordinary", None,),
                20,
                100,
            )
            .await
            .unwrap(),
        AuthorizationOutcome::Allowed
    );

    close(store, &directory).await;
}

#[tokio::test]
async fn authorization_honors_inclusive_expiry_and_revocation_boundaries() {
    let (directory, path) = database_path("policy-boundaries");
    let store = Store::open(&path).unwrap();
    store
        .register_caller(
            CallerId::from("boundary-caller"),
            CallerCredential::new("boundary credential"),
            1,
        )
        .await
        .unwrap();

    let mut expiring = grant(
        "expiring-grant",
        "boundary-caller",
        "boundary-project",
        "expiring",
        ResourceScope::Any,
    );
    expiring.expires_at_ms = Some(50);
    store
        .put_grant(PutGrant {
            grant: expiring,
            created_at_ms: 10,
        })
        .await
        .unwrap();
    let mut revoked = grant(
        "revoked-grant",
        "boundary-caller",
        "boundary-project",
        "revoked",
        ResourceScope::Any,
    );
    revoked.revoked_at_ms = Some(70);
    store
        .put_grant(PutGrant {
            grant: revoked,
            created_at_ms: 11,
        })
        .await
        .unwrap();

    for (capability_name, now_ms, expected) in [
        ("expiring", 49, AuthorizationOutcome::Allowed),
        ("expiring", 50, AuthorizationOutcome::Denied),
        ("revoked", 69, AuthorizationOutcome::Allowed),
        ("revoked", 70, AuthorizationOutcome::Denied),
    ] {
        assert_eq!(
            store
                .authorize(
                    authorization(
                        "boundary-caller",
                        "boundary-project",
                        capability_name,
                        "resource",
                        None,
                    ),
                    now_ms,
                    100,
                )
                .await
                .unwrap(),
            expected
        );
    }

    close(store, &directory).await;
}

#[tokio::test]
async fn authorization_rechecks_caller_revocation_after_grant_creation() {
    let (directory, path) = database_path("policy-caller-revocation");
    let store = Store::open(&path).unwrap();
    store
        .register_caller(
            CallerId::from("revocable-policy-caller"),
            CallerCredential::new("revocable policy credential"),
            1,
        )
        .await
        .unwrap();
    store
        .put_grant(PutGrant {
            grant: grant(
                "revocable-caller-grant",
                "revocable-policy-caller",
                "revocable-project",
                "operate",
                ResourceScope::Any,
            ),
            created_at_ms: 10,
        })
        .await
        .unwrap();
    let request = authorization(
        "revocable-policy-caller",
        "revocable-project",
        "operate",
        "resource",
        None,
    );
    assert_eq!(
        store.authorize(request.clone(), 20, 100).await.unwrap(),
        AuthorizationOutcome::Allowed
    );
    assert_eq!(
        store
            .revoke_caller(CallerId::from("revocable-policy-caller"), 21)
            .await
            .unwrap(),
        CallerRevocation::Revoked
    );
    assert_eq!(
        store.authorize(request, 22, 100).await.unwrap(),
        AuthorizationOutcome::Denied
    );

    close(store, &directory).await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // The exact receipt lifecycle is one atomic end-to-end invariant.
async fn stateful_flow_approval_is_request_bound_and_reusable_after_restart() {
    let (directory, path, store, flow_resource) =
        open_flow_authorization_store("stateful-flow-approval", ApprovalRequirement::None).await;
    let initial = flow_authorization_request(
        "stateful-flow-a",
        flow_resource.clone(),
        None,
        true,
        "stateful-challenge-a",
    );
    let FlowAuthorizationOutcome::ApprovalRequired {
        approval_id,
        expires_at_ms,
    } = store.authorize_flow_run(initial, 100, 20).await.unwrap()
    else {
        panic!("stateful schema must require approval despite an unconditional grant")
    };
    assert_eq!(expires_at_ms, 120);

    let repeated = store
        .authorize_flow_run(
            flow_authorization_request(
                "stateful-flow-a",
                flow_resource.clone(),
                None,
                true,
                "stateful-challenge-retry",
            ),
            101,
            20,
        )
        .await
        .unwrap();
    assert_eq!(
        repeated,
        FlowAuthorizationOutcome::ApprovalRequired {
            approval_id: approval_id.clone(),
            expires_at_ms: 120,
        }
    );

    assert_eq!(
        store
            .revoke_grant(GrantId::from("flow-auth-grant"), 102)
            .await
            .unwrap(),
        GrantRevocation::Revoked
    );
    let mut approval_grant = grant(
        "flow-auth-approval-grant",
        "flow-auth-subject",
        "flow-auth-project",
        "flow.run",
        ResourceScope::Exact(flow_resource.clone()),
    );
    approval_grant.approval = ApprovalRequirement::Once;
    store
        .put_grant(PutGrant {
            grant: approval_grant,
            created_at_ms: 102,
        })
        .await
        .unwrap();
    assert_eq!(
        store
            .decide_approval(
                approval_id.clone(),
                CallerId::from("flow-auth-reviewer"),
                ApprovalDecision::Approve,
                103,
            )
            .await
            .unwrap(),
        ApprovalDecisionOutcome::Approved
    );

    assert_eq!(
        store
            .authorize(
                authorization(
                    "flow-auth-subject",
                    "flow-auth-project",
                    "flow.run",
                    flow_resource.as_str(),
                    Some(approval_id.clone()),
                ),
                104,
                20,
            )
            .await
            .unwrap(),
        AuthorizationOutcome::Denied,
        "a flow-bound receipt must not be consumable through generic authorization"
    );
    assert_eq!(
        store
            .authorize_flow_run(
                flow_authorization_request(
                    "stateful-flow-wrong",
                    flow_resource.clone(),
                    Some(approval_id.clone()),
                    true,
                    "stateful-wrong-request",
                ),
                105,
                20,
            )
            .await
            .unwrap(),
        FlowAuthorizationOutcome::Denied
    );

    let accepted = flow_authorization_request(
        "stateful-flow-a",
        flow_resource.clone(),
        Some(approval_id.clone()),
        true,
        "stateful-accept",
    );
    assert!(matches!(
        store
            .authorize_flow_run(accepted.clone(), 106, 20)
            .await
            .unwrap(),
        FlowAuthorizationOutcome::Accepted(AcceptOutcome::Created { .. })
    ));
    let mut pending_alias = accepted.clone();
    pending_alias.accept.request_id = RequestId::from("stateful-flow-alias");
    pending_alias.audit.event_id = "stateful-flow-alias".to_owned();
    assert!(matches!(
        store.authorize_flow_run(pending_alias, 106, 20).await,
        Err(StoreError::RequestIdConflict(request_id))
            if request_id == RequestId::from("stateful-flow-alias")
    ));
    let lease = store
        .claim("flow-auth-worker", 107, 1_000)
        .await
        .unwrap()
        .unwrap()
        .lease;
    assert_eq!(lease.request_id, RequestId::from("stateful-flow-a"));
    store
        .validate_flow_operation_resource(lease.clone(), flow_resource.clone(), 120)
        .await
        .unwrap();
    assert!(matches!(
        store
            .validate_flow_operation_resource(
                lease.clone(),
                ResourceName::parse("flow:other:revision=1:digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:workspace=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
                120,
            )
            .await,
        Err(StoreError::CorruptFlowAuthorization(request_id))
            if request_id == RequestId::from("stateful-flow-a")
    ));
    assert_eq!(
        store
            .validate_flow_effect_authorization(lease.clone(), 121)
            .await
            .unwrap(),
        FlowEffectAuthorization::Allowed,
        "a receipt consumed before expiry remains reusable at later boundaries"
    );
    assert!(matches!(
        store
            .authorize_flow_run(
                AuthorizeFlowRun {
                    audit: AuthorizationAudit {
                        event_id: "stateful-existing".to_owned(),
                        ..accepted.audit
                    },
                    ..accepted
                },
                122,
                20,
            )
            .await
            .unwrap(),
        FlowAuthorizationOutcome::Accepted(AcceptOutcome::Existing { .. })
    ));
    store.shutdown().await.unwrap();

    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT state, flow_request_id, decided_at_ms, consumed_at_ms
                 FROM approvals WHERE approval_id = ?1",
                [approval_id.as_str()],
                |row| Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                )),
            )
            .unwrap(),
        (
            "consumed".to_owned(),
            "stateful-flow-a".to_owned(),
            103,
            106
        )
    );
    drop(connection);

    let reopened = Store::open(&path).unwrap();
    assert_eq!(
        reopened
            .validate_flow_effect_authorization(lease.clone(), 123)
            .await
            .unwrap(),
        FlowEffectAuthorization::Allowed
    );
    assert_eq!(
        reopened
            .revoke_caller(CallerId::from("flow-auth-subject"), 124)
            .await
            .unwrap(),
        CallerRevocation::Revoked
    );
    assert_eq!(
        reopened
            .validate_flow_effect_authorization(lease.clone(), 125)
            .await
            .unwrap(),
        FlowEffectAuthorization::Denied
    );
    reopened.shutdown().await.unwrap();

    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE approvals SET flow_request_id = 'wrong-request'
             WHERE approval_id = ?1",
            [approval_id.as_str()],
        )
        .unwrap();
    drop(connection);
    let reopened = Store::open(&path).unwrap();
    assert!(matches!(
        reopened
            .validate_flow_effect_authorization(lease, 126)
            .await,
        Err(StoreError::CorruptFlowAuthorization(request_id))
            if request_id == RequestId::from("stateful-flow-a")
    ));

    close(reopened, &directory).await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One test covers both durable authorization proof kinds.
async fn flow_effect_boundaries_recheck_unconditional_and_approved_policy() {
    let (directory, _path, store, flow_resource) =
        open_flow_authorization_store("flow-effect-policy", ApprovalRequirement::None).await;
    assert!(matches!(
        store
            .authorize_flow_run(
                flow_authorization_request(
                    "read-only-unconditional",
                    flow_resource.clone(),
                    None,
                    false,
                    "read-only-unconditional-accept",
                ),
                100,
                20,
            )
            .await
            .unwrap(),
        FlowAuthorizationOutcome::Accepted(AcceptOutcome::Created { .. })
    ));
    let unconditional = store
        .claim("flow-auth-worker-a", 101, 1_000)
        .await
        .unwrap()
        .unwrap()
        .lease;
    assert_eq!(
        store
            .validate_flow_effect_authorization(unconditional.clone(), 102)
            .await
            .unwrap(),
        FlowEffectAuthorization::Allowed
    );
    store
        .revoke_grant(GrantId::from("flow-auth-grant"), 103)
        .await
        .unwrap();
    let mut approval_grant = grant(
        "read-only-approval-grant",
        "flow-auth-subject",
        "flow-auth-project",
        "flow.run",
        ResourceScope::Exact(flow_resource.clone()),
    );
    approval_grant.approval = ApprovalRequirement::Once;
    store
        .put_grant(PutGrant {
            grant: approval_grant,
            created_at_ms: 104,
        })
        .await
        .unwrap();
    assert_eq!(
        store
            .validate_flow_effect_authorization(unconditional.clone(), 105)
            .await
            .unwrap(),
        FlowEffectAuthorization::Denied,
        "a receiptless flow cannot cross a boundary after policy requires approval"
    );
    store
        .finish(
            unconditional,
            106,
            TerminalState::Failed,
            b"authorization revoked before the effect".to_vec(),
        )
        .await
        .unwrap();

    let FlowAuthorizationOutcome::ApprovalRequired { approval_id, .. } = store
        .authorize_flow_run(
            flow_authorization_request(
                "read-only-approved",
                flow_resource.clone(),
                None,
                false,
                "read-only-approved-challenge",
            ),
            200,
            10,
        )
        .await
        .unwrap()
    else {
        panic!("policy-approved read-only flow must create an exact challenge")
    };
    store
        .decide_approval(
            approval_id.clone(),
            CallerId::from("flow-auth-reviewer"),
            ApprovalDecision::Approve,
            201,
        )
        .await
        .unwrap();
    assert!(matches!(
        store
            .authorize_flow_run(
                flow_authorization_request(
                    "read-only-approved",
                    flow_resource.clone(),
                    Some(approval_id),
                    false,
                    "read-only-approved-accept",
                ),
                202,
                10,
            )
            .await
            .unwrap(),
        FlowAuthorizationOutcome::Accepted(AcceptOutcome::Created { .. })
    ));
    let approved = store
        .claim("flow-auth-worker-b", 203, 1_000)
        .await
        .unwrap()
        .unwrap()
        .lease;
    assert_eq!(
        store
            .validate_flow_effect_authorization(approved.clone(), 211)
            .await
            .unwrap(),
        FlowEffectAuthorization::Allowed
    );
    let mut deny = grant(
        "read-only-deny",
        "flow-auth-subject",
        "flow-auth-project",
        "flow.run",
        ResourceScope::Exact(flow_resource),
    );
    deny.effect = Effect::Deny;
    store
        .put_grant(PutGrant {
            grant: deny,
            created_at_ms: 212,
        })
        .await
        .unwrap();
    assert_eq!(
        store
            .validate_flow_effect_authorization(approved, 213)
            .await
            .unwrap(),
        FlowEffectAuthorization::Denied
    );

    close(store, &directory).await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Expiry and rollback exercise one receipt state machine.
async fn flow_approval_expiry_and_failed_accept_do_not_consume_receipts() {
    let (directory, path, store, flow_resource) =
        open_flow_authorization_store("flow-approval-rollback", ApprovalRequirement::Once).await;
    let FlowAuthorizationOutcome::ApprovalRequired {
        approval_id: expiring,
        expires_at_ms: 105,
    } = store
        .authorize_flow_run(
            flow_authorization_request(
                "flow-expiring",
                flow_resource.clone(),
                None,
                false,
                "flow-expiring-challenge",
            ),
            100,
            5,
        )
        .await
        .unwrap()
    else {
        panic!("flow should require an expiring approval")
    };
    assert_eq!(
        store
            .decide_approval(
                expiring.clone(),
                CallerId::from("flow-auth-reviewer"),
                ApprovalDecision::Approve,
                105,
            )
            .await
            .unwrap(),
        ApprovalDecisionOutcome::Expired
    );
    assert_eq!(
        store
            .authorize_flow_run(
                flow_authorization_request(
                    "flow-expiring",
                    flow_resource.clone(),
                    Some(expiring),
                    false,
                    "flow-expiring-retry",
                ),
                106,
                5,
            )
            .await
            .unwrap(),
        FlowAuthorizationOutcome::ApprovalExpired
    );

    let FlowAuthorizationOutcome::ApprovalRequired {
        approval_id: approved,
        ..
    } = store
        .authorize_flow_run(
            flow_authorization_request(
                "flow-audit-rollback",
                flow_resource.clone(),
                None,
                false,
                "flow-rollback-challenge",
            ),
            110,
            20,
        )
        .await
        .unwrap()
    else {
        panic!("flow should require approval")
    };
    store
        .decide_approval(
            approved.clone(),
            CallerId::from("flow-auth-reviewer"),
            ApprovalDecision::Approve,
            111,
        )
        .await
        .unwrap();
    store
        .append_audit_event(audit_event(
            "flow-authorization-collision",
            "flow-auth-project",
            "flow-auth-subject",
            10,
            10_000,
        ))
        .await
        .unwrap();
    assert!(matches!(
        store
            .authorize_flow_run(
                flow_authorization_request(
                    "flow-audit-rollback",
                    flow_resource.clone(),
                    Some(approved.clone()),
                    false,
                    "flow-authorization-collision",
                ),
                112,
                20,
            )
            .await,
        Err(StoreError::AuditEventAlreadyExists)
    ));
    assert!(matches!(
        store
            .authorize_flow_run(
                flow_authorization_request(
                    "flow-audit-rollback",
                    flow_resource,
                    Some(approved.clone()),
                    false,
                    "flow-rollback-accepted",
                ),
                113,
                20,
            )
            .await
            .unwrap(),
        FlowAuthorizationOutcome::Accepted(AcceptOutcome::Created { .. })
    ));
    store.shutdown().await.unwrap();

    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT state, flow_request_id FROM approvals WHERE approval_id = ?1",
                [approved.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .unwrap(),
        ("consumed".to_owned(), "flow-audit-rollback".to_owned())
    );
    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Corrupt, missing, and valid FIFO heads form one recovery contract.
async fn flow_rows_without_exact_authorization_proof_never_execute() {
    let (directory, path, store, flow_resource) =
        open_flow_authorization_store("flow-proof-corruption", ApprovalRequirement::None).await;
    let mut bypass = request(
        "flow-public-bypass",
        "flow-auth-subject",
        "flow-auth-project",
        "flow-public-bypass",
        b"flow",
    );
    bypass.operation_kind = "flow_run".to_owned();
    assert!(matches!(
        store.accept(bypass, 20).await,
        Err(StoreError::InvalidState(_))
    ));
    for (request_id, audit_id) in [
        ("flow-corrupt-proof", "flow-corrupt-proof-accept"),
        ("flow-missing-proof", "flow-missing-proof-accept"),
        ("flow-valid-followup", "flow-valid-followup-accept"),
    ] {
        assert!(matches!(
            store
                .authorize_flow_run(
                    flow_authorization_request(
                        request_id,
                        flow_resource.clone(),
                        None,
                        false,
                        audit_id,
                    ),
                    30,
                    20,
                )
                .await
                .unwrap(),
            FlowAuthorizationOutcome::Accepted(AcceptOutcome::Created { .. })
        ));
    }
    store.shutdown().await.unwrap();

    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE flow_authorizations SET effect_fingerprint = zeroblob(32)
             WHERE request_id = 'flow-corrupt-proof'",
            [],
        )
        .unwrap();
    connection
        .execute(
            "DELETE FROM flow_authorizations WHERE request_id = 'flow-missing-proof'",
            [],
        )
        .unwrap();
    drop(connection);

    let reopened = Store::open(&path).unwrap();
    assert!(matches!(
        reopened.claim("flow-proof-worker", 32, 100).await,
        Err(StoreError::CorruptFlowAuthorization(corrupt))
            if corrupt == RequestId::from("flow-corrupt-proof")
    ));
    let before = reopened
        .replay(RequestId::from("flow-corrupt-proof"), 0)
        .await
        .unwrap();
    assert_eq!(
        before
            .events
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>(),
        vec!["accepted"]
    );
    assert!(before.result.is_none());
    assert_eq!(
        reopened
            .fail_corrupt_flow_authorization(
                RequestId::from("flow-corrupt-proof"),
                32,
                b"corrupt proof".to_vec(),
            )
            .await
            .unwrap(),
        FlowAuthorizationRecoveryOutcome::Failed(super::StoredResult {
            state: RequestState::Failed,
            payload: b"corrupt proof".to_vec(),
            completed_at_ms: 32,
        })
    );
    let after = reopened
        .replay(RequestId::from("flow-corrupt-proof"), 0)
        .await
        .unwrap();
    assert_eq!(
        after
            .events
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>(),
        vec!["accepted", "failed"]
    );
    assert_eq!(after.result.unwrap().payload, b"corrupt proof");

    assert!(matches!(
        reopened.claim("flow-proof-worker", 33, 100).await,
        Err(StoreError::CorruptFlowAuthorization(corrupt))
            if corrupt == RequestId::from("flow-missing-proof")
    ));
    assert_eq!(
        reopened
            .cancel(
                RequestId::from("flow-missing-proof"),
                34,
                b"cancelled during quarantine".to_vec(),
            )
            .await
            .unwrap(),
        CancelOutcome::Cancelled
    );
    assert_eq!(
        reopened
            .fail_corrupt_flow_authorization(
                RequestId::from("flow-missing-proof"),
                35,
                b"must not replace cancellation".to_vec(),
            )
            .await
            .unwrap(),
        FlowAuthorizationRecoveryOutcome::AlreadyTerminal(super::StoredResult {
            state: RequestState::Cancelled,
            payload: b"cancelled during quarantine".to_vec(),
            completed_at_ms: 34,
        })
    );
    assert!(matches!(
        reopened
            .authorize_flow_run(
                flow_authorization_request(
                    "flow-missing-proof",
                    flow_resource,
                    None,
                    false,
                    "flow-missing-terminal-retry",
                ),
                36,
                20,
            )
            .await
            .unwrap(),
        FlowAuthorizationOutcome::Accepted(AcceptOutcome::Existing {
            state: RequestState::Cancelled,
            ..
        })
    ));
    assert_eq!(
        reopened
            .fail_corrupt_flow_authorization(
                RequestId::from("flow-valid-followup"),
                37,
                b"must not fail valid flow".to_vec(),
            )
            .await
            .unwrap(),
        FlowAuthorizationRecoveryOutcome::NoLongerEligible
    );
    let valid = reopened
        .claim("flow-proof-worker", 38, 100)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        valid.lease.request_id,
        RequestId::from("flow-valid-followup")
    );
    assert_eq!(
        reopened
            .validate_flow_effect_authorization(valid.lease, 39)
            .await
            .unwrap(),
        FlowEffectAuthorization::Allowed
    );

    close(reopened, &directory).await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Receipt corruption and both replay identities are one contract.
async fn quarantined_receipt_corruption_replays_for_exact_and_idempotent_retries() {
    let (directory, path, store, flow_resource) =
        open_flow_authorization_store("flow-receipt-quarantine", ApprovalRequirement::None).await;
    let FlowAuthorizationOutcome::ApprovalRequired { approval_id, .. } = store
        .authorize_flow_run(
            flow_authorization_request(
                "flow-corrupt-receipt",
                flow_resource.clone(),
                None,
                true,
                "flow-corrupt-receipt-challenge",
            ),
            100,
            20,
        )
        .await
        .unwrap()
    else {
        panic!("stateful flow must require an exact receipt")
    };
    store
        .decide_approval(
            approval_id.clone(),
            CallerId::from("flow-auth-reviewer"),
            ApprovalDecision::Approve,
            101,
        )
        .await
        .unwrap();
    let accepted = flow_authorization_request(
        "flow-corrupt-receipt",
        flow_resource,
        Some(approval_id.clone()),
        true,
        "flow-corrupt-receipt-accept",
    );
    assert!(matches!(
        store
            .authorize_flow_run(accepted.clone(), 102, 20)
            .await
            .unwrap(),
        FlowAuthorizationOutcome::Accepted(AcceptOutcome::Created { .. })
    ));
    store.shutdown().await.unwrap();

    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE approvals SET flow_request_id = 'wrong-request'
             WHERE approval_id = ?1",
            [approval_id.as_str()],
        )
        .unwrap();
    drop(connection);

    let reopened = Store::open(&path).unwrap();
    assert!(matches!(
        reopened.claim("flow-receipt-worker", 103, 100).await,
        Err(StoreError::CorruptFlowAuthorization(request_id))
            if request_id == RequestId::from("flow-corrupt-receipt")
    ));
    assert!(matches!(
        reopened
            .fail_corrupt_flow_authorization(
                RequestId::from("flow-corrupt-receipt"),
                104,
                b"receipt corruption failure".to_vec(),
            )
            .await
            .unwrap(),
        FlowAuthorizationRecoveryOutcome::Failed(_)
    ));

    let mut exact = accepted.clone();
    exact.audit.event_id = "flow-corrupt-receipt-exact-retry".to_owned();
    assert!(matches!(
        reopened.authorize_flow_run(exact, 105, 20).await.unwrap(),
        FlowAuthorizationOutcome::Accepted(AcceptOutcome::Existing {
            state: RequestState::Failed,
            ..
        })
    ));
    let mut idempotent = accepted;
    idempotent.accept.request_id = RequestId::from("flow-corrupt-receipt-observer");
    idempotent.audit.event_id = "flow-corrupt-receipt-idempotent-retry".to_owned();
    assert!(matches!(
        reopened.authorize_flow_run(idempotent, 106, 20).await,
        Err(StoreError::RequestIdConflict(request_id))
            if request_id == RequestId::from("flow-corrupt-receipt-observer")
    ));
    assert_eq!(
        reopened
            .replay(RequestId::from("flow-corrupt-receipt"), 0)
            .await
            .unwrap()
            .result
            .unwrap()
            .payload,
        b"receipt corruption failure"
    );

    close(reopened, &directory).await;
}

#[tokio::test]
async fn cancellation_fences_effect_authorization_and_effect_started_checkpoint() {
    let (directory, path) = database_path("flow-effect-cancel-fence");
    let store = Store::open(&path).unwrap();
    let (lease, mut run, evaluated) = checkpointed_flow(&store, "flow-effect-cancel").await;
    let effect = match evaluated.decision() {
        RunDecision::EvaluateEffect { effect, .. } => effect.clone(),
        other => panic!("expected effect evaluation, got {other:?}"),
    };
    assert_eq!(
        store
            .validate_flow_effect_authorization(lease.clone(), 23)
            .await
            .unwrap(),
        FlowEffectAuthorization::Allowed
    );
    assert_eq!(
        store
            .cancel(lease.request_id.clone(), 24, b"cancelled".to_vec())
            .await
            .unwrap(),
        CancelOutcome::CancellationRequested
    );
    assert!(matches!(
        store
            .validate_flow_effect_authorization(lease.clone(), 25)
            .await,
        Err(StoreError::StaleLease(request_id)) if request_id == lease.request_id
    ));
    let started = run.prepare_effect(&effect, 25).unwrap();
    assert!(matches!(started.decision(), RunDecision::Execute { .. }));
    assert!(matches!(
        store
            .save_flow_checkpoint(SaveFlowCheckpoint {
                lease: lease.clone(),
                expected_revision: 2,
                snapshot: started.snapshot().clone(),
                transition: started.transition().cloned(),
                terminal_result: None,
                updated_at_ms: 25,
            })
            .await,
        Err(StoreError::FlowEffectStartConflict(request_id)) if request_id == lease.request_id
    ));

    close(store, &directory).await;
}

#[tokio::test]
async fn approvals_are_exact_durable_and_consumed_atomically_once() {
    let (directory, path, store) = open_approval_store("durable-approvals").await;
    let exact_request = authorization(
        "approval-subject",
        "approval-project",
        "deploy",
        "release-a",
        None,
    );
    let AuthorizationOutcome::ApprovalRequired {
        approval_id,
        expires_at_ms,
    } = store
        .authorize(exact_request.clone(), 100, 20)
        .await
        .unwrap()
    else {
        panic!("approval-requiring grant should return an approval ID")
    };
    assert_eq!(expires_at_ms, 120);
    store.shutdown().await.unwrap();

    let reopened = Store::open(&path).unwrap();
    let mut repeated = exact_request.clone();
    repeated.approval_id = Some(approval_id.clone());
    assert_eq!(
        reopened.authorize(repeated.clone(), 101, 20).await.unwrap(),
        AuthorizationOutcome::ApprovalRequired {
            approval_id: approval_id.clone(),
            expires_at_ms: 120,
        }
    );
    assert_eq!(
        reopened
            .authorize(
                authorization(
                    "approval-subject",
                    "approval-project",
                    "deploy",
                    "release-b",
                    Some(approval_id.clone()),
                ),
                101,
                20,
            )
            .await
            .unwrap(),
        AuthorizationOutcome::Denied
    );
    assert_eq!(
        reopened
            .decide_approval(
                approval_id.clone(),
                CallerId::from("approval-reviewer"),
                ApprovalDecision::Approve,
                102,
            )
            .await
            .unwrap(),
        ApprovalDecisionOutcome::Approved
    );

    let first_store = reopened.clone();
    let second_store = reopened.clone();
    let first_request = repeated.clone();
    let second_request = repeated.clone();
    let (first, second) = tokio::join!(
        first_store.authorize(first_request, 103, 20),
        second_store.authorize(second_request, 103, 20),
    );
    let outcomes = [first.unwrap(), second.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == AuthorizationOutcome::Allowed)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == AuthorizationOutcome::Denied)
            .count(),
        1
    );
    reopened.shutdown().await.unwrap();

    let reopened = Store::open(&path).unwrap();
    assert_eq!(
        reopened.authorize(repeated, 104, 20).await.unwrap(),
        AuthorizationOutcome::Denied
    );

    close(reopened, &directory).await;
}

#[tokio::test]
async fn project_approval_decisions_require_active_requester_and_exact_project() {
    let (directory, _path, store) = open_approval_store("project-bound-approval").await;
    let AuthorizationOutcome::ApprovalRequired { approval_id, .. } = store
        .authorize(
            authorization(
                "approval-subject",
                "approval-project",
                "deploy",
                "release-a",
                None,
            ),
            100,
            20,
        )
        .await
        .unwrap()
    else {
        panic!("approval-requiring grant should return an approval ID")
    };

    assert!(matches!(
        store
            .decide_project_approval(
                approval_id.clone(),
                ProjectId::from("approval-project"),
                CallerId::from("unknown-reviewer"),
                ApprovalDecision::Approve,
                101,
            )
            .await,
        Err(StoreError::InvalidApprovalState)
    ));
    for decision in [ApprovalDecision::Approve, ApprovalDecision::Deny] {
        assert!(matches!(
            store
                .decide_project_approval(
                    approval_id.clone(),
                    ProjectId::from("approval-project"),
                    CallerId::from("approval-reviewer"),
                    decision,
                    101,
                )
                .await,
            Err(StoreError::ApprovalNotFound(id)) if id == approval_id
        ));
    }
    assert!(matches!(
        store
            .decide_project_approval(
                approval_id.clone(),
                ProjectId::from("other-project"),
                CallerId::from("approval-subject"),
                ApprovalDecision::Approve,
                101,
            )
            .await,
        Err(StoreError::ApprovalNotFound(id)) if id == approval_id
    ));
    assert_eq!(
        store
            .decide_project_approval(
                approval_id,
                ProjectId::from("approval-project"),
                CallerId::from("approval-subject"),
                ApprovalDecision::Approve,
                102,
            )
            .await
            .unwrap(),
        ApprovalDecisionOutcome::Approved
    );

    close(store, &directory).await;
}

#[tokio::test]
async fn audit_failure_rolls_back_approval_creation() {
    let (directory, path, store) = open_approval_store("audit-approval-create-rollback").await;
    store
        .append_audit_event(audit_event("collision", "other", "other", 10, 100))
        .await
        .unwrap();
    assert!(matches!(
        store
            .authorize_audited(
                authorization(
                    "approval-subject",
                    "approval-project",
                    "deploy",
                    "release-a",
                    None,
                ),
                authorization_audit("collision", 200),
                100,
                20,
            )
            .await,
        Err(StoreError::AuditEventAlreadyExists)
    ));
    store.shutdown().await.unwrap();
    let connection = Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM approvals", [], |row| row
                .get::<_, u32>(0))
            .unwrap(),
        0
    );
    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn audit_failure_rolls_back_one_time_approval_consumption() {
    let (directory, _path, store) = open_approval_store("audit-approval-consume-rollback").await;
    let request = authorization(
        "approval-subject",
        "approval-project",
        "deploy",
        "release-a",
        None,
    );
    let AuthorizationOutcome::ApprovalRequired { approval_id, .. } =
        store.authorize(request.clone(), 100, 20).await.unwrap()
    else {
        panic!("approval-requiring grant should return an approval ID")
    };
    store
        .decide_approval(
            approval_id.clone(),
            CallerId::from("approval-reviewer"),
            ApprovalDecision::Approve,
            101,
        )
        .await
        .unwrap();
    store
        .append_audit_event(audit_event("collision", "other", "other", 10, 100))
        .await
        .unwrap();
    let mut approved = request;
    approved.approval_id = Some(approval_id);
    assert!(matches!(
        store
            .authorize_audited(
                approved.clone(),
                authorization_audit("collision", 200),
                102,
                20,
            )
            .await,
        Err(StoreError::AuditEventAlreadyExists)
    ));
    assert_eq!(
        store.authorize(approved, 103, 20).await.unwrap(),
        AuthorizationOutcome::Allowed
    );
    close(store, &directory).await;
}

async fn assert_denied_decision_retry_is_idempotent(store: &Store, denied_id: &ApprovalId) {
    assert_eq!(
        store
            .decide_approval(
                denied_id.clone(),
                CallerId::from("approval-reviewer"),
                ApprovalDecision::Deny,
                111,
            )
            .await
            .unwrap(),
        ApprovalDecisionOutcome::Denied
    );
    assert_eq!(
        store
            .decide_approval(
                denied_id.clone(),
                CallerId::from("approval-reviewer"),
                ApprovalDecision::Deny,
                112,
            )
            .await
            .unwrap(),
        ApprovalDecisionOutcome::Denied,
        "an identical retry after a lost response must be idempotent"
    );
    assert!(matches!(
        store
            .decide_approval(
                denied_id.clone(),
                CallerId::from("approval-reviewer"),
                ApprovalDecision::Approve,
                112,
            )
            .await,
        Err(StoreError::InvalidApprovalState)
    ));
}

async fn assert_expired_decision_retry_is_idempotent(store: &Store, expiring_id: &ApprovalId) {
    assert_eq!(
        store
            .decide_approval(
                expiring_id.clone(),
                CallerId::from("approval-reviewer"),
                ApprovalDecision::Deny,
                131,
            )
            .await
            .unwrap(),
        ApprovalDecisionOutcome::Expired,
        "an expired decision response must also be safely repeatable"
    );
}

#[tokio::test]
async fn approval_decisions_return_denied_and_expired_outcomes() {
    let (directory, _path, store) = open_approval_store("approval-outcomes").await;
    let exact_request = authorization(
        "approval-subject",
        "approval-project",
        "deploy",
        "release-a",
        None,
    );
    let AuthorizationOutcome::ApprovalRequired {
        approval_id: denied_id,
        ..
    } = store
        .authorize(exact_request.clone(), 110, 20)
        .await
        .unwrap()
    else {
        panic!("a new exact effect should request a new approval")
    };
    assert_denied_decision_retry_is_idempotent(&store, &denied_id).await;
    let mut denied_request = exact_request.clone();
    denied_request.approval_id = Some(denied_id);
    assert_eq!(
        store.authorize(denied_request, 112, 20).await.unwrap(),
        AuthorizationOutcome::ApprovalDenied
    );

    let AuthorizationOutcome::ApprovalRequired {
        approval_id: expiring_id,
        expires_at_ms: 130,
    } = store.authorize(exact_request, 120, 10).await.unwrap()
    else {
        panic!("a new exact effect should request an expiring approval")
    };
    assert_eq!(
        store
            .decide_approval(
                expiring_id.clone(),
                CallerId::from("approval-reviewer"),
                ApprovalDecision::Approve,
                130,
            )
            .await
            .unwrap(),
        ApprovalDecisionOutcome::Expired
    );
    assert_expired_decision_retry_is_idempotent(&store, &expiring_id).await;
    assert_eq!(
        store
            .authorize(
                authorization(
                    "approval-subject",
                    "approval-project",
                    "deploy",
                    "release-a",
                    Some(expiring_id),
                ),
                131,
                10,
            )
            .await
            .unwrap(),
        AuthorizationOutcome::ApprovalExpired
    );

    close(store, &directory).await;
}

#[tokio::test]
async fn audit_sequence_event_identity_and_records_survive_restart() {
    let (directory, path) = database_path("audit-restart");
    let store = Store::open(&path).unwrap();
    let first = store
        .append_audit_event(audit_event("event-a1", "project-a", "caller-a", 10, 100))
        .await
        .unwrap();
    let second = store
        .append_audit_event(audit_event("event-b1", "project-b", "caller-b", 11, 101))
        .await
        .unwrap();
    assert_eq!(first.sequence, 1);
    assert_eq!(first.event_id, "event-a1");
    assert_eq!(first.redacted_detail, "event=event-a1");
    assert_eq!(second.sequence, 2);
    store.shutdown().await.unwrap();

    let reopened = Store::open(&path).unwrap();
    let third = reopened
        .append_audit_event(audit_event("event-a2", "project-a", "caller-a", 12, 102))
        .await
        .unwrap();
    assert_eq!(third.sequence, 3);
    let export = reopened
        .export_audit_events(ProjectId::from("project-a"), 0, None, 10)
        .await
        .unwrap();
    assert_eq!(
        export
            .events
            .iter()
            .map(|event| (event.sequence, event.event_id.as_str()))
            .collect::<Vec<_>>(),
        [(1, "event-a1"), (3, "event-a2")]
    );
    assert_eq!(export.events[0], first);
    assert_eq!(export.events[1], third);

    close(reopened, &directory).await;
}

#[tokio::test]
async fn audit_export_is_project_scoped_ordered_paginated_and_deterministic() {
    let (directory, path) = database_path("audit-export");
    let store = Store::open(&path).unwrap();
    for (event_id, project_id, now_ms) in [
        ("a-1", "project-a", 10),
        ("b-1", "project-b", 11),
        ("a-2", "project-a", 12),
        ("a-3", "project-a", 13),
    ] {
        store
            .append_audit_event(audit_event(event_id, project_id, "caller", now_ms, 100))
            .await
            .unwrap();
    }

    let first_page = store
        .export_audit_events(ProjectId::from("project-a"), 0, None, 2)
        .await
        .unwrap();
    assert_eq!(first_page.version, AUDIT_EXPORT_VERSION);
    assert_eq!(first_page.project_id, ProjectId::from("project-a"));
    assert_eq!(first_page.after_sequence, 0);
    assert_eq!(first_page.through_sequence, 4);
    assert_eq!(first_page.next_after_sequence, 3);
    assert!(first_page.has_more);
    assert_eq!(
        first_page
            .events
            .iter()
            .map(|event| (event.sequence, event.event_id.as_str()))
            .collect::<Vec<_>>(),
        [(1, "a-1"), (3, "a-2")]
    );
    assert_eq!(
        store
            .export_audit_events(ProjectId::from("project-a"), 0, None, 2)
            .await
            .unwrap(),
        first_page
    );
    store
        .append_audit_event(audit_event("a-4", "project-a", "caller", 14, 100))
        .await
        .unwrap();

    let second_page = store
        .export_audit_events(
            ProjectId::from("project-a"),
            first_page.next_after_sequence,
            Some(first_page.through_sequence),
            2,
        )
        .await
        .unwrap();
    assert_eq!(second_page.next_after_sequence, 4);
    assert!(!second_page.has_more);
    assert_eq!(second_page.events[0].event_id, "a-3");
    let other_project = store
        .export_audit_events(ProjectId::from("project-b"), 0, None, 10)
        .await
        .unwrap();
    assert_eq!(other_project.events.len(), 1);
    assert_eq!(other_project.events[0].event_id, "b-1");
    assert!(
        other_project
            .events
            .iter()
            .all(|event| event.project_id == ProjectId::from("project-b"))
    );

    close(store, &directory).await;
}

#[tokio::test]
async fn audit_pruning_is_project_scoped_bounded_inclusive_and_idempotent() {
    let (directory, path) = database_path("audit-prune");
    let store = Store::open(&path).unwrap();
    for (event_id, project_id, retain_until_ms) in [
        ("a-expired-1", "project-a", 20),
        ("b-expired", "project-b", 20),
        ("a-expired-2", "project-a", 20),
        ("a-future", "project-a", 21),
    ] {
        store
            .append_audit_event(audit_event(
                event_id,
                project_id,
                "caller",
                10,
                retain_until_ms,
            ))
            .await
            .unwrap();
    }

    assert_eq!(
        store
            .prune_audit_events(ProjectId::from("project-a"), 19, 1)
            .await
            .unwrap(),
        AuditPruneOutcome {
            deleted: 0,
            has_more: false,
        }
    );
    assert_eq!(
        store
            .prune_audit_events(ProjectId::from("project-a"), 20, 1)
            .await
            .unwrap(),
        AuditPruneOutcome {
            deleted: 1,
            has_more: true,
        }
    );
    let remaining = store
        .export_audit_events(ProjectId::from("project-a"), 0, None, 10)
        .await
        .unwrap();
    assert_eq!(
        remaining
            .events
            .iter()
            .map(|event| event.event_id.as_str())
            .collect::<Vec<_>>(),
        ["a-expired-2", "a-future"]
    );
    let other_project = store
        .export_audit_events(ProjectId::from("project-b"), 0, None, 10)
        .await
        .unwrap();
    assert_eq!(other_project.events[0].event_id, "b-expired");

    assert_eq!(
        store
            .prune_audit_events(ProjectId::from("project-a"), 20, 1)
            .await
            .unwrap(),
        AuditPruneOutcome {
            deleted: 1,
            has_more: false,
        }
    );
    assert_eq!(
        store
            .prune_audit_events(ProjectId::from("project-a"), 20, 1)
            .await
            .unwrap(),
        AuditPruneOutcome {
            deleted: 0,
            has_more: false,
        }
    );
    assert_eq!(
        store
            .prune_audit_events(ProjectId::from("project-a"), 21, 10)
            .await
            .unwrap()
            .deleted,
        1
    );

    close(store, &directory).await;
}

#[tokio::test]
async fn audit_fields_cursors_limits_and_timestamps_are_validated_before_storage() {
    let (directory, path) = database_path("audit-validation");
    let store = Store::open(&path).unwrap();
    let valid = audit_event("valid", "project", "caller", 10, 20);
    let invalid = [
        AppendAuditEvent {
            event_id: String::new(),
            ..valid.clone()
        },
        AppendAuditEvent {
            event_id: "x".repeat(MAX_AUDIT_EVENT_ID_BYTES + 1),
            ..valid.clone()
        },
        AppendAuditEvent {
            project_id: ProjectId::from("x".repeat(MAX_AUDIT_PROJECT_ID_BYTES + 1)),
            ..valid.clone()
        },
        AppendAuditEvent {
            caller_id: CallerId::from("x".repeat(MAX_AUDIT_CALLER_ID_BYTES + 1)),
            ..valid.clone()
        },
        AppendAuditEvent {
            action: "x".repeat(MAX_AUDIT_ACTION_BYTES + 1),
            ..valid.clone()
        },
        AppendAuditEvent {
            decision: "x".repeat(MAX_AUDIT_DECISION_BYTES + 1),
            ..valid.clone()
        },
        AppendAuditEvent {
            outcome: "x".repeat(MAX_AUDIT_OUTCOME_BYTES + 1),
            ..valid.clone()
        },
        AppendAuditEvent {
            retain_until_ms: 9,
            ..valid.clone()
        },
    ];
    for event in invalid {
        assert!(matches!(
            store.append_audit_event(event).await,
            Err(StoreError::InvalidAuditEvent(_))
        ));
    }
    for event in [
        AppendAuditEvent {
            occurred_at_ms: u64::MAX,
            retain_until_ms: u64::MAX,
            ..valid.clone()
        },
        AppendAuditEvent {
            retain_until_ms: u64::MAX,
            ..valid.clone()
        },
    ] {
        assert!(matches!(
            store.append_audit_event(event).await,
            Err(StoreError::TimestampOutOfRange(_))
        ));
    }
    assert!(matches!(
        store
            .export_audit_events(ProjectId::from("project"), 0, None, 0)
            .await,
        Err(StoreError::InvalidAuditBatchLimit { .. })
    ));
    assert!(matches!(
        store
            .prune_audit_events(ProjectId::from("project"), 20, MAX_AUDIT_BATCH_SIZE + 1,)
            .await,
        Err(StoreError::InvalidAuditBatchLimit { .. })
    ));
    assert!(matches!(
        store
            .export_audit_events(ProjectId::from("project"), u64::MAX, None, 1)
            .await,
        Err(StoreError::AuditCursorOutOfRange(u64::MAX))
    ));
    let stored = store.append_audit_event(valid.clone()).await.unwrap();
    assert_eq!(stored.sequence, 1);
    assert_eq!(
        store.append_audit_event(valid.clone()).await.unwrap(),
        stored
    );
    let conflicting = AppendAuditEvent {
        outcome: "changed".to_owned(),
        ..valid
    };
    assert!(matches!(
        store.append_audit_event(conflicting).await,
        Err(StoreError::AuditEventAlreadyExists)
    ));
    close(store, &directory).await;
}

#[tokio::test]
async fn audit_export_rejects_a_high_water_before_the_exclusive_cursor() {
    let (directory, path) = database_path("audit-cursor-order");
    let store = Store::open(&path).unwrap();
    assert!(matches!(
        store
            .export_audit_events(ProjectId::from("project"), 2, Some(1), 1)
            .await,
        Err(StoreError::InvalidAuditCursorRange {
            after: 2,
            through: 1
        })
    ));
    assert!(matches!(
        store
            .export_audit_events(ProjectId::from("project"), 0, Some(1), 1)
            .await,
        Err(StoreError::AuditHighWaterAhead {
            through: 1,
            maximum: 0
        })
    ));
    close(store, &directory).await;
}

#[tokio::test]
async fn audit_rejects_control_and_format_characters_in_every_text_field() {
    let (directory, path) = database_path("audit-injection");
    let store = Store::open(&path).unwrap();
    let valid = audit_event("valid", "project", "caller", 10, 20);
    let injected = [
        AppendAuditEvent {
            event_id: "bad\n".to_owned(),
            ..valid.clone()
        },
        AppendAuditEvent {
            project_id: ProjectId::from("bad\r"),
            ..valid.clone()
        },
        AppendAuditEvent {
            caller_id: CallerId::from("bad\t"),
            ..valid.clone()
        },
        AppendAuditEvent {
            action: "bad\u{202e}".to_owned(),
            ..valid.clone()
        },
        AppendAuditEvent {
            decision: "bad\u{200d}".to_owned(),
            ..valid.clone()
        },
        AppendAuditEvent {
            outcome: "bad\u{00ad}".to_owned(),
            ..valid.clone()
        },
    ];
    for event in injected {
        assert!(matches!(
            store.append_audit_event(event).await,
            Err(StoreError::InvalidAuditEvent(_))
        ));
    }
    for (event_id, detail) in [
        ("detail-control", "bad\n"),
        ("detail-format", "bad\u{2066}"),
        ("detail-secret", "Authorization: Bearer LeakedSecret"),
    ] {
        store
            .append_audit_event(AppendAuditEvent {
                event_id: event_id.to_owned(),
                redacted_detail: detail.to_owned(),
                ..valid.clone()
            })
            .await
            .unwrap();
    }
    let events = store
        .export_audit_events(ProjectId::from("project"), 0, None, 10)
        .await
        .unwrap()
        .events;
    assert_eq!(events.len(), 3);
    assert!(events.iter().all(|event| {
        !event
            .redacted_detail
            .chars()
            .any(|character| character.is_control() || character == '\u{2066}')
    }));
    let secret = events
        .iter()
        .find(|event| event.event_id == "detail-secret")
        .unwrap();
    assert!(secret.redacted_detail.contains("[REDACTED]"));
    assert!(!secret.redacted_detail.contains("LeakedSecret"));
    close(store, &directory).await;
}

#[tokio::test]
async fn model_registry_persists_metadata_only_and_rejects_conflicts() {
    let (directory, path) = database_path("model-registry");
    let store = Store::open(&path).unwrap();
    let model = registered_model(&directory.join("user-owned.gguf"));

    assert_eq!(store.put_model(model.clone()).await.unwrap(), model);
    assert_eq!(store.put_model(model.clone()).await.unwrap(), model);
    assert_eq!(store.model(model.key.clone()).await.unwrap(), model);

    let conflicting = RegisteredModel {
        digest: ContentDigest::from_sha256([3; 32]),
        ..model.clone()
    };
    assert!(matches!(
        store.put_model(conflicting).await,
        Err(StoreError::ModelConflict(model_id)) if model_id == model.key.id()
    ));

    store.shutdown().await.unwrap();
    let connection = Connection::open(&path).unwrap();
    let blob_columns: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('models') WHERE upper(type) = 'BLOB'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(blob_columns, 0);
    let stored_path: String = connection
        .query_row("SELECT path FROM models", [], |row| row.get(0))
        .unwrap();
    assert_eq!(stored_path, model.path.to_string_lossy());
    let stored_counts: (i64, i64) = connection
        .query_row(
            "SELECT gguf_tensor_count, gguf_metadata_kv_count FROM models",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(stored_counts, (17, 29));
    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn model_registry_rejects_invalid_size_and_https_provenance() {
    let (directory, path) = database_path("model-registry-validation");
    let store = Store::open(&path).unwrap();
    let valid = registered_model(&directory.join("user-owned.gguf"));

    for size_bytes in [
        ModelDescriptor::MIN_SIZE_BYTES - 1,
        ModelDescriptor::MAX_SIZE_BYTES + 1,
    ] {
        let invalid = RegisteredModel {
            size_bytes,
            ..valid.clone()
        };
        assert!(matches!(
            store.put_model(invalid).await,
            Err(StoreError::InvalidModelRecord(_))
        ));
    }

    for gguf in [
        GgufMetadata {
            tensor_count: 0,
            ..valid.gguf
        },
        GgufMetadata {
            tensor_count: GgufMetadata::MAX_TENSOR_COUNT + 1,
            ..valid.gguf
        },
        GgufMetadata {
            metadata_kv_count: GgufMetadata::MAX_METADATA_KV_COUNT + 1,
            ..valid.gguf
        },
    ] {
        let invalid = RegisteredModel {
            gguf,
            ..valid.clone()
        };
        assert!(matches!(
            store.put_model(invalid).await,
            Err(StoreError::InvalidModelRecord(_))
        ));
    }

    let invalid_source = RegisteredModel {
        source: ModelSource::Https {
            canonical_url: "https:// ".to_owned(),
        },
        ..valid
    };
    assert!(matches!(
        store.put_model(invalid_source).await,
        Err(StoreError::InvalidModelRecord(_))
    ));
    close(store, &directory).await;
}

#[tokio::test]
async fn model_registry_reports_corrupt_stored_https_provenance() {
    let (directory, path) = database_path("model-registry-corrupt-source");
    let store = Store::open(&path).unwrap();
    let model = registered_model(&directory.join("user-owned.gguf"));
    store.put_model(model.clone()).await.unwrap();
    store.shutdown().await.unwrap();

    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE models SET source_kind = 'https', source_identity = 'https:// '",
            [],
        )
        .unwrap();
    drop(connection);

    let store = Store::open(&path).unwrap();
    assert!(matches!(
        store.model(model.key).await,
        Err(StoreError::InvalidModelRecord(_))
    ));
    close(store, &directory).await;
}

#[tokio::test]
async fn model_registry_reports_corrupt_stored_gguf_counts() {
    let (directory, path) = database_path("model-registry-corrupt-counts");
    let store = Store::open(&path).unwrap();
    let model = registered_model(&directory.join("user-owned.gguf"));
    store.put_model(model.clone()).await.unwrap();
    store.shutdown().await.unwrap();

    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "ignore_check_constraints", true)
        .unwrap();
    connection
        .execute("UPDATE models SET gguf_tensor_count = 0", [])
        .unwrap();
    drop(connection);

    assert!(matches!(
        Store::open(&path),
        Err(StoreError::IntegrityCheckFailed(_))
    ));
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Covers create, idempotent save, semantic replay, and restart.
async fn flow_checkpoint_create_update_and_exact_replay_are_atomic() {
    let (directory, path) = database_path("flow-checkpoint-atomic");
    let store = Store::open(&path).unwrap();
    let (lease, mut run) = leased_flow(&store, "flow-request").await;

    assert!(
        store
            .load_flow_checkpoint(lease.clone(), 21)
            .await
            .unwrap()
            .is_none()
    );
    let created = store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease: lease.clone(),
            expected_revision: 0,
            snapshot: run.snapshot().clone(),
            transition: None,
            terminal_result: None,
            updated_at_ms: 21,
        })
        .await
        .unwrap();
    assert_eq!(created.disposition, FlowCheckpointDisposition::Created);
    assert_eq!(created.checkpoint.checkpoint_revision, 1);
    assert!(created.event.is_none());

    let update = run.next_decision(22).unwrap();
    let RunDecision::EvaluateEffect { effect, .. } = update.decision() else {
        panic!("flow should require effect evaluation")
    };
    let effect = effect.clone();
    let transition = update.transition().unwrap().clone();
    let save = SaveFlowCheckpoint {
        lease: lease.clone(),
        expected_revision: 1,
        snapshot: update.snapshot().clone(),
        transition: Some(transition.clone()),
        terminal_result: None,
        updated_at_ms: 22,
    };
    let updated = store.save_flow_checkpoint(save.clone()).await.unwrap();
    assert_eq!(updated.disposition, FlowCheckpointDisposition::Updated);
    assert_eq!(updated.checkpoint.checkpoint_revision, 2);
    let event = updated.event.unwrap();
    assert_eq!(event.sequence, 3);
    assert_eq!(event.kind, "flow_effect_evaluation_required");
    assert_eq!(
        rmp_serde::from_slice::<RunTransition>(&event.payload).unwrap(),
        transition
    );

    let mut replay_save = save.clone();
    replay_save.updated_at_ms = 23;
    let unchanged = store.save_flow_checkpoint(replay_save).await.unwrap();
    assert_eq!(unchanged.disposition, FlowCheckpointDisposition::Unchanged);
    assert_eq!(unchanged.checkpoint.updated_at_ms, 22);
    assert!(unchanged.event.is_none());
    let unchanged_without_transition = store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            expected_revision: 2,
            transition: None,
            updated_at_ms: 24,
            ..save
        })
        .await
        .unwrap();
    assert_eq!(
        unchanged_without_transition.disposition,
        FlowCheckpointDisposition::Unchanged
    );
    assert_eq!(unchanged_without_transition.checkpoint.updated_at_ms, 22);
    assert!(unchanged_without_transition.event.is_none());
    let replay = store
        .replay(RequestId::from("flow-request"), 0)
        .await
        .unwrap();
    assert_eq!(replay.events.len(), 3);
    assert_eq!(replay.events[2], event);

    let started = run.prepare_effect(&effect, 25).unwrap();
    let semantic_transition = started.transition().unwrap().clone();
    assert!(matches!(
        semantic_transition.semantic_events(),
        [pam_flow::FlowSemanticEvent::Waiting {
            step_id,
            reason: pam_flow::FlowWaitReason::EffectResult,
            not_before_ms: None,
        }] if step_id == "inspect"
    ));
    let semantic_event = store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease: lease.clone(),
            expected_revision: 2,
            snapshot: started.snapshot().clone(),
            transition: Some(semantic_transition.clone()),
            terminal_result: None,
            updated_at_ms: 25,
        })
        .await
        .unwrap()
        .event
        .unwrap();
    assert_eq!(semantic_event.sequence, 4);
    assert_eq!(semantic_event.kind, "flow_effect_started");
    assert_eq!(
        rmp_serde::from_slice::<RunTransition>(&semantic_event.payload).unwrap(),
        semantic_transition
    );
    store.shutdown().await.unwrap();

    let reopened = Store::open(&path).unwrap();
    let replay = reopened
        .replay(RequestId::from("flow-request"), 0)
        .await
        .unwrap();
    assert_eq!(replay.events.len(), 4);
    assert_eq!(replay.events[3], semantic_event);

    close(reopened, &directory).await;
}

#[tokio::test]
async fn flow_checkpoint_rejects_cross_run_transition_without_mutation() {
    let (directory, path) = database_path("flow-checkpoint-successor-validation");
    let store = Store::open(&path).unwrap();
    let (lease, mut run) = leased_flow(&store, "successor-flow").await;
    let initial = run.snapshot().clone();
    store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease: lease.clone(),
            expected_revision: 0,
            snapshot: initial.clone(),
            transition: None,
            terminal_result: None,
            updated_at_ms: 21,
        })
        .await
        .unwrap();

    let candidate = run.next_decision(22).unwrap();
    let mut other = FlowRun::start(
        RunId::parse("other-successor-flow").unwrap(),
        flow_definition_with_step(1, "collect"),
    )
    .unwrap();
    let wrong_transition = other
        .next_decision(22)
        .unwrap()
        .transition()
        .unwrap()
        .clone();
    assert_eq!(
        wrong_transition.sequence(),
        candidate.transition().unwrap().sequence()
    );
    assert_ne!(&wrong_transition, candidate.transition().unwrap());

    assert!(matches!(
        store
            .save_flow_checkpoint(SaveFlowCheckpoint {
                lease: lease.clone(),
                expected_revision: 1,
                snapshot: candidate.snapshot().clone(),
                transition: Some(wrong_transition.clone()),
                terminal_result: None,
                updated_at_ms: 22,
            })
            .await,
        Err(StoreError::InvalidFlowCheckpoint(_))
    ));
    let unchanged = store
        .load_flow_checkpoint(lease.clone(), 23)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.snapshot, initial);
    assert_eq!(unchanged.checkpoint_revision, 1);

    let correct = SaveFlowCheckpoint {
        lease: lease.clone(),
        expected_revision: 1,
        snapshot: candidate.snapshot().clone(),
        transition: candidate.transition().cloned(),
        terminal_result: None,
        updated_at_ms: 24,
    };
    store.save_flow_checkpoint(correct).await.unwrap();
    assert!(matches!(
        store
            .save_flow_checkpoint(SaveFlowCheckpoint {
                lease: lease.clone(),
                expected_revision: 1,
                snapshot: candidate.snapshot().clone(),
                transition: Some(wrong_transition),
                terminal_result: None,
                updated_at_ms: 25,
            })
            .await,
        Err(StoreError::FlowCheckpointConflict(request_id))
            if request_id == RequestId::from("successor-flow")
    ));
    let replay = store
        .replay(RequestId::from("successor-flow"), 0)
        .await
        .unwrap();
    assert_eq!(replay.events.len(), 3);
    assert_eq!(
        store
            .load_flow_checkpoint(lease, 27)
            .await
            .unwrap()
            .unwrap()
            .checkpoint_revision,
        2
    );

    close(store, &directory).await;
}

#[tokio::test]
async fn flow_checkpoint_rejects_changed_snapshot_without_transition() {
    let (directory, path) = database_path("flow-checkpoint-missing-transition");
    let store = Store::open(&path).unwrap();
    let (lease, mut run, evaluation) = checkpointed_flow(&store, "missing-transition-flow").await;
    let effect = match evaluation.decision() {
        RunDecision::EvaluateEffect { effect, .. } => effect.clone(),
        other => panic!("expected effect evaluation, got {other:?}"),
    };
    let changed_without_transition = run.prepare_effect(&effect, 24).unwrap();

    assert!(matches!(
        store
            .save_flow_checkpoint(SaveFlowCheckpoint {
                lease: lease.clone(),
                expected_revision: 2,
                snapshot: changed_without_transition.snapshot().clone(),
                transition: None,
                terminal_result: None,
                updated_at_ms: 24,
            })
            .await,
        Err(StoreError::InvalidFlowCheckpoint(_))
    ));
    assert_eq!(
        store
            .load_flow_checkpoint(lease.clone(), 25)
            .await
            .unwrap()
            .unwrap()
            .checkpoint_revision,
        2
    );
    assert_eq!(
        store
            .replay(RequestId::from("missing-transition-flow"), 0)
            .await
            .unwrap()
            .events
            .len(),
        3
    );

    close(store, &directory).await;
}

#[tokio::test]
async fn flow_checkpoint_requires_the_exact_initial_snapshot_shape() {
    let (directory, path) = database_path("flow-checkpoint-initial-shape");
    let store = Store::open(&path).unwrap();
    let (lease, mut run) = leased_flow(&store, "initial-shape-flow").await;
    let advanced = run.next_decision(21).unwrap();

    assert!(matches!(
        store
            .save_flow_checkpoint(SaveFlowCheckpoint {
                lease: lease.clone(),
                expected_revision: 0,
                snapshot: advanced.snapshot().clone(),
                transition: advanced.transition().cloned(),
                terminal_result: None,
                updated_at_ms: 21,
            })
            .await,
        Err(StoreError::InvalidFlowCheckpoint(_))
    ));
    assert!(
        store
            .load_flow_checkpoint(lease.clone(), 22)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .replay(RequestId::from("initial-shape-flow"), 0)
            .await
            .unwrap()
            .events
            .len(),
        2
    );

    close(store, &directory).await;
}

#[tokio::test]
async fn flow_checkpoint_rejects_optimistic_revision_conflicts_atomically() {
    let (directory, path) = database_path("flow-checkpoint-revision-conflict");
    let store = Store::open(&path).unwrap();
    let (lease, mut run, update) = checkpointed_flow(&store, "revision-flow").await;

    let effect = match update.decision() {
        RunDecision::EvaluateEffect { effect, .. } => effect.clone(),
        other => panic!("expected effect evaluation, got {other:?}"),
    };
    let next = run.prepare_effect(&effect, 24).unwrap();
    let conflict = store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease: lease.clone(),
            expected_revision: 1,
            snapshot: next.snapshot().clone(),
            transition: next.transition().cloned(),
            terminal_result: None,
            updated_at_ms: 24,
        })
        .await;
    assert!(matches!(
        conflict,
        Err(StoreError::FlowCheckpointRevisionConflict {
            expected: 1,
            actual: 2,
            ..
        })
    ));
    assert_eq!(
        store
            .load_flow_checkpoint(lease.clone(), 25)
            .await
            .unwrap()
            .unwrap()
            .checkpoint_revision,
        2
    );
    assert_eq!(
        store
            .replay(RequestId::from("revision-flow"), 0)
            .await
            .unwrap()
            .events
            .len(),
        3
    );

    close(store, &directory).await;
}

#[tokio::test]
async fn flow_checkpoint_rejects_definition_and_request_identity_mismatches() {
    let (directory, path) = database_path("flow-checkpoint-identity-conflict");
    let store = Store::open(&path).unwrap();
    let (lease, _, _) = checkpointed_flow(&store, "identity-flow").await;

    let mismatched =
        FlowRun::start(RunId::parse("identity-flow").unwrap(), flow_definition(2)).unwrap();
    assert!(matches!(
        store
            .save_flow_checkpoint(SaveFlowCheckpoint {
                lease: lease.clone(),
                expected_revision: 2,
                snapshot: mismatched.snapshot().clone(),
                transition: None,
                terminal_result: None,
                updated_at_ms: 26,
            })
            .await,
        Err(StoreError::FlowDefinitionDigestMismatch(request_id))
            if request_id == RequestId::from("identity-flow")
    ));

    let wrong_request =
        FlowRun::start(RunId::parse("another-request").unwrap(), flow_definition(1)).unwrap();
    assert!(matches!(
        store
            .save_flow_checkpoint(SaveFlowCheckpoint {
                lease: lease.clone(),
                expected_revision: 2,
                snapshot: wrong_request.snapshot().clone(),
                transition: None,
                terminal_result: None,
                updated_at_ms: 27,
            })
            .await,
        Err(StoreError::FlowCheckpointRequestMismatch(request_id))
            if request_id == RequestId::from("identity-flow")
    ));

    close(store, &directory).await;
}

#[tokio::test]
async fn flow_checkpoint_survives_restart_and_requires_a_live_lease() {
    let (directory, path) = database_path("flow-checkpoint-restart");
    let store = Store::open(&path).unwrap();
    let (lease, run) = leased_flow(&store, "restart-flow").await;
    let snapshot = run.snapshot().clone();
    store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease: lease.clone(),
            expected_revision: 0,
            snapshot: snapshot.clone(),
            transition: None,
            terminal_result: None,
            updated_at_ms: 21,
        })
        .await
        .unwrap();
    store.shutdown().await.unwrap();

    let store = Store::open(&path).unwrap();
    let restored = store
        .load_flow_checkpoint(lease.clone(), 22)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(restored.snapshot, snapshot);
    assert_eq!(restored.checkpoint_revision, 1);
    assert!(matches!(
        store.load_flow_checkpoint(lease.clone(), 1_020).await,
        Err(StoreError::StaleLease(request_id))
            if request_id == RequestId::from("restart-flow")
    ));
    assert!(matches!(
        store
            .save_flow_checkpoint(SaveFlowCheckpoint {
                lease,
                expected_revision: 1,
                snapshot: restored.snapshot,
                transition: None,
                terminal_result: None,
                updated_at_ms: 1_020,
            })
            .await,
        Err(StoreError::StaleLease(_))
    ));

    close(store, &directory).await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Covers the persisted legacy row and its first exact CAS.
async fn legacy_flow_checkpoint_upgrades_atomically_before_its_next_transition() {
    #[derive(serde::Serialize)]
    struct LegacyStep<'a> {
        id: &'a str,
        idempotency_identity: pam_flow::IdempotencyIdentity,
        approval: &'a pam_flow::StepApprovalState,
        state: &'a pam_flow::StepState,
        results: Vec<()>,
        blocked_report: Option<&'a EffectReport>,
    }

    #[derive(serde::Serialize)]
    struct LegacySnapshot<'a> {
        snapshot_version: u16,
        run_id: &'a RunId,
        definition_digest: pam_flow::FlowDigest,
        status: pam_flow::RunStatus,
        cancel_requested: bool,
        transition_sequence: u64,
        steps: Vec<LegacyStep<'a>>,
    }

    let (directory, path) = database_path("flow-checkpoint-legacy-upgrade");
    let store = Store::open(&path).unwrap();
    let definition = flow_definition(1);
    let (lease, run) =
        leased_flow_with_definition(&store, "legacy-upgrade", definition.clone()).await;
    let snapshot = run.snapshot().clone();
    store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease: lease.clone(),
            expected_revision: 0,
            snapshot: snapshot.clone(),
            transition: None,
            terminal_result: None,
            updated_at_ms: 21,
        })
        .await
        .unwrap();
    store.shutdown().await.unwrap();

    let legacy = LegacySnapshot {
        snapshot_version: 1,
        run_id: snapshot.run_id(),
        definition_digest: snapshot.definition_digest(),
        status: snapshot.status(),
        cancel_requested: snapshot.cancel_requested(),
        transition_sequence: snapshot.transition_sequence(),
        steps: snapshot
            .steps()
            .iter()
            .map(|step| {
                assert_eq!(step.results().len(), 0);
                LegacyStep {
                    id: step.id(),
                    idempotency_identity: step.idempotency_identity(),
                    approval: step.approval(),
                    state: step.state(),
                    results: Vec::new(),
                    blocked_report: step.blocked_report(),
                }
            })
            .collect(),
    };
    let legacy_bytes = rmp_serde::to_vec_named(&legacy).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE flow_runs SET snapshot = ?1 WHERE request_id = ?2",
            rusqlite::params![legacy_bytes, "legacy-upgrade"],
        )
        .unwrap();
    drop(connection);

    let store = Store::open(&path).unwrap();
    let checkpoint = store
        .load_flow_checkpoint(lease.clone(), 31)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(checkpoint.snapshot.snapshot_version(), 1);
    let mut resumed = FlowRun::resume(
        &RunId::parse("legacy-upgrade").unwrap(),
        definition,
        checkpoint.snapshot,
    )
    .unwrap();
    let upgraded = store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease: lease.clone(),
            expected_revision: checkpoint.checkpoint_revision,
            snapshot: resumed.snapshot().clone(),
            transition: None,
            terminal_result: None,
            updated_at_ms: 32,
        })
        .await
        .unwrap();
    assert_eq!(
        upgraded.checkpoint.snapshot.snapshot_version(),
        pam_flow::FLOW_SNAPSHOT_VERSION
    );
    assert!(upgraded.event.is_none());
    let repeated = store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease: lease.clone(),
            expected_revision: checkpoint.checkpoint_revision,
            snapshot: resumed.snapshot().clone(),
            transition: None,
            terminal_result: None,
            updated_at_ms: 32,
        })
        .await
        .unwrap();
    assert_eq!(repeated.disposition, FlowCheckpointDisposition::Unchanged);
    assert_eq!(
        repeated.checkpoint.checkpoint_revision,
        upgraded.checkpoint.checkpoint_revision
    );
    assert!(repeated.event.is_none());

    let update = resumed.next_decision(33).unwrap();
    let advanced = store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease,
            expected_revision: upgraded.checkpoint.checkpoint_revision,
            snapshot: update.snapshot().clone(),
            transition: update.transition().cloned(),
            terminal_result: None,
            updated_at_ms: 33,
        })
        .await
        .unwrap();
    assert!(advanced.event.is_some());

    close(store, &directory).await;
}

#[tokio::test]
async fn corrupt_flow_checkpoint_bytes_are_rejected_on_load() {
    let (directory, path) = database_path("flow-checkpoint-corrupt");
    let store = Store::open(&path).unwrap();
    let (lease, run) = leased_flow(&store, "corrupt-flow").await;
    store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease: lease.clone(),
            expected_revision: 0,
            snapshot: run.snapshot().clone(),
            transition: None,
            terminal_result: None,
            updated_at_ms: 21,
        })
        .await
        .unwrap();
    store.shutdown().await.unwrap();

    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE flow_runs SET snapshot = X'01' WHERE request_id = 'corrupt-flow'",
            [],
        )
        .unwrap();
    drop(connection);

    let store = Store::open(&path).unwrap();
    assert!(matches!(
        store.load_flow_checkpoint(lease, 22).await,
        Err(StoreError::CorruptFlowCheckpoint(request_id))
            if request_id == RequestId::from("corrupt-flow")
    ));
    close(store, &directory).await;
}

#[tokio::test]
async fn forged_terminal_cancellation_override_is_rejected_as_corrupt() {
    let (directory, path) = database_path("flow-checkpoint-forged-override");
    let store = Store::open(&path).unwrap();
    let lease = terminal_flow_with_checkpoint(
        &store,
        "forged-terminal-override",
        RunOutcome::Blocked,
        b"ordinary blocked result",
        false,
    )
    .await;
    store.shutdown().await.unwrap();

    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE flow_runs
             SET terminal_cancellation_override = 1
             WHERE request_id = 'forged-terminal-override'",
            [],
        )
        .unwrap();
    drop(connection);

    let store = Store::open(&path).unwrap();
    assert!(matches!(
        store.load_flow_checkpoint(lease, 40).await,
        Err(StoreError::CorruptFlowCheckpoint(request_id))
            if request_id == RequestId::from("forged-terminal-override")
    ));
    assert!(matches!(
        store.recover_all_leases(40).await,
        Err(StoreError::CorruptFlowCheckpoint(request_id))
            if request_id == RequestId::from("forged-terminal-override")
    ));
    close(store, &directory).await;
}

#[tokio::test]
async fn terminal_cancellation_override_requires_its_exact_durable_transition() {
    let (directory, path) = database_path("flow-checkpoint-override-transition");
    let store = Store::open(&path).unwrap();
    let request_id = "override-transition-corrupt";
    let lease = reconciliation_unknown_after_cancellation(
        &store,
        request_id,
        b"blocked reconciliation result",
    )
    .await;
    store.shutdown().await.unwrap();

    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE events SET payload = X'00'
             WHERE request_id = ?1 AND kind = 'flow_reconciliation_unknown'",
            [request_id],
        )
        .unwrap();
    drop(connection);

    let store = Store::open(&path).unwrap();
    assert!(matches!(
        store.load_flow_checkpoint(lease, 40).await,
        Err(StoreError::CorruptFlowCheckpoint(corrupt_id))
            if corrupt_id == RequestId::from(request_id)
    ));
    assert!(matches!(
        store
            .cancel(
                RequestId::from(request_id),
                40,
                b"generic cancellation".to_vec(),
            )
            .await,
        Err(StoreError::CorruptFlowCheckpoint(corrupt_id))
            if corrupt_id == RequestId::from(request_id)
    ));
    close(store, &directory).await;
}
