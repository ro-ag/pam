use std::{
    fs,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use pam_core::{
    ApprovalId, CallerCredential, CallerId, GrantId, IdempotencyKey, ProjectId, RequestId,
};
use pam_daemon::{DaemonConfig, request_exchange, request_status, serve_until};
use pam_platform::LocalEndpoint;
use pam_policy::{ApprovalRequirement, CapabilityName, Effect, Grant, ResourceName, ResourceScope};
use pam_protocol::{
    ApprovalDecision as ProtocolApprovalDecision, ApprovalDecisionDisposition, FailureCode,
    MAX_FRAME_SIZE, OperationTruth, PROTOCOL_VERSION, RequestEnvelope, ResultBody, ResultPayload,
    SourceAvailability, encode,
};
use pam_store::{
    AcceptRequest, ApprovalDecision, AuthorizationOutcome, AuthorizationRequest,
    CallerAuthentication, PutGrant, Store, StoreError, TerminalState,
};
use tokio::{sync::oneshot, task::JoinHandle};
use zeromq::{DealerSocket, Socket, SocketSend, ZmqMessage};

const TEST_CREDENTIAL: &str = "integration-caller-credential";

fn test_runtime(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let base = if cfg!(unix) {
        PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    };
    base.join(format!(
        "pam-it-{name}-{}-{}",
        std::process::id(),
        nonce % 1_000_000
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn brief_crosses_transport_with_explicit_unavailable_provenance() {
    let runtime = test_runtime("brief-round-trip");
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let (shutdown, daemon) = start_daemon(endpoint.clone()).await;
    for _ in 0..40 {
        if endpoint.socket_path().is_some_and(std::path::Path::exists) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let request = RequestEnvelope::brief(
        RequestId::from("brief-round-trip"),
        CallerId::from("integration-test"),
        ProjectId::from("project-round-trip"),
        IdempotencyKey::from("brief-round-trip"),
    )
    .authenticated(CallerCredential::new(TEST_CREDENTIAL));

    let exchange = request_exchange(&endpoint, &request, Duration::from_secs(1))
        .await
        .unwrap();
    assert!(exchange.events.is_empty());
    let ResultBody::Success {
        truth,
        payload: ResultPayload::Brief(brief),
    } = exchange.result.body
    else {
        panic!("brief should return a typed result")
    };
    assert_eq!(brief.provenance.len(), 1);
    assert_eq!(
        brief.provenance[0].availability,
        SourceAvailability::Unavailable
    );
    assert_eq!(truth, OperationTruth::Unresolved);

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn network_diagnostics_require_an_authenticated_project_grant() {
    let runtime = test_runtime("network-policy");
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = endpoint.runtime_dir().join("state.sqlite3");
    let (shutdown, daemon) = start_daemon(endpoint.clone()).await;
    for _ in 0..40 {
        if endpoint.socket_path().is_some_and(std::path::Path::exists) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let request = |suffix: &str| {
        RequestEnvelope::network_diagnostics(
            RequestId::new(format!("network-{suffix}")),
            CallerId::from("integration-test"),
            ProjectId::from("project-round-trip"),
            IdempotencyKey::new(format!("network-{suffix}")),
        )
        .authenticated(CallerCredential::new(TEST_CREDENTIAL))
    };

    let denied = request_exchange(&endpoint, &request("denied"), Duration::from_secs(1))
        .await
        .unwrap();
    assert!(matches!(
        denied.result.body,
        ResultBody::Failure(ref failure) if failure.code == FailureCode::Forbidden
    ));

    let store = Store::open(&state_path).unwrap();
    store
        .put_grant(PutGrant {
            grant: Grant {
                id: GrantId::from("integration-network-diagnostics"),
                caller: CallerId::from("integration-test"),
                project: ProjectId::from("project-round-trip"),
                capability: CapabilityName::parse("network.diagnostics").unwrap(),
                resource: ResourceScope::Any,
                effect: Effect::Allow,
                approval: ApprovalRequirement::None,
                expires_at_ms: None,
                revoked_at_ms: None,
            },
            created_at_ms: 2,
        })
        .await
        .unwrap();
    store.shutdown().await.unwrap();

    let allowed = request_exchange(&endpoint, &request("allowed"), Duration::from_secs(5))
        .await
        .unwrap();
    assert!(matches!(
        allowed.result.body,
        ResultBody::Success {
            payload: ResultPayload::NetworkDiagnostics(_),
            ..
        }
    ));

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

fn status_request() -> RequestEnvelope {
    RequestEnvelope::status(
        RequestId::from("request-round-trip"),
        CallerId::from("integration-test"),
        ProjectId::from("project-round-trip"),
        IdempotencyKey::from("status-round-trip"),
    )
    .authenticated(CallerCredential::new(TEST_CREDENTIAL))
}

fn stop_request(request_id: &str, caller_id: &str, credential: Option<&str>) -> RequestEnvelope {
    let request = RequestEnvelope::stop(
        RequestId::from(request_id),
        CallerId::from(caller_id),
        ProjectId::from("project-round-trip"),
        IdempotencyKey::new(format!("{request_id}-key")),
    );
    credential.map_or(request.clone(), |credential| {
        request.authenticated(CallerCredential::new(credential))
    })
}

fn approval_status(request_id: &str, approval_id: Option<ApprovalId>) -> RequestEnvelope {
    let request = RequestEnvelope::status(
        RequestId::from(request_id),
        CallerId::from("approval-caller"),
        ProjectId::from("project-round-trip"),
        IdempotencyKey::new(format!("{request_id}-key")),
    )
    .authenticated(CallerCredential::new("approval-caller-credential"));
    match approval_id {
        Some(approval_id) => request.with_approval(approval_id),
        None => request,
    }
}

fn approval_project_current(request_id: &str, approval_id: Option<ApprovalId>) -> RequestEnvelope {
    let request = RequestEnvelope::project_current(
        RequestId::from(request_id),
        CallerId::from("approval-caller"),
        ProjectId::from("project-round-trip"),
        IdempotencyKey::new(format!("{request_id}-key")),
    )
    .authenticated(CallerCredential::new("approval-caller-credential"));
    match approval_id {
        Some(approval_id) => request.with_approval(approval_id),
        None => request,
    }
}

fn approval_decision_request(
    request_id: &str,
    project_id: &str,
    caller_id: &str,
    credential: Option<&str>,
    approval_id: ApprovalId,
    decision: ProtocolApprovalDecision,
) -> RequestEnvelope {
    let request = RequestEnvelope::approval_decide(
        RequestId::from(request_id),
        CallerId::from(caller_id),
        ProjectId::from(project_id),
        IdempotencyKey::new(format!("{request_id}-key")),
        approval_id,
        decision,
    );
    credential.map_or(request.clone(), |credential| {
        request.authenticated(CallerCredential::new(credential))
    })
}

async fn approve_challenge(state_path: &std::path::Path, body: ResultBody) -> ApprovalId {
    let ResultBody::Failure(failure) = body else {
        panic!("approval-gated capability should return a challenge")
    };
    assert_eq!(failure.code, FailureCode::ApprovalRequired);
    let approval_id = failure
        .approval
        .expect("typed approval challenge")
        .approval_id;
    let store = Store::open(state_path).unwrap();
    store
        .decide_approval(
            approval_id.clone(),
            CallerId::from("integration-test"),
            ApprovalDecision::Approve,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
                .try_into()
                .unwrap(),
        )
        .await
        .unwrap();
    store.shutdown().await.unwrap();
    approval_id
}

async fn seed_approval_caller(state_path: &std::path::Path) {
    let seed = Store::open(state_path).unwrap();
    seed.register_caller(
        CallerId::from("approval-caller"),
        CallerCredential::new("approval-caller-credential"),
        1,
    )
    .await
    .unwrap();
    for capability in [
        "daemon.status",
        "daemon.stop",
        "project.current",
        "brief.read",
    ] {
        seed.put_grant(PutGrant {
            grant: Grant {
                id: GrantId::new(format!("approval-{capability}")),
                caller: CallerId::from("approval-caller"),
                project: ProjectId::from("project-round-trip"),
                capability: CapabilityName::parse(capability).unwrap(),
                resource: if capability == "project.current" {
                    ResourceScope::Exact(ResourceName::parse("project").unwrap())
                } else {
                    ResourceScope::Any
                },
                effect: Effect::Allow,
                approval: ApprovalRequirement::Once,
                expires_at_ms: None,
                revoked_at_ms: None,
            },
            created_at_ms: 1,
        })
        .await
        .unwrap();
    }
    seed.shutdown().await.unwrap();
}

async fn start_daemon(
    endpoint: LocalEndpoint,
) -> (
    oneshot::Sender<()>,
    JoinHandle<Result<(), pam_daemon::DaemonError>>,
) {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let state_path = endpoint.runtime_dir().join("state.sqlite3");
    let store = Store::open(&state_path).unwrap();
    let caller_id = CallerId::from("integration-test");
    let credential = CallerCredential::new(TEST_CREDENTIAL);
    if store
        .authenticate_caller(caller_id.clone(), credential.clone())
        .await
        .unwrap()
        == CallerAuthentication::UnknownCaller
    {
        store
            .register_caller(caller_id, credential, 1)
            .await
            .unwrap();
    }
    for capability in ["daemon.status", "daemon.stop", "brief.read"] {
        let result = store
            .put_grant(PutGrant {
                grant: Grant {
                    id: GrantId::new(format!("integration-{capability}")),
                    caller: CallerId::from("integration-test"),
                    project: ProjectId::from("project-round-trip"),
                    capability: CapabilityName::parse(capability).unwrap(),
                    resource: ResourceScope::Any,
                    effect: Effect::Allow,
                    approval: ApprovalRequirement::None,
                    expires_at_ms: None,
                    revoked_at_ms: None,
                },
                created_at_ms: 1,
            })
            .await;
        assert!(
            result.is_ok() || matches!(result, Err(StoreError::GrantAlreadyExists(_))),
            "integration grant should be present"
        );
    }
    store.shutdown().await.unwrap();
    let daemon = tokio::spawn(serve_until(
        DaemonConfig {
            endpoint,
            recover: false,
            model: None,
            state_path: Some(state_path),
            brief_provider: None,
        },
        async {
            let _ = shutdown_rx.await;
        },
    ));
    (shutdown_tx, daemon)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_crosses_transport_and_returns_an_immediate_result() {
    let runtime = test_runtime("round-trip");
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let (shutdown, daemon) = start_daemon(endpoint.clone()).await;

    for _ in 0..40 {
        if endpoint.socket_path().is_some_and(std::path::Path::exists) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let mut malformed_client = DealerSocket::new();
    malformed_client.connect(endpoint.address()).await.unwrap();
    let mut multipart = ZmqMessage::from(vec![1]);
    multipart.push_back(vec![2].into());
    malformed_client.send(multipart).await.unwrap();
    malformed_client
        .send(vec![0; MAX_FRAME_SIZE + 1].into())
        .await
        .unwrap();

    let request = status_request();
    let exchange = request_status(&endpoint, &request, Duration::from_secs(1))
        .await
        .unwrap();

    assert_eq!(exchange.result.request_id, request.request_id);
    assert_eq!(exchange.result.project_id, request.project_id);
    assert!(exchange.events.is_empty());

    let ResultBody::Success { truth, payload } = exchange.result.body else {
        panic!("status should succeed")
    };
    assert_eq!(truth, OperationTruth::Observed);
    let ResultPayload::Status(status) = payload else {
        panic!("status should return a status payload")
    };
    assert!(status.ready);
    assert!(status.healthy);
    assert_eq!(status.queue_depth, 0);

    let mut future_request = status_request();
    future_request.protocol_version = PROTOCOL_VERSION + 1;
    let future_exchange = request_status(&endpoint, &future_request, Duration::from_secs(1))
        .await
        .unwrap();
    assert!(future_exchange.events.is_empty());
    let ResultBody::Failure(failure) = future_exchange.result.body else {
        panic!("future protocol request should receive a typed failure")
    };
    assert_eq!(failure.code, FailureCode::UnsupportedProtocolVersion);

    shutdown.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), daemon)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(endpoint.ownership_path().exists());
    assert!(endpoint.socket_path().is_none_or(|path| !path.exists()));

    let (second_shutdown, second_daemon) = start_daemon(endpoint.clone()).await;
    for _ in 0..40 {
        if endpoint.socket_path().is_some_and(std::path::Path::exists) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    request_status(&endpoint, &status_request(), Duration::from_secs(1))
        .await
        .unwrap();
    second_shutdown.send(()).unwrap();
    second_daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_denies_unauthorized_callers_acknowledges_before_teardown_and_allows_restart() {
    let runtime = test_runtime("stop-round-trip");
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = endpoint.runtime_dir().join("state.sqlite3");
    let (shutdown, daemon) = start_daemon(endpoint.clone()).await;
    for _ in 0..40 {
        if endpoint.socket_path().is_some_and(std::path::Path::exists) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let store = Store::open(&state_path).unwrap();
    store
        .register_caller(
            CallerId::from("stop-denied-caller"),
            CallerCredential::new("stop-denied-credential"),
            2,
        )
        .await
        .unwrap();
    store.shutdown().await.unwrap();

    for (request, expected) in [
        (
            stop_request("stop-unauthenticated", "integration-test", None),
            FailureCode::Unauthenticated,
        ),
        (
            stop_request(
                "stop-policy-denied",
                "stop-denied-caller",
                Some("stop-denied-credential"),
            ),
            FailureCode::Forbidden,
        ),
    ] {
        let exchange = request_exchange(&endpoint, &request, Duration::from_secs(1))
            .await
            .unwrap();
        assert!(matches!(
            exchange.result.body,
            ResultBody::Failure(ref failure) if failure.code == expected
        ));
        assert!(!daemon.is_finished());
        assert!(endpoint.socket_path().is_some_and(std::path::Path::exists));
    }

    let stop = stop_request("stop-allowed", "integration-test", Some(TEST_CREDENTIAL));
    let acknowledged = request_exchange(&endpoint, &stop, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(acknowledged.result.request_id, stop.request_id);
    assert_eq!(acknowledged.result.project_id, stop.project_id);
    assert!(matches!(
        acknowledged.result.body,
        ResultBody::Success {
            truth: OperationTruth::Changed,
            payload: ResultPayload::DaemonLifecycle(ref result),
        } if result.stopping
    ));

    drop(shutdown);
    tokio::time::timeout(Duration::from_secs(2), daemon)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(endpoint.ownership_path().exists());
    assert!(endpoint.socket_path().is_none_or(|path| !path.exists()));

    let (second_shutdown, second_daemon) = start_daemon(endpoint.clone()).await;
    for _ in 0..40 {
        if endpoint.socket_path().is_some_and(std::path::Path::exists) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    request_status(&endpoint, &status_request(), Duration::from_secs(1))
        .await
        .unwrap();
    request_exchange(
        &endpoint,
        &stop_request(
            "stop-after-restart",
            "integration-test",
            Some(TEST_CREDENTIAL),
        ),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    drop(second_shutdown);
    second_daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test]
async fn unavailable_daemon_returns_recovery_without_auto_start() {
    let runtime = test_runtime("unavailable");
    let endpoint = LocalEndpoint::ipc(runtime.clone());

    let error = request_status(&endpoint, &status_request(), Duration::from_millis(50))
        .await
        .unwrap_err();

    assert!(error.is_unavailable());
    assert_eq!(error.recovery_action(), Some("pam daemon"));
    assert!(!endpoint.ownership_path().exists());
    assert!(!endpoint.socket_path().unwrap().exists());
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authentication_rejects_missing_wrong_and_revoked_credentials() {
    let runtime = test_runtime("authentication");
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = endpoint.runtime_dir().join("state.sqlite3");
    let (shutdown, daemon) = start_daemon(endpoint.clone()).await;
    for _ in 0..40 {
        if endpoint.socket_path().is_some_and(std::path::Path::exists) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let missing = RequestEnvelope::status(
        RequestId::from("auth-missing"),
        CallerId::from("integration-test"),
        ProjectId::from("project-round-trip"),
        IdempotencyKey::from("auth-missing"),
    );
    let wrong = RequestEnvelope::status(
        RequestId::from("auth-wrong"),
        CallerId::from("integration-test"),
        ProjectId::from("project-round-trip"),
        IdempotencyKey::from("auth-wrong"),
    )
    .authenticated(CallerCredential::new("wrong credential"));

    let missing_failure = request_status(&endpoint, &missing, Duration::from_secs(1))
        .await
        .unwrap()
        .result;
    let wrong_failure = request_status(&endpoint, &wrong, Duration::from_secs(1))
        .await
        .unwrap()
        .result;
    for result in [missing_failure, wrong_failure] {
        let ResultBody::Failure(failure) = result.body else {
            panic!("unauthenticated request should fail")
        };
        assert_eq!(failure.code, FailureCode::Unauthenticated);
        assert_eq!(failure.message, "caller authentication failed");
        assert_eq!(failure.recovery.as_deref(), Some("pam caller register"));
    }

    let valid = status_request();
    assert!(matches!(
        request_status(&endpoint, &valid, Duration::from_secs(1))
            .await
            .unwrap()
            .result
            .body,
        ResultBody::Success { .. }
    ));

    let store = Store::open(&state_path).unwrap();
    assert_eq!(
        store
            .revoke_caller(CallerId::from("integration-test"), 2)
            .await
            .unwrap(),
        pam_store::CallerRevocation::Revoked
    );
    store.shutdown().await.unwrap();
    let revoked = RequestEnvelope::status(
        RequestId::from("auth-revoked"),
        CallerId::from("integration-test"),
        ProjectId::from("project-round-trip"),
        IdempotencyKey::from("auth-revoked"),
    )
    .authenticated(CallerCredential::new(TEST_CREDENTIAL));
    let revoked_result = request_status(&endpoint, &revoked, Duration::from_secs(1))
        .await
        .unwrap()
        .result;
    let ResultBody::Failure(failure) = revoked_result.body else {
        panic!("revoked caller should fail")
    };
    assert_eq!(failure.code, FailureCode::Unauthenticated);
    assert_eq!(failure.message, "caller authentication failed");

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // One transport fixture proves the complete approval-decision boundary.
async fn project_current_and_remote_approval_decisions_are_scoped_and_fail_closed() {
    let runtime = test_runtime("project-current-approval");
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = endpoint.runtime_dir().join("state.sqlite3");
    seed_approval_caller(&state_path).await;

    let seed = Store::open(&state_path).unwrap();
    seed.register_caller(
        CallerId::from("revoked-reviewer"),
        CallerCredential::new("revoked-reviewer-credential"),
        2,
    )
    .await
    .unwrap();
    seed.revoke_caller(CallerId::from("revoked-reviewer"), 3)
        .await
        .unwrap();
    seed.accept(
        AcceptRequest {
            request_id: RequestId::from("current-terminal"),
            caller_id: CallerId::from("approval-caller"),
            project_id: ProjectId::from("project-round-trip"),
            idempotency_key: IdempotencyKey::from("current-terminal-key"),
            operation_kind: "test.operation".to_owned(),
            operation: b"operation-blob-secret".to_vec(),
        },
        4,
    )
    .await
    .unwrap();
    let terminal = seed.claim("seed-worker", 5, 100).await.unwrap().unwrap();
    seed.finish(
        terminal.lease,
        6,
        TerminalState::Succeeded,
        b"result-blob-secret".to_vec(),
    )
    .await
    .unwrap();
    seed.shutdown().await.unwrap();

    let (shutdown, daemon) = start_daemon(endpoint.clone()).await;
    for _ in 0..40 {
        if endpoint.socket_path().is_some_and(std::path::Path::exists) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // project.current is a baseline read: an authenticated caller with no
    // matching grant is served instead of rejected. Explicit deny and
    // approval-required grants (exercised below) still take over.
    let ungranted = RequestEnvelope::project_current(
        RequestId::from("current-ungranted"),
        CallerId::from("integration-test"),
        ProjectId::from("project-round-trip"),
        IdempotencyKey::from("current-ungranted-key"),
    )
    .authenticated(CallerCredential::new(TEST_CREDENTIAL));
    assert!(matches!(
        request_exchange(&endpoint, &ungranted, Duration::from_secs(1))
            .await
            .unwrap()
            .result
            .body,
        ResultBody::Success { .. }
    ));

    let current = approval_project_current("current-challenge", None);
    let challenged = request_exchange(&endpoint, &current, Duration::from_secs(1))
        .await
        .unwrap();
    assert!(challenged.events.is_empty());
    let ResultBody::Failure(challenge_failure) = challenged.result.body else {
        panic!("project.current should require its configured one-time approval")
    };
    assert_eq!(challenge_failure.code, FailureCode::ApprovalRequired);
    let approval_id = challenge_failure.approval.unwrap().approval_id;

    for unauthenticated in [
        approval_decision_request(
            "decision-missing",
            "project-round-trip",
            "approval-caller",
            None,
            approval_id.clone(),
            ProtocolApprovalDecision::Approve,
        ),
        approval_decision_request(
            "decision-wrong-caller",
            "project-round-trip",
            "other-caller",
            Some("approval-caller-credential"),
            approval_id.clone(),
            ProtocolApprovalDecision::Approve,
        ),
        approval_decision_request(
            "decision-revoked",
            "project-round-trip",
            "revoked-reviewer",
            Some("revoked-reviewer-credential"),
            approval_id.clone(),
            ProtocolApprovalDecision::Approve,
        ),
    ] {
        assert!(matches!(
            request_exchange(&endpoint, &unauthenticated, Duration::from_secs(1))
                .await
                .unwrap()
                .result
                .body,
            ResultBody::Failure(ref failure) if failure.code == FailureCode::Unauthenticated
        ));
    }

    let wrong_project = approval_decision_request(
        "decision-wrong-project",
        "other-project",
        "approval-caller",
        Some("approval-caller-credential"),
        approval_id.clone(),
        ProtocolApprovalDecision::Approve,
    );
    let wrong_project_result = request_exchange(&endpoint, &wrong_project, Duration::from_secs(1))
        .await
        .unwrap()
        .result;
    let ResultBody::Failure(wrong_project_failure) = wrong_project_result.body else {
        panic!("a project-mismatched approval decision must fail")
    };
    assert_eq!(wrong_project_failure.code, FailureCode::Forbidden);
    assert_eq!(
        wrong_project_failure.message,
        "approval is unavailable for this project or caller"
    );
    assert!(!wrong_project_failure.message.contains(approval_id.as_str()));

    for (request_id, decision) in [
        (
            "decision-other-caller-approve",
            ProtocolApprovalDecision::Approve,
        ),
        ("decision-other-caller-deny", ProtocolApprovalDecision::Deny),
    ] {
        let other_caller = approval_decision_request(
            request_id,
            "project-round-trip",
            "integration-test",
            Some(TEST_CREDENTIAL),
            approval_id.clone(),
            decision,
        );
        let result = request_exchange(&endpoint, &other_caller, Duration::from_secs(1))
            .await
            .unwrap()
            .result;
        let ResultBody::Failure(failure) = result.body else {
            panic!("another active caller must not decide the requester's approval")
        };
        assert_eq!(failure.code, FailureCode::Forbidden);
        assert_eq!(
            failure.message,
            "approval is unavailable for this project or caller"
        );
        assert!(!failure.message.contains(approval_id.as_str()));
    }

    let malformed = approval_decision_request(
        "decision-receipt-shaped",
        "project-round-trip",
        "approval-caller",
        Some("approval-caller-credential"),
        approval_id.clone(),
        ProtocolApprovalDecision::Approve,
    )
    .with_approval(ApprovalId::from("unexpected-receipt"));
    assert!(matches!(
        request_exchange(&endpoint, &malformed, Duration::from_secs(1))
            .await
            .unwrap()
            .result
            .body,
        ResultBody::Failure(ref failure) if failure.code == FailureCode::InvalidRequest
    ));
    let oversized_approval_id = approval_decision_request(
        "decision-oversized-id",
        "project-round-trip",
        "approval-caller",
        Some("approval-caller-credential"),
        ApprovalId::from("x".repeat(257)),
        ProtocolApprovalDecision::Approve,
    );
    assert!(matches!(
        request_exchange(
            &endpoint,
            &oversized_approval_id,
            Duration::from_secs(1),
        )
        .await
        .unwrap()
        .result
        .body,
        ResultBody::Failure(ref failure) if failure.code == FailureCode::InvalidRequest
    ));

    let approve = approval_decision_request(
        "decision-approve",
        "project-round-trip",
        "approval-caller",
        Some("approval-caller-credential"),
        approval_id.clone(),
        ProtocolApprovalDecision::Approve,
    );
    let approved = request_exchange(&endpoint, &approve, Duration::from_secs(1))
        .await
        .unwrap();
    assert!(approved.events.is_empty());
    assert!(matches!(
        approved.result.body,
        ResultBody::Success {
            truth: OperationTruth::Changed,
            payload: ResultPayload::ApprovalDecision(ref result),
        } if result.approval_id == approval_id
            && result.disposition == ApprovalDecisionDisposition::Approved
    ));
    let approved_retry = request_exchange(
        &endpoint,
        &approval_decision_request(
            "decision-approve-retry",
            "project-round-trip",
            "approval-caller",
            Some("approval-caller-credential"),
            approval_id.clone(),
            ProtocolApprovalDecision::Approve,
        ),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert!(matches!(
        approved_retry.result.body,
        ResultBody::Success {
            payload: ResultPayload::ApprovalDecision(ref result),
            ..
        } if result.approval_id == approval_id
            && result.disposition == ApprovalDecisionDisposition::Approved
    ));
    assert!(matches!(
        request_exchange(
            &endpoint,
            &approval_decision_request(
                "decision-approve-conflict",
                "project-round-trip",
                "approval-caller",
                Some("approval-caller-credential"),
                approval_id.clone(),
                ProtocolApprovalDecision::Deny,
            ),
            Duration::from_secs(1),
        )
        .await
        .unwrap()
        .result
        .body,
        ResultBody::Failure(ref failure) if failure.code == FailureCode::Forbidden
    ));

    let exact_retry = approval_project_current("current-approved", Some(approval_id.clone()));
    let current_result = request_exchange(&endpoint, &exact_retry, Duration::from_secs(1))
        .await
        .unwrap();
    assert!(current_result.events.is_empty());
    let encoded_current = encode(&current_result.result).unwrap();
    assert!(
        !encoded_current
            .windows(b"operation-blob-secret".len())
            .any(|window| window == b"operation-blob-secret")
    );
    assert!(
        !encoded_current
            .windows(b"result-blob-secret".len())
            .any(|window| window == b"result-blob-secret")
    );
    assert!(matches!(
        current_result.result.body,
        ResultBody::Success {
            truth: OperationTruth::Observed,
            payload: ResultPayload::ProjectCurrent(ref current),
        } if current.latest.as_ref().is_some_and(|latest|
            latest.request_id.as_str() == "current-terminal"
                && latest.operation_kind() == "test.operation")
    ));
    let store = Store::open(&state_path).unwrap();
    assert!(matches!(
        store.snapshot(exact_retry.request_id.clone()).await,
        Err(StoreError::RequestNotFound(_))
    ));
    store.shutdown().await.unwrap();
    assert!(matches!(
        request_exchange(
            &endpoint,
            &approval_project_current("current-reused", Some(approval_id)),
            Duration::from_secs(1),
        )
        .await
        .unwrap()
        .result
        .body,
        ResultBody::Failure(ref failure) if failure.code == FailureCode::Forbidden
    ));

    let denied_challenge = request_exchange(
        &endpoint,
        &approval_project_current("current-deny-challenge", None),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    let ResultBody::Failure(denied_failure) = denied_challenge.result.body else {
        panic!("a fresh project current request should create a fresh challenge")
    };
    let denied_id = denied_failure.approval.unwrap().approval_id;
    let denied = request_exchange(
        &endpoint,
        &approval_decision_request(
            "decision-deny",
            "project-round-trip",
            "approval-caller",
            Some("approval-caller-credential"),
            denied_id.clone(),
            ProtocolApprovalDecision::Deny,
        ),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert!(matches!(
        denied.result.body,
        ResultBody::Success {
            payload: ResultPayload::ApprovalDecision(ref result),
            ..
        } if result.approval_id == denied_id
            && result.disposition == ApprovalDecisionDisposition::Denied
    ));
    assert!(matches!(
        request_exchange(
            &endpoint,
            &approval_decision_request(
                "decision-deny-retry",
                "project-round-trip",
                "approval-caller",
                Some("approval-caller-credential"),
                denied_id.clone(),
                ProtocolApprovalDecision::Deny,
            ),
            Duration::from_secs(1),
        )
        .await
        .unwrap()
        .result
        .body,
        ResultBody::Success {
            payload: ResultPayload::ApprovalDecision(ref result),
            ..
        } if result.approval_id == denied_id
            && result.disposition == ApprovalDecisionDisposition::Denied
    ));

    let store = Store::open(&state_path).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let AuthorizationOutcome::ApprovalRequired {
        approval_id: expired_id,
        ..
    } = store
        .authorize(
            AuthorizationRequest {
                caller_id: CallerId::from("approval-caller"),
                project_id: ProjectId::from("project-round-trip"),
                capability: CapabilityName::parse("project.current").unwrap(),
                resource: ResourceName::parse("project").unwrap(),
                approval_id: None,
            },
            now,
            1,
        )
        .await
        .unwrap()
    else {
        panic!("the approval-required grant should create an expiring challenge")
    };
    store.shutdown().await.unwrap();
    tokio::time::sleep(Duration::from_millis(2)).await;
    let expired = request_exchange(
        &endpoint,
        &approval_decision_request(
            "decision-expired",
            "project-round-trip",
            "approval-caller",
            Some("approval-caller-credential"),
            expired_id.clone(),
            ProtocolApprovalDecision::Approve,
        ),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert!(matches!(
        expired.result.body,
        ResultBody::Success {
            payload: ResultPayload::ApprovalDecision(ref result),
            ..
        } if result.approval_id == expired_id
            && result.disposition == ApprovalDecisionDisposition::Expired
    ));
    assert!(matches!(
        request_exchange(
            &endpoint,
            &approval_decision_request(
                "decision-expired-retry",
                "project-round-trip",
                "approval-caller",
                Some("approval-caller-credential"),
                expired_id.clone(),
                ProtocolApprovalDecision::Deny,
            ),
            Duration::from_secs(1),
        )
        .await
        .unwrap()
        .result
        .body,
        ResultBody::Success {
            payload: ResultPayload::ApprovalDecision(ref result),
            ..
        } if result.approval_id == expired_id
            && result.disposition == ApprovalDecisionDisposition::Expired
    ));

    request_exchange(
        &endpoint,
        &stop_request(
            "stop-current-approval-test",
            "integration-test",
            Some(TEST_CREDENTIAL),
        ),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    drop(shutdown);
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_approval_is_required_bound_to_effect_and_consumed_once() {
    let runtime = test_runtime("policy-approval");
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = endpoint.runtime_dir().join("state.sqlite3");
    seed_approval_caller(&state_path).await;

    let (shutdown, daemon) = start_daemon(endpoint.clone()).await;
    for _ in 0..40 {
        if endpoint.socket_path().is_some_and(std::path::Path::exists) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let challenge_result = request_status(
        &endpoint,
        &approval_status("approval-request", None),
        Duration::from_secs(1),
    )
    .await
    .unwrap()
    .result;
    let challenge = approve_challenge(&state_path, challenge_result.body).await;

    let wrong_effect = RequestEnvelope::brief(
        RequestId::from("approval-wrong-effect"),
        CallerId::from("approval-caller"),
        ProjectId::from("project-round-trip"),
        IdempotencyKey::from("approval-wrong-effect-key"),
    )
    .authenticated(CallerCredential::new("approval-caller-credential"))
    .with_approval(challenge.clone());
    let wrong = request_exchange(&endpoint, &wrong_effect, Duration::from_secs(1))
        .await
        .unwrap();
    assert!(matches!(
        wrong.result.body,
        ResultBody::Failure(ref failure) if failure.code == FailureCode::Forbidden
    ));

    let approved = approval_status("approval-approved", Some(challenge.clone()));
    assert!(matches!(
        request_status(&endpoint, &approved, Duration::from_secs(1))
            .await
            .unwrap()
            .result
            .body,
        ResultBody::Success { .. }
    ));
    let replay = approval_status("approval-replay", Some(challenge));
    assert!(matches!(
        request_status(&endpoint, &replay, Duration::from_secs(1))
            .await
            .unwrap()
            .result
            .body,
        ResultBody::Failure(ref failure) if failure.code == FailureCode::Forbidden
    ));

    let stop = stop_request(
        "approval-stop",
        "approval-caller",
        Some("approval-caller-credential"),
    );
    let stop_challenge = request_exchange(&endpoint, &stop, Duration::from_secs(1))
        .await
        .unwrap();
    let stop_approval = approve_challenge(&state_path, stop_challenge.result.body).await;
    let stopped = request_exchange(
        &endpoint,
        &stop.with_approval(stop_approval),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert!(matches!(
        stopped.result.body,
        ResultBody::Success {
            payload: ResultPayload::DaemonLifecycle(_),
            ..
        }
    ));

    drop(shutdown);
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}
