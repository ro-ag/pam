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
use pam_policy::{ApprovalRequirement, CapabilityName, Effect, Grant, ResourceScope};
use pam_protocol::{
    Event, FailureCode, MAX_FRAME_SIZE, OperationTruth, PROTOCOL_VERSION, RequestEnvelope,
    ResultBody, ResultPayload, SourceAvailability,
};
use pam_store::{ApprovalDecision, CallerAuthentication, PutGrant, Store, StoreError};
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

async fn seed_approval_caller(state_path: &std::path::Path) {
    let seed = Store::open(state_path).unwrap();
    seed.register_caller(
        CallerId::from("approval-caller"),
        CallerCredential::new("approval-caller-credential"),
        1,
    )
    .await
    .unwrap();
    for capability in ["daemon.status", "brief.read"] {
        seed.put_grant(PutGrant {
            grant: Grant {
                id: GrantId::new(format!("approval-{capability}")),
                caller: CallerId::from("approval-caller"),
                project: ProjectId::from("project-round-trip"),
                capability: CapabilityName::parse(capability).unwrap(),
                resource: ResourceScope::Any,
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
    for capability in ["daemon.status", "brief.read"] {
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
async fn status_crosses_transport_queue_events_and_result() {
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
    assert_eq!(
        exchange
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(exchange.events.iter().all(|event| {
        event.request_id == request.request_id && event.project_id == request.project_id
    }));
    assert_eq!(
        exchange
            .events
            .iter()
            .map(|event| event.event.clone())
            .collect::<Vec<_>>(),
        vec![Event::Accepted, Event::Started, Event::Completed]
    );

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
    let ResultBody::Failure(challenge_failure) = challenge_result.body else {
        panic!("approval-gated capability should return a challenge")
    };
    assert_eq!(challenge_failure.code, FailureCode::ApprovalRequired);
    let challenge = challenge_failure
        .approval
        .expect("typed approval challenge");

    let decision_store = Store::open(&state_path).unwrap();
    let decision_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    decision_store
        .decide_approval(
            challenge.approval_id.clone(),
            CallerId::from("integration-test"),
            ApprovalDecision::Approve,
            decision_time,
        )
        .await
        .unwrap();
    decision_store.shutdown().await.unwrap();

    let wrong_effect = RequestEnvelope::brief(
        RequestId::from("approval-wrong-effect"),
        CallerId::from("approval-caller"),
        ProjectId::from("project-round-trip"),
        IdempotencyKey::from("approval-wrong-effect-key"),
    )
    .authenticated(CallerCredential::new("approval-caller-credential"))
    .with_approval(challenge.approval_id.clone());
    let wrong = request_exchange(&endpoint, &wrong_effect, Duration::from_secs(1))
        .await
        .unwrap();
    assert!(matches!(
        wrong.result.body,
        ResultBody::Failure(ref failure) if failure.code == FailureCode::Forbidden
    ));

    let approved = approval_status("approval-approved", Some(challenge.approval_id.clone()));
    assert!(matches!(
        request_status(&endpoint, &approved, Duration::from_secs(1))
            .await
            .unwrap()
            .result
            .body,
        ResultBody::Success { .. }
    ));
    let replay = approval_status("approval-replay", Some(challenge.approval_id));
    assert!(matches!(
        request_status(&endpoint, &replay, Duration::from_secs(1))
            .await
            .unwrap()
            .result
            .body,
        ResultBody::Failure(ref failure) if failure.code == FailureCode::Forbidden
    ));

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}
