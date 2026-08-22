use std::{
    fs,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use pam_core::{CallerCredential, CallerId, GrantId, IdempotencyKey, ProjectId, RequestId};
use pam_daemon::{DaemonConfig, request_exchange, serve_until};
use pam_platform::LocalEndpoint;
use pam_policy::{ApprovalRequirement, CapabilityName, Effect, Grant, ResourceScope};
use pam_protocol::{
    FailureCode, OperationTruth, RequestEnvelope, ResultBody, ResultPayload, encode,
};
use pam_store::{AppendAuditEvent, CallerAuthentication, PutGrant, Store};
use sha2::{Digest as _, Sha256};
use tokio::{sync::oneshot, task::JoinHandle};

const TEST_CREDENTIAL: &str = "observatory-caller-credential";

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

fn seeded_audit_event(event_id: &str, occurred_at_ms: u64) -> AppendAuditEvent {
    AppendAuditEvent {
        event_id: event_id.to_owned(),
        project_id: ProjectId::from("project-observatory"),
        caller_id: CallerId::from("seeded-caller"),
        action: "policy.authorize".to_owned(),
        decision: "allow".to_owned(),
        outcome: "completed".to_owned(),
        redacted_detail: "seeded-secret-detail".to_owned(),
        occurred_at_ms,
        retain_until_ms: occurred_at_ms + 1_000_000,
    }
}

fn activity_request(
    request_id: &str,
    caller_id: &str,
    credential: &str,
    limit: u32,
) -> RequestEnvelope {
    RequestEnvelope::daemon_activity(
        RequestId::from(request_id),
        CallerId::from(caller_id),
        ProjectId::from("project-observatory"),
        IdempotencyKey::new(format!("{request_id}-key")),
        limit,
    )
    .authenticated(CallerCredential::new(credential))
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
    let caller_id = CallerId::from("observatory-test");
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

async fn wait_until_ready(endpoint: &LocalEndpoint) {
    for _ in 0..40 {
        if endpoint.socket_path().is_some_and(std::path::Path::exists) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[allow(clippy::too_many_lines)] // One transport fixture proves the complete activity read boundary.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_activity_is_newest_first_bounded_baseline_and_deny_overridable() {
    let runtime = test_runtime("activity-round-trip");
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = endpoint.runtime_dir().join("state.sqlite3");

    let seed = Store::open(&state_path).unwrap();
    for (event_id, occurred_at_ms) in [("seed-1", 10), ("seed-2", 11), ("seed-3", 12)] {
        seed.append_audit_event(seeded_audit_event(event_id, occurred_at_ms))
            .await
            .unwrap();
    }
    seed.register_caller(
        CallerId::from("denied-observer"),
        CallerCredential::new("denied-observer-credential"),
        2,
    )
    .await
    .unwrap();
    // daemon.activity is a baseline capability, so denial coverage needs an
    // explicit deny grant.
    seed.put_grant(PutGrant {
        grant: Grant {
            id: GrantId::from("activity-denied-grant"),
            caller: CallerId::from("denied-observer"),
            project: ProjectId::from("project-observatory"),
            capability: CapabilityName::parse("daemon.activity").unwrap(),
            resource: ResourceScope::Any,
            effect: Effect::Deny,
            approval: ApprovalRequirement::None,
            expires_at_ms: None,
            revoked_at_ms: None,
        },
        created_at_ms: 3,
    })
    .await
    .unwrap();
    seed.shutdown().await.unwrap();

    let (shutdown, daemon) = start_daemon(endpoint.clone()).await;
    wait_until_ready(&endpoint).await;

    // A bounded page is newest-first and reports the remaining backlog.
    let bounded = request_exchange(
        &endpoint,
        &activity_request("activity-bounded", "observatory-test", TEST_CREDENTIAL, 1),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    let ResultBody::Success {
        truth,
        payload: ResultPayload::DaemonActivity(bounded_activity),
    } = bounded.result.body
    else {
        panic!("a baseline activity read should return a typed result")
    };
    assert_eq!(truth, OperationTruth::Observed);
    assert_eq!(bounded_activity.events.len(), 1);
    assert!(bounded_activity.truncated);

    // Zero requests the server default; an oversized limit is clamped instead
    // of rejected. Both return every stored event, newest first, without the
    // redacted detail.
    for (request_id, limit) in [("activity-default", 0), ("activity-oversized", 10_000)] {
        let exchange = request_exchange(
            &endpoint,
            &activity_request(request_id, "observatory-test", TEST_CREDENTIAL, limit),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let encoded = encode(&exchange.result).unwrap();
        assert!(
            !encoded
                .windows(b"seeded-secret-detail".len())
                .any(|window| window == b"seeded-secret-detail")
        );
        let ResultBody::Success {
            payload: ResultPayload::DaemonActivity(activity),
            ..
        } = exchange.result.body
        else {
            panic!("activity reads should return a typed result")
        };
        assert!(!activity.truncated);
        assert!(activity.events.len() >= 3);
        assert!(
            activity
                .events
                .windows(2)
                .all(|pair| pair[0].sequence > pair[1].sequence),
            "events must be strictly newest-first"
        );
        let seeded: Vec<_> = activity
            .events
            .iter()
            .filter(|event| event.caller_id.as_str() == "seeded-caller")
            .collect();
        assert_eq!(
            seeded
                .iter()
                .map(|event| (event.sequence, event.occurred_at_ms))
                .collect::<Vec<_>>(),
            [(3, 12), (2, 11), (1, 10)]
        );
        assert!(
            seeded
                .iter()
                .all(|event| event.project_id.as_str() == "project-observatory"
                    && event.action == "policy.authorize"
                    && event.decision == "allow"
                    && event.outcome == "completed")
        );
    }

    // An explicit deny grant overrides the baseline allowance.
    let denied = request_exchange(
        &endpoint,
        &activity_request(
            "activity-denied",
            "denied-observer",
            "denied-observer-credential",
            5,
        ),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert!(matches!(
        denied.result.body,
        ResultBody::Failure(ref failure) if failure.code == FailureCode::Forbidden
    ));

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_list_returns_revocations_without_credential_material() {
    let runtime = test_runtime("caller-list-round-trip");
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let state_path = endpoint.runtime_dir().join("state.sqlite3");

    let seed = Store::open(&state_path).unwrap();
    seed.register_caller(
        CallerId::from("listed-active"),
        CallerCredential::new("listed-active-credential"),
        10,
    )
    .await
    .unwrap();
    seed.register_caller(
        CallerId::from("listed-revoked"),
        CallerCredential::new("listed-revoked-credential"),
        20,
    )
    .await
    .unwrap();
    seed.revoke_caller(CallerId::from("listed-revoked"), 30)
        .await
        .unwrap();
    seed.shutdown().await.unwrap();

    let (shutdown, daemon) = start_daemon(endpoint.clone()).await;
    wait_until_ready(&endpoint).await;

    let request = RequestEnvelope::caller_list(
        RequestId::from("caller-list"),
        CallerId::from("observatory-test"),
        ProjectId::from("project-observatory"),
        IdempotencyKey::from("caller-list-key"),
    )
    .authenticated(CallerCredential::new(TEST_CREDENTIAL));
    let exchange = request_exchange(&endpoint, &request, Duration::from_secs(1))
        .await
        .unwrap();

    let encoded = encode(&exchange.result).unwrap();
    for credential in [
        "listed-active-credential",
        "listed-revoked-credential",
        TEST_CREDENTIAL,
    ] {
        assert!(
            !encoded
                .windows(credential.len())
                .any(|window| window == credential.as_bytes())
        );
        let digest: [u8; 32] = Sha256::digest(credential.as_bytes()).into();
        assert!(
            !encoded.windows(digest.len()).any(|window| window == digest),
            "credential digests must never cross the caller list contract"
        );
    }

    let ResultBody::Success {
        truth,
        payload: ResultPayload::CallerList(list),
    } = exchange.result.body
    else {
        panic!("a baseline caller list read should return a typed result")
    };
    assert_eq!(truth, OperationTruth::Observed);
    let revoked = list
        .callers
        .iter()
        .find(|caller| caller.caller_id.as_str() == "listed-revoked")
        .expect("revoked callers stay listed");
    assert_eq!(revoked.registered_at_ms, 20);
    assert_eq!(revoked.revoked_at_ms, Some(30));
    let active = list
        .callers
        .iter()
        .find(|caller| caller.caller_id.as_str() == "listed-active")
        .expect("active callers are listed");
    assert_eq!(active.registered_at_ms, 10);
    assert_eq!(active.revoked_at_ms, None);

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}
