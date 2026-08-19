use std::fs;

use pam_core::{
    ApprovalId, CallerCredential, CallerId, GrantId, IdempotencyKey, ProjectId, RequestId,
};
use pam_policy::{ApprovalRequirement, CapabilityName, Effect, Grant, ResourceName, ResourceScope};
use rusqlite::Connection;

use super::{
    AcceptOutcome, AcceptRequest, ApprovalDecision, ApprovalDecisionOutcome, AuthorizationOutcome,
    AuthorizationRequest, CallerAuthentication, CallerRevocation, CancelOutcome, GrantRevocation,
    PutGrant, RequestState, Store, StoreError, TerminalState,
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

async fn close(store: Store, directory: &std::path::Path) {
    store.shutdown().await.unwrap();
    fs::remove_dir_all(directory).unwrap();
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
        CancelOutcome::CancellationRequested
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
