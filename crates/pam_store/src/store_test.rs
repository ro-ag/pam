use std::fs;

use pam_core::{CallerId, IdempotencyKey, ProjectId, RequestId};
use rusqlite::Connection;

use super::{
    AcceptOutcome, AcceptRequest, CancelOutcome, RequestState, Store, StoreError, TerminalState,
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

async fn close(store: Store, directory: &std::path::Path) {
    store.shutdown().await.unwrap();
    fs::remove_dir_all(directory).unwrap();
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
