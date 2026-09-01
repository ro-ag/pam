use std::sync::Arc;
use std::time::Duration;

use pam_proto::{Caller, Envelope, PROTOCOL_VERSION};
use pam_store::{Actor, AuditEntry, Decision, RequestState, Store};
use tokio::sync::watch;
use tokio::time::{Instant, advance, timeout};

use crate::policy::CapabilityClass;
use crate::queue::{
    ACTION_CANCEL, ACTION_LEASE_REAPED, AdmitOutcome, CAUSE_CANCELLED, CAUSE_LEASE_EXPIRED,
    CancelOutcome, QueueError, QueueManager,
};

const DEADLINE: Duration = Duration::from_secs(5);
const REPO_A: &str = "/repo/a";
const REPO_B: &str = "/repo/b";

fn envelope(id: &str, repo: &str, args: serde_json::Value, key: Option<&str>) -> Envelope {
    Envelope {
        v: PROTOCOL_VERSION,
        id: id.to_owned(),
        capability: "echo".to_owned(),
        client_version: env!("CARGO_PKG_VERSION").to_owned(),
        caller: Caller {
            agent: "claude".to_owned(),
            repo: repo.to_owned(),
            pid: 4242,
        },
        args,
        idempotency_key: key.map(str::to_owned),
        deadline_ms: 60_000,
        wait: true,
    }
}

/// The executor-style audit entry tests hand to `complete`.
fn execute_entry() -> AuditEntry<'static> {
    AuditEntry {
        action: "execute",
        decision: Decision::Allow,
        actor: Actor::System,
        detail: None,
    }
}

async fn manager() -> (Arc<Store>, Arc<QueueManager>) {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let queue = Arc::new(QueueManager::new(Arc::clone(&store)));
    (store, queue)
}

/// Admits as non-destructive (the ordinary laned class) and unwraps.
async fn admit(queue: &QueueManager, envelope: &Envelope) -> AdmitOutcome {
    queue
        .admit(envelope, CapabilityClass::NonDestructive)
        .await
        .unwrap()
}

/// Admits and places on the lane (the full pre-gate + post-gate pair),
/// panicking on attach or bypass; returns the lane position.
async fn enqueue(queue: &QueueManager, envelope: &Envelope) -> usize {
    assert_eq!(admit(queue, envelope).await, AdmitOutcome::Admitted);
    queue
        .place_in_lane(&envelope.id, &envelope.caller.repo, envelope.deadline_ms)
        .await
}

#[tokio::test]
async fn enqueue_new_inserts_queued_row_with_lane_position() {
    timeout(DEADLINE, async {
        let (store, queue) = manager().await;

        // Positions count per lane, zero-based.
        for (i, expected) in [(1, 0), (2, 1), (3, 2)] {
            let env = envelope(
                &format!("req_a{i}"),
                REPO_A,
                serde_json::json!({ "n": i }),
                None,
            );
            assert_eq!(enqueue(&queue, &env).await, expected);
        }
        let env = envelope("req_b1", REPO_B, serde_json::json!({ "n": 1 }), None);
        assert_eq!(enqueue(&queue, &env).await, 0);

        let row = store.get_request("req_a1").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Queued);
        assert_eq!(row.repo, REPO_A);
        assert_eq!(row.args_json, r#"{"n":1}"#);
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn same_repo_serializes_through_the_lease() {
    timeout(DEADLINE, async {
        let (store, queue) = manager().await;
        enqueue(
            &queue,
            &envelope("req_1", REPO_A, serde_json::json!({ "n": 1 }), None),
        )
        .await;
        enqueue(
            &queue,
            &envelope("req_2", REPO_A, serde_json::json!({ "n": 2 }), None),
        )
        .await;

        let work = queue.take_next(REPO_A).await.unwrap().unwrap();
        assert_eq!(work.request_id, "req_1");
        let row = store.get_request("req_1").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Running);

        // One running per lane: the second request waits for the lease.
        assert!(queue.take_next(REPO_A).await.unwrap().is_none());

        assert!(
            queue
                .complete("req_1", RequestState::Done, Some("ok"), execute_entry())
                .await
                .unwrap()
        );
        let row = store.get_request("req_1").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Done);
        assert_eq!(row.outcome.as_deref(), Some("ok"));

        let work = queue.take_next(REPO_A).await.unwrap().unwrap();
        assert_eq!(work.request_id, "req_2");
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn different_repos_run_in_parallel() {
    timeout(DEADLINE, async {
        let (_store, queue) = manager().await;
        enqueue(
            &queue,
            &envelope("req_a", REPO_A, serde_json::json!({}), None),
        )
        .await;
        enqueue(
            &queue,
            &envelope("req_b", REPO_B, serde_json::json!({}), None),
        )
        .await;

        let work_a = queue.take_next(REPO_A).await.unwrap().unwrap();
        let work_b = queue.take_next(REPO_B).await.unwrap().unwrap();
        assert_eq!(work_a.request_id, "req_a");
        assert_eq!(work_b.request_id, "req_b");
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn read_only_bypasses_lanes_but_leaves_a_running_row() {
    timeout(DEADLINE, async {
        let (store, queue) = manager().await;
        let env = envelope("req_ro", REPO_A, serde_json::json!({}), None);
        let outcome = queue.admit(&env, CapabilityClass::ReadOnly).await.unwrap();
        assert_eq!(outcome, AdmitOutcome::Bypass);

        // The row exists for the audit trail, already running.
        let row = store.get_request("req_ro").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Running);
        // ...but never entered a lane.
        assert!(queue.take_next(REPO_A).await.unwrap().is_none());
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn dedupe_by_idempotency_key_attaches() {
    timeout(DEADLINE, async {
        let (store, queue) = manager().await;
        let first = envelope(
            "req_1",
            REPO_A,
            serde_json::json!({ "n": 1 }),
            Some("key-1"),
        );
        assert_eq!(enqueue(&queue, &first).await, 0);

        // Same key attaches even though the args differ.
        let dup = envelope(
            "req_2",
            REPO_A,
            serde_json::json!({ "n": 2 }),
            Some("key-1"),
        );
        assert_eq!(
            admit(&queue, &dup).await,
            AdmitOutcome::Attached {
                existing_request_id: "req_1".to_owned()
            }
        );
        // No second row was inserted.
        assert!(store.get_request("req_2").await.unwrap().is_none());

        // A different key is new work.
        let other = envelope(
            "req_3",
            REPO_A,
            serde_json::json!({ "n": 1 }),
            Some("key-2"),
        );
        assert_eq!(enqueue(&queue, &other).await, 1);
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn dedupe_by_shape_attaches_and_different_args_do_not() {
    timeout(DEADLINE, async {
        let (store, queue) = manager().await;
        let first = envelope("req_1", REPO_A, serde_json::json!({ "n": 1 }), None);
        enqueue(&queue, &first).await;

        // Same capability + repo + args, no key: attach.
        let dup = envelope("req_2", REPO_A, serde_json::json!({ "n": 1 }), None);
        assert_eq!(
            admit(&queue, &dup).await,
            AdmitOutcome::Attached {
                existing_request_id: "req_1".to_owned()
            }
        );
        assert!(store.get_request("req_2").await.unwrap().is_none());

        // Different args or different repo: new work.
        let other_args = envelope("req_3", REPO_A, serde_json::json!({ "n": 2 }), None);
        assert_eq!(enqueue(&queue, &other_args).await, 1);
        let other_repo = envelope("req_4", REPO_B, serde_json::json!({ "n": 1 }), None);
        assert_eq!(enqueue(&queue, &other_repo).await, 0);
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn dedupe_also_attaches_to_running_requests() {
    timeout(DEADLINE, async {
        let (_store, queue) = manager().await;
        enqueue(
            &queue,
            &envelope("req_1", REPO_A, serde_json::json!({}), Some("k")),
        )
        .await;
        let work = queue.take_next(REPO_A).await.unwrap().unwrap();
        assert_eq!(work.request_id, "req_1");

        // Running is still in-flight: the retry attaches.
        let dup = envelope("req_2", REPO_A, serde_json::json!({}), Some("k"));
        assert_eq!(
            admit(&queue, &dup).await,
            AdmitOutcome::Attached {
                existing_request_id: "req_1".to_owned()
            }
        );
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn terminal_request_does_not_attach() {
    timeout(DEADLINE, async {
        let (_store, queue) = manager().await;
        enqueue(
            &queue,
            &envelope("req_1", REPO_A, serde_json::json!({}), Some("k")),
        )
        .await;
        queue.take_next(REPO_A).await.unwrap().unwrap();
        queue
            .complete("req_1", RequestState::Done, Some("ok"), execute_entry())
            .await
            .unwrap();

        // The same key after completion runs fresh work.
        let retry = envelope("req_2", REPO_A, serde_json::json!({}), Some("k"));
        assert_eq!(enqueue(&queue, &retry).await, 0);
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn cancel_queued_is_terminal_audited_and_skipped_by_the_lane() {
    timeout(DEADLINE, async {
        let (store, queue) = manager().await;
        enqueue(
            &queue,
            &envelope("req_1", REPO_A, serde_json::json!({ "n": 1 }), None),
        )
        .await;
        enqueue(
            &queue,
            &envelope("req_2", REPO_A, serde_json::json!({ "n": 2 }), None),
        )
        .await;

        let outcome = queue.cancel("req_1", Actor::Human).await.unwrap();
        assert_eq!(outcome, CancelOutcome::CancelledQueued);

        // Terminal failed with cause cancelled...
        let row = store.get_request("req_1").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed);
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_CANCELLED));
        // ...with its own audit row naming the actor.
        let audit = store.audit_for_request("req_1").await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, ACTION_CANCEL);
        assert_eq!(audit[0].decision, Decision::Deny);
        assert_eq!(audit[0].actor, Actor::Human);
        assert!(audit[0].detail.as_deref().unwrap().contains("human"));

        // The lane skips the cancelled request.
        let work = queue.take_next(REPO_A).await.unwrap().unwrap();
        assert_eq!(work.request_id, "req_2");
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn cancel_running_signals_the_lease_holder() {
    timeout(DEADLINE, async {
        let (store, queue) = manager().await;
        enqueue(
            &queue,
            &envelope("req_1", REPO_A, serde_json::json!({}), None),
        )
        .await;
        let mut work = queue.take_next(REPO_A).await.unwrap().unwrap();

        let outcome = queue.cancel("req_1", Actor::System).await.unwrap();
        assert_eq!(outcome, CancelOutcome::SignalledRunning);

        // The holder observes the cooperative signal...
        work.cancel.changed().await.unwrap();
        assert!(*work.cancel.borrow());
        // ...while the row stays running until the executor finishes
        // through complete (which owns the terminal write on this path).
        let row = store.get_request("req_1").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Running);
        assert!(
            queue
                .complete(
                    "req_1",
                    RequestState::Failed,
                    Some(CAUSE_CANCELLED),
                    execute_entry(),
                )
                .await
                .unwrap()
        );
        let row = store.get_request("req_1").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed);
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn cancel_unknown_or_terminal_request_is_not_found() {
    timeout(DEADLINE, async {
        let (_store, queue) = manager().await;
        assert_eq!(
            queue.cancel("req_ghost", Actor::Human).await.unwrap(),
            CancelOutcome::NotFound
        );

        // A completed request has nothing left to cancel either.
        enqueue(
            &queue,
            &envelope("req_1", REPO_A, serde_json::json!({}), None),
        )
        .await;
        queue.take_next(REPO_A).await.unwrap().unwrap();
        queue
            .complete("req_1", RequestState::Done, None, execute_entry())
            .await
            .unwrap();
        assert_eq!(
            queue.cancel("req_1", Actor::Human).await.unwrap(),
            CancelOutcome::NotFound
        );
    })
    .await
    .expect("test within deadline");
}

#[tokio::test(start_paused = true)]
async fn lease_reaping_fails_the_row_audits_and_frees_the_lane() {
    timeout(DEADLINE, async {
        let (store, queue) = manager().await;
        let mut env = envelope("req_1", REPO_A, serde_json::json!({ "n": 1 }), None);
        env.deadline_ms = 100;
        enqueue(&queue, &env).await;
        enqueue(
            &queue,
            &envelope("req_2", REPO_A, serde_json::json!({ "n": 2 }), None),
        )
        .await;

        let mut work = queue.take_next(REPO_A).await.unwrap().unwrap();
        assert_eq!(work.request_id, "req_1");

        // Not yet expired: nothing reaped, lane still busy.
        assert!(queue.reap_expired(Instant::now()).await.unwrap().is_empty());
        assert!(queue.take_next(REPO_A).await.unwrap().is_none());

        advance(Duration::from_millis(200)).await;
        let reaped = queue.reap_expired(Instant::now()).await.unwrap();
        assert_eq!(reaped, ["req_1"]);

        // Terminal failed with cause lease_expired, audited as a system
        // timeout.
        let row = store.get_request("req_1").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed);
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_LEASE_EXPIRED));
        let audit = store.audit_for_request("req_1").await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, ACTION_LEASE_REAPED);
        assert_eq!(audit[0].decision, Decision::Timeout);
        assert_eq!(audit[0].actor, Actor::System);

        // The stale holder was signalled, and a late complete is a no-op.
        work.cancel.changed().await.unwrap();
        assert!(*work.cancel.borrow());
        assert!(
            !queue
                .complete("req_1", RequestState::Done, Some("late"), execute_entry())
                .await
                .unwrap()
        );
        let row = store.get_request("req_1").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed);

        // The lane is free for the next request.
        let work = queue.take_next(REPO_A).await.unwrap().unwrap();
        assert_eq!(work.request_id, "req_2");
    })
    .await
    .expect("test within deadline");
}

#[tokio::test(start_paused = true)]
async fn background_reaper_collects_expired_leases() {
    timeout(DEADLINE, async {
        let (store, queue) = manager().await;
        let mut env = envelope("req_1", REPO_A, serde_json::json!({}), None);
        env.deadline_ms = 20;
        enqueue(&queue, &env).await;
        queue.take_next(REPO_A).await.unwrap().unwrap();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = Arc::clone(&queue).run_reaper(Duration::from_millis(50), shutdown_rx);

        // The paused clock auto-advances while everything is idle; poll
        // until the reaper has done its job.
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let row = store.get_request("req_1").await.unwrap().unwrap();
            if row.state == RequestState::Failed {
                assert_eq!(row.outcome.as_deref(), Some(CAUSE_LEASE_EXPIRED));
                break;
            }
        }

        shutdown_tx.send(true).unwrap();
        handle.await.unwrap();
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn complete_refuses_non_terminal_states() {
    timeout(DEADLINE, async {
        let (_store, queue) = manager().await;
        enqueue(
            &queue,
            &envelope("req_1", REPO_A, serde_json::json!({}), None),
        )
        .await;
        queue.take_next(REPO_A).await.unwrap().unwrap();

        for state in [
            RequestState::Queued,
            RequestState::Running,
            RequestState::WaitingApproval,
        ] {
            let err = queue
                .complete("req_1", state, None, execute_entry())
                .await
                .unwrap_err();
            assert!(
                matches!(err, QueueError::NotTerminal { .. }),
                "{state:?} must be refused, got {err:?}"
            );
        }
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn rebuild_from_store_restores_lane_order() {
    timeout(DEADLINE, async {
        let (store, queue) = manager().await;
        // Rows straight in the store, as a previous daemon left them
        // (same-second inserts: the id tie-break keeps order).
        for (id, repo) in [("req_a1", REPO_A), ("req_b1", REPO_B), ("req_a2", REPO_A)] {
            store
                .insert_request(id, "echo", repo, "claude", "{}", None)
                .await
                .unwrap();
        }
        // One row already terminal must not be restored.
        store
            .insert_request("req_done", "echo", REPO_A, "claude", "{}", None)
            .await
            .unwrap();
        store
            .finish_request("req_done", RequestState::Done, Some("ok"), execute_entry())
            .await
            .unwrap();

        assert_eq!(queue.rebuild_from_store().await.unwrap(), 3);

        let work = queue.take_next(REPO_A).await.unwrap().unwrap();
        assert_eq!(work.request_id, "req_a1");
        let work = queue.take_next(REPO_B).await.unwrap().unwrap();
        assert_eq!(work.request_id, "req_b1");
        assert!(queue.take_next(REPO_A).await.unwrap().is_none());
        queue
            .complete("req_a1", RequestState::Done, None, execute_entry())
            .await
            .unwrap();
        let work = queue.take_next(REPO_A).await.unwrap().unwrap();
        assert_eq!(work.request_id, "req_a2");
    })
    .await
    .expect("test within deadline");
}
