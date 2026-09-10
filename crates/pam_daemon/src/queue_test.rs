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
        .unwrap()
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

        // Same key attaches only when the complete operation shape matches.
        let dup = envelope(
            "req_2",
            REPO_A,
            serde_json::json!({ "n": 1 }),
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
            enqueue(
                &queue,
                &envelope(id, repo, serde_json::json!({"id": id}), None),
            )
            .await;
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

#[tokio::test]
async fn recovery_pages_do_not_skip_rows_failed_between_pages() {
    let (store, queue) = manager().await;
    for number in (0..39).rev() {
        let id = format!("recovery_{number:02}");
        if number % 3 == 0 {
            // These legacy rows are failed during recovery. OFFSET pagination
            // would skip surviving rows as the queued set shrinks.
            store
                .insert_request(&id, "echo", REPO_A, "claude", "{}", None)
                .await
                .unwrap();
        } else {
            enqueue(
                &queue,
                &envelope(&id, REPO_A, serde_json::json!({"id": id}), None),
            )
            .await;
        }
    }
    let expected: Vec<String> = store
        .list_queued_ordered()
        .await
        .unwrap()
        .into_iter()
        .filter(|row| row.queue_authorized)
        .map(|row| row.id)
        .collect();
    let restarted = QueueManager::new(Arc::clone(&store));
    assert_eq!(restarted.rebuild_from_store().await.unwrap(), 26);
    for number in 0..39 {
        let id = format!("recovery_{number:02}");
        if number % 3 == 0 {
            let row = store.get_request(&id).await.unwrap().unwrap();
            assert_eq!(row.state, RequestState::Failed);
            assert_eq!(row.outcome.as_deref(), Some("admission_invalid"));
        }
    }
    for id in expected {
        let work = restarted.take_next(REPO_A).await.unwrap().unwrap();
        assert_eq!(work.request_id, id);
        restarted
            .complete(&id, RequestState::Done, None, execute_entry())
            .await
            .unwrap();
    }
    assert!(restarted.take_next(REPO_A).await.unwrap().is_none());
}

#[tokio::test]
async fn oversized_legacy_queue_requires_operator_repair_without_deleting_work() {
    let (store, queue) = manager().await;
    let oversized = "x".repeat(usize::try_from(crate::queue::MAX_ADMITTED_BYTES).unwrap() + 1);
    store
        .insert_request(
            "legacy_oversized",
            "echo",
            REPO_A,
            "claude",
            &oversized,
            None,
        )
        .await
        .unwrap();
    let error = queue.rebuild_from_store().await.unwrap_err();
    assert!(matches!(error, QueueError::LegacyQueueOversized));
    assert_eq!(error.cause(), "legacy_queue_oversized");
    assert!(error.recovery().contains("back up"));
    assert!(queue.ready_repos().await.is_empty());
    // Inspection happens deliberately in this test, not on the recovery path.
    let row = store
        .get_request("legacy_oversized")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.state, RequestState::Queued);
    assert_eq!(row.args_json.len(), oversized.len());
}

#[tokio::test]
async fn pre_gate_admission_is_not_recovered_and_legacy_queued_rows_fail_closed() {
    let (store, queue) = manager().await;
    let env = envelope("before_gate", REPO_A, serde_json::json!({}), None);
    assert_eq!(admit(&queue, &env).await, AdmitOutcome::Admitted);
    let admitted = store.get_request(&env.id).await.unwrap().unwrap();
    assert_eq!(admitted.state, RequestState::Running);
    assert!(!admitted.queue_authorized);
    assert!(admitted.expires_at_ms.is_some());
    store
        .insert_request("legacy", "echo", REPO_A, "claude", "{}", None)
        .await
        .unwrap();
    let restarted = QueueManager::new(Arc::clone(&store));
    assert_eq!(restarted.rebuild_from_store().await.unwrap(), 0);
    assert!(restarted.take_next(REPO_A).await.unwrap().is_none());
    let legacy = store.get_request("legacy").await.unwrap().unwrap();
    assert_eq!(legacy.state, RequestState::Failed);
    assert_eq!(legacy.outcome.as_deref(), Some("admission_invalid"));
}

#[tokio::test]
async fn idempotency_keys_never_attach_across_repository_capability_or_arguments() {
    let (_store, queue) = manager().await;
    enqueue(
        &queue,
        &envelope("base", REPO_A, serde_json::json!({"n":1}), Some("k")),
    )
    .await;
    for (id, repo, args, capability) in [
        ("other_repo", REPO_B, serde_json::json!({"n":1}), "echo"),
        ("other_args", REPO_A, serde_json::json!({"n":2}), "echo"),
        ("other_cap", REPO_A, serde_json::json!({"n":1}), "release"),
    ] {
        let mut request = envelope(id, repo, args, Some("k"));
        request.capability = capability.into();
        assert_eq!(admit(&queue, &request).await, AdmitOutcome::Admitted);
    }
}

#[tokio::test]
async fn placement_cannot_extend_expiry_or_change_admitted_repository() {
    let (store, queue) = manager().await;
    let env = envelope("bound", REPO_A, serde_json::json!({}), None);
    admit(&queue, &env).await;
    let expires = store
        .get_request(&env.id)
        .await
        .unwrap()
        .unwrap()
        .expires_at_ms;
    assert!(matches!(
        queue.place_in_lane(&env.id, REPO_B, u64::MAX).await,
        Err(QueueError::NotAdmitted)
    ));
    queue
        .place_in_lane(&env.id, REPO_A, u64::MAX)
        .await
        .unwrap();
    let row = store.get_request(&env.id).await.unwrap().unwrap();
    assert_eq!(row.expires_at_ms, expires);
    assert!(row.queue_authorized);
    assert!(matches!(
        queue.place_in_lane(&env.id, REPO_A, 60_000).await,
        Err(QueueError::NotAdmitted)
    ));
}

#[tokio::test]
async fn restart_refuses_expired_authorized_work_without_refreshing_deadline() {
    let (store, queue) = manager().await;
    store
        .insert_admitted_request("expired", "echo", REPO_A, "claude", "{}", None, 1)
        .await
        .unwrap();
    assert!(
        store
            .authorize_queued_request("expired", REPO_A, 0)
            .await
            .unwrap()
    );
    assert_eq!(queue.rebuild_from_store().await.unwrap(), 0);
    let row = store.get_request("expired").await.unwrap().unwrap();
    assert_eq!(row.expires_at_ms, Some(1));
    assert_eq!(row.outcome.as_deref(), Some(CAUSE_LEASE_EXPIRED));
}

#[tokio::test(start_paused = true)]
async fn time_waiting_in_a_lane_consumes_the_original_deadline() {
    let (store, queue) = manager().await;
    let mut env = envelope("waiting", REPO_A, serde_json::json!({}), None);
    env.deadline_ms = 100;
    enqueue(&queue, &env).await;
    advance(Duration::from_millis(101)).await;
    assert!(queue.take_next(REPO_A).await.unwrap().is_none());
    assert_eq!(
        store
            .get_request(&env.id)
            .await
            .unwrap()
            .unwrap()
            .outcome
            .as_deref(),
        Some(CAUSE_LEASE_EXPIRED)
    );
}

#[tokio::test]
async fn admission_count_and_byte_limits_refuse_before_retaining_work() {
    let (store, queue) = manager().await;
    for i in 0..crate::queue::MAX_ADMITTED_REQUESTS {
        let env = envelope(
            &format!("pending_{i}"),
            REPO_A,
            serde_json::json!({"i":i}),
            None,
        );
        assert_eq!(admit(&queue, &env).await, AdmitOutcome::Admitted);
    }
    let extra = envelope("extra", REPO_A, serde_json::json!({}), None);
    let error = queue
        .admit(&extra, CapabilityClass::ReadOnly)
        .await
        .unwrap_err();
    assert_eq!(error.cause(), "queue_count_limit");
    assert!(store.get_request("extra").await.unwrap().is_none());
    let (store, queue) = manager().await;
    let huge = envelope(
        "huge",
        REPO_A,
        serde_json::json!({"body": "x".repeat(usize::try_from(crate::queue::MAX_ADMITTED_BYTES).unwrap())}),
        None,
    );
    let error = queue
        .admit(&huge, CapabilityClass::NonDestructive)
        .await
        .unwrap_err();
    assert_eq!(error.cause(), "queue_bytes_limit");
    assert!(store.get_request("huge").await.unwrap().is_none());
}

#[tokio::test]
async fn grant_revocation_invalidates_queued_work_even_after_regrant_and_restart() {
    let (store, queue) = manager().await;
    enqueue(
        &queue,
        &envelope("old", REPO_A, serde_json::json!({}), None),
    )
    .await;
    let revision = store
        .get_request("old")
        .await
        .unwrap()
        .unwrap()
        .authorization_revision;
    assert_eq!(revision, Some(0));
    store.insert_grant("flow.example.run").await.unwrap();
    store.revoke_grant("flow.example.run").await.unwrap();
    store.insert_grant("flow.example.run").await.unwrap();
    assert_eq!(store.grant_revocation_revision().await.unwrap(), 1);
    assert!(queue.take_next(REPO_A).await.unwrap().is_none());
    assert_eq!(
        store
            .get_request("old")
            .await
            .unwrap()
            .unwrap()
            .outcome
            .as_deref(),
        Some("authorization_changed")
    );

    enqueue(
        &queue,
        &envelope("restart", REPO_A, serde_json::json!({}), None),
    )
    .await;
    store.revoke_grant("flow.example.run").await.unwrap();
    let restarted = QueueManager::new(Arc::clone(&store));
    assert_eq!(restarted.rebuild_from_store().await.unwrap(), 0);
    assert_eq!(
        store
            .get_request("restart")
            .await
            .unwrap()
            .unwrap()
            .outcome
            .as_deref(),
        Some("authorization_changed")
    );
}

#[tokio::test]
async fn deadline_winner_orders_keep_timeout_cause_and_retained_evidence() {
    timeout(DEADLINE, async {
        for reaper_first in [false, true] {
            let (store, queue) = manager().await;
            let env = envelope("deadline", REPO_A, serde_json::json!({}), None);
            enqueue(&queue, &env).await;
            let work = queue.take_next(REPO_A).await.unwrap().unwrap();
            store
                .insert_evidence(
                    "ev_failed_attempt",
                    &env.id,
                    "log.source",
                    b"failed attempt\n",
                    None,
                )
                .await
                .unwrap();
            if reaper_first {
                assert_eq!(
                    queue
                        .reap_expired(work.lease_deadline)
                        .await
                        .unwrap()
                        .as_slice(),
                    std::slice::from_ref(&env.id)
                );
                assert!(!queue.expire(&env.id).await.unwrap());
            } else {
                assert!(queue.expire(&env.id).await.unwrap());
                assert!(
                    queue
                        .reap_expired(work.lease_deadline)
                        .await
                        .unwrap()
                        .is_empty()
                );
            }
            // A woken executor must not relabel expiry as user cancellation.
            assert!(*work.cancel.borrow());
            assert!(
                !queue
                    .complete(
                        &env.id,
                        RequestState::Failed,
                        Some(CAUSE_CANCELLED),
                        execute_entry()
                    )
                    .await
                    .unwrap()
            );
            let row = store.get_request(&env.id).await.unwrap().unwrap();
            assert_eq!(row.state, RequestState::Failed);
            assert_eq!(row.outcome.as_deref(), Some(CAUSE_LEASE_EXPIRED));
            let audit = store.audit_for_request(&env.id).await.unwrap();
            assert_eq!(audit.len(), 1);
            assert_eq!(audit[0].action, ACTION_LEASE_REAPED);
            assert_eq!(audit[0].decision, Decision::Timeout);
            assert_eq!(
                store
                    .get_evidence("ev_failed_attempt")
                    .await
                    .unwrap()
                    .unwrap()
                    .content,
                b"failed attempt\n"
            );
        }
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn deadline_expiry_removes_queued_work_without_calling_it_cancelled() {
    timeout(DEADLINE, async {
        let (store, queue) = manager().await;
        let env = envelope("queued_deadline", REPO_A, serde_json::json!({}), None);
        enqueue(&queue, &env).await;
        assert!(queue.expire(&env.id).await.unwrap());
        assert!(queue.take_next(REPO_A).await.unwrap().is_none());
        let row = store.get_request(&env.id).await.unwrap().unwrap();
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_LEASE_EXPIRED));
        assert!(!queue.expire(&env.id).await.unwrap());
        assert_eq!(store.audit_for_request(&env.id).await.unwrap().len(), 1);
    })
    .await
    .expect("test within deadline");
}
