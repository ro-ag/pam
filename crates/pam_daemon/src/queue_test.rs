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
        .place_in_lane(&envelope.id, &envelope.caller.repo)
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
    // Admission uses real wall time, while the reaper uses Tokio's paused clock.
    // Admit and obtain the lease before starting the observation timeout.
    let (store, queue) = manager().await;
    let env = envelope("req_1", REPO_A, serde_json::json!({}), None);
    enqueue(&queue, &env).await;
    let work = queue.take_next(REPO_A).await.unwrap().unwrap();
    advance(
        work.lease_deadline
            .saturating_duration_since(Instant::now())
            + Duration::from_millis(1),
    )
    .await;

    timeout(DEADLINE, async {
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
    // Nothing timed out: a row recovery refused to restore is audited as
    // a recovery refusal, not as a reaped lease.
    let audit = store.audit_for_request("legacy").await.unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].action, crate::queue::ACTION_RECOVERY_REFUSAL);
    assert_eq!(audit[0].detail.as_deref(), Some("admission_invalid"));
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
        queue.place_in_lane(&env.id, REPO_B).await,
        Err(QueueError::NotAdmitted)
    ));
    queue.place_in_lane(&env.id, REPO_A).await.unwrap();
    let row = store.get_request(&env.id).await.unwrap().unwrap();
    assert_eq!(row.expires_at_ms, expires);
    assert!(row.queue_authorized);
    assert!(matches!(
        queue.place_in_lane(&env.id, REPO_A).await,
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
    // The queued request is an `echo`: revoking the grant it depends on
    // voids it, and granting it again does not bring it back.
    store.insert_grant("echo").await.unwrap();
    store.revoke_grant("echo").await.unwrap();
    store.insert_grant("echo").await.unwrap();
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
    store.revoke_grant("echo").await.unwrap();
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
    let audit = store.audit_for_request("restart").await.unwrap();
    assert!(
        audit
            .iter()
            .any(|row| row.action == crate::queue::ACTION_RECOVERY_REFUSAL),
        "{audit:?}"
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

// --- parked watches -------------------------------------------------------

fn wall_now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// A `flow.run` envelope: the only capability the store lets a lease park.
fn flow_envelope(id: &str, repo: &str) -> Envelope {
    let mut env = envelope(id, repo, serde_json::json!({ "id": "parked" }), None);
    env.capability = "flow.run".to_owned();
    env
}

/// A repository a flow may run in: a real directory the scope policy
/// names, which the journal's checkpoint authorization insists on.
struct FlowRepo {
    _dir: tempfile::TempDir,
    path: String,
}

async fn flow_repo(store: &Store) -> FlowRepo {
    let dir = tempfile::tempdir().unwrap();
    let path = dir
        .path()
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    store
        .set_setting(
            crate::scope_policy::SETTING_SCOPE_POLICY,
            &serde_json::json!({"version":1,"repositories":[{"root":path,"connectors":[]}]})
                .to_string(),
        )
        .await
        .unwrap();
    FlowRepo { _dir: dir, path }
}

/// Opens the flow journal a parked checkpoint needs in state `ready`,
/// exactly as the flow engine does on its first run of the ticket.
async fn ready_journal(store: &Store, id: &str, repo: &str) {
    let flow = pam_flow::parse(
        "schema: 1\nid: parked\nname: Parked\nsteps:\n  - id: look\n    run: [git, status]\n",
    )
    .unwrap();
    crate::flow_recovery::Recovery::open(
        store,
        id,
        &flow,
        std::path::Path::new(repo),
        &pam_flow::Vars::new(),
    )
    .await
    .unwrap();
}

/// Admits, places and leases a parkable flow request in a fresh scoped
/// repository, returning that repository.
async fn leased_flow(store: &Store, queue: &QueueManager, id: &str) -> FlowRepo {
    let repo = flow_repo(store).await;
    enqueue(queue, &flow_envelope(id, &repo.path)).await;
    ready_journal(store, id, &repo.path).await;
    let work = queue.take_next(&repo.path).await.unwrap().unwrap();
    assert_eq!(work.request_id, id);
    repo
}

#[tokio::test]
async fn park_frees_the_lane_and_wake_due_returns_the_ticket_only_when_due() {
    timeout(DEADLINE, async {
        let (store, queue) = manager().await;
        let repo = leased_flow(&store, &queue, "flow_1").await;
        let lane = repo.path.as_str();
        let resume = wall_now_ms() + 30_000;

        assert!(queue.park("flow_1", resume).await.unwrap());
        // Durable: the row is queued again with its poll time, and the
        // in-memory lease and lane are both released.
        let row = store.get_request("flow_1").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Queued);
        assert_eq!(row.resume_at_ms, Some(resume));
        assert!(queue.leased_ids().await.is_empty());
        assert!(queue.ready_repos().await.is_empty());
        assert!(queue.take_next(lane).await.unwrap().is_none());
        timeout(Duration::from_secs(1), queue.work_available())
            .await
            .expect("parking wakes the executor loop");

        // Other work on the same repository runs while the watch waits.
        enqueue(
            &queue,
            &envelope("other", lane, serde_json::json!({ "n": 2 }), None),
        )
        .await;
        let work = queue.take_next(lane).await.unwrap().unwrap();
        assert_eq!(work.request_id, "other");
        assert!(
            queue
                .complete("other", RequestState::Done, None, execute_entry())
                .await
                .unwrap()
        );

        // Not due: nothing moves, and the lane stays empty.
        assert_eq!(queue.wake_due(Instant::now(), resume - 1).await.unwrap(), 0);
        assert!(queue.take_next(lane).await.unwrap().is_none());
        let row = store.get_request("flow_1").await.unwrap().unwrap();
        assert_eq!(row.resume_at_ms, Some(resume));

        // Due: back into the lane, poll time cleared, leased again next.
        assert_eq!(queue.wake_due(Instant::now(), resume).await.unwrap(), 1);
        assert_eq!(queue.ready_repos().await, [lane]);
        let row = store.get_request("flow_1").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Queued);
        assert_eq!(row.resume_at_ms, None);
        let work = queue.take_next(lane).await.unwrap().unwrap();
        assert_eq!(work.request_id, "flow_1");
        let row = store.get_request("flow_1").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Running);
        assert_eq!(queue.leased_ids().await, ["flow_1"]);

        // Waking again is a no-op; a finished ticket can no longer park.
        assert_eq!(queue.wake_due(Instant::now(), resume).await.unwrap(), 0);
        assert!(
            queue
                .complete("flow_1", RequestState::Done, Some("ok"), execute_entry())
                .await
                .unwrap()
        );
        assert!(!queue.park("flow_1", resume).await.unwrap());
        assert!(queue.take_parked_terminals().await.is_empty());
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn park_refuses_stale_times_and_non_flow_leases_and_keeps_the_lease() {
    timeout(DEADLINE, async {
        let (store, queue) = manager().await;
        let _repo = leased_flow(&store, &queue, "flow_1").await;
        // A poll time that is not in the future is refused durably.
        assert!(!queue.park("flow_1", wall_now_ms()).await.unwrap());
        assert_eq!(queue.leased_ids().await, ["flow_1"]);
        let row = store.get_request("flow_1").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Running);
        assert_eq!(row.resume_at_ms, None);
        // Nothing but the lease holder may park, and only a flow may.
        assert!(!queue.park("ghost", wall_now_ms() + 30_000).await.unwrap());
        enqueue(
            &queue,
            &envelope("echo_1", REPO_B, serde_json::json!({}), None),
        )
        .await;
        queue.take_next(REPO_B).await.unwrap().unwrap();
        assert!(!queue.park("echo_1", wall_now_ms() + 30_000).await.unwrap());
        let row = store.get_request("echo_1").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Running);
        // Both leases are intact: completion still owns the terminal write.
        for id in ["flow_1", "echo_1"] {
            assert!(
                queue
                    .complete(id, RequestState::Done, None, execute_entry())
                    .await
                    .unwrap()
            );
        }
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn wake_due_expires_a_parked_ticket_and_parks_its_terminal_for_the_executor() {
    timeout(DEADLINE, async {
        let (store, queue) = manager().await;
        let repo = leased_flow(&store, &queue, "flow_1").await;
        let lane = repo.path.as_str();
        let resume = wall_now_ms() + 30_000;
        assert!(queue.park("flow_1", resume).await.unwrap());
        assert!(queue.take_parked_terminals().await.is_empty());

        // Past the original monotonic deadline the checkpoint expires
        // without dispatch: terminal timeout, audited as a reaped lease.
        let past_deadline = Instant::now() + Duration::from_hours(2);
        assert_eq!(queue.wake_due(past_deadline, resume - 1).await.unwrap(), 0);
        let row = store.get_request("flow_1").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed);
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_LEASE_EXPIRED));
        let audit = store.audit_for_request("flow_1").await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, ACTION_LEASE_REAPED);
        assert_eq!(audit[0].decision, Decision::Timeout);
        // The original waiter is finished through the executor loop's drain,
        // exactly once.
        assert_eq!(queue.take_parked_terminals().await, ["flow_1"]);
        assert!(queue.take_parked_terminals().await.is_empty());
        assert!(queue.take_next(lane).await.unwrap().is_none());
        assert_eq!(queue.wake_due(past_deadline, resume).await.unwrap(), 0);
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn wake_due_refuses_a_parked_ticket_whose_authorization_changed() {
    timeout(DEADLINE, async {
        let (store, queue) = manager().await;
        let repo = leased_flow(&store, &queue, "flow_1").await;
        let lane = repo.path.as_str();
        let resume = wall_now_ms() + 30_000;
        assert!(queue.park("flow_1", resume).await.unwrap());
        // A step grant revoked while parked: a flow run depends on it.
        store.insert_grant("flow.step:parked/look").await.unwrap();
        store.revoke_grant("flow.step:parked/look").await.unwrap();

        assert_eq!(queue.wake_due(Instant::now(), resume).await.unwrap(), 0);
        let row = store.get_request("flow_1").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed);
        assert_eq!(row.outcome.as_deref(), Some("authorization_changed"));
        let audit = store.audit_for_request("flow_1").await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, crate::queue::ACTION_RECOVERY_REFUSAL);
        assert_eq!(audit[0].detail.as_deref(), Some("authorization_changed"));
        assert_eq!(queue.take_parked_terminals().await, ["flow_1"]);
        assert!(queue.take_next(lane).await.unwrap().is_none());
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn cancel_of_a_parked_ticket_is_terminal_audited_and_never_woken() {
    timeout(DEADLINE, async {
        let (store, queue) = manager().await;
        let repo = leased_flow(&store, &queue, "flow_1").await;
        let lane = repo.path.as_str();
        let resume = wall_now_ms() + 30_000;
        assert!(queue.park("flow_1", resume).await.unwrap());

        let outcome = queue.cancel("flow_1", Actor::Human).await.unwrap();
        assert_eq!(outcome, CancelOutcome::CancelledQueued);
        let row = store.get_request("flow_1").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed);
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_CANCELLED));
        let audit = store.audit_for_request("flow_1").await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, ACTION_CANCEL);
        assert_eq!(audit[0].actor, Actor::Human);
        // Explicit cancellation answers its caller directly: it is not a
        // parked terminal, and the due time no longer wakes anything.
        assert!(queue.take_parked_terminals().await.is_empty());
        assert_eq!(queue.wake_due(Instant::now(), resume).await.unwrap(), 0);
        assert!(queue.take_next(lane).await.unwrap().is_none());
        assert_eq!(
            queue.cancel("flow_1", Actor::Human).await.unwrap(),
            CancelOutcome::NotFound
        );
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn rebuild_from_store_restores_parked_rows_as_parked_not_runnable() {
    timeout(DEADLINE, async {
        let (store, queue) = manager().await;
        let repo = leased_flow(&store, &queue, "flow_1").await;
        let lane = repo.path.as_str();
        let resume = wall_now_ms() + 30_000;
        assert!(queue.park("flow_1", resume).await.unwrap());
        // An ordinary queued row on the same repository sits in the lane.
        enqueue(
            &queue,
            &envelope("plain", lane, serde_json::json!({}), None),
        )
        .await;

        let restarted = QueueManager::new(Arc::clone(&store));
        assert_eq!(restarted.rebuild_from_store().await.unwrap(), 2);
        // The parked checkpoint keeps its schedule instead of racing the lane.
        let work = restarted.take_next(lane).await.unwrap().unwrap();
        assert_eq!(work.request_id, "plain");
        restarted
            .complete("plain", RequestState::Done, None, execute_entry())
            .await
            .unwrap();
        assert!(restarted.take_next(lane).await.unwrap().is_none());
        let row = store.get_request("flow_1").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Queued);
        assert_eq!(row.resume_at_ms, Some(resume));
        assert_eq!(
            restarted
                .wake_due(Instant::now(), resume - 1)
                .await
                .unwrap(),
            0
        );
        assert_eq!(restarted.wake_due(Instant::now(), resume).await.unwrap(), 1);
        let work = restarted.take_next(lane).await.unwrap().unwrap();
        assert_eq!(work.request_id, "flow_1");
    })
    .await
    .expect("test within deadline");
}

#[tokio::test(start_paused = true)]
async fn parked_terminal_backpressure_retains_admissions_until_the_executor_drains() {
    use crate::queue::MAX_PARKED_TERMINALS;
    // Fill the terminal notice buffer with reaped leases, one per repository
    // (one lease per lane), through the background reaper's path.
    let (store, queue) = manager().await;
    for i in 0..MAX_PARKED_TERMINALS {
        let mut env = envelope(
            &format!("lease_{i:03}"),
            &format!("/repo/{i}"),
            serde_json::json!({ "i": i }),
            None,
        );
        env.deadline_ms = 5_000;
        enqueue(&queue, &env).await;
        queue
            .take_next(&format!("/repo/{i}"))
            .await
            .unwrap()
            .unwrap();
    }
    advance(Duration::from_secs(6)).await;
    assert_eq!(
        queue.reap_expired_notifying(Instant::now()).await.unwrap(),
        MAX_PARKED_TERMINALS
    );
    assert!(queue.leased_ids().await.is_empty());

    // A parked checkpoint whose deadline has passed is not terminalized
    // while its notice cannot fit: the admission is retained as-is.
    let _repo = leased_flow(&store, &queue, "flow_1").await;
    let resume = wall_now_ms() + 30_000;
    assert!(queue.park("flow_1", resume).await.unwrap());
    let past_deadline = Instant::now() + Duration::from_hours(2);
    assert_eq!(queue.wake_due(past_deadline, resume).await.unwrap(), 0);
    let row = store.get_request("flow_1").await.unwrap().unwrap();
    assert_eq!(row.state, RequestState::Queued);
    assert_eq!(row.resume_at_ms, Some(resume));
    // Likewise a queued row past its deadline stays queued rather than
    // failing without a deliverable notice.
    let mut stale = envelope("stale", REPO_B, serde_json::json!({}), None);
    stale.deadline_ms = 5_000;
    enqueue(&queue, &stale).await;
    advance(Duration::from_secs(6)).await;
    assert!(queue.take_next(REPO_B).await.unwrap().is_none());
    let row = store.get_request("stale").await.unwrap().unwrap();
    assert_eq!(row.state, RequestState::Queued);

    // Draining the notices releases the backpressure: the same sweeps
    // now terminalize both, and their notices follow.
    let drained = queue.take_parked_terminals().await;
    assert_eq!(drained.len(), MAX_PARKED_TERMINALS);
    assert!(drained.iter().all(|id| id.starts_with("lease_")));
    assert_eq!(queue.wake_due(past_deadline, resume).await.unwrap(), 0);
    assert!(queue.take_next(REPO_B).await.unwrap().is_none());
    for id in ["flow_1", "stale"] {
        let row = store.get_request(id).await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed, "{id}");
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_LEASE_EXPIRED), "{id}");
    }
    let mut notices = queue.take_parked_terminals().await;
    notices.sort();
    assert_eq!(notices, ["flow_1", "stale"]);
}

/// Revoking a capability the queued request never depended on used to void
/// it (the revision was one global count). Only its own grant does now —
/// both at the lease and across a restart.
#[tokio::test]
async fn an_unrelated_revocation_leaves_queued_and_parked_work_alone() {
    timeout(DEADLINE, async {
        let (store, queue) = manager().await;
        enqueue(
            &queue,
            &envelope("keeps_running", REPO_A, serde_json::json!({}), None),
        )
        .await;
        let repo = leased_flow(&store, &queue, "flow_keeps").await;
        let resume = wall_now_ms() + 30_000;
        assert!(queue.park("flow_keeps", resume).await.unwrap());

        // Somebody revokes a grant neither request depends on.
        store.insert_grant("some.other.capability").await.unwrap();
        store.revoke_grant("some.other.capability").await.unwrap();
        assert_eq!(store.grant_revocation_revision().await.unwrap(), 1);

        // The parked flow wakes onto its lane instead of being refused.
        assert_eq!(queue.wake_due(Instant::now(), resume).await.unwrap(), 1);
        assert!(queue.take_parked_terminals().await.is_empty());
        let woken = queue.take_next(&repo.path).await.unwrap().unwrap();
        assert_eq!(woken.request_id, "flow_keeps");

        // A restart restores the queued echo rather than failing it.
        let restarted = QueueManager::new(Arc::clone(&store));
        assert_eq!(restarted.rebuild_from_store().await.unwrap(), 1);
        let leased = restarted.take_next(REPO_A).await.unwrap().unwrap();
        assert_eq!(leased.request_id, "keeps_running");
        assert_eq!(
            store
                .get_request("keeps_running")
                .await
                .unwrap()
                .unwrap()
                .state,
            RequestState::Running
        );
    })
    .await
    .expect("test within deadline");
}

/// A row past its deadline with no owner in memory — a terminal write the
/// store refused, a handler that was cut off — used to stay `running`
/// forever and count against the 128-request admission cap.
#[tokio::test]
async fn a_row_stranded_past_its_deadline_is_closed_and_stops_counting() {
    timeout(DEADLINE, async {
        let store = Arc::new(Store::open_in_memory().await.unwrap());
        let queue =
            QueueManager::new(Arc::clone(&store)).with_reconcile_grace(Duration::from_secs(5));
        let now = wall_now_ms();
        // Stranded: deadline a minute ago. Fresh: deadline a minute ahead.
        // Late: past its deadline but inside the grace — its handler may
        // still be writing its own verdict.
        for (id, expires) in [
            ("stranded", now - 60_000),
            ("fresh", now + 60_000),
            ("late", now - 1_000),
        ] {
            store
                .insert_admitted_request(id, "query", REPO_A, "claude", "{}", None, expires)
                .await
                .unwrap();
        }

        // Admission already ignores what can no longer run...
        let (live, _) = store.admission_usage_at(now).await.unwrap();
        assert_eq!(live, 1, "only the fresh row holds an admission slot");
        let (all, _) = store.admission_usage().await.unwrap();
        assert_eq!(all, 3);

        // ...and the reconciler gives the stranded row its terminal state.
        assert_eq!(queue.reconcile_expired(now).await.unwrap(), 1);
        let row = store.get_request("stranded").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed);
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_LEASE_EXPIRED));
        let audit = store.audit_for_request("stranded").await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, ACTION_LEASE_REAPED);
        assert_eq!(audit[0].decision, Decision::Timeout);
        assert_eq!(audit[0].actor, Actor::System);
        // Its waiters are released through the executor loop's drain.
        assert_eq!(queue.take_parked_terminals().await, ["stranded"]);

        // The other two are left alone, and a second pass finds nothing.
        for id in ["fresh", "late"] {
            assert_eq!(
                store.get_request(id).await.unwrap().unwrap().state,
                RequestState::Running,
                "{id}"
            );
        }
        assert_eq!(queue.reconcile_expired(now).await.unwrap(), 0);

        // Once the grace has passed for the late row, it is closed too.
        assert_eq!(queue.reconcile_expired(now + 10_000).await.unwrap(), 1);
        assert_eq!(
            store.get_request("late").await.unwrap().unwrap().state,
            RequestState::Failed
        );
    })
    .await
    .expect("test within deadline");
}

/// Stranded rows used to be able to lock everyone out: 128 of them and
/// every request, `status` and `cancel` included, was refused
/// `queue_count_limit` until the daemon restarted.
#[tokio::test]
async fn rows_past_their_deadline_do_not_exhaust_the_admission_cap() {
    timeout(DEADLINE, async {
        let (store, queue) = manager().await;
        let expired = wall_now_ms() - 60_000;
        for index in 0..crate::queue::MAX_ADMITTED_REQUESTS {
            store
                .insert_admitted_request(
                    &format!("stranded_{index}"),
                    "query",
                    REPO_A,
                    "claude",
                    "{}",
                    None,
                    expired,
                )
                .await
                .unwrap();
        }
        // The cap is full of rows that can never run; a new request is
        // admitted all the same.
        let outcome = queue
            .admit(
                &envelope("still_admitted", REPO_A, serde_json::json!({}), None),
                CapabilityClass::NonDestructive,
            )
            .await
            .unwrap();
        assert_eq!(outcome, AdmitOutcome::Admitted);
    })
    .await
    .expect("test within deadline");
}

/// The reconciler also frees what the stranded row held in memory: its
/// lease and its lane.
#[tokio::test]
async fn reconciling_a_leased_row_releases_its_lane_and_signals_the_holder() {
    timeout(DEADLINE, async {
        let store = Arc::new(Store::open_in_memory().await.unwrap());
        let queue =
            QueueManager::new(Arc::clone(&store)).with_reconcile_grace(Duration::from_secs(1));
        // The deadline only has to be shorter than the follower's: the
        // reconciler below is handed a clock past this row's recorded expiry,
        // so no real time has to pass (a 50 ms deadline used to expire under
        // load between admission and lane placement).
        let mut short = envelope("held", REPO_A, serde_json::json!({}), None);
        short.deadline_ms = 30_000;
        enqueue(&queue, &short).await;
        let work = queue.take_next(REPO_A).await.unwrap().unwrap();
        enqueue(
            &queue,
            &envelope("next", REPO_A, serde_json::json!({ "n": 2 }), None),
        )
        .await;
        assert!(
            queue.take_next(REPO_A).await.unwrap().is_none(),
            "lane busy"
        );

        // Past the deadline and the grace, as the reaper would see it if its
        // own lease sweep had been failing; still inside the follower's
        // 60 s deadline, which was recorded after this one.
        let expires = store
            .get_request("held")
            .await
            .unwrap()
            .unwrap()
            .expires_at_ms
            .unwrap();
        let later = expires + 2_000;
        assert_eq!(queue.reconcile_expired(later).await.unwrap(), 1);
        assert!(*work.cancel.borrow(), "the holder is told to stop");
        assert!(queue.leased_ids().await.is_empty());
        let next = queue.take_next(REPO_A).await.unwrap().unwrap();
        assert_eq!(next.request_id, "next");
    })
    .await
    .expect("test within deadline");
}

/// The last resort when the store keeps refusing a terminal write: the lane
/// is handed back without one, instead of staying busy until the lease
/// deadline.
#[tokio::test]
async fn abandoning_a_lease_frees_the_lane_without_a_terminal_write() {
    timeout(DEADLINE, async {
        let (store, queue) = manager().await;
        enqueue(
            &queue,
            &envelope("first", REPO_A, serde_json::json!({ "n": 1 }), None),
        )
        .await;
        enqueue(
            &queue,
            &envelope("second", REPO_A, serde_json::json!({ "n": 2 }), None),
        )
        .await;
        let work = queue.take_next(REPO_A).await.unwrap().unwrap();
        assert_eq!(work.request_id, "first");

        // The store refuses the completion: ownership is retained...
        queue.fail_next_completes(1);
        assert!(
            queue
                .complete("first", RequestState::Done, Some("solved"), execute_entry())
                .await
                .is_err()
        );
        assert_eq!(queue.leased_ids().await, ["first"]);
        assert!(queue.take_next(REPO_A).await.unwrap().is_none());

        // ...until the lease is abandoned, and the lane serves on.
        assert!(queue.abandon_lease("first").await);
        assert!(
            !queue.abandon_lease("first").await,
            "nothing left to abandon"
        );
        let next = queue.take_next(REPO_A).await.unwrap().unwrap();
        assert_eq!(next.request_id, "second");
        // The row was not touched: its verdict is the caller's to record.
        assert_eq!(
            store.get_request("first").await.unwrap().unwrap().state,
            RequestState::Running
        );
    })
    .await
    .expect("test within deadline");
}

/// Admission writes the origin in the INSERT that creates the row: it
/// survives placement and the lease, and it changes nothing about dedupe —
/// a duplicate from another connection attaches to the original, whose row
/// keeps the original's origin.
#[tokio::test]
async fn admit_from_records_the_origin_and_changes_nothing_else() {
    use pam_store::{RequestIngress, RequestOrigin};

    timeout(DEADLINE, async {
        let (store, queue) = manager().await;
        let peer = RequestOrigin {
            ingress: RequestIngress::Public,
            peer_uid: Some(501),
            peer_pid: Some(4_100),
            relayed: true,
        };
        let first = envelope("req_origin", REPO_A, serde_json::json!({ "n": 1 }), None);
        assert_eq!(
            queue
                .admit_from(&first, CapabilityClass::NonDestructive, &peer)
                .await
                .unwrap(),
            AdmitOutcome::Admitted
        );
        queue.place_in_lane("req_origin", REPO_A).await.unwrap();
        let row = store.get_request("req_origin").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Queued);
        assert_eq!(row.origin, peer);

        // The same work from the private plane attaches: who asks is not
        // part of what was asked.
        let duplicate = envelope(
            "req_origin_dup",
            REPO_A,
            serde_json::json!({ "n": 1 }),
            None,
        );
        assert_eq!(
            queue
                .admit_from(
                    &duplicate,
                    CapabilityClass::NonDestructive,
                    &RequestOrigin::ADMIN
                )
                .await
                .unwrap(),
            AdmitOutcome::Attached {
                existing_request_id: "req_origin".to_owned()
            }
        );
        assert!(store.get_request("req_origin_dup").await.unwrap().is_none());

        // A bypass row and an administration submission.
        let read = envelope("req_origin_read", REPO_B, serde_json::json!({}), None);
        assert_eq!(
            queue
                .admit_from(&read, CapabilityClass::ReadOnly, &RequestOrigin::ADMIN)
                .await
                .unwrap(),
            AdmitOutcome::Bypass
        );
        let row = store.get_request("req_origin_read").await.unwrap().unwrap();
        assert_eq!(row.origin, RequestOrigin::ADMIN);

        // `admit` is `admit_from` for a caller with no peer to report.
        let plain = envelope(
            "req_origin_plain",
            REPO_B,
            serde_json::json!({ "n": 2 }),
            None,
        );
        admit(&queue, &plain).await;
        let row = store
            .get_request("req_origin_plain")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.origin, RequestOrigin::PUBLIC);

        // The lease moves the row's state and leaves its origin alone.
        let leased = queue.take_next(REPO_A).await.unwrap().expect("a lease");
        assert_eq!(leased.request_id, "req_origin");
        let row = store.get_request("req_origin").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Running);
        assert_eq!(row.origin, peer);
    })
    .await
    .expect("test within deadline");
}
