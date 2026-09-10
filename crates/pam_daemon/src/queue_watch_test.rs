use std::{sync::Arc, time::Duration};

use pam_proto::{Caller, Envelope, PROTOCOL_VERSION};
use pam_store::{Actor, AuditEntry, Decision, FlowJournalIdentity, RequestState, Store};
use tokio::time::Instant;

use crate::{
    policy::CapabilityClass,
    queue::{AdmitOutcome, CancelOutcome, QueueManager},
};

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn request(id: &str) -> Envelope {
    Envelope {
        v: PROTOCOL_VERSION,
        id: id.to_owned(),
        capability: "flow.run".to_owned(),
        client_version: env!("CARGO_PKG_VERSION").to_owned(),
        caller: Caller {
            agent: "test".to_owned(),
            repo: "/repo".to_owned(),
            pid: 42,
        },
        args: serde_json::json!({"flow":id}),
        idempotency_key: None,
        deadline_ms: 60_000,
        wait: false,
    }
}

async fn enqueue(queue: &QueueManager, id: &str) {
    assert_eq!(
        queue
            .admit(&request(id), CapabilityClass::NonDestructive)
            .await
            .unwrap(),
        AdmitOutcome::Admitted
    );
    queue.place_in_lane(id, "/repo", 60_000).await.unwrap();
}

async fn ready_checkpoint(store: &Store, id: &str) {
    store
        .begin_flow_journal(
            &FlowJournalIdentity {
                request_id: id.to_owned(),
                flow_digest: "a".repeat(64),
                repository: "/repo".to_owned(),
                input_fingerprint: "b".repeat(64),
            },
            "{}",
        )
        .await
        .unwrap();
}

fn audit() -> AuditEntry<'static> {
    AuditEntry {
        action: "execute",
        decision: Decision::Allow,
        actor: Actor::System,
        detail: None,
    }
}

#[tokio::test]
async fn parked_watch_releases_lane_and_resumes_same_admission() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let queue = QueueManager::new(Arc::clone(&store));
    enqueue(&queue, "watch").await;
    enqueue(&queue, "other").await;
    let original = queue.take_next("/repo").await.unwrap().unwrap();
    ready_checkpoint(&store, "watch").await;
    let usage = store.admission_usage().await.unwrap();
    let resume = now_ms() + 10_000;
    assert!(queue.park("watch", resume).await.unwrap());
    tokio::time::timeout(Duration::from_millis(100), queue.work_available())
        .await
        .unwrap();
    assert_eq!(store.admission_usage().await.unwrap(), usage);
    assert_eq!(
        queue
            .admit(&request("watch"), CapabilityClass::NonDestructive)
            .await
            .unwrap(),
        AdmitOutcome::Attached {
            existing_request_id: "watch".to_owned()
        }
    );
    let other = queue.take_next("/repo").await.unwrap().unwrap();
    assert_eq!(other.request_id, "other");
    queue
        .complete("other", RequestState::Done, Some("ok"), audit())
        .await
        .unwrap();
    assert!(queue.ready_repos().await.is_empty());
    assert_eq!(queue.wake_due(Instant::now(), resume - 1).await.unwrap(), 0);
    assert_eq!(queue.wake_due(Instant::now(), resume).await.unwrap(), 1);
    let resumed = queue.take_next("/repo").await.unwrap().unwrap();
    assert_eq!(resumed.request_id, "watch");
    assert_eq!(resumed.lease_deadline, original.lease_deadline);
}

#[tokio::test]
async fn restart_restores_parking_and_original_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("watch.db");
    let resume = now_ms() + 10_000;
    let expiry;
    {
        let store = Arc::new(Store::open(&path).await.unwrap());
        let queue = QueueManager::new(Arc::clone(&store));
        enqueue(&queue, "watch").await;
        queue.take_next("/repo").await.unwrap().unwrap();
        ready_checkpoint(&store, "watch").await;
        assert!(queue.park("watch", resume).await.unwrap());
        expiry = store
            .get_request("watch")
            .await
            .unwrap()
            .unwrap()
            .expires_at_ms;
    }
    let store = Arc::new(Store::open(&path).await.unwrap());
    let queue = QueueManager::new(Arc::clone(&store));
    assert_eq!(queue.rebuild_from_store().await.unwrap(), 1);
    assert!(queue.ready_repos().await.is_empty());
    assert_eq!(store.admission_usage().await.unwrap().0, 1);
    assert_eq!(queue.wake_due(Instant::now(), resume).await.unwrap(), 1);
    assert_eq!(
        queue.take_next("/repo").await.unwrap().unwrap().request_id,
        "watch"
    );
    assert_eq!(
        store
            .get_request("watch")
            .await
            .unwrap()
            .unwrap()
            .expires_at_ms,
        expiry
    );
}

#[tokio::test]
async fn parked_cancel_expiry_and_revocation_do_not_resume() {
    for mode in ["cancel", "expire", "wall_expire", "revoke"] {
        let store = Arc::new(Store::open_in_memory().await.unwrap());
        let queue = QueueManager::new(Arc::clone(&store));
        enqueue(&queue, mode).await;
        let lease = queue.take_next("/repo").await.unwrap().unwrap();
        ready_checkpoint(&store, mode).await;
        let resume = now_ms() + 10_000;
        assert!(queue.park(mode, resume).await.unwrap());
        match mode {
            "cancel" => assert_eq!(
                queue.cancel(mode, Actor::System).await.unwrap(),
                CancelOutcome::CancelledQueued
            ),
            "expire" => {
                assert_eq!(
                    queue.wake_due(lease.lease_deadline, resume).await.unwrap(),
                    0
                );
            }
            "wall_expire" => {
                let expiry = store
                    .get_request(mode)
                    .await
                    .unwrap()
                    .unwrap()
                    .expires_at_ms
                    .unwrap();
                assert_eq!(queue.wake_due(Instant::now(), expiry).await.unwrap(), 0);
            }
            _ => {
                store.insert_grant("flow.run").await.unwrap();
                store.revoke_grant("flow.run").await.unwrap();
                store.insert_grant("flow.run").await.unwrap();
            }
        }
        assert_eq!(queue.wake_due(Instant::now(), resume).await.unwrap(), 0);
        assert!(queue.take_next("/repo").await.unwrap().is_none());
        let row = store.get_request(mode).await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed);
        let cause = match mode {
            "cancel" => "cancelled",
            "expire" | "wall_expire" => "lease_expired",
            _ => "authorization_changed",
        };
        assert_eq!(row.outcome.as_deref(), Some(cause));
        let notices = queue.take_parked_terminals().await;
        if mode == "cancel" {
            assert!(
                notices.is_empty(),
                "explicit cancellation has its own router completion"
            );
        } else {
            assert_eq!(notices, [mode]);
        }
        assert!(queue.take_parked_terminals().await.is_empty());
        assert_eq!(queue.wake_due(Instant::now(), resume).await.unwrap(), 0);
        assert!(queue.take_parked_terminals().await.is_empty());
        assert_eq!(store.admission_usage().await.unwrap().0, 0);
    }
}

#[tokio::test]
async fn parked_admission_counts_toward_capacity_across_rebuild() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let queue = QueueManager::new(Arc::clone(&store));
    enqueue(&queue, "watch").await;
    queue.take_next("/repo").await.unwrap().unwrap();
    ready_checkpoint(&store, "watch").await;
    assert!(queue.park("watch", now_ms() + 30_000).await.unwrap());
    for index in 1..crate::queue::MAX_ADMITTED_REQUESTS {
        enqueue(&queue, &format!("queued-{index}")).await;
    }
    let usage = store.admission_usage().await.unwrap();
    assert_eq!(usage.0, crate::queue::MAX_ADMITTED_REQUESTS);
    let rebuilt = QueueManager::new(Arc::clone(&store));
    assert_eq!(rebuilt.rebuild_from_store().await.unwrap(), 128);
    assert_eq!(store.admission_usage().await.unwrap(), usage);
    let error = rebuilt
        .admit(&request("overflow"), CapabilityClass::NonDestructive)
        .await
        .unwrap_err();
    assert_eq!(error.cause(), "queue_count_limit");
    assert_eq!(
        rebuilt.cancel("watch", Actor::System).await.unwrap(),
        CancelOutcome::CancelledQueued
    );
    assert_eq!(
        rebuilt
            .admit(&request("overflow"), CapabilityClass::NonDestructive)
            .await
            .unwrap(),
        AdmitOutcome::Admitted
    );
}

#[tokio::test]
async fn failed_park_keeps_the_existing_lease_and_lane() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let queue = QueueManager::new(Arc::clone(&store));
    enqueue(&queue, "watch").await;
    enqueue(&queue, "other").await;
    queue.take_next("/repo").await.unwrap().unwrap();
    ready_checkpoint(&store, "watch").await;
    assert!(
        store
            .prepare_flow_attempt("watch", 0, "step", 1, true)
            .await
            .unwrap()
    );
    assert!(!queue.park("watch", now_ms() + 10_000).await.unwrap());
    assert_eq!(queue.leased_ids().await, ["watch"]);
    assert!(queue.take_next("/repo").await.unwrap().is_none());
    assert_eq!(
        store.get_request("watch").await.unwrap().unwrap().state,
        RequestState::Running
    );
}

async fn park_for_notice(queue: &QueueManager, store: &Store, id: &str) -> (Instant, i64) {
    enqueue(queue, id).await;
    let lease = queue.take_next("/repo").await.unwrap().unwrap();
    ready_checkpoint(store, id).await;
    let resume = now_ms() + 10_000;
    assert!(queue.park(id, resume).await.unwrap());
    // Consume the lane-release notification so the terminal notification below
    // must be produced by the sweep itself.
    tokio::time::timeout(Duration::from_millis(100), queue.work_available())
        .await
        .unwrap();
    (lease.lease_deadline, resume)
}

#[tokio::test]
async fn full_terminal_notice_buffer_retains_new_parked_admissions_until_drain() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let queue = QueueManager::new(Arc::clone(&store));
    let mut expected = Vec::new();
    for index in 0..crate::queue::MAX_PARKED_TERMINALS {
        let id = format!("expired-{index}");
        let (deadline, resume) = park_for_notice(&queue, &store, &id).await;
        assert_eq!(queue.wake_due(deadline, resume).await.unwrap(), 0);
        tokio::time::timeout(Duration::from_millis(100), queue.work_available())
            .await
            .unwrap();
        expected.push(id);
    }
    assert_eq!(store.admission_usage().await.unwrap().0, 0);
    let (deadline, resume) = park_for_notice(&queue, &store, "pending-notice").await;
    assert_eq!(queue.wake_due(deadline, resume).await.unwrap(), 0);
    tokio::time::timeout(Duration::from_millis(100), queue.work_available())
        .await
        .unwrap();
    let pending = store.get_request("pending-notice").await.unwrap().unwrap();
    assert_eq!(pending.state, RequestState::Queued);
    assert_eq!(pending.resume_at_ms, Some(resume));
    assert_eq!(store.admission_usage().await.unwrap().0, 1);
    assert!(
        store
            .audit_for_request("pending-notice")
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(queue.take_parked_terminals().await, expected);
    assert!(queue.take_parked_terminals().await.is_empty());
    assert_eq!(queue.wake_due(deadline, resume).await.unwrap(), 0);
    assert_eq!(queue.take_parked_terminals().await, ["pending-notice"]);
    assert!(queue.take_parked_terminals().await.is_empty());
    assert_eq!(store.admission_usage().await.unwrap().0, 0);
    assert_eq!(
        store
            .get_request("pending-notice")
            .await
            .unwrap()
            .unwrap()
            .outcome
            .as_deref(),
        Some("lease_expired")
    );
}
