use std::sync::Arc;
use std::time::Duration;

use pam_proto::Event;
use pam_store::{Actor, ApprovalResolution, Decision, RequestState, Store, StoreError};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::approval::{
    ACTION_APPROVAL, ACTION_GRANT_FROM_APPROVAL, ApprovalError, ApprovalOutcome, ApprovalService,
    DEFAULT_APPROVAL_TIMEOUT, NOTE_CANCELLED, Resolution,
};
use crate::transport::EventPublisher;

const DEADLINE: Duration = Duration::from_secs(5);

/// Approval timeout for tests that resolve before it; long enough to
/// never fire.
const LONG_TIMEOUT: Duration = Duration::from_mins(10);

const CAPABILITY: &str = "release";

async fn service_with(
    timeout: Duration,
) -> (
    Arc<Store>,
    Arc<ApprovalService>,
    mpsc::Receiver<(String, Event)>,
) {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let (events, rx) = EventPublisher::for_tests();
    let service = Arc::new(ApprovalService::new(Arc::clone(&store), events, timeout));
    (store, service, rx)
}

async fn insert_request(store: &Store, id: &str) {
    store
        .insert_request(id, CAPABILITY, "/repo/a", "claude", "{}", None)
        .await
        .unwrap();
}

/// Spawns a `request_approval` wait for `id`; returns the cancel sender
/// and the join handle carrying the outcome.
fn spawn_wait(
    service: &Arc<ApprovalService>,
    id: &str,
) -> (
    watch::Sender<bool>,
    JoinHandle<Result<ApprovalOutcome, StoreError>>,
) {
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let service = Arc::clone(service);
    let id = id.to_owned();
    let handle = tokio::spawn(async move {
        service
            .request_approval(&id, CAPABILITY, &mut cancel_rx)
            .await
    });
    (cancel_tx, handle)
}

/// Receives the next event and asserts it is `id`'s `approval_pending`
/// — the signal that the wait is registered and resolvable.
async fn expect_pending_event(rx: &mut mpsc::Receiver<(String, Event)>, id: &str) {
    let (topic, event) = rx.recv().await.expect("event published");
    assert_eq!(topic, id);
    assert_eq!(event, Event::ApprovalPending);
}

#[tokio::test]
async fn approve_resolves_row_and_audits_without_touching_request_state() {
    timeout(DEADLINE, async {
        let (store, service, mut events) = service_with(LONG_TIMEOUT).await;
        insert_request(&store, "req_1").await;

        let (_cancel, wait) = spawn_wait(&service, "req_1");
        expect_pending_event(&mut events, "req_1").await;

        // The wait parked the request and left an unresolved row the
        // pending list surfaces.
        let row = store.get_request("req_1").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::WaitingApproval);
        let pending = service.pending().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].request_id, "req_1");
        assert_eq!(pending[0].capability, CAPABILITY);
        assert_eq!(pending[0].repo, "/repo/a");
        assert_eq!(pending[0].caller_agent, "claude");

        service
            .resolve("req_1", Resolution::Approve { remember: false })
            .await
            .unwrap();
        let outcome = wait.await.unwrap().unwrap();
        assert_eq!(outcome, ApprovalOutcome::Approved { remember: false });

        // Approval row resolved, resolution audited, pending list empty.
        let approval = store.approval_for_request("req_1").await.unwrap().unwrap();
        assert_eq!(approval.resolution, Some(ApprovalResolution::Approved));
        assert!(approval.resolved_ts.is_some());
        let audit = store.audit_for_request("req_1").await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, ACTION_APPROVAL);
        assert_eq!(audit[0].decision, Decision::Approve);
        assert_eq!(audit[0].actor, Actor::Human);
        assert!(audit[0].detail.as_deref().unwrap().contains(CAPABILITY));
        assert!(service.pending().await.unwrap().is_empty());

        // No grant without remember, and the request-state transition
        // out of waiting_approval belongs to the pipeline, not here.
        assert!(!store.active_grant(CAPABILITY).await.unwrap());
        let row = store.get_request("req_1").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::WaitingApproval);
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn approve_with_remember_inserts_an_audited_grant() {
    timeout(DEADLINE, async {
        let (store, service, mut events) = service_with(LONG_TIMEOUT).await;
        insert_request(&store, "req_1").await;

        let (_cancel, wait) = spawn_wait(&service, "req_1");
        expect_pending_event(&mut events, "req_1").await;
        service
            .resolve("req_1", Resolution::Approve { remember: true })
            .await
            .unwrap();
        let outcome = wait.await.unwrap().unwrap();
        assert_eq!(outcome, ApprovalOutcome::Approved { remember: true });

        assert!(store.active_grant(CAPABILITY).await.unwrap());
        let audit = store.audit_for_request("req_1").await.unwrap();
        let approval: Vec<_> = audit
            .iter()
            .filter(|row| row.action == ACTION_APPROVAL)
            .collect();
        assert_eq!(approval.len(), 1);
        assert!(approval[0].detail.as_deref().unwrap().contains("true"));
        let grant: Vec<_> = audit
            .iter()
            .filter(|row| row.action == ACTION_GRANT_FROM_APPROVAL)
            .collect();
        assert_eq!(grant.len(), 1);
        assert_eq!(grant[0].decision, Decision::Allow);
        assert_eq!(grant[0].actor, Actor::Human);
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn deny_resolves_denied_and_audits_the_human_denial() {
    timeout(DEADLINE, async {
        let (store, service, mut events) = service_with(LONG_TIMEOUT).await;
        insert_request(&store, "req_1").await;

        let (_cancel, wait) = spawn_wait(&service, "req_1");
        expect_pending_event(&mut events, "req_1").await;
        service.resolve("req_1", Resolution::Deny).await.unwrap();
        assert_eq!(wait.await.unwrap().unwrap(), ApprovalOutcome::Denied);

        let approval = store.approval_for_request("req_1").await.unwrap().unwrap();
        assert_eq!(approval.resolution, Some(ApprovalResolution::Denied));
        assert_eq!(approval.note, None);
        let audit = store.audit_for_request("req_1").await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, ACTION_APPROVAL);
        assert_eq!(audit[0].decision, Decision::Deny);
        assert_eq!(audit[0].actor, Actor::Human);
    })
    .await
    .expect("test within deadline");
}

#[tokio::test(start_paused = true)]
async fn unanswered_approval_times_out_and_audits_the_system_timeout() {
    // The clock is paused, so the outer deadline must sit beyond the
    // approval timeout — auto-advance jumps to the earliest timer.
    timeout(DEFAULT_APPROVAL_TIMEOUT + DEADLINE, async {
        let (store, service, mut events) = service_with(DEFAULT_APPROVAL_TIMEOUT).await;
        insert_request(&store, "req_1").await;

        let (_cancel, wait) = spawn_wait(&service, "req_1");
        expect_pending_event(&mut events, "req_1").await;

        // Nobody answers; the paused clock races through the 15 minutes.
        assert_eq!(wait.await.unwrap().unwrap(), ApprovalOutcome::TimedOut);

        let approval = store.approval_for_request("req_1").await.unwrap().unwrap();
        assert_eq!(approval.resolution, Some(ApprovalResolution::Timeout));
        let audit = store.audit_for_request("req_1").await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, ACTION_APPROVAL);
        assert_eq!(audit[0].decision, Decision::Timeout);
        assert_eq!(audit[0].actor, Actor::System);

        // The wait is gone: a late resolution has nowhere to land.
        assert!(matches!(
            service.resolve("req_1", Resolution::Deny).await,
            Err(ApprovalError::NotFound { .. })
        ));
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn cancel_during_the_wait_resolves_denied_with_note() {
    timeout(DEADLINE, async {
        let (store, service, mut events) = service_with(LONG_TIMEOUT).await;
        insert_request(&store, "req_1").await;

        let (cancel, wait) = spawn_wait(&service, "req_1");
        expect_pending_event(&mut events, "req_1").await;
        cancel.send(true).unwrap();
        assert_eq!(wait.await.unwrap().unwrap(), ApprovalOutcome::Cancelled);

        let approval = store.approval_for_request("req_1").await.unwrap().unwrap();
        assert_eq!(approval.resolution, Some(ApprovalResolution::Denied));
        assert_eq!(approval.note.as_deref(), Some(NOTE_CANCELLED));
        let audit = store.audit_for_request("req_1").await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, ACTION_APPROVAL);
        assert_eq!(audit[0].decision, Decision::Deny);
        assert_eq!(audit[0].actor, Actor::System);
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn resolve_without_a_pending_wait_is_not_found() {
    timeout(DEADLINE, async {
        let (_store, service, _events) = service_with(LONG_TIMEOUT).await;
        assert!(matches!(
            service.resolve("req_missing", Resolution::Deny).await,
            Err(ApprovalError::NotFound { .. })
        ));
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn a_second_resolution_of_the_same_request_is_not_found() {
    timeout(DEADLINE, async {
        let (store, service, mut events) = service_with(LONG_TIMEOUT).await;
        insert_request(&store, "req_1").await;

        let (_cancel, wait) = spawn_wait(&service, "req_1");
        expect_pending_event(&mut events, "req_1").await;
        service
            .resolve("req_1", Resolution::Approve { remember: false })
            .await
            .unwrap();
        wait.await.unwrap().unwrap();

        assert!(matches!(
            service.resolve("req_1", Resolution::Deny).await,
            Err(ApprovalError::NotFound { .. })
        ));
        // The row kept the first resolution.
        let approval = store.approval_for_request("req_1").await.unwrap().unwrap();
        assert_eq!(approval.resolution, Some(ApprovalResolution::Approved));
    })
    .await
    .expect("test within deadline");
}
