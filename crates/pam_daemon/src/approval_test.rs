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
    let service = Arc::new(ApprovalService::new(
        Arc::clone(&store),
        events,
        timeout,
        crate::managed_policy_service::PolicyHandle::none(),
    ));
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

fn snapshot(program: &str, argv: &[&str]) -> crate::approval::StepSnapshot {
    crate::approval::StepSnapshot::new(
        "flowdigest",
        "flow.step:ship/push",
        program.to_owned(),
        argv.iter().map(|arg| (*arg).to_owned()).collect(),
        Some("/repo/a".to_owned()),
        vec!["GIT_ASKPASS".to_owned()],
    )
}

/// Spawns a wait that carries a step snapshot.
fn spawn_step_wait(
    service: &Arc<ApprovalService>,
    id: &str,
    step: crate::approval::StepSnapshot,
) -> (
    watch::Sender<bool>,
    JoinHandle<Result<ApprovalOutcome, StoreError>>,
) {
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let service = Arc::clone(service);
    let id = id.to_owned();
    let handle = tokio::spawn(async move {
        service
            .request_approval_with(&id, "flow.step:ship/push", Some(step), &mut cancel_rx)
            .await
    });
    (cancel_tx, handle)
}

#[test]
fn the_snapshot_digest_binds_the_flow_the_step_and_every_resolved_field() {
    let base = snapshot("/usr/bin/git", &["push", "origin", "main"]);
    assert_eq!(base.digest.len(), 64);
    assert_eq!(base, snapshot("/usr/bin/git", &["push", "origin", "main"]));

    let different = [
        snapshot("/opt/evil/git", &["push", "origin", "main"]),
        snapshot("/usr/bin/git", &["push", "origin", "main", "--force"]),
        // The same words split differently are different arguments.
        snapshot("/usr/bin/git", &["push", "origin main"]),
        crate::approval::StepSnapshot::new(
            "another-flow-digest",
            "flow.step:ship/push",
            base.program.clone(),
            base.argv.clone(),
            base.cwd.clone(),
            base.env_keys.clone(),
        ),
        crate::approval::StepSnapshot::new(
            "flowdigest",
            "flow.step:ship/other",
            base.program.clone(),
            base.argv.clone(),
            base.cwd.clone(),
            base.env_keys.clone(),
        ),
        crate::approval::StepSnapshot::new(
            "flowdigest",
            "flow.step:ship/push",
            base.program.clone(),
            base.argv.clone(),
            Some("/somewhere/else".to_owned()),
            base.env_keys.clone(),
        ),
        crate::approval::StepSnapshot::new(
            "flowdigest",
            "flow.step:ship/push",
            base.program.clone(),
            base.argv.clone(),
            base.cwd.clone(),
            vec!["LD_PRELOAD".to_owned()],
        ),
    ];
    for other in different {
        assert_ne!(other.digest, base.digest, "{other:?}");
    }

    // The wire shape the approval card reads.
    let wire = serde_json::to_value(&base).unwrap();
    assert_eq!(wire["program"], "/usr/bin/git");
    assert_eq!(wire["argv"], serde_json::json!(["push", "origin", "main"]));
    assert_eq!(wire["cwd"], "/repo/a");
    assert_eq!(wire["env_keys"], serde_json::json!(["GIT_ASKPASS"]));
    assert_eq!(wire["digest"], base.digest);
}

/// The card shows what was captured when the wait began, and an answer is
/// pinned to it: a digest that is not the pending wait's resolves nothing.
#[tokio::test]
async fn a_pinned_resolution_must_name_the_snapshot_that_is_pending() {
    timeout(DEADLINE, async {
        let (store, service, mut events) = service_with(LONG_TIMEOUT).await;
        insert_request(&store, "req_pin").await;
        let step = snapshot("/usr/bin/git", &["push", "origin", "main"]);
        let (_cancel, wait) = spawn_step_wait(&service, "req_pin", step.clone());
        expect_pending_event(&mut events, "req_pin").await;

        assert_eq!(service.snapshot("req_pin").await, Some(step.clone()));
        assert_eq!(service.snapshot("req_other").await, None);

        // The human answered a card showing something else (an earlier
        // step of this request, or the flow before it was edited).
        let stale = snapshot("/usr/bin/git", &["status"]);
        let error = service
            .resolve_pinned(
                "req_pin",
                Resolution::Approve { remember: true },
                Some(&stale.digest),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, ApprovalError::Changed { .. }), "{error:?}");
        // Nothing was resolved, nothing granted, and the wait is intact.
        assert!(!wait.is_finished());
        assert!(!store.active_grant("flow.step:ship/push").await.unwrap());
        let approval = store
            .approval_for_request("req_pin")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(approval.resolution, None);
        assert_eq!(service.snapshot("req_pin").await, Some(step.clone()));

        // The digest of what is actually pending resolves it.
        service
            .resolve_pinned(
                "req_pin",
                Resolution::Approve { remember: false },
                Some(&step.digest),
            )
            .await
            .unwrap();
        assert_eq!(
            wait.await.unwrap().unwrap(),
            ApprovalOutcome::Approved { remember: false }
        );
        // The snapshot lives exactly as long as the wait.
        assert_eq!(service.snapshot("req_pin").await, None);
    })
    .await
    .unwrap();
}

/// A wait with no snapshot (a plain capability approval) cannot satisfy a
/// pinned answer: the pin fails closed rather than being ignored.
#[tokio::test]
async fn a_pinned_resolution_of_a_wait_without_a_snapshot_is_refused() {
    timeout(DEADLINE, async {
        let (store, service, mut events) = service_with(LONG_TIMEOUT).await;
        insert_request(&store, "req_plain").await;
        let (_cancel, wait) = spawn_wait(&service, "req_plain");
        expect_pending_event(&mut events, "req_plain").await;

        let error = service
            .resolve_pinned("req_plain", Resolution::Deny, Some("0".repeat(64).as_str()))
            .await
            .unwrap_err();
        assert!(matches!(error, ApprovalError::Changed { .. }), "{error:?}");
        assert!(!wait.is_finished());

        service
            .resolve("req_plain", Resolution::Deny)
            .await
            .unwrap();
        assert_eq!(wait.await.unwrap().unwrap(), ApprovalOutcome::Denied);
    })
    .await
    .unwrap();
}

/// `resolve` used to return as soon as the decision was handed over. It now
/// returns once the waiter has recorded it, so "approved" is true the
/// moment the human is told so.
#[tokio::test]
async fn resolve_returns_only_once_the_resolution_is_durable() {
    timeout(DEADLINE, async {
        let (store, service, mut events) = service_with(LONG_TIMEOUT).await;
        insert_request(&store, "req_durable").await;
        let (_cancel, wait) = spawn_wait(&service, "req_durable");
        expect_pending_event(&mut events, "req_durable").await;

        service
            .resolve("req_durable", Resolution::Approve { remember: true })
            .await
            .unwrap();
        // No polling: by the time resolve returns, the row, the audit row
        // and the remembered grant are all there.
        let approval = store
            .approval_for_request("req_durable")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(approval.resolution, Some(ApprovalResolution::Approved));
        assert!(store.active_grant(CAPABILITY).await.unwrap());
        let audit = store.audit_for_request("req_durable").await.unwrap();
        assert!(audit.iter().any(|row| row.action == ACTION_APPROVAL));
        assert!(
            audit
                .iter()
                .any(|row| row.action == ACTION_GRANT_FROM_APPROVAL)
        );
        wait.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

/// The human must not be told "approved" for an approval the daemon did
/// not record as approved. Here the approval row is resolved behind the
/// service's back (the state a lost race with the timeout leaves): the
/// waiter's write fails, and the resolver is told the approval is not
/// pending instead of being handed a success.
#[tokio::test]
async fn a_resolution_the_daemon_could_not_record_is_not_reported_as_delivered() {
    timeout(DEADLINE, async {
        let (store, service, mut events) = service_with(LONG_TIMEOUT).await;
        insert_request(&store, "req_lost").await;
        let (_cancel, wait) = spawn_wait(&service, "req_lost");
        expect_pending_event(&mut events, "req_lost").await;

        store
            .resolve_approval("req_lost", ApprovalResolution::Timeout, None)
            .await
            .unwrap();

        let error = service
            .resolve("req_lost", Resolution::Approve { remember: true })
            .await
            .unwrap_err();
        assert!(matches!(error, ApprovalError::NotFound { .. }), "{error:?}");
        // The waiter reports the bookkeeping failure to its own caller...
        assert!(wait.await.unwrap().is_err());
        // ...and nothing the human "approved" took effect.
        assert!(!store.active_grant(CAPABILITY).await.unwrap());
        let approval = store
            .approval_for_request("req_lost")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(approval.resolution, Some(ApprovalResolution::Timeout));
    })
    .await
    .unwrap();
}

/// The approval row and the request's `waiting_approval` state are one
/// transaction: a request that already finished gets neither.
#[tokio::test]
async fn a_finished_request_cannot_be_parked_for_approval() {
    timeout(DEADLINE, async {
        let (store, service, _events) = service_with(LONG_TIMEOUT).await;
        store
            .insert_running_request("req_done", CAPABILITY, "/repo/a", "claude", "{}", None)
            .await
            .unwrap();
        store
            .finish_request(
                "req_done",
                RequestState::Failed,
                Some("cancelled"),
                pam_store::AuditEntry {
                    action: "cancel",
                    decision: Decision::Deny,
                    actor: Actor::System,
                    detail: None,
                },
            )
            .await
            .unwrap();

        let (_cancel, mut cancel_rx) = watch::channel(false);
        let error = service
            .request_approval("req_done", CAPABILITY, &mut cancel_rx)
            .await
            .unwrap_err();
        assert!(
            matches!(error, StoreError::AlreadyTerminal { .. }),
            "{error:?}"
        );
        assert!(
            store
                .approval_for_request("req_done")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.get_request("req_done").await.unwrap().unwrap().state,
            RequestState::Failed
        );
        assert!(service.pending().await.unwrap().is_empty());
    })
    .await
    .unwrap();
}
