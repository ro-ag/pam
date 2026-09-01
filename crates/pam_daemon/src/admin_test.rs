use std::sync::Arc;
use std::time::Duration;

use pam_proto::{Caller, Envelope, Event, Outcome, PROTOCOL_VERSION, Response};
use pam_store::{Actor, ApprovalResolution, Decision, RequestState, Store, StoreError};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::admin::{
    ACTION_ADMIN, ACTION_ADMIN_DENIED, ADMIN_CALLER_AGENT, ADMIN_REPO, AdminService,
    CAUSE_ADMIN_DENIED, CAUSE_ALREADY_GRANTED, CAUSE_INVALID_ADMIN_ARGS, CAUSE_NO_ACTIVE_GRANT,
    CAUSE_NO_PENDING_APPROVAL, CAUSE_UNKNOWN_ADMIN_OP, OP_ACTIVITY_LIST, OP_APPROVALS_PENDING,
    OP_APPROVALS_RESOLVE, OP_CALLERS_LIST, OP_GRANTS_ADD, OP_GRANTS_LIST, OP_GRANTS_REVOKE,
    OP_PROFILE_GET, OP_PROFILE_SET,
};
use crate::approval::{ApprovalOutcome, ApprovalService};
use crate::policy::{PROFILE_SETTING_KEY, Profile};
use crate::transport::EventPublisher;

const DEADLINE: Duration = Duration::from_secs(5);

/// Approval timeout long enough to never fire in these tests.
const LONG_TIMEOUT: Duration = Duration::from_mins(10);

async fn service() -> (Arc<Store>, AdminService, mpsc::Receiver<(String, Event)>) {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let (events, rx) = EventPublisher::for_tests();
    let approvals = Arc::new(ApprovalService::new(
        Arc::clone(&store),
        events,
        LONG_TIMEOUT,
    ));
    let admin = AdminService::new(Arc::clone(&store), approvals);
    (store, admin, rx)
}

/// [`service`] plus a clone of the approval service, for tests driving
/// a real approval wait.
async fn service_with_approvals() -> (
    Arc<Store>,
    AdminService,
    Arc<ApprovalService>,
    mpsc::Receiver<(String, Event)>,
) {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let (events, rx) = EventPublisher::for_tests();
    let approvals = Arc::new(ApprovalService::new(
        Arc::clone(&store),
        events,
        LONG_TIMEOUT,
    ));
    let admin = AdminService::new(Arc::clone(&store), Arc::clone(&approvals));
    (store, admin, approvals, rx)
}

/// An admin envelope carrying the GUI tripwire identity.
fn admin_envelope(id: &str, op: &str, args: serde_json::Value) -> Envelope {
    envelope_as(ADMIN_CALLER_AGENT, id, op, args)
}

fn envelope_as(agent: &str, id: &str, op: &str, args: serde_json::Value) -> Envelope {
    Envelope {
        v: PROTOCOL_VERSION,
        id: id.to_owned(),
        capability: op.to_owned(),
        client_version: env!("CARGO_PKG_VERSION").to_owned(),
        caller: Caller {
            agent: agent.to_owned(),
            repo: "/repo/anywhere".to_owned(),
            pid: 4242,
        },
        args,
        idempotency_key: None,
        deadline_ms: 4_000,
        wait: true,
    }
}

/// Unwraps a [`Response::Result`], asserting the outcome.
fn expect_result(response: Response, outcome: Outcome) -> serde_json::Value {
    match response {
        Response::Result {
            outcome: got, body, ..
        } => {
            assert_eq!(got, outcome, "result outcome");
            body
        }
        other => panic!("expected a result, got {other:?}"),
    }
}

/// Unwraps a [`Response::Refusal`], asserting the cause and that the
/// recovery line is present.
fn expect_refusal(response: Response, cause: &str) -> String {
    match response {
        Response::Refusal {
            cause: got,
            detail,
            recovery,
            ..
        } => {
            assert_eq!(got, cause, "refusal cause");
            assert!(!recovery.is_empty(), "refusal carries a recovery line");
            detail
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// Asserts the admin op's request row reached `state` with exactly one
/// audit row of `action`, and returns that audit row's fields.
async fn assert_admin_row(
    store: &Store,
    id: &str,
    state: RequestState,
    action: &str,
) -> (Decision, Actor, Option<String>) {
    let row = store
        .get_request(id)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("admin request {id} has a row"));
    assert_eq!(row.state, state, "admin request state");
    assert_eq!(row.repo, ADMIN_REPO, "admin rows belong to the gui repo");
    let audit: Vec<_> = store
        .audit_for_request(id)
        .await
        .unwrap()
        .into_iter()
        .filter(|row| row.action == action)
        .collect();
    assert_eq!(audit.len(), 1, "exactly one {action} audit row");
    let row = audit.into_iter().next().unwrap();
    (row.decision, row.actor, row.detail)
}

#[tokio::test]
async fn profile_get_returns_platform_default_when_unset() {
    timeout(DEADLINE, async {
        let (store, admin, _events) = service().await;

        let response = admin
            .handle(&admin_envelope(
                "req_a1",
                OP_PROFILE_GET,
                serde_json::json!({}),
            ))
            .await;

        let body = expect_result(response, Outcome::Verified);
        assert_eq!(body["profile"], Profile::platform_default().as_str());
        let (decision, actor, _) =
            assert_admin_row(&store, "req_a1", RequestState::Done, ACTION_ADMIN).await;
        assert_eq!(decision, Decision::Allow);
        assert_eq!(actor, Actor::Human);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn profile_set_validates_persists_and_reads_back() {
    timeout(DEADLINE, async {
        let (store, admin, _events) = service().await;

        let response = admin
            .handle(&admin_envelope(
                "req_a2",
                OP_PROFILE_SET,
                serde_json::json!({ "profile": "strict" }),
            ))
            .await;

        let body = expect_result(response, Outcome::Changed);
        assert_eq!(body["profile"], "strict");
        assert_eq!(body["applies"], "next_daemon_start");
        assert_eq!(
            store.get_setting(PROFILE_SETTING_KEY).await.unwrap(),
            Some("\"strict\"".to_owned())
        );
        assert_admin_row(&store, "req_a2", RequestState::Done, ACTION_ADMIN).await;

        let response = admin
            .handle(&admin_envelope(
                "req_a3",
                OP_PROFILE_GET,
                serde_json::json!({}),
            ))
            .await;
        let body = expect_result(response, Outcome::Verified);
        assert_eq!(body["profile"], "strict");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn profile_set_refuses_an_unknown_profile() {
    timeout(DEADLINE, async {
        let (store, admin, _events) = service().await;

        let response = admin
            .handle(&admin_envelope(
                "req_a4",
                OP_PROFILE_SET,
                serde_json::json!({ "profile": "yolo" }),
            ))
            .await;

        expect_refusal(response, CAUSE_INVALID_ADMIN_ARGS);
        assert_eq!(
            store.get_setting(PROFILE_SETTING_KEY).await.unwrap(),
            None,
            "an invalid profile writes nothing"
        );
        let (decision, actor, _) =
            assert_admin_row(&store, "req_a4", RequestState::Refused, ACTION_ADMIN).await;
        assert_eq!(decision, Decision::Refuse);
        assert_eq!(actor, Actor::System);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn grants_add_list_revoke_round_trip_keeps_history() {
    timeout(DEADLINE, async {
        let (store, admin, _events) = service().await;

        let response = admin
            .handle(&admin_envelope(
                "req_g1",
                OP_GRANTS_ADD,
                serde_json::json!({ "capability": "deploy" }),
            ))
            .await;
        expect_result(response, Outcome::Changed);
        assert!(store.active_grant("deploy").await.unwrap());

        let response = admin
            .handle(&admin_envelope(
                "req_g2",
                OP_GRANTS_REVOKE,
                serde_json::json!({ "capability": "deploy" }),
            ))
            .await;
        expect_result(response, Outcome::Changed);
        assert!(!store.active_grant("deploy").await.unwrap());

        let response = admin
            .handle(&admin_envelope(
                "req_g3",
                OP_GRANTS_LIST,
                serde_json::json!({}),
            ))
            .await;
        let body = expect_result(response, Outcome::Verified);
        let grants = body["grants"].as_array().unwrap();
        assert_eq!(grants.len(), 1, "revoked history stays listed");
        assert_eq!(grants[0]["capability"], "deploy");
        assert!(grants[0]["revoked_ts"].is_i64(), "revocation timestamped");

        for id in ["req_g1", "req_g2", "req_g3"] {
            assert_admin_row(&store, id, RequestState::Done, ACTION_ADMIN).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn grants_add_refuses_a_duplicate_active_grant() {
    timeout(DEADLINE, async {
        let (store, admin, _events) = service().await;
        store.insert_grant("deploy").await.unwrap();

        let response = admin
            .handle(&admin_envelope(
                "req_g4",
                OP_GRANTS_ADD,
                serde_json::json!({ "capability": "deploy" }),
            ))
            .await;

        expect_refusal(response, CAUSE_ALREADY_GRANTED);
        assert_admin_row(&store, "req_g4", RequestState::Refused, ACTION_ADMIN).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn grants_revoke_without_an_active_grant_refuses() {
    timeout(DEADLINE, async {
        let (store, admin, _events) = service().await;

        let response = admin
            .handle(&admin_envelope(
                "req_g5",
                OP_GRANTS_REVOKE,
                serde_json::json!({ "capability": "deploy" }),
            ))
            .await;

        expect_refusal(response, CAUSE_NO_ACTIVE_GRANT);
        assert_admin_row(&store, "req_g5", RequestState::Refused, ACTION_ADMIN).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn grants_ops_refuse_a_missing_capability_argument() {
    timeout(DEADLINE, async {
        let (_store, admin, _events) = service().await;

        let response = admin
            .handle(&admin_envelope(
                "req_g6",
                OP_GRANTS_ADD,
                serde_json::json!({}),
            ))
            .await;

        expect_refusal(response, CAUSE_INVALID_ADMIN_ARGS);
    })
    .await
    .unwrap();
}

/// Spawns a real approval wait for `id` (request row inserted first).
async fn spawn_approval_wait(
    store: &Arc<Store>,
    approvals: &Arc<ApprovalService>,
    events: &mut mpsc::Receiver<(String, Event)>,
    id: &str,
) -> (
    watch::Sender<bool>,
    JoinHandle<Result<ApprovalOutcome, StoreError>>,
) {
    store
        .insert_request(id, "release", "/repo/a", "claude", "{}", None)
        .await
        .unwrap();
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let approvals = Arc::clone(approvals);
    let id_owned = id.to_owned();
    let wait = tokio::spawn(async move {
        approvals
            .request_approval(&id_owned, "release", &mut cancel_rx)
            .await
    });
    // The approval_pending event marks the wait as registered.
    let (topic, event) = events.recv().await.expect("pending event");
    assert_eq!(topic, id);
    assert_eq!(event, Event::ApprovalPending);
    (cancel_tx, wait)
}

#[tokio::test]
async fn approvals_pending_lists_the_waiting_request() {
    timeout(DEADLINE, async {
        let (store, admin, approvals, mut events) = service_with_approvals().await;
        let (_cancel, wait) = spawn_approval_wait(&store, &approvals, &mut events, "req_w1").await;

        let response = admin
            .handle(&admin_envelope(
                "req_p1",
                OP_APPROVALS_PENDING,
                serde_json::json!({}),
            ))
            .await;

        let body = expect_result(response, Outcome::Verified);
        let pending = body["pending"].as_array().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0]["request_id"], "req_w1");
        assert_eq!(pending[0]["capability"], "release");

        // Clean the wait up so the task does not outlive the test.
        approvals
            .resolve("req_w1", crate::approval::Resolution::Deny)
            .await
            .unwrap();
        wait.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn approvals_resolve_approves_the_waiting_request_with_remember() {
    timeout(DEADLINE, async {
        let (store, admin, approvals, mut events) = service_with_approvals().await;
        let (_cancel, wait) = spawn_approval_wait(&store, &approvals, &mut events, "req_w2").await;

        let response = admin
            .handle(&admin_envelope(
                "req_r1",
                OP_APPROVALS_RESOLVE,
                serde_json::json!({
                    "request_id": "req_w2",
                    "resolution": "approved",
                    "remember": true,
                    "note": "looks safe",
                }),
            ))
            .await;

        let body = expect_result(response, Outcome::Changed);
        assert_eq!(body["resolution"], "approved");
        assert_eq!(body["remember"], true);
        assert_eq!(
            wait.await.unwrap().unwrap(),
            ApprovalOutcome::Approved { remember: true }
        );
        let approval = store
            .approval_for_request("req_w2")
            .await
            .unwrap()
            .expect("approval row");
        assert_eq!(approval.resolution, Some(ApprovalResolution::Approved));
        // The note travels in the admin op's audit detail.
        let (_, _, detail) =
            assert_admin_row(&store, "req_r1", RequestState::Done, ACTION_ADMIN).await;
        assert!(detail.unwrap().contains("looks safe"));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn approvals_resolve_refuses_an_unknown_request_id() {
    timeout(DEADLINE, async {
        let (store, admin, _events) = service().await;

        let response = admin
            .handle(&admin_envelope(
                "req_r2",
                OP_APPROVALS_RESOLVE,
                serde_json::json!({ "request_id": "req_nope", "resolution": "approved" }),
            ))
            .await;

        expect_refusal(response, CAUSE_NO_PENDING_APPROVAL);
        assert_admin_row(&store, "req_r2", RequestState::Refused, ACTION_ADMIN).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn approvals_resolve_refuses_a_bad_resolution_value() {
    timeout(DEADLINE, async {
        let (_store, admin, _events) = service().await;

        let response = admin
            .handle(&admin_envelope(
                "req_r3",
                OP_APPROVALS_RESOLVE,
                serde_json::json!({ "request_id": "req_x", "resolution": "maybe" }),
            ))
            .await;

        expect_refusal(response, CAUSE_INVALID_ADMIN_ARGS);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn activity_list_filters_by_agent_and_state() {
    timeout(DEADLINE, async {
        let (store, admin, _events) = service().await;
        store
            .insert_request("req_h1", "echo", "/repo/a", "claude", "{}", None)
            .await
            .unwrap();
        store
            .insert_request("req_h2", "echo", "/repo/b", "codex", "{}", None)
            .await
            .unwrap();

        let response = admin
            .handle(&admin_envelope(
                "req_l1",
                OP_ACTIVITY_LIST,
                serde_json::json!({ "agent": "claude", "state": "queued" }),
            ))
            .await;

        let body = expect_result(response, Outcome::Verified);
        let requests = body["requests"].as_array().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["id"], "req_h1");
        assert_eq!(requests[0]["agent"], "claude");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn activity_list_refuses_an_unknown_state_filter() {
    timeout(DEADLINE, async {
        let (_store, admin, _events) = service().await;

        let response = admin
            .handle(&admin_envelope(
                "req_l2",
                OP_ACTIVITY_LIST,
                serde_json::json!({ "state": "levitating" }),
            ))
            .await;

        expect_refusal(response, CAUSE_INVALID_ADMIN_ARGS);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn callers_list_returns_the_observed_registry() {
    timeout(DEADLINE, async {
        let (store, admin, _events) = service().await;
        store.upsert_caller("claude", "/repo/a").await.unwrap();
        store.upsert_caller("codex", "/repo/b").await.unwrap();

        let response = admin
            .handle(&admin_envelope(
                "req_c1",
                OP_CALLERS_LIST,
                serde_json::json!({}),
            ))
            .await;

        let body = expect_result(response, Outcome::Verified);
        let callers = body["callers"].as_array().unwrap();
        assert_eq!(callers.len(), 2);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tripwire_refuses_and_audits_a_non_gui_caller() {
    timeout(DEADLINE, async {
        let (store, admin, _events) = service().await;

        let response = admin
            .handle(&envelope_as(
                "claude",
                "req_t1",
                OP_GRANTS_ADD,
                serde_json::json!({ "capability": "deploy" }),
            ))
            .await;

        let detail = expect_refusal(response, CAUSE_ADMIN_DENIED);
        assert!(detail.contains("GUI-only"));
        assert!(
            !store.active_grant("deploy").await.unwrap(),
            "the tripwired op must not run"
        );
        let (decision, actor, audit_detail) =
            assert_admin_row(&store, "req_t1", RequestState::Refused, ACTION_ADMIN_DENIED).await;
        assert_eq!(decision, Decision::Refuse);
        assert_eq!(actor, Actor::System);
        assert!(audit_detail.unwrap().contains("claude"));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unknown_admin_op_refuses_legibly() {
    timeout(DEADLINE, async {
        let (store, admin, _events) = service().await;

        let response = admin
            .handle(&admin_envelope(
                "req_u1",
                "admin.self.destruct",
                serde_json::json!({}),
            ))
            .await;

        expect_refusal(response, CAUSE_UNKNOWN_ADMIN_OP);
        let (decision, actor, _) =
            assert_admin_row(&store, "req_u1", RequestState::Refused, ACTION_ADMIN).await;
        assert_eq!(decision, Decision::Refuse);
        assert_eq!(actor, Actor::System);
    })
    .await
    .unwrap();
}
