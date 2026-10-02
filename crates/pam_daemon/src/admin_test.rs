use std::sync::Arc;
use std::time::Duration;

use pam_proto::{Caller, Envelope, Event, Outcome, PROTOCOL_VERSION, Response};
use pam_store::{Actor, ApprovalResolution, AuditEntry, Decision, RequestState, Store, StoreError};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::admin::{
    ACTION_ADMIN, ACTION_ADMIN_DENIED, ADMIN_CALLER_AGENT, ADMIN_REPO, AdminService,
    CAUSE_ADMIN_DENIED, CAUSE_ALREADY_GRANTED, CAUSE_INVALID_ADMIN_ARGS, CAUSE_NO_ACTIVE_GRANT,
    CAUSE_NO_PENDING_APPROVAL, CAUSE_UNKNOWN_ADMIN_OP, OP_ACTIVITY_LIST, OP_APPROVALS_PENDING,
    OP_APPROVALS_RESOLVE, OP_AUDIT_REQUEST, OP_CALLERS_LIST, OP_GRANTS_ADD, OP_GRANTS_LIST,
    OP_GRANTS_REVOKE, OP_PROFILE_GET, OP_PROFILE_SET,
};
use crate::approval::{ApprovalOutcome, ApprovalService};
use crate::connector_service::ConnectorService;
use crate::log_service::LogService;
use crate::model_service::ModelService;
use crate::policy::Profile;
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
    let models = ModelService::new(Arc::clone(&store)).await.unwrap();
    let logs = LogService::new(Arc::clone(&store), Arc::clone(&models));
    let connectors = Arc::new(ConnectorService::from_parts(Arc::clone(&store), None, None));
    let flows = crate::flow_service_test::flows_for_tests(
        std::path::Path::new("pam-tests-have-no-flow-library"),
        &store,
        &approvals,
        &connectors,
        &logs,
    )
    .await;
    let admin = AdminService::new(
        Arc::clone(&store),
        approvals,
        models,
        logs,
        connectors,
        flows,
        crate::flow_service_test::closed_submit(),
    );
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
    let models = ModelService::new(Arc::clone(&store)).await.unwrap();
    let logs = LogService::new(Arc::clone(&store), Arc::clone(&models));
    let connectors = Arc::new(ConnectorService::from_parts(Arc::clone(&store), None, None));
    let flows = crate::flow_service_test::flows_for_tests(
        std::path::Path::new("pam-tests-have-no-flow-library"),
        &store,
        &approvals,
        &connectors,
        &logs,
    )
    .await;
    let admin = AdminService::new(
        Arc::clone(&store),
        Arc::clone(&approvals),
        models,
        logs,
        connectors,
        flows,
        crate::flow_service_test::closed_submit(),
    );
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
        // The change goes through the running gate — the one source of
        // truth — so it governs at once, not at the next daemon start.
        assert_eq!(body["applies"], "now");
        assert_eq!(admin.flows.gate().profile(), Profile::Strict);
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
            admin.flows.gate().profile(),
            Profile::platform_default(),
            "an invalid profile changes nothing"
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
        // A plain request: its args ride along, nothing else is known.
        assert_eq!(pending[0]["args"], serde_json::json!({}));
        assert_eq!(pending[0]["repository"], serde_json::Value::Null);
        assert_eq!(pending[0]["effect"], serde_json::Value::Null);

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
async fn approvals_pending_carries_the_flow_step_repository_and_effect() {
    timeout(DEADLINE, async {
        let (store, admin, approvals, mut events) = service_with_approvals().await;
        // A gated push of the builtin guarded-land flow: the request row is
        // the flow run itself, the approval names the step.
        let args = serde_json::json!({
            "id": "guarded-land",
            "inputs": {
                "repository": "https://github.test/team/repo.git",
                "commit": "a".repeat(40),
            },
        });
        store
            .insert_request(
                "req_w5",
                "flow.run",
                "/repo/a",
                "claude",
                &args.to_string(),
                None,
            )
            .await
            .unwrap();
        let (_cancel_tx, mut cancel_rx) = watch::channel(false);
        let waiting = Arc::clone(&approvals);
        let wait = tokio::spawn(async move {
            waiting
                .request_approval("req_w5", "flow.step:guarded-land/push", &mut cancel_rx)
                .await
        });
        let (topic, event) = events.recv().await.expect("pending event");
        assert_eq!(topic, "req_w5");
        assert_eq!(event, Event::ApprovalPending);

        let response = admin
            .handle(&admin_envelope(
                "req_p5",
                OP_APPROVALS_PENDING,
                serde_json::json!({}),
            ))
            .await;

        let body = expect_result(response, Outcome::Verified);
        let pending = body["pending"].as_array().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0]["capability"], "flow.step:guarded-land/push");
        assert_eq!(pending[0]["args"], args);
        assert_eq!(
            pending[0]["repository"],
            "https://github.test/team/repo.git"
        );
        assert_eq!(pending[0]["effect"], "stateful");

        approvals
            .resolve("req_w5", crate::approval::Resolution::Deny)
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

/// The note lands in the audit detail column, which is a receipt: a note
/// over the cap is refused up front, before the approval is touched.
#[tokio::test]
async fn approvals_resolve_refuses_a_note_over_the_cap_without_resolving() {
    timeout(DEADLINE, async {
        let (store, admin, approvals, mut events) = service_with_approvals().await;
        let (_cancel, wait) = spawn_approval_wait(&store, &approvals, &mut events, "req_w9").await;

        let response = admin
            .handle(&admin_envelope(
                "req_r9",
                OP_APPROVALS_RESOLVE,
                serde_json::json!({
                    "request_id": "req_w9",
                    "resolution": "approved",
                    "note": "n".repeat(crate::admin::MAX_APPROVAL_NOTE_BYTES + 1),
                }),
            ))
            .await;
        expect_refusal(response, CAUSE_INVALID_ADMIN_ARGS);
        assert_admin_row(&store, "req_r9", RequestState::Refused, ACTION_ADMIN).await;
        assert!(!wait.is_finished(), "the approval is still pending");

        // Exactly the cap is fine.
        let response = admin
            .handle(&admin_envelope(
                "req_r10",
                OP_APPROVALS_RESOLVE,
                serde_json::json!({
                    "request_id": "req_w9",
                    "resolution": "denied",
                    "note": "n".repeat(crate::admin::MAX_APPROVAL_NOTE_BYTES),
                }),
            ))
            .await;
        expect_result(response, Outcome::Changed);
        assert_eq!(wait.await.unwrap().unwrap(), ApprovalOutcome::Denied);
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
async fn activity_list_hides_the_gui_own_probes_when_asked() {
    timeout(DEADLINE, async {
        let (store, admin, _events) = service().await;
        store
            .insert_request("req_p1", "echo", "/repo/a", "claude", "{}", None)
            .await
            .unwrap();
        store
            .insert_request("req_p2", "status", "/repo/a", "pam-gui", "{}", None)
            .await
            .unwrap();
        store
            .insert_request(
                "req_p3",
                "admin.callers.list",
                "/repo/a",
                "pam-gui",
                "{}",
                None,
            )
            .await
            .unwrap();
        // The one admin op a human drives by hand stays visible.
        store
            .insert_request(
                "req_p4",
                "admin.log.compress",
                "/repo/a",
                "pam-gui",
                "{}",
                None,
            )
            .await
            .unwrap();

        let response = admin
            .handle(&admin_envelope(
                "req_l3",
                OP_ACTIVITY_LIST,
                serde_json::json!({ "hide_probes": true }),
            ))
            .await;

        let body = expect_result(response, Outcome::Verified);
        let requests = body["requests"].as_array().unwrap();
        let ids: Vec<&str> = requests
            .iter()
            .map(|row| row["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["req_p4", "req_p1"]);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn activity_list_refuses_a_non_bool_hide_probes() {
    timeout(DEADLINE, async {
        let (_store, admin, _events) = service().await;

        let response = admin
            .handle(&admin_envelope(
                "req_l4",
                OP_ACTIVITY_LIST,
                serde_json::json!({ "hide_probes": "yes" }),
            ))
            .await;

        expect_refusal(response, CAUSE_INVALID_ADMIN_ARGS);
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
async fn audit_request_lists_a_requests_rows_oldest_first() {
    timeout(DEADLINE, async {
        let (store, admin, _events) = service().await;
        store
            .insert_request("req_ad1", "repo.push", "/repo/a", "claude", "{}", None)
            .await
            .unwrap();
        // A plain-string detail first, so the handler's JSON parse has a
        // row that is not JSON to pass through untouched.
        store
            .append_audit(
                "req_ad1",
                "enqueue",
                Decision::Allow,
                Actor::System,
                Some("queued behind the gate"),
            )
            .await
            .unwrap();
        store
            .finish_request(
                "req_ad1",
                RequestState::Refused,
                Some("not_granted"),
                AuditEntry {
                    action: "execute",
                    decision: Decision::Refuse,
                    actor: Actor::Policy,
                    detail: Some(
                        r#"{"cause":"not_granted","detail":"repo.push is not granted","recovery":"Grant it in Settings › Security."}"#,
                    ),
                },
            )
            .await
            .unwrap();

        let response = admin
            .handle(&admin_envelope(
                "req_q1",
                OP_AUDIT_REQUEST,
                serde_json::json!({ "request_id": "req_ad1" }),
            ))
            .await;

        let body = expect_result(response, Outcome::Verified);
        assert_eq!(body["request_id"], "req_ad1");
        let rows = body["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!(rows[0]["action"], "enqueue");
        assert_eq!(rows[0]["decision"], "allow");
        assert_eq!(rows[0]["actor"], "system");
        assert_eq!(
            rows[0]["detail"], "queued behind the gate",
            "a non-JSON detail stays the raw string"
        );
        let last = rows.last().unwrap();
        assert!(
            last["id"].as_i64().unwrap() > rows[0]["id"].as_i64().unwrap(),
            "oldest first"
        );
        assert_eq!(last["action"], "execute");
        assert_eq!(last["decision"], "refuse");
        assert_eq!(last["actor"], "policy");
        assert_eq!(last["detail"]["cause"], "not_granted");
        assert!(last["ts"].as_i64().unwrap() > 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn audit_request_answers_empty_for_an_unknown_id_and_refuses_a_missing_one() {
    timeout(DEADLINE, async {
        let (_store, admin, _events) = service().await;
        let response = admin
            .handle(&admin_envelope(
                "req_q2",
                OP_AUDIT_REQUEST,
                serde_json::json!({ "request_id": "req_nope" }),
            ))
            .await;
        let body = expect_result(response, Outcome::Verified);
        assert_eq!(body["rows"].as_array().unwrap().len(), 0);

        let response = admin
            .handle(&admin_envelope(
                "req_q3",
                OP_AUDIT_REQUEST,
                serde_json::json!({}),
            ))
            .await;
        expect_refusal(response, CAUSE_INVALID_ADMIN_ARGS);

        let response = admin
            .handle(&admin_envelope(
                "req_q4",
                OP_AUDIT_REQUEST,
                serde_json::json!({ "request_id": "" }),
            ))
            .await;
        expect_refusal(response, CAUSE_INVALID_ADMIN_ARGS);
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

/// A real approval wait for a gated flow step, carrying the snapshot the
/// flow engine hands over when the wait begins.
async fn spawn_step_wait(
    store: &Arc<Store>,
    approvals: &Arc<ApprovalService>,
    events: &mut mpsc::Receiver<(String, Event)>,
    id: &str,
    step: crate::approval::StepSnapshot,
) -> JoinHandle<Result<ApprovalOutcome, StoreError>> {
    store
        .insert_request(
            id,
            "flow.run",
            "/repo/a",
            "claude",
            "{\"id\":\"ship\"}",
            None,
        )
        .await
        .unwrap();
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let approvals = Arc::clone(approvals);
    let id_owned = id.to_owned();
    let wait = tokio::spawn(async move {
        // Held for the wait: a dropped sender reads as cancellation.
        let _cancel_tx = cancel_tx;
        approvals
            .request_approval_with(&id_owned, "flow.step:ship/push", Some(step), &mut cancel_rx)
            .await
    });
    let (topic, event) = events.recv().await.expect("pending event");
    assert_eq!(topic, id);
    assert_eq!(event, Event::ApprovalPending);
    wait
}

fn push_step() -> crate::approval::StepSnapshot {
    crate::approval::StepSnapshot::new(
        "flowdigest",
        "flow.step:ship/push",
        "/usr/bin/git".to_owned(),
        vec![
            "push".to_owned(),
            "origin".to_owned(),
            "refs/heads/x y".to_owned(),
        ],
        Some("/repo/a".to_owned()),
        vec!["GIT_ASKPASS".to_owned()],
    )
}

/// The approval card must show what the waiting run will execute, as that
/// run resolved it — not a re-reading of the flow file at display time.
#[tokio::test]
async fn approvals_pending_carries_the_resolved_step_of_the_waiting_run() {
    timeout(DEADLINE, async {
        let (store, admin, approvals, mut events) = service_with_approvals().await;
        let step = push_step();
        let step_wait =
            spawn_step_wait(&store, &approvals, &mut events, "req_step", step.clone()).await;
        let (_cancel, plain_wait) =
            spawn_approval_wait(&store, &approvals, &mut events, "req_plain").await;

        let response = admin
            .handle(&admin_envelope(
                "req_p_resolved",
                OP_APPROVALS_PENDING,
                serde_json::json!({}),
            ))
            .await;
        let body = expect_result(response, Outcome::Verified);
        let pending = body["pending"].as_array().unwrap();
        let entry = |id: &str| {
            pending
                .iter()
                .find(|entry| entry["request_id"] == id)
                .unwrap_or_else(|| panic!("{id} is pending: {body}"))
        };

        let resolved = &entry("req_step")["resolved"];
        assert_eq!(resolved["program"], "/usr/bin/git");
        // One element per argument: a space inside one stays inside it.
        assert_eq!(
            resolved["argv"],
            serde_json::json!(["push", "origin", "refs/heads/x y"])
        );
        assert_eq!(resolved["cwd"], "/repo/a");
        assert_eq!(resolved["env_keys"], serde_json::json!(["GIT_ASKPASS"]));
        assert_eq!(resolved["digest"], step.digest);
        // A plain capability approval has no step to show.
        assert!(entry("req_plain").get("resolved").is_none());

        for id in ["req_step", "req_plain"] {
            approvals
                .resolve(id, crate::approval::Resolution::Deny)
                .await
                .unwrap();
        }
        step_wait.await.unwrap().unwrap();
        plain_wait.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

/// Editing the flow, or the request moving on to another gated step, after
/// the card was shown must not let "approve" authorize something else.
#[tokio::test]
async fn approvals_resolve_refuses_a_digest_that_is_not_the_pending_snapshot() {
    timeout(DEADLINE, async {
        let (store, admin, approvals, mut events) = service_with_approvals().await;
        let step = push_step();
        let wait =
            spawn_step_wait(&store, &approvals, &mut events, "req_pinned", step.clone()).await;

        let response = admin
            .handle(&admin_envelope(
                "req_r_stale",
                OP_APPROVALS_RESOLVE,
                serde_json::json!({
                    "request_id": "req_pinned",
                    "resolution": "approved",
                    "remember": true,
                    "expected_digest": "0".repeat(64),
                }),
            ))
            .await;
        // The cause the GUI keys on, shared with a pinned flow.run.
        expect_refusal(response, "flow_changed");
        assert_eq!(crate::admin::CAUSE_FLOW_CHANGED, "flow_changed");
        assert!(!wait.is_finished(), "the approval stays pending");
        assert!(!store.active_grant("flow.step:ship/push").await.unwrap());
        assert_admin_row(&store, "req_r_stale", RequestState::Refused, ACTION_ADMIN).await;

        // A digest that is not a string is a malformed request, not a pin.
        let response = admin
            .handle(&admin_envelope(
                "req_r_bad",
                OP_APPROVALS_RESOLVE,
                serde_json::json!({
                    "request_id": "req_pinned",
                    "resolution": "approved",
                    "expected_digest": 7,
                }),
            ))
            .await;
        expect_refusal(response, CAUSE_INVALID_ADMIN_ARGS);
        assert!(!wait.is_finished());

        // The digest of the card that is actually pending resolves it.
        let response = admin
            .handle(&admin_envelope(
                "req_r_ok",
                OP_APPROVALS_RESOLVE,
                serde_json::json!({
                    "request_id": "req_pinned",
                    "resolution": "approved",
                    "expected_digest": step.digest,
                }),
            ))
            .await;
        expect_result(response, Outcome::Changed);
        assert_eq!(
            wait.await.unwrap().unwrap(),
            ApprovalOutcome::Approved { remember: false }
        );
        let (_, _, detail) =
            assert_admin_row(&store, "req_r_ok", RequestState::Done, ACTION_ADMIN).await;
        assert!(detail.unwrap().contains("\"pinned\":true"));
    })
    .await
    .unwrap();
}

/// A grant change and the audit row that explains it are one transaction
/// with the admin request's own terminal state: exactly one audit row, and
/// it is the admin op's.
#[tokio::test]
async fn a_grant_change_is_written_with_its_audit_row_and_terminal_state() {
    timeout(DEADLINE, async {
        let (store, admin, _events) = service().await;
        for (id, op) in [
            ("req_atomic_add", OP_GRANTS_ADD),
            ("req_atomic_revoke", OP_GRANTS_REVOKE),
        ] {
            let response = admin
                .handle(&admin_envelope(
                    id,
                    op,
                    serde_json::json!({ "capability": "deploy" }),
                ))
                .await;
            expect_result(response, Outcome::Changed);
            let (decision, actor, detail) =
                assert_admin_row(&store, id, RequestState::Done, ACTION_ADMIN).await;
            assert_eq!((decision, actor), (Decision::Allow, Actor::Human));
            assert!(detail.unwrap().contains("deploy"));
            assert_eq!(store.audit_for_request(id).await.unwrap().len(), 1);
        }
        assert!(!store.active_grant("deploy").await.unwrap());

        // A revoke with nothing to revoke changes nothing and is refused
        // through the ordinary path.
        let response = admin
            .handle(&admin_envelope(
                "req_atomic_none",
                OP_GRANTS_REVOKE,
                serde_json::json!({ "capability": "deploy" }),
            ))
            .await;
        expect_refusal(response, CAUSE_NO_ACTIVE_GRANT);
        assert_admin_row(
            &store,
            "req_atomic_none",
            RequestState::Refused,
            ACTION_ADMIN,
        )
        .await;
    })
    .await
    .unwrap();
}

/// An admin success whose terminal row the store will not take used to be
/// answered as a success with no audit row and no log line.
#[tokio::test]
async fn an_admin_success_that_cannot_be_recorded_is_refused_and_recorded_later() {
    timeout(DEADLINE, async {
        let (store, admin, _events) = service().await;
        admin.terminals.fail_next(3);
        let response = admin
            .handle(&admin_envelope(
                "req_unrecorded_admin",
                OP_GRANTS_LIST,
                serde_json::json!({}),
            ))
            .await;
        expect_refusal(response, crate::daemon::CAUSE_INTERNAL_ERROR);
        assert_eq!(
            store
                .get_request("req_unrecorded_admin")
                .await
                .unwrap()
                .unwrap()
                .state,
            RequestState::Running
        );

        // The daemon's maintenance loop does this on its tick.
        assert_eq!(admin.terminals.retry_parked().await, 1);
        assert_admin_row(
            &store,
            "req_unrecorded_admin",
            RequestState::Done,
            ACTION_ADMIN,
        )
        .await;
    })
    .await
    .unwrap();
}

/// A flow edited after the request started must not be described on the
/// old request's behalf: the card would show the new step's effect and
/// repository for a run that is executing the old definition.
#[tokio::test]
async fn approvals_pending_does_not_describe_a_flow_edited_after_the_request_started() {
    timeout(DEADLINE, async {
        let (store, admin, approvals, mut events) = service_with_approvals().await;
        let args = serde_json::json!({
            "id": "guarded-land",
            "inputs": {
                "repository": "https://github.test/team/repo.git",
                "commit": "a".repeat(40),
            },
        });
        store
            .insert_request(
                "req_edited",
                "flow.run",
                "/repo/a",
                "claude",
                &args.to_string(),
                None,
            )
            .await
            .unwrap();
        // The request's journal names the flow it is running — by a digest
        // that is not the one the library's flow has now.
        store
            .begin_flow_journal(
                &pam_store::FlowJournalIdentity {
                    request_id: "req_edited".to_owned(),
                    flow_digest: "0".repeat(64),
                    repository: "/repo/a".to_owned(),
                    input_fingerprint: "1".repeat(64),
                },
                "{}",
            )
            .await
            .unwrap();
        let (_cancel_tx, mut cancel_rx) = watch::channel(false);
        let waiting = Arc::clone(&approvals);
        let wait = tokio::spawn(async move {
            waiting
                .request_approval("req_edited", "flow.step:guarded-land/push", &mut cancel_rx)
                .await
        });
        let (_, event) = events.recv().await.expect("pending event");
        assert_eq!(event, Event::ApprovalPending);

        let response = admin
            .handle(&admin_envelope(
                "req_p_edited",
                OP_APPROVALS_PENDING,
                serde_json::json!({}),
            ))
            .await;
        let body = expect_result(response, Outcome::Verified);
        let entry = &body["pending"][0];
        assert_eq!(entry["request_id"], "req_edited");
        assert_eq!(entry["flow_edited"], true);
        // Nothing is read off the edited file: null, never a guess.
        assert_eq!(entry["repository"], serde_json::Value::Null);
        assert_eq!(entry["effect"], serde_json::Value::Null);
        // What the agent submitted is still shown as submitted.
        assert_eq!(entry["args"], args);

        approvals
            .resolve("req_edited", crate::approval::Resolution::Deny)
            .await
            .unwrap();
        wait.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}
