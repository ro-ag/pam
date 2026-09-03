use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use pam_proto::{Caller, Envelope, Outcome, PROTOCOL_VERSION, Response};
use pam_store::Store;
use serde_json::{Value, json};

use crate::admin::{
    ACTION_ADMIN, ADMIN_CALLER_AGENT, ADMIN_REPO, AdminService, CAUSE_INVALID_ADMIN_ARGS,
};
use crate::admin_retention::{
    OP_RETENTION_GET, OP_RETENTION_PRUNE, OP_RETENTION_SET, RETENTION_ADMIN_OPS,
};
use crate::approval::ApprovalService;
use crate::connector_service::ConnectorService;
use crate::daemon::TERMINAL_ACTIONS;
use crate::log_service::LogService;
use crate::model_service::ModelService;
use crate::retention::CAUSE_RETENTION_INVALID;
use crate::transport::EventPublisher;

/// Approval timeout long enough never to fire here.
const LONG_TIMEOUT: Duration = Duration::from_mins(10);

/// An admin service over an in-memory store; every op runs through the
/// whole service (row, tripwire, deadline, audit).
struct Fixture {
    store: Arc<Store>,
    admin: AdminService,
    next: AtomicU32,
}

async fn fixture() -> Fixture {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let (events, _rx) = EventPublisher::for_tests();
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
    Fixture {
        store,
        admin,
        next: AtomicU32::new(0),
    }
}

impl Fixture {
    /// One admin envelope from the GUI, with a fresh request id.
    fn envelope(&self, op: &str, args: Value) -> Envelope {
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        Envelope {
            v: PROTOCOL_VERSION,
            id: format!("req_retention_{index:03}"),
            capability: op.to_owned(),
            client_version: env!("CARGO_PKG_VERSION").to_owned(),
            caller: Caller {
                agent: ADMIN_CALLER_AGENT.to_owned(),
                repo: ADMIN_REPO.to_owned(),
                pid: 4242,
            },
            args,
            idempotency_key: None,
            deadline_ms: 15_000,
            wait: true,
        }
    }

    /// Every request the fixture ran carries exactly one terminal audit
    /// row, and its `admin` detail names the op.
    async fn assert_audited(&self, id: &str) {
        let rows = self.store.audit_for_request(id).await.unwrap();
        let terminal: Vec<&str> = rows
            .iter()
            .map(|row| row.action.as_str())
            .filter(|action| TERMINAL_ACTIONS.contains(action))
            .collect();
        assert_eq!(
            terminal.len(),
            1,
            "request {id} should have exactly one terminal audit row, got {terminal:?}"
        );
        assert!(
            rows.iter().any(|row| row.action == ACTION_ADMIN),
            "request {id} has an {ACTION_ADMIN} audit row"
        );
    }
}

/// Unwraps a result body, asserting the outcome.
fn body_of(response: Response, outcome: Outcome) -> Value {
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

/// The cause of a refusal, asserting a recovery line came with it.
fn cause_of(response: Response) -> String {
    match response {
        Response::Refusal {
            cause, recovery, ..
        } => {
            assert!(!recovery.is_empty(), "a refusal carries a recovery line");
            cause
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn the_bridge_whitelist_names_every_op_once() {
    let mut sorted = RETENTION_ADMIN_OPS.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), RETENTION_ADMIN_OPS.len());
    assert_eq!(RETENTION_ADMIN_OPS.len(), 3);
    for op in RETENTION_ADMIN_OPS {
        assert!(op.starts_with("admin.retention."), "{op} is misnamed");
    }
}

#[tokio::test]
async fn get_on_a_fresh_store_is_forever_and_never_pruned() {
    let f = fixture().await;
    let envelope = f.envelope(OP_RETENTION_GET, json!({}));
    let body = body_of(f.admin.handle(&envelope).await, Outcome::Verified);
    assert_eq!(
        body,
        json!({ "evidence_days": null, "audit_days": null, "last_run": null })
    );
    f.assert_audited(&envelope.id).await;
}

#[tokio::test]
async fn set_persists_prunes_at_once_and_round_trips() {
    let f = fixture().await;
    let body = body_of(
        f.admin
            .handle(&f.envelope(
                OP_RETENTION_SET,
                json!({ "audit_days": 365, "evidence_days": 90 }),
            ))
            .await,
        Outcome::Changed,
    );
    assert_eq!(body["evidence_days"], 90);
    assert_eq!(body["audit_days"], 365);
    assert!(body["last_run"]["ts"].is_i64(), "a save prunes at once");

    let body = body_of(
        f.admin
            .handle(&f.envelope(OP_RETENTION_GET, json!({})))
            .await,
        Outcome::Verified,
    );
    assert_eq!(body["evidence_days"], 90);

    // `null` clears one window; the other is untouched.
    let body = body_of(
        f.admin
            .handle(&f.envelope(OP_RETENTION_SET, json!({ "evidence_days": null })))
            .await,
        Outcome::Changed,
    );
    assert_eq!(
        body,
        json!({ "evidence_days": null, "audit_days": 365, "last_run": body["last_run"] })
    );
}

#[tokio::test]
async fn set_refuses_the_order_violation_and_bad_args() {
    let f = fixture().await;
    f.admin
        .handle(&f.envelope(OP_RETENTION_SET, json!({ "audit_days": 90 })))
        .await;
    assert_eq!(
        cause_of(
            f.admin
                .handle(&f.envelope(OP_RETENTION_SET, json!({ "evidence_days": 365 })))
                .await
        ),
        CAUSE_RETENTION_INVALID
    );
    assert_eq!(
        cause_of(
            f.admin
                .handle(&f.envelope(OP_RETENTION_SET, json!({ "evidence_days": "soon" })))
                .await
        ),
        CAUSE_INVALID_ADMIN_ARGS
    );
    assert_eq!(
        cause_of(
            f.admin
                .handle(&f.envelope(OP_RETENTION_SET, json!({ "evidence_days": -1 })))
                .await
        ),
        CAUSE_INVALID_ADMIN_ARGS
    );
}

#[tokio::test]
async fn prune_answers_a_report_and_every_op_leaves_one_audit_row() {
    let f = fixture().await;
    let envelope = f.envelope(OP_RETENTION_PRUNE, json!({}));
    let body = body_of(f.admin.handle(&envelope).await, Outcome::Verified);
    assert_eq!(body["requests"], 0);
    assert_eq!(body["evidence_rows"], 0);
    assert!(body["ts"].is_i64());
    f.assert_audited(&envelope.id).await;
    assert!(
        f.store
            .terminal_requests_missing_audit(TERMINAL_ACTIONS)
            .await
            .unwrap()
            .is_empty()
    );
}
