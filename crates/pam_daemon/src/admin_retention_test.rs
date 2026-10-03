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
    policy: Arc<crate::managed_policy_service::PolicyHandle>,
    admin: AdminService,
    next: AtomicU32,
}

async fn fixture() -> Fixture {
    fixture_with(None).await
}

/// The same, with the managed policy file `policy` (a trusted, scripted one)
/// read by the daemon's services.
async fn fixture_with(policy: Option<&str>) -> Fixture {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let policy = match policy {
        Some(text) => {
            crate::managed_policy_service::PolicyHandle::load(
                Arc::clone(&store),
                Arc::new(crate::daemon_test::ScriptedPolicy::new(Some(text))),
                std::path::Path::new("pam-tests-have-no-base"),
            )
            .await
        }
        None => crate::managed_policy_service::PolicyHandle::none(),
    };
    let (events, _rx) = EventPublisher::for_tests();
    let approvals = Arc::new(ApprovalService::new(
        Arc::clone(&store),
        events,
        LONG_TIMEOUT,
        Arc::clone(&policy),
    ));
    let models = ModelService::new(Arc::clone(&store), Arc::clone(&policy))
        .await
        .unwrap();
    let logs = LogService::new(Arc::clone(&store), Arc::clone(&models));
    let connectors = Arc::new(ConnectorService::from_parts(
        Arc::clone(&store),
        None,
        None,
        Arc::clone(&policy),
    ));
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
        Arc::clone(&policy),
    );
    Fixture {
        store,
        policy,
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
        json!({
            "evidence_days": null,
            "audit_days": null,
            "effective": {
                "evidence_days": { "source": "default", "locked": false },
                "audit_days": { "source": "default", "locked": false },
            },
            "last_run": null,
            "clock_guard": null
        })
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
        json!({
            "evidence_days": null,
            "audit_days": 365,
            "effective": {
                "evidence_days": { "source": "user", "locked": false },
                "audit_days": { "source": "user", "locked": false },
            },
            "last_run": body["last_run"],
            "clock_guard": null
        })
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
    assert_eq!(body["clock_guard_overridden"], false);
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

/// A finished request for the pass to look at.
async fn old_finished_request(f: &Fixture, id: &str) {
    f.store
        .insert_request(id, "release", "ro-ag/pam", "claude", "{}", None)
        .await
        .unwrap();
    f.store
        .finish_request(
            id,
            pam_store::RequestState::Done,
            None,
            pam_store::AuditEntry {
                action: "execute",
                decision: pam_store::Decision::Allow,
                actor: pam_store::Actor::System,
                detail: None,
            },
        )
        .await
        .unwrap();
}

/// How far the staged clock jumps.
const JUMP_SECS: i64 = 100 * 86_400;

#[tokio::test]
async fn a_forward_jump_surfaces_in_the_status_and_manual_prune_confirms_it() {
    let f = fixture().await;
    // Sixty finished requests and a 30-day audit window, saved on time: the
    // save's own pass runs, removes nothing and sets the watermark.
    for index in 0..60 {
        old_finished_request(&f, &format!("victim_{index}")).await;
    }
    let body = body_of(
        f.admin
            .handle(&f.envelope(OP_RETENTION_SET, json!({ "audit_days": 30 })))
            .await,
        Outcome::Changed,
    );
    assert!(body["clock_guard"].is_null(), "{body}");
    assert_eq!(body["last_run"]["requests"], 0, "{body}");
    let on_time = body["last_run"].clone();

    // The clock jumps 100 days: every record now looks older than the
    // window. A settings save prunes at once but is not a decision about
    // the clock: the pass is held back, and the reply says why, how much
    // it would have removed (the store's own count), and how to recover.
    f.admin
        .retention_clock_ahead
        .store(JUMP_SECS, std::sync::atomic::Ordering::SeqCst);
    let body = body_of(
        f.admin
            .handle(&f.envelope(OP_RETENTION_SET, json!({ "audit_days": 30 })))
            .await,
        Outcome::Changed,
    );
    assert_eq!(body["clock_guard"]["cause"], "retention_clock_jump");
    assert!(
        body["clock_guard"]["recovery"]
            .as_str()
            .unwrap()
            .contains("run retention manually from Settings"),
        "{body}"
    );
    let eligible = body["clock_guard"]["eligible_rows"]
        .as_u64()
        .expect("counted");
    let total = body["clock_guard"]["total_rows"].as_u64().expect("counted");
    assert!(
        (60..=total).contains(&eligible),
        "the sixty records and the earlier admin rows: {body}"
    );
    assert_eq!(body["last_run"], on_time, "no pass completed: {body}");
    assert!(f.store.get_request("victim_0").await.unwrap().is_some());

    // The status reply keeps saying so until a pass completes.
    let body = body_of(
        f.admin
            .handle(&f.envelope(OP_RETENTION_GET, json!({})))
            .await,
        Outcome::Verified,
    );
    assert_eq!(body["clock_guard"]["cause"], "retention_clock_jump");
    assert!(body["clock_guard"]["jump_secs"].as_i64().unwrap() >= 99 * 86_400);

    // Prune now is the human's confirmation: it proceeds, says it overrode
    // the guard (in the reply and in its one audit row), removes what was
    // held back, and the notice goes.
    let envelope = f.envelope(OP_RETENTION_PRUNE, json!({}));
    let body = body_of(f.admin.handle(&envelope).await, Outcome::Changed);
    assert_eq!(body["clock_guard_overridden"], true);
    assert!(body["ts"].is_i64());
    assert!(body["requests"].as_u64().unwrap() >= 60, "{body}");
    assert!(f.store.get_request("victim_0").await.unwrap().is_none());
    f.assert_audited(&envelope.id).await;
    let audit = f.store.audit_for_request(&envelope.id).await.unwrap();
    assert!(
        audit.iter().any(|row| row
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("\"clock_guard_overridden\":true"))),
        "{audit:?}"
    );
    let body = body_of(
        f.admin
            .handle(&f.envelope(OP_RETENTION_GET, json!({})))
            .await,
        Outcome::Verified,
    );
    assert!(body["clock_guard"].is_null());
}

/// A forward jump over a store the pass would barely touch asks nobody: the
/// daemon counts, finds one old record, and runs.
#[tokio::test]
async fn a_forward_jump_that_would_remove_little_is_not_held_back() {
    let f = fixture().await;
    old_finished_request(&f, "lonely").await;
    body_of(
        f.admin
            .handle(&f.envelope(OP_RETENTION_SET, json!({ "audit_days": 30 })))
            .await,
        Outcome::Changed,
    );
    f.admin
        .retention_clock_ahead
        .store(JUMP_SECS, std::sync::atomic::Ordering::SeqCst);
    let body = body_of(
        f.admin
            .handle(&f.envelope(OP_RETENTION_SET, json!({ "audit_days": 30 })))
            .await,
        Outcome::Changed,
    );
    assert!(body["clock_guard"].is_null(), "{body}");
    assert!(
        body["last_run"]["requests"].as_u64().unwrap() >= 1,
        "{body}"
    );
    assert!(f.store.get_request("lonely").await.unwrap().is_none());
}

// ---- the managed policy -------------------------------------------------

const CEILING: &str = r#"{
    "version": 1, "revision": "r9", "contact": "it@example.test",
    "retention": { "evidence_days": { "max": 30 }, "audit_days": { "max": 90 } }
}"#;

impl Fixture {
    /// The op's request carries the terminal `admin`/`refuse` row and the
    /// policy's `policy.locked_write` row, whose detail names the op, the
    /// key, the cause and the full digest of the policy that refused.
    async fn assert_refused_by_policy(&self, id: &str, op: &str, cause: &str, key: &str) {
        let rows = self.store.audit_for_request(id).await.unwrap();
        assert!(
            rows.iter().any(
                |row| row.action == ACTION_ADMIN && row.decision == pam_store::Decision::Refuse
            ),
            "{rows:?}"
        );
        let row = rows
            .iter()
            .find(|row| row.action == "policy.locked_write")
            .unwrap_or_else(|| panic!("no policy.locked_write row in {rows:?}"));
        assert_eq!(row.decision, pam_store::Decision::Refuse);
        assert_eq!(row.actor, pam_store::Actor::Policy);
        let detail: Value = serde_json::from_str(row.detail.as_deref().unwrap()).unwrap();
        assert_eq!(detail["op"], op);
        assert_eq!(detail["cause"], cause);
        assert_eq!(detail["keys"], json!([key]));
        assert_eq!(detail["revision"], "r9");
        let digest = detail["digest"].as_str().unwrap();
        assert_eq!(digest.len(), 64);
        assert_eq!(Some(digest), self.policy.view().digest());
    }
}

#[tokio::test]
async fn get_reports_the_windows_in_force_and_where_they_came_from() {
    let f = fixture_with(Some(CEILING)).await;
    let body = body_of(
        f.admin
            .handle(&f.envelope(OP_RETENTION_GET, json!({})))
            .await,
        Outcome::Verified,
    );
    // Nothing stored reads as forever, which the ceiling turns into the ceiling.
    assert_eq!(body["evidence_days"], 30);
    assert_eq!(body["audit_days"], 90);
    assert_eq!(body["effective"]["audit_days"]["source"], "policy");
    assert_eq!(body["effective"]["audit_days"]["locked"], false);
    assert_eq!(body["effective"]["audit_days"]["clamped"], true);
    assert_eq!(
        body["effective"]["audit_days"]["constraint"],
        json!({ "max": 90 })
    );
    assert_eq!(body["effective"]["audit_days"]["state"], "applied");
}

#[tokio::test]
async fn set_refuses_forever_under_a_ceiling_and_audits_the_refusal() {
    let f = fixture_with(Some(CEILING)).await;
    f.store
        .set_setting("retention.audit_days", "60")
        .await
        .unwrap();
    let envelope = f.envelope(OP_RETENTION_SET, json!({ "audit_days": null }));
    match f.admin.handle(&envelope).await {
        Response::Refusal {
            cause,
            detail,
            recovery,
            ..
        } => {
            assert_eq!(cause, "policy_not_allowed");
            assert!(detail.contains("retention.audit_days"), "{detail}");
            assert!(detail.contains("it@example.test"), "{detail}");
            assert!(detail.contains("rev r9"), "{detail}");
            assert_eq!(recovery, crate::managed_policy::RECOVERY_MANAGED);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    f.assert_refused_by_policy(
        &envelope.id,
        OP_RETENTION_SET,
        "policy_not_allowed",
        "retention.audit_days",
    )
    .await;
    // The row is byte-identical and no pass ran.
    assert_eq!(
        f.store
            .get_setting("retention.audit_days")
            .await
            .unwrap()
            .as_deref(),
        Some("60")
    );
    assert_eq!(
        f.store.get_setting("retention.last_run").await.unwrap(),
        None
    );

    // Inside the bounds the save goes through.
    let body = body_of(
        f.admin
            .handle(&f.envelope(
                OP_RETENTION_SET,
                json!({ "audit_days": 45, "evidence_days": 20 }),
            ))
            .await,
        Outcome::Changed,
    );
    assert_eq!(body["audit_days"], 45);
    assert_eq!(body["evidence_days"], 20);
}

#[tokio::test]
async fn set_refuses_a_locked_window_with_setting_locked() {
    let f = fixture_with(Some(
        r#"{ "version": 1, "revision": "r9",
             "retention": { "audit_days": { "locked": 365 } } }"#,
    ))
    .await;
    let envelope = f.envelope(OP_RETENTION_SET, json!({ "audit_days": 400 }));
    assert_eq!(cause_of(f.admin.handle(&envelope).await), "setting_locked");
    f.assert_refused_by_policy(
        &envelope.id,
        OP_RETENTION_SET,
        "setting_locked",
        "retention.audit_days",
    )
    .await;
    assert_eq!(
        f.store.get_setting("retention.audit_days").await.unwrap(),
        None
    );
    // The locked value is what get answers, and it is read-only for the GUI.
    let body = body_of(
        f.admin
            .handle(&f.envelope(OP_RETENTION_GET, json!({})))
            .await,
        Outcome::Verified,
    );
    assert_eq!(body["audit_days"], 365);
    assert_eq!(body["effective"]["audit_days"]["locked"], true);
}
