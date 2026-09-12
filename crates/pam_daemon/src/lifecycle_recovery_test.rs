//! Restart decisions exercise durable rows across an actual store close/reopen.
use std::time::{SystemTime, UNIX_EPOCH};

use pam_store::{
    ApprovalResolution, FlowJournalIdentity, FlowJournalState, RequestBudgetCharge, RequestState,
    Store,
};

use crate::lifecycle::recover_stuck_rows;

const REPO: &str = "/recovery-fixture";
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn future_expiry() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
        + 3_600_000
}

async fn admitted(store: &Store, id: &str, expiry: i64) {
    store
        .insert_admitted_request(id, "flow.run", REPO, "test", "{}", None, expiry)
        .await
        .unwrap();
    // Explicit time zero permits constructing a deterministically expired durable row.
    assert!(store.authorize_queued_request(id, REPO, 0).await.unwrap());
    assert!(store.start_queued_request(id, 0).await.unwrap());
    store
        .begin_flow_journal(
            &FlowJournalIdentity {
                request_id: id.to_owned(),
                flow_digest: DIGEST.to_owned(),
                repository: REPO.to_owned(),
                input_fingerprint: DIGEST.to_owned(),
            },
            "{}",
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn prepared_read_requeues_with_original_admission_and_spent_budget() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    let expiry = future_expiry();
    let original_revision;
    {
        let store = Store::open(&path).await.unwrap();
        admitted(&store, "read", expiry).await;
        original_revision = store
            .get_request("read")
            .await
            .unwrap()
            .unwrap()
            .authorization_revision;
        store.load_request_budget("read").await.unwrap();
        store
            .reserve_request_budget("read", RequestBudgetCharge::Http(1234))
            .await
            .unwrap()
            .unwrap();
        assert!(
            store
                .prepare_flow_attempt("read", 0, "inspect", 1, false)
                .await
                .unwrap()
        );
    }
    let store = Store::open(&path).await.unwrap();
    assert_eq!(recover_stuck_rows(&store).await.unwrap(), 1);
    let row = store.get_request("read").await.unwrap().unwrap();
    assert_eq!(row.state, RequestState::Queued);
    assert_eq!(row.expires_at_ms, Some(expiry));
    assert_eq!(row.authorization_revision, original_revision);
    assert!(row.queue_authorized);
    let journal = store.read_flow_journal("read").await.unwrap().unwrap();
    assert_eq!(journal.state, FlowJournalState::Ready);
    assert_eq!(journal.revision, 2);
    let budget = store.load_request_budget("read").await.unwrap();
    assert_eq!(budget.http_bytes, 1234);
    assert_eq!(budget.http_calls, 1);
    assert_eq!(recover_stuck_rows(&store).await.unwrap(), 0);
}

#[tokio::test]
async fn prepared_effect_is_uncertain_across_two_restarts_never_automatically_requeued() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    {
        let store = Store::open(&path).await.unwrap();
        admitted(&store, "effect", future_expiry()).await;
        assert!(
            store
                .prepare_flow_attempt("effect", 0, "publish", 1, true)
                .await
                .unwrap()
        );
    }
    {
        let store = Store::open(&path).await.unwrap();
        assert_eq!(recover_stuck_rows(&store).await.unwrap(), 1);
        let row = store.get_request("effect").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed);
        assert_eq!(row.outcome.as_deref(), Some("flow_effect_uncertain"));
        assert_eq!(
            store
                .read_flow_journal("effect")
                .await
                .unwrap()
                .unwrap()
                .state,
            FlowJournalState::Uncertain
        );
    }
    let store = Store::open(&path).await.unwrap();
    assert_eq!(recover_stuck_rows(&store).await.unwrap(), 0);
    assert_eq!(
        store.get_request("effect").await.unwrap().unwrap().state,
        RequestState::Failed
    );
    assert_eq!(store.audit_for_request("effect").await.unwrap().len(), 1);
}

#[tokio::test]
async fn ready_and_completed_journals_resume_only_with_original_live_authorization() {
    for completed in [false, true] {
        for guard in ["valid", "expired", "revoked"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("state.db");
            let expiry = if guard == "expired" {
                1
            } else {
                future_expiry()
            };
            {
                let store = Store::open(&path).await.unwrap();
                admitted(&store, "guard", expiry).await;
                if completed {
                    assert!(
                        store
                            .prepare_flow_attempt("guard", 0, "read", 1, false)
                            .await
                            .unwrap()
                    );
                    assert!(
                        store
                            .settle_flow_attempt("guard", 1, "{}", &[], true)
                            .await
                            .unwrap()
                    );
                }
                if guard == "revoked" {
                    store.insert_grant("flow.run").await.unwrap();
                    store.revoke_grant("flow.run").await.unwrap();
                }
            }
            let store = Store::open(&path).await.unwrap();
            assert_eq!(recover_stuck_rows(&store).await.unwrap(), 1);
            let row = store.get_request("guard").await.unwrap().unwrap();
            assert_eq!(
                row.state,
                if guard == "valid" {
                    RequestState::Queued
                } else {
                    RequestState::Failed
                },
                "completed={completed} guard={guard}"
            );
            assert_eq!(row.expires_at_ms, Some(expiry));
        }
    }
}

#[tokio::test]
async fn waiting_approval_is_expired_before_requeue_and_legacy_work_stays_failed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    {
        let store = Store::open(&path).await.unwrap();
        admitted(&store, "waiting", future_expiry()).await;
        store
            .update_request_state("waiting", RequestState::WaitingApproval, None)
            .await
            .unwrap();
        store.insert_approval("waiting", "flow.run").await.unwrap();
        store
            .insert_running_request("legacy", "flow.run", REPO, "test", "{}", None)
            .await
            .unwrap();
    }
    let store = Store::open(&path).await.unwrap();
    assert_eq!(recover_stuck_rows(&store).await.unwrap(), 2);
    assert_eq!(
        store.get_request("waiting").await.unwrap().unwrap().state,
        RequestState::Queued
    );
    assert_eq!(
        store
            .approval_for_request("waiting")
            .await
            .unwrap()
            .unwrap()
            .resolution,
        Some(ApprovalResolution::Timeout)
    );
    assert!(store.list_pending_approvals().await.unwrap().is_empty());
    let legacy = store.get_request("legacy").await.unwrap().unwrap();
    assert_eq!(legacy.state, RequestState::Failed);
    assert_eq!(legacy.outcome.as_deref(), Some("daemon_restart"));
}

async fn landing_intent(store: &Store, id: &str, expiry: i64) {
    landing_intent_for(store, id, expiry, "push").await;
}
async fn landing_intent_for(store: &Store, id: &str, expiry: i64, operation: &str) {
    admitted(store, id, expiry).await;
    let document = serde_json::json!({
        "version":1,"flow_digest":DIGEST,"repository":REPO,
        "intent":{"step_id":operation,"operation":operation,"state":"prepared"},
        "frozen":{"commit":"c".repeat(40)}
    })
    .to_string();
    assert!(
        store
            .save_landing_session(id, None, &document, 0)
            .await
            .unwrap()
    );
    assert!(
        store
            .prepare_flow_attempt(id, 0, operation, 1, true)
            .await
            .unwrap()
    );
}

/// A prepared sync intent survives a daemon restart exactly like push and
/// merge: the original ticket requeues for read-only reconciliation, the
/// journal stays effectful on the sync step, and nothing is replayed here.
#[tokio::test]
async fn prepared_sync_intent_requeues_the_original_ticket_for_reconciliation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    let expiry = future_expiry();
    {
        let store = Store::open(&path).await.unwrap();
        landing_intent_for(&store, "landing", expiry, "sync").await;
    }
    let store = Store::open(&path).await.unwrap();
    let session = store
        .read_landing_session("landing")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recover_stuck_rows(&store).await.unwrap(), 1);
    let landing = store.get_request("landing").await.unwrap().unwrap();
    assert_eq!(landing.state, RequestState::Queued);
    assert_eq!(landing.expires_at_ms, Some(expiry));
    assert_eq!(
        store
            .read_landing_session("landing")
            .await
            .unwrap()
            .unwrap(),
        session,
        "the journalled sync lease is untouched by recovery"
    );
    let journal = store.read_flow_journal("landing").await.unwrap().unwrap();
    assert_eq!(journal.state, FlowJournalState::Ready);
    assert!(journal.effectful);
    assert_eq!(journal.step_id.as_deref(), Some("sync"));
}

#[tokio::test]
async fn typed_landing_requeues_original_ticket_for_reconciliation_but_generic_write_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    let expiry = future_expiry();
    {
        let store = Store::open(&path).await.unwrap();
        landing_intent(&store, "landing", expiry).await;
        admitted(&store, "ordinary", expiry).await;
        assert!(
            store
                .prepare_flow_attempt("ordinary", 0, "push", 1, true)
                .await
                .unwrap()
        );
        store.load_request_budget("landing").await.unwrap();
        store
            .reserve_request_budget("landing", RequestBudgetCharge::Http(123))
            .await
            .unwrap()
            .unwrap();
    }
    let store = Store::open(&path).await.unwrap();
    let session = store
        .read_landing_session("landing")
        .await
        .unwrap()
        .unwrap();
    let before = store.get_request("landing").await.unwrap().unwrap();
    assert_eq!(recover_stuck_rows(&store).await.unwrap(), 2);
    let landing = store.get_request("landing").await.unwrap().unwrap();
    assert_eq!(landing.state, RequestState::Queued);
    assert_eq!(landing.expires_at_ms, Some(expiry));
    assert_eq!(
        landing.authorization_revision,
        before.authorization_revision
    );
    assert_eq!(
        store
            .read_landing_session("landing")
            .await
            .unwrap()
            .unwrap(),
        session
    );
    let journal = store.read_flow_journal("landing").await.unwrap().unwrap();
    assert_eq!(journal.state, FlowJournalState::Ready);
    assert!(journal.effectful);
    assert_eq!(journal.step_id.as_deref(), Some("push"));
    assert_eq!(
        store
            .load_request_budget("landing")
            .await
            .unwrap()
            .http_bytes,
        123
    );
    assert_eq!(
        store
            .get_request("ordinary")
            .await
            .unwrap()
            .unwrap()
            .outcome
            .as_deref(),
        Some("flow_effect_uncertain")
    );
    assert_eq!(recover_stuck_rows(&store).await.unwrap(), 0);
}

#[tokio::test]
async fn expired_revoked_or_mismatched_landing_intent_stays_terminal_uncertain() {
    for guard in ["expired", "revoked", "wrong_step"] {
        let store = Store::open_in_memory().await.unwrap();
        let expiry = if guard == "expired" {
            1
        } else {
            future_expiry()
        };
        landing_intent(&store, "landing", expiry).await;
        if guard == "revoked" {
            store.insert_grant("flow.run").await.unwrap();
            store.revoke_grant("flow.run").await.unwrap();
        }
        if guard == "wrong_step" {
            let mut document: serde_json::Value = serde_json::from_str(
                &store
                    .read_landing_session("landing")
                    .await
                    .unwrap()
                    .unwrap()
                    .document,
            )
            .unwrap();
            document["intent"]["step_id"] = serde_json::json!("other");
            assert!(
                store
                    .save_landing_session("landing", Some(0), &document.to_string(), 0)
                    .await
                    .unwrap()
            );
        }
        assert_eq!(recover_stuck_rows(&store).await.unwrap(), 1, "{guard}");
        let row = store.get_request("landing").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed, "{guard}");
        assert_eq!(
            row.outcome.as_deref(),
            Some("flow_effect_uncertain"),
            "{guard}"
        );
        assert_eq!(
            store
                .read_flow_journal("landing")
                .await
                .unwrap()
                .unwrap()
                .state,
            FlowJournalState::Uncertain
        );
    }
}
