use crate::{
    Actor, AuditEntry, Decision, FlowJournalIdentity, FlowJournalState, RequestState, Store,
};

fn proof(operation: &str) -> serde_json::Value {
    serde_json::json!({"version":1,"flow_digest":"a".repeat(64),"repository":"/repo",
        "intent":{"step_id":"effect","operation":operation,"state":"prepared","remote_id":42}})
}

async fn prepared(store: &Store, id: &str, document: &str) {
    store
        .insert_admitted_request(id, "flow.run", "/repo", "test", "{}", None, 10_000)
        .await
        .unwrap();
    assert!(
        store
            .authorize_queued_request(id, "/repo", 0)
            .await
            .unwrap()
    );
    assert!(store.start_queued_request(id, 0).await.unwrap());
    store
        .begin_flow_journal(
            &FlowJournalIdentity {
                request_id: id.to_owned(),
                flow_digest: "a".repeat(64),
                repository: "/repo".to_owned(),
                input_fingerprint: "b".repeat(64),
            },
            r#"{"evidence_id":"snapshot","next_step":2}"#,
        )
        .await
        .unwrap();
    assert!(
        store
            .save_landing_session(id, None, document, 0)
            .await
            .unwrap()
    );
    assert!(
        store
            .prepare_flow_attempt(id, 0, "effect", 1, true)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn recovery_cas_preserves_original_intent_checkpoint_and_admission_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    {
        let store = Store::open(&path).await.unwrap();
        prepared(&store, "r", &proof("push").to_string()).await;
    }
    let store = Store::open(&path).await.unwrap();
    let before = store.read_flow_journal("r").await.unwrap().unwrap();
    let admission = store.get_request("r").await.unwrap().unwrap();
    let session = store.read_landing_session("r").await.unwrap().unwrap();
    assert!(
        !store
            .recover_landing_reconciliation("r", 0, 1)
            .await
            .unwrap()
    );
    assert!(
        store
            .recover_landing_reconciliation("r", 1, 1)
            .await
            .unwrap()
    );
    assert!(
        !store
            .recover_landing_reconciliation("r", 1, 1)
            .await
            .unwrap()
    );
    let after = store.read_flow_journal("r").await.unwrap().unwrap();
    assert_eq!(after.state, FlowJournalState::Ready);
    assert_eq!(after.revision, 2);
    assert!(after.effectful);
    assert_eq!(after.identity, before.identity);
    assert_eq!(after.attempt, before.attempt);
    assert_eq!(after.step_id, before.step_id);
    assert_eq!(after.checkpoint_json, before.checkpoint_json);
    assert_eq!(after.evidence_refs, before.evidence_refs);
    assert_eq!(
        store.read_landing_session("r").await.unwrap().unwrap(),
        session
    );
    assert!(store.requeue_journaled_flow("r", 1).await.unwrap());
    let resumed = store.get_request("r").await.unwrap().unwrap();
    assert_eq!(resumed.expires_at_ms, admission.expires_at_ms);
    assert_eq!(
        resumed.authorization_revision,
        admission.authorization_revision
    );
}

#[tokio::test]
async fn only_exact_private_prepared_landing_proof_allows_reconciliation() {
    for field in [
        "version",
        "flow_digest",
        "repository",
        "step_id",
        "operation",
        "state",
    ] {
        let store = Store::open_in_memory().await.unwrap();
        let mut document = proof("merge");
        match field {
            "version" => document[field] = serde_json::json!(2),
            "flow_digest" | "repository" => document[field] = serde_json::json!("other"),
            _ => document["intent"][field] = serde_json::json!("other"),
        }
        prepared(&store, "r", &document.to_string()).await;
        assert!(
            !store
                .recover_landing_reconciliation("r", 1, 1)
                .await
                .unwrap(),
            "{field}"
        );
        assert_eq!(
            store.read_flow_journal("r").await.unwrap().unwrap().state,
            FlowJournalState::Prepared
        );
    }
    for operation in ["push", "ensure_pr", "merge", "sync"] {
        let store = Store::open_in_memory().await.unwrap();
        prepared(&store, "r", &proof(operation).to_string()).await;
        assert!(
            store
                .recover_landing_reconciliation("r", 1, 1)
                .await
                .unwrap(),
            "{operation}"
        );
    }
}

#[tokio::test]
async fn original_expiry_revocation_and_terminal_state_cannot_be_refreshed() {
    for guard in ["expired", "revoked", "terminal"] {
        let store = Store::open_in_memory().await.unwrap();
        prepared(&store, "r", &proof("push").to_string()).await;
        if guard == "revoked" {
            store.insert_grant("flow.run").await.unwrap();
            store.revoke_grant("flow.run").await.unwrap();
            store.insert_grant("flow.run").await.unwrap();
        }
        if guard == "terminal" {
            store
                .finish_request("r", RequestState::Failed, Some("cancelled"), audit())
                .await
                .unwrap();
        }
        let now = if guard == "expired" { 10_000 } else { 1 };
        assert!(
            !store
                .recover_landing_reconciliation("r", 1, now)
                .await
                .unwrap(),
            "{guard}"
        );
        assert_eq!(
            store
                .read_landing_session("r")
                .await
                .unwrap()
                .unwrap()
                .revision,
            0
        );
    }
}

fn audit() -> AuditEntry<'static> {
    AuditEntry {
        action: "cancel",
        decision: Decision::Refuse,
        actor: Actor::System,
        detail: None,
    }
}

/// Requires the terminal choke point to recognize the retained prepared intent,
/// including cancellation/expiry in the gap between journal recovery and requeue.
#[tokio::test]
async fn recovered_ready_intent_remains_uncertain_on_terminal_failure() {
    for cause in ["cancelled", "deadline_exceeded"] {
        let store = Store::open_in_memory().await.unwrap();
        prepared(&store, "r", &proof("sync").to_string()).await;
        assert!(
            store
                .recover_landing_reconciliation("r", 1, 1)
                .await
                .unwrap()
        );
        assert!(
            store
                .finish_request("r", RequestState::Failed, Some(cause), audit())
                .await
                .unwrap()
        );
        let request = store.get_request("r").await.unwrap().unwrap();
        assert_eq!(request.outcome.as_deref(), Some("flow_effect_uncertain"));
        assert_eq!(
            store.read_flow_journal("r").await.unwrap().unwrap().state,
            FlowJournalState::Uncertain
        );
    }
}

#[tokio::test]
async fn session_documents_are_bounded_and_compare_and_swap_owned() {
    let store = Store::open_in_memory().await.unwrap();
    prepared(&store, "r", &proof("push").to_string()).await;
    assert!(
        !store
            .save_landing_session("r", None, "{}", 1)
            .await
            .unwrap()
    );
    assert!(
        !store
            .save_landing_session("r", Some(4), "{}", 1)
            .await
            .unwrap()
    );
    assert!(
        store
            .save_landing_session("r", Some(0), "{}", 1)
            .await
            .unwrap()
    );
    assert!(
        !store
            .recover_landing_reconciliation("r", 1, 1)
            .await
            .unwrap()
    );
    for bad in [
        "[]".to_owned(),
        "{".to_owned(),
        serde_json::json!({"x":"a".repeat(131_072)}).to_string(),
    ] {
        assert!(
            store
                .save_landing_session("r", Some(1), &bad, 1)
                .await
                .is_err()
        );
    }
    assert_eq!(
        store
            .read_landing_session("r")
            .await
            .unwrap()
            .unwrap()
            .document,
        "{}"
    );
}
