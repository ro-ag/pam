use crate::{
    Actor, AuditEntry, Decision, FlowJournalIdentity, FlowJournalState, RequestState, Store,
};

async fn prepared(store: &Store, id: &str, effectful: bool) {
    store
        .insert_request(id, "flow.run", "/repo", "test", "{}", None)
        .await
        .unwrap();
    store
        .update_request_state(id, RequestState::Running, None)
        .await
        .unwrap();
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
    assert!(
        store
            .prepare_flow_attempt(id, 0, "step", 1, effectful)
            .await
            .unwrap()
    );
}

fn audit() -> AuditEntry<'static> {
    AuditEntry {
        action: "execute",
        decision: Decision::Allow,
        actor: Actor::System,
        detail: Some(r#"{"original":true}"#),
    }
}

#[tokio::test]
async fn every_terminal_outcome_preserves_unsettled_effect_uncertainty() {
    let store = Store::open_in_memory().await.unwrap();
    for (id, state, cause) in [
        ("cancel", RequestState::Failed, "cancelled"),
        ("done", RequestState::Done, "verified"),
        ("refused", RequestState::Refused, "deadline_exceeded"),
    ] {
        prepared(&store, id, true).await;
        assert!(
            store
                .finish_request(id, state, Some(cause), audit())
                .await
                .unwrap()
        );
        let request = store.get_request(id).await.unwrap().unwrap();
        assert_eq!(request.state, RequestState::Failed);
        assert_eq!(request.outcome.as_deref(), Some("flow_effect_uncertain"));
        let journal = store.read_flow_journal(id).await.unwrap().unwrap();
        assert_eq!(journal.state, FlowJournalState::Uncertain);
        assert_eq!(journal.revision, 2);
        let rows = store.audit_for_request(id).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "execute");
        assert_eq!(rows[0].actor, Actor::System);
        assert_eq!(rows[0].decision, Decision::Refuse);
        let detail: serde_json::Value =
            serde_json::from_str(rows[0].detail.as_deref().unwrap()).unwrap();
        assert_eq!(detail["cause"], "flow_effect_uncertain");
        assert_eq!(detail["requested_cause"], cause);
        assert_eq!(detail["requested_state"], state.as_str());
        assert_eq!(detail["requested_decision"], "allow");
        assert_eq!(detail["requested_detail"], r#"{"original":true}"#);
        assert_eq!(detail["reconciliation_required"], true);
        assert!(
            !store
                .finish_request(id, RequestState::Done, Some("late_success"), audit())
                .await
                .unwrap()
        );
        assert_eq!(store.read_flow_journal(id).await.unwrap().unwrap(), journal);
        assert_eq!(store.audit_for_request(id).await.unwrap(), rows);
        assert_eq!(store.get_request(id).await.unwrap().unwrap(), request);
        assert!(
            !store
                .settle_flow_attempt(id, 1, "{}", &[], true)
                .await
                .unwrap()
        );
    }
}

#[tokio::test]
async fn already_uncertain_effect_forces_failure_without_advancing_revision() {
    let store = Store::open_in_memory().await.unwrap();
    prepared(&store, "r", true).await;
    assert!(store.mark_flow_uncertain("r", 1).await.unwrap());
    assert!(
        store
            .finish_request("r", RequestState::Done, None, audit())
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .get_request("r")
            .await
            .unwrap()
            .unwrap()
            .outcome
            .as_deref(),
        Some("flow_effect_uncertain")
    );
    assert_eq!(
        store
            .read_flow_journal("r")
            .await
            .unwrap()
            .unwrap()
            .revision,
        2
    );
}

#[tokio::test]
async fn prepared_read_keeps_requested_terminal_outcome_and_audit() {
    let store = Store::open_in_memory().await.unwrap();
    prepared(&store, "read", false).await;
    assert!(
        store
            .finish_request("read", RequestState::Refused, Some("cancelled"), audit())
            .await
            .unwrap()
    );
    let request = store.get_request("read").await.unwrap().unwrap();
    assert_eq!(request.state, RequestState::Refused);
    assert_eq!(request.outcome.as_deref(), Some("cancelled"));
    let journal = store.read_flow_journal("read").await.unwrap().unwrap();
    assert_eq!(journal.state, FlowJournalState::Prepared);
    assert_eq!(journal.revision, 1);
    let rows = store.audit_for_request("read").await.unwrap();
    assert_eq!(rows[0].decision, Decision::Allow);
    assert_eq!(rows[0].detail.as_deref(), audit().detail);
}
