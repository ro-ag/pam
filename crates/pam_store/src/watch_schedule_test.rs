use crate::{FlowJournalIdentity, RequestState, Store};

async fn running(store: &Store, id: &str) {
    store
        .insert_admitted_request(id, "flow.run", "/repo", "test", "{}", None, 10_000)
        .await
        .unwrap();
    assert!(
        store
            .authorize_queued_request(id, "/repo", 1000)
            .await
            .unwrap()
    );
    assert!(store.start_queued_request(id, 1000).await.unwrap());
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

#[tokio::test]
async fn parking_preserves_admission_and_never_dispatches_before_due() {
    let store = Store::open_in_memory().await.unwrap();
    running(&store, "r").await;
    let before = store.get_request("r").await.unwrap().unwrap();
    assert!(!store.park_flow_request("r", 1000, 1000).await.unwrap());
    assert!(!store.park_flow_request("r", 10_001, 1000).await.unwrap());
    assert!(store.park_flow_request("r", 5000, 1000).await.unwrap());
    let parked = store.get_request("r").await.unwrap().unwrap();
    assert_eq!(parked.state, RequestState::Queued);
    assert_eq!(parked.resume_at_ms, Some(5000));
    assert_eq!(parked.expires_at_ms, before.expires_at_ms);
    assert_eq!(parked.authorization_revision, before.authorization_revision);
    assert_eq!(store.admission_usage().await.unwrap().0, 1);
    assert!(!store.start_queued_request("r", 4999).await.unwrap());
    assert!(!store.wake_parked_flow_request("r", 4999).await.unwrap());
    assert!(store.wake_parked_flow_request("r", 5000).await.unwrap());
    assert!(!store.wake_parked_flow_request("r", 5000).await.unwrap());
    assert!(store.start_queued_request("r", 5000).await.unwrap());
    let resumed = store.get_request("r").await.unwrap().unwrap();
    assert_eq!(resumed.resume_at_ms, None);
    assert_eq!(resumed.expires_at_ms, before.expires_at_ms);
}

#[tokio::test]
async fn prepared_or_uncertain_effect_cannot_park() {
    let store = Store::open_in_memory().await.unwrap();
    running(&store, "r").await;
    assert!(
        store
            .prepare_flow_attempt("r", 0, "effect", 1, true)
            .await
            .unwrap()
    );
    assert!(!store.park_flow_request("r", 5000, 1000).await.unwrap());
    assert!(store.mark_flow_uncertain("r", 1).await.unwrap());
    assert!(!store.park_flow_request("r", 5000, 1000).await.unwrap());
    assert_eq!(
        store.get_request("r").await.unwrap().unwrap().state,
        RequestState::Running
    );
}

#[tokio::test]
async fn revocation_and_original_expiry_prevent_resume() {
    let store = Store::open_in_memory().await.unwrap();
    running(&store, "expired").await;
    running(&store, "revoked").await;
    assert!(
        store
            .park_flow_request("expired", 5000, 1000)
            .await
            .unwrap()
    );
    assert!(
        store
            .park_flow_request("revoked", 5000, 1000)
            .await
            .unwrap()
    );
    assert!(
        !store
            .wake_parked_flow_request("expired", 10_000)
            .await
            .unwrap()
    );
    store.insert_grant("flow.run").await.unwrap();
    store.revoke_grant("flow.run").await.unwrap();
    store.insert_grant("flow.run").await.unwrap();
    assert!(
        !store
            .wake_parked_flow_request("revoked", 5000)
            .await
            .unwrap()
    );
    assert!(!store.start_queued_request("revoked", 5000).await.unwrap());
}
