use crate::{FlowJournalBegin, FlowJournalIdentity, FlowJournalState, Store};

fn identity(id: &str) -> FlowJournalIdentity {
    FlowJournalIdentity {
        request_id: id.to_owned(),
        flow_digest: "a".repeat(64),
        repository: "/repo".to_owned(),
        input_fingerprint: "b".repeat(64),
    }
}

async fn seed(store: &Store, id: &str) {
    store
        .insert_request(id, "flow.run", "/repo", "test", "{}", None)
        .await
        .unwrap();
    assert_eq!(
        store
            .begin_flow_journal(&identity(id), r#"{"next_step":0}"#)
            .await
            .unwrap(),
        FlowJournalBegin::Inserted
    );
}

#[tokio::test]
async fn identity_binding_and_completed_checkpoint_are_immutable() {
    let store = Store::open_in_memory().await.unwrap();
    seed(&store, "r").await;
    assert!(
        store
            .prepare_flow_attempt("r", 0, "read", 1, false)
            .await
            .unwrap()
    );
    assert!(
        store
            .settle_flow_attempt(
                "r",
                1,
                r#"{"next_step":1,"snapshot":"ev"}"#,
                &["ev".to_owned()],
                true
            )
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .begin_flow_journal(&identity("r"), "{}")
            .await
            .unwrap(),
        FlowJournalBegin::Existing
    );
    let mut other = identity("r");
    other.flow_digest = "c".repeat(64);
    assert_eq!(
        store.begin_flow_journal(&other, "{}").await.unwrap(),
        FlowJournalBegin::Conflict
    );
    assert!(
        !store
            .prepare_flow_attempt("r", 2, "read", 2, false)
            .await
            .unwrap()
    );
    assert!(
        !store
            .settle_flow_attempt("r", 2, "{}", &[], false)
            .await
            .unwrap()
    );
    let row = store.read_flow_journal("r").await.unwrap().unwrap();
    assert_eq!(row.revision, 2);
    assert_eq!(row.state, FlowJournalState::Completed);
    assert_eq!(row.evidence_refs, ["ev"]);
    assert!(row.checkpoint_json.contains("snapshot"));
}

#[tokio::test]
async fn stale_and_concurrent_attempt_owners_cannot_advance_twice() {
    let store = Store::open_in_memory().await.unwrap();
    seed(&store, "r").await;
    let (a, b) = tokio::join!(
        store.prepare_flow_attempt("r", 0, "step", 1, false),
        store.prepare_flow_attempt("r", 0, "step", 1, false)
    );
    assert_ne!(a.unwrap(), b.unwrap());
    assert!(
        !store
            .settle_flow_attempt("r", 0, "{}", &[], false)
            .await
            .unwrap()
    );
    let (a, b) = tokio::join!(
        store.settle_flow_attempt("r", 1, "{}", &[], false),
        store.settle_flow_attempt("r", 1, "{}", &[], false)
    );
    assert_ne!(a.unwrap(), b.unwrap());
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
async fn interrupted_effect_is_never_abandoned_or_replayed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    {
        let store = Store::open(&path).await.unwrap();
        seed(&store, "effect").await;
        assert!(
            store
                .prepare_flow_attempt("effect", 0, "write", 1, true)
                .await
                .unwrap()
        );
    }
    let store = Store::open(&path).await.unwrap();
    let row = store.read_flow_journal("effect").await.unwrap().unwrap();
    assert_eq!(row.state, FlowJournalState::Prepared);
    assert!(row.effectful);
    assert!(!store.abandon_read_attempt("effect", 1).await.unwrap());
    assert!(
        !store
            .prepare_flow_attempt("effect", 1, "write", 2, true)
            .await
            .unwrap()
    );
    assert!(store.mark_flow_uncertain("effect", 1).await.unwrap());
    assert!(
        !store
            .settle_flow_attempt("effect", 2, "{}", &[], true)
            .await
            .unwrap()
    );
    assert!(
        !store
            .prepare_flow_attempt("effect", 2, "write", 2, true)
            .await
            .unwrap()
    );
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

#[tokio::test]
async fn interrupted_read_retains_prior_checkpoint_and_can_retry_with_new_ownership() {
    let store = Store::open_in_memory().await.unwrap();
    seed(&store, "read").await;
    assert!(
        store
            .prepare_flow_attempt("read", 0, "first", 1, false)
            .await
            .unwrap()
    );
    assert!(
        store
            .settle_flow_attempt(
                "read",
                1,
                r#"{"next_step":1,"budget_spent":10}"#,
                &["ev-first".to_owned()],
                false
            )
            .await
            .unwrap()
    );
    assert!(
        store
            .prepare_flow_attempt("read", 2, "second", 1, false)
            .await
            .unwrap()
    );
    assert!(!store.mark_flow_uncertain("read", 3).await.unwrap());
    assert!(store.abandon_read_attempt("read", 3).await.unwrap());
    let row = store.read_flow_journal("read").await.unwrap().unwrap();
    assert_eq!(row.checkpoint_json, r#"{"next_step":1,"budget_spent":10}"#);
    assert_eq!(row.evidence_refs, ["ev-first"]);
    assert!(
        store
            .prepare_flow_attempt("read", 4, "second", 2, false)
            .await
            .unwrap()
    );
    assert!(
        !store
            .settle_flow_attempt("read", 3, "{}", &[], false)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn invalid_json_references_and_generations_fail_without_progress() {
    let store = Store::open_in_memory().await.unwrap();
    seed(&store, "r").await;
    for checkpoint in [
        "[]".to_owned(),
        "broken".to_owned(),
        format!("{{\"x\":\"{}\"}}", "x".repeat(131_072)),
    ] {
        assert!(
            store
                .begin_flow_journal(&identity("r"), &checkpoint)
                .await
                .is_err()
        );
    }
    assert!(
        store
            .prepare_flow_attempt("r", -1, "step", 1, false)
            .await
            .is_err()
    );
    assert!(
        store
            .prepare_flow_attempt("r", i64::MAX, "step", 1, false)
            .await
            .is_err()
    );
    assert!(
        store
            .prepare_flow_attempt("r", 0, "step", 0, false)
            .await
            .is_err()
    );
    assert!(
        store
            .prepare_flow_attempt("r", 0, "step", 257, false)
            .await
            .is_err()
    );
    assert!(
        store
            .prepare_flow_attempt("r", 0, &"x".repeat(257), 1, false)
            .await
            .is_err()
    );
    assert!(
        store
            .prepare_flow_attempt("r", 0, "step", 1, false)
            .await
            .unwrap()
    );
    for refs in [
        vec!["ev".to_owned(); 129],
        vec!["x".repeat(129)],
        vec!["\n".to_owned()],
    ] {
        assert!(
            store
                .settle_flow_attempt("r", 1, "{}", &refs, false)
                .await
                .is_err()
        );
    }
    assert_eq!(
        store
            .read_flow_journal("r")
            .await
            .unwrap()
            .unwrap()
            .revision,
        1
    );
}

#[tokio::test]
async fn request_foreign_key_and_checkpoint_origin_kind_size_are_enforced() {
    let store = Store::open_in_memory().await.unwrap();
    assert!(
        store
            .begin_flow_journal(&identity("missing"), "{}")
            .await
            .is_err()
    );
    assert!(store.read_flow_journal("missing").await.unwrap().is_none());
    seed(&store, "r").await;
    store
        .insert_request("other", "flow.run", "/other", "test", "{}", None)
        .await
        .unwrap();
    store
        .insert_evidence("valid", "r", "flow.checkpoint", b"{}", None)
        .await
        .unwrap();
    store
        .insert_evidence("wrong-kind", "r", "connector.result", b"{}", None)
        .await
        .unwrap();
    store
        .insert_evidence("other-origin", "other", "flow.checkpoint", b"{}", None)
        .await
        .unwrap();
    store
        .insert_evidence(
            "oversized",
            "r",
            "flow.checkpoint",
            &vec![b'x'; 1_048_577],
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        store.read_flow_checkpoint("r", "valid").await.unwrap(),
        Some(b"{}".to_vec())
    );
    for id in ["wrong-kind", "other-origin", "missing"] {
        assert!(store.read_flow_checkpoint("r", id).await.unwrap().is_none());
    }
    assert!(store.read_flow_checkpoint("r", "oversized").await.is_err());
}
