use crate::{CorrelationBind, Store};

async fn seed(store: &Store) {
    store
        .insert_request("r", "flow.run", "/repo", "test", "{}", None)
        .await
        .unwrap();
}

#[tokio::test]
async fn identities_are_immutable_and_concurrent_duplicates_agree() {
    let store = Store::open_in_memory().await.unwrap();
    seed(&store).await;
    let (a, b) = tokio::join!(
        store.bind_correlation_target("r", "{}"),
        store.bind_correlation_target("r", "{}")
    );
    assert_eq!(a.unwrap(), CorrelationBind::Inserted);
    assert_eq!(b.unwrap(), CorrelationBind::Existing);
    assert_eq!(
        store
            .bind_correlation_target("r", r#"{"other":true}"#)
            .await
            .unwrap(),
        CorrelationBind::Conflict
    );
    let (a, b) = tokio::join!(
        store.bind_correlation_step("r", "build", "{}"),
        store.bind_correlation_step("r", "build", "{}")
    );
    assert_eq!(a.unwrap(), CorrelationBind::Inserted);
    assert_eq!(b.unwrap(), CorrelationBind::Existing);
    assert_eq!(
        store
            .bind_correlation_step("r", "build", r#"{"other":true}"#)
            .await
            .unwrap(),
        CorrelationBind::Conflict
    );
    assert_eq!(
        store.read_correlation_target("r").await.unwrap().as_deref(),
        Some("{}")
    );
    assert_eq!(
        store.read_correlation_steps("r").await.unwrap()[0].canonical_json,
        "{}"
    );
}

#[tokio::test]
async fn missing_parents_and_invalid_or_oversized_json_refuse() {
    let store = Store::open_in_memory().await.unwrap();
    assert!(store.bind_correlation_target("r", "{}").await.is_err());
    seed(&store).await;
    assert!(
        store
            .bind_correlation_step("r", "step", "{}")
            .await
            .is_err()
    );
    for json in [
        "[]".to_owned(),
        "null".to_owned(),
        "invalid".to_owned(),
        format!("{{\"x\":\"{}\"}}", "x".repeat(16384)),
    ] {
        assert!(store.bind_correlation_target("r", &json).await.is_err());
    }
    store.bind_correlation_target("r", "{}").await.unwrap();
    assert!(store.bind_correlation_step("r", "", "{}").await.is_err());
    assert!(
        store
            .bind_correlation_step("r", "step", &format!("{{\"x\":\"{}\"}}", "x".repeat(8192)))
            .await
            .is_err()
    );
    assert!(
        store
            .read_correlation_target("absent")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .read_correlation_steps("absent")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn full_step_budget_keeps_existing_bindings_readable() {
    let store = Store::open_in_memory().await.unwrap();
    seed(&store).await;
    store.bind_correlation_target("r", "{}").await.unwrap();
    let json = format!("{{\"x\":\"{}\"}}", "x".repeat(8184));
    assert_eq!(json.len(), 8192);
    for n in 0..64 {
        store
            .bind_correlation_step("r", &n.to_string(), &json)
            .await
            .unwrap();
    }
    assert!(
        store
            .bind_correlation_step("r", "overflow", "{}")
            .await
            .is_err()
    );
    assert_eq!(
        store.bind_correlation_step("r", "0", &json).await.unwrap(),
        CorrelationBind::Existing
    );
    assert_eq!(store.read_correlation_steps("r").await.unwrap().len(), 64);
}

#[tokio::test]
async fn identities_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    {
        let store = Store::open(&path).await.unwrap();
        seed(&store).await;
        store.bind_correlation_target("r", "{}").await.unwrap();
        store
            .bind_correlation_step("r", "build", "{}")
            .await
            .unwrap();
    }
    let store = Store::open(&path).await.unwrap();
    assert_eq!(
        store.bind_correlation_target("r", "{}").await.unwrap(),
        CorrelationBind::Existing
    );
    assert_eq!(
        store.read_correlation_steps("r").await.unwrap()[0].step_id,
        "build"
    );
}

#[tokio::test]
async fn request_retention_removes_bindings_and_never_allows_orphans() {
    let store = Store::open_in_memory().await.unwrap();
    seed(&store).await;
    store.bind_correlation_target("r", "{}").await.unwrap();
    store
        .bind_correlation_step("r", "build", "{}")
        .await
        .unwrap();
    store
        .update_request_state("r", crate::RequestState::Done, Some("ok"))
        .await
        .unwrap();
    store.prune_requests_before(i64::MAX).await.unwrap();
    assert!(store.read_correlation_target("r").await.unwrap().is_none());
    assert!(store.read_correlation_steps("r").await.unwrap().is_empty());
    assert!(store.bind_correlation_target("r", "{}").await.is_err());
    for table in ["correlation_step", "correlation_target"] {
        let mut rows = store
            .conn
            .query(&format!("SELECT COUNT(*) FROM {table}"), ())
            .await
            .unwrap();
        assert_eq!(
            rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
            0
        );
    }
}
