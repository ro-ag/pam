use crate::Store;
use serde_json::{Value, json};

fn binding() -> Value {
    json!({"schema_version":1,"target_id":"target","decision":{"status":"matched"},
        "origin":{"connector":"github","call":"run","base_url":"https://api.example/"},
        "identity":{"repository":"team/app","run_id":9,"run_attempt":3}})
}

async fn seed(store: &Store) -> String {
    store
        .insert_request("r", "flow.run", "/repo", "test", "{}", None)
        .await
        .unwrap();
    store.bind_correlation_target("r", "{}").await.unwrap();
    let encoded = binding().to_string();
    store
        .bind_correlation_step("r", "run", &encoded)
        .await
        .unwrap();
    encoded
}

#[tokio::test]
async fn growing_membership_is_durable_and_parent_identity_is_immutable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("membership.db");
    let encoded;
    {
        let store = Store::open(&path).await.unwrap();
        encoded = seed(&store).await;
        assert_eq!(
            store
                .append_correlation_membership("r", "run", &encoded, &[2, 1])
                .await
                .unwrap(),
            Some(vec![1, 2])
        );
        assert_eq!(
            store
                .append_correlation_membership("r", "run", &encoded, &[2, 3])
                .await
                .unwrap(),
            Some(vec![1, 2, 3])
        );
        assert_eq!(
            store.read_correlation_steps("r").await.unwrap()[0].canonical_json,
            encoded
        );
    }
    let store = Store::open(&path).await.unwrap();
    assert_eq!(
        store
            .read_correlation_membership("r", "run", &encoded)
            .await
            .unwrap(),
        Some(vec![1, 2, 3])
    );
    for (pointer, replacement) in [
        ("/origin/base_url", json!("https://other.example/")),
        ("/identity/repository", json!("fork/app")),
        ("/identity/run_id", json!(10)),
        ("/identity/run_attempt", json!(4)),
    ] {
        let mut forged = binding();
        *forged.pointer_mut(pointer).unwrap() = replacement;
        assert_eq!(
            store
                .append_correlation_membership("r", "run", &forged.to_string(), &[99])
                .await
                .unwrap(),
            None
        );
    }
    assert_eq!(
        store
            .read_correlation_membership("r", "run", &encoded)
            .await
            .unwrap(),
        Some(vec![1, 2, 3])
    );
}

#[tokio::test]
async fn overflow_and_invalid_membership_refuse_without_partial_append() {
    let store = Store::open_in_memory().await.unwrap();
    let encoded = seed(&store).await;
    let ids: Vec<u64> = (1..=256).collect();
    assert_eq!(
        store
            .append_correlation_membership("r", "run", &encoded, &ids)
            .await
            .unwrap(),
        Some(ids.clone())
    );
    for incoming in [vec![257], vec![0], vec![1; 257]] {
        assert!(
            store
                .append_correlation_membership("r", "run", &encoded, &incoming)
                .await
                .is_err()
        );
    }
    assert_eq!(
        store
            .read_correlation_membership("r", "run", &encoded)
            .await
            .unwrap(),
        Some(ids)
    );
    assert_eq!(
        store
            .append_correlation_membership("missing", "run", &encoded, &[9])
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn concurrent_observations_preserve_the_union() {
    let store = Store::open_in_memory().await.unwrap();
    let encoded = seed(&store).await;
    let (a, b) = tokio::join!(
        store.append_correlation_membership("r", "run", &encoded, &[1]),
        store.append_correlation_membership("r", "run", &encoded, &[2]),
    );
    assert!(a.unwrap().is_some());
    assert!(b.unwrap().is_some());
    assert_eq!(
        store
            .read_correlation_membership("r", "run", &encoded)
            .await
            .unwrap(),
        Some(vec![1, 2])
    );
}
