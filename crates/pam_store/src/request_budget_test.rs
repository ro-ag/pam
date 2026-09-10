use crate::{RequestBudgetCharge, Store};

async fn seed(store: &Store) {
    store
        .insert_request("budget", "flow.run", "/repo", "test", "{}", None)
        .await
        .unwrap();
    store.load_request_budget("budget").await.unwrap();
}

#[tokio::test]
async fn reopen_restores_spent_bytes_without_renewal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    {
        let store = Store::open(&path).await.unwrap();
        seed(&store).await;
        store
            .reserve_request_budget("budget", RequestBudgetCharge::Http(134_217_728))
            .await
            .unwrap()
            .unwrap();
    }
    let store = Store::open(&path).await.unwrap();
    let restored = store.load_request_budget("budget").await.unwrap();
    assert_eq!(restored.http_bytes, 134_217_728);
    assert_eq!(restored.http_calls, 1);
    assert!(
        store
            .reserve_request_budget("budget", RequestBudgetCharge::Http(1))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(store.load_request_budget("budget").await.unwrap(), restored);
}

#[tokio::test]
async fn concurrent_reservations_cannot_exceed_a_shared_cap() {
    let store = Store::open_in_memory().await.unwrap();
    seed(&store).await;
    let (a, b) = tokio::join!(
        store.reserve_request_budget("budget", RequestBudgetCharge::Command(100_000_000)),
        store.reserve_request_budget("budget", RequestBudgetCharge::Command(100_000_000))
    );
    assert_eq!(
        usize::from(a.unwrap().is_some()) + usize::from(b.unwrap().is_some()),
        1
    );
    assert_eq!(
        store
            .load_request_budget("budget")
            .await
            .unwrap()
            .command_bytes,
        100_000_000
    );
}

#[tokio::test]
async fn counters_and_request_identity_fail_closed() {
    let store = Store::open_in_memory().await.unwrap();
    assert!(store.load_request_budget("missing").await.is_err());
    assert!(
        store
            .reserve_request_budget("missing", RequestBudgetCharge::Attempt)
            .await
            .unwrap()
            .is_none()
    );
    seed(&store).await;
    for _ in 0..256 {
        assert!(
            store
                .reserve_request_budget("budget", RequestBudgetCharge::Attempt)
                .await
                .unwrap()
                .is_some()
        );
    }
    assert!(
        store
            .reserve_request_budget("budget", RequestBudgetCharge::Attempt)
            .await
            .unwrap()
            .is_none()
    );
    for charge in [
        RequestBudgetCharge::Http(0),
        RequestBudgetCharge::Http(u64::MAX),
        RequestBudgetCharge::Command(0),
        RequestBudgetCharge::Command(u64::MAX),
    ] {
        assert!(
            store
                .reserve_request_budget("budget", charge)
                .await
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(
        store
            .load_request_budget("budget")
            .await
            .unwrap()
            .http_calls,
        0
    );
}

#[tokio::test]
async fn database_failure_cannot_manufacture_a_reservation() {
    let store = Store::open_in_memory().await.unwrap();
    seed(&store).await;
    store
        .conn
        .execute("DROP TABLE request_budget", ())
        .await
        .unwrap();
    assert!(
        store
            .reserve_request_budget("budget", RequestBudgetCharge::Attempt)
            .await
            .is_err()
    );
    assert!(store.load_request_budget("budget").await.is_err());
}
