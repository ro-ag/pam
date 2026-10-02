//! Cancel-safety of the store's transactions: whatever ends a store call
//! inside `BEGIN`..`COMMIT` — a deadline, an aborted task, a panic, an
//! error — the next call finds the connection outside any transaction and
//! none of the abandoned writes visible or durable.

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use crate::{Actor, AuditEntry, Decision, RequestState, Store, StoreError};

fn entry(action: &str) -> AuditEntry<'_> {
    AuditEntry {
        action,
        decision: Decision::Allow,
        actor: Actor::System,
        detail: None,
    }
}

async fn half_written(store: &Store) -> Option<String> {
    store.get_setting("half").await.unwrap()
}

/// The transaction every test abandons: one write, then it never finishes.
async fn write_then_hang(store: &Store) -> Result<(), StoreError> {
    let conn = store.lock().await?;
    conn.begin().await?;
    conn.execute("INSERT INTO setting(key,value) VALUES('half','1')", ())
        .await?;
    std::future::pending::<()>().await;
    conn.end(Ok(())).await
}

/// A terminal write and its audit row land together on a healthy store.
async fn assert_next_transaction_works(store: &Store, id: &str) {
    store
        .insert_request(id, "echo", "/repo", "agent", "{}", None)
        .await
        .unwrap();
    assert!(
        store
            .finish_request(id, RequestState::Done, Some("verified"), entry("execute"))
            .await
            .unwrap(),
        "the next transaction must run, not fail inside the abandoned one"
    );
    assert_eq!(
        store.get_request(id).await.unwrap().unwrap().state,
        RequestState::Done
    );
    assert_eq!(store.audit_for_request(id).await.unwrap().len(), 1);
}

#[tokio::test]
async fn the_engine_refuses_a_begin_inside_an_open_transaction() {
    // The failure the gate exists for, reproduced on the bare engine: a
    // transaction left open makes every later BEGIN an error, and writes
    // made meanwhile sit inside it, uncommitted.
    let store = Store::open_in_memory().await.unwrap();
    let conn = store.lock().await.unwrap();
    conn.execute("BEGIN", ()).await.unwrap();
    assert!(!conn.is_autocommit().unwrap());
    let nested = conn.execute("BEGIN", ()).await.unwrap_err();
    assert!(
        nested.to_string().contains("within a transaction"),
        "unexpected engine answer: {nested}"
    );
    conn.execute("ROLLBACK", ()).await.unwrap();
}

#[tokio::test]
async fn a_deadline_inside_a_transaction_is_rolled_back_before_the_next_call() {
    let store = Store::open_in_memory().await.unwrap();
    // The caller's deadline fires between BEGIN and COMMIT and drops the
    // future, exactly as `timeout_at(deadline, capability.execute(..))` does.
    let dropped = tokio::time::timeout(Duration::from_millis(20), write_then_hang(&store)).await;
    assert!(dropped.is_err(), "the transaction must still be open");

    assert_eq!(
        half_written(&store).await,
        None,
        "a write from the abandoned transaction is visible"
    );
    assert_next_transaction_works(&store, "after_deadline").await;
}

#[tokio::test]
async fn a_connection_left_inside_a_raw_transaction_is_recovered_by_the_next_lock() {
    let store = Store::open_in_memory().await.unwrap();
    {
        // What a dropped statement future leaves behind: BEGIN ran, the
        // guard is released, nobody will ever COMMIT.
        let conn = store.lock().await.unwrap();
        conn.execute("BEGIN", ()).await.unwrap();
        conn.execute("INSERT INTO setting(key,value) VALUES('half','1')", ())
            .await
            .unwrap();
    }
    assert_eq!(half_written(&store).await, None);
    assert_next_transaction_works(&store, "after_raw_begin").await;
    // The connection is in autocommit again, not inside a second leak.
    assert!(store.lock().await.unwrap().is_autocommit().unwrap());
}

#[tokio::test]
async fn an_aborted_task_inside_a_transaction_does_not_wedge_the_store() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn({
        let store = Arc::clone(&store);
        async move {
            let conn = store.lock().await?;
            conn.begin().await?;
            conn.execute("INSERT INTO setting(key,value) VALUES('half','1')", ())
                .await?;
            let _ = entered_tx.send(());
            std::future::pending::<()>().await;
            conn.end(Ok::<(), StoreError>(())).await
        }
    });
    entered_rx.await.unwrap();
    // `tasks.abort_all()` at shutdown, or a handler task cancelled mid-write.
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());

    assert_eq!(half_written(&store).await, None);
    assert_next_transaction_works(&store, "after_abort").await;
}

#[tokio::test]
async fn a_panic_inside_a_transaction_does_not_wedge_the_store() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let task = tokio::spawn({
        let store = Arc::clone(&store);
        async move {
            let conn = store.lock().await.unwrap();
            conn.begin().await.unwrap();
            conn.execute("INSERT INTO setting(key,value) VALUES('half','1')", ())
                .await
                .unwrap();
            panic!("injected panic inside a store transaction");
        }
    });
    assert!(task.await.unwrap_err().is_panic());

    assert_eq!(half_written(&store).await, None);
    assert_next_transaction_works(&store, "after_panic").await;
}

#[tokio::test]
async fn an_error_inside_a_transaction_rolls_back_and_returns_that_error() {
    // `end` with an error; the store methods' own error paths are covered
    // by the injected-failure tests in `store_integrity_test`.
    let store = Store::open_in_memory().await.unwrap();
    let conn = store.lock().await.unwrap();
    conn.begin().await.unwrap();
    conn.execute("INSERT INTO setting(key,value) VALUES('half','1')", ())
        .await
        .unwrap();
    let error = conn
        .end(Err::<(), _>(StoreError::NotFound {
            table: "request",
            id: "injected".to_owned(),
        }))
        .await
        .unwrap_err();
    assert!(matches!(error, StoreError::NotFound { .. }));
    // Rolled back by `end` itself, not deferred to the next lock.
    assert!(conn.is_autocommit().unwrap());
    drop(conn);
    assert_eq!(half_written(&store).await, None);
    assert_next_transaction_works(&store, "after_error").await;
}

#[tokio::test]
async fn writes_after_an_abandoned_transaction_are_durable_and_its_own_are_not() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    {
        let store = Store::open(&path).await.unwrap();
        let dropped =
            tokio::time::timeout(Duration::from_millis(20), write_then_hang(&store)).await;
        assert!(dropped.is_err());
        // Without the recovery these autocommit writes would join the open
        // transaction: visible in this process, gone after the restart.
        store.set_setting("after", "1").await.unwrap();
        assert_next_transaction_works(&store, "durable").await;
    }
    let store = Store::open(&path).await.unwrap();
    assert_eq!(
        store.get_setting("after").await.unwrap().as_deref(),
        Some("1")
    );
    assert_eq!(half_written(&store).await, None);
    assert_eq!(
        store.get_request("durable").await.unwrap().unwrap().state,
        RequestState::Done
    );
    assert_eq!(store.audit_for_request("durable").await.unwrap().len(), 1);
}

#[tokio::test]
async fn finish_request_dropped_at_any_poll_leaves_state_and_audit_consistent() {
    // Drop the real terminal write after 0, 1, 2, ... polls. Wherever the
    // engine yields, the request is either still in flight with no audit
    // row or terminal with exactly one, and the store keeps working.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("state.sqlite3"))
        .await
        .unwrap();
    for polls in 0..64_usize {
        let id = format!("req_{polls}");
        store
            .insert_request(&id, "echo", "/repo", "agent", "{}", None)
            .await
            .unwrap();
        let mut completed = false;
        {
            let mut finish = pin!(store.finish_request(
                &id,
                RequestState::Failed,
                Some("cancelled"),
                entry("cancel")
            ));
            let mut cx = Context::from_waker(Waker::noop());
            for _ in 0..polls {
                if let Poll::Ready(result) = finish.as_mut().poll(&mut cx) {
                    assert!(result.unwrap());
                    completed = true;
                    break;
                }
            }
        }
        let row = store.get_request(&id).await.unwrap().unwrap();
        let audit = store.audit_for_request(&id).await.unwrap();
        if row.state.is_terminal() {
            assert_eq!(audit.len(), 1, "terminal without its audit row");
        } else {
            assert!(!completed);
            assert!(audit.is_empty(), "audit row without the terminal state");
            assert!(
                store
                    .finish_request(
                        &id,
                        RequestState::Failed,
                        Some("cancelled"),
                        entry("cancel")
                    )
                    .await
                    .unwrap()
            );
        }
        if completed {
            // Every later iteration would complete on the same poll.
            break;
        }
    }
}
