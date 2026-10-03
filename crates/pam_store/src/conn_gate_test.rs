//! What the gate promises about a store call that does not end normally.
//!
//! A job, once started, runs to its end: whatever happens to its caller — a
//! deadline, an aborted task — its transaction commits whole or not at all,
//! and the next call finds the connection outside any transaction. A caller
//! that goes away before its job starts leaves nothing behind. A panic or an
//! error inside a transaction rolls it back. Callers are served one at a
//! time.

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use rusqlite::params;
use tokio::sync::oneshot;

use crate::{Actor, AuditEntry, Decision, RequestState, Store, StoreError};

/// What a defect inside a store job looks like to the gate.
fn injected_panic() -> Result<(), StoreError> {
    panic!("injected panic inside a store job")
}

fn entry(action: &str) -> AuditEntry<'_> {
    AuditEntry {
        action,
        decision: Decision::Allow,
        actor: Actor::System,
        detail: None,
    }
}

async fn setting(store: &Store, key: &'static str) -> Option<String> {
    store.get_setting(key).await.unwrap()
}

async fn half_written(store: &Store) -> Option<String> {
    setting(store, "half").await
}

const WRITE_HALF: &str = "INSERT INTO setting(key,value) VALUES('half','1')";
const WRITE_REST: &str = "INSERT INTO setting(key,value) VALUES('rest','1')";

/// A two-write transaction that stops between its writes: it reports that
/// it has started, then waits to be released (or for its releaser to go
/// away) before the second write.
fn paused_transaction(
    store: &Store,
) -> (
    impl Future<Output = Result<(), StoreError>> + '_,
    oneshot::Receiver<()>,
    mpsc::Sender<()>,
) {
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let call = store.transact(move |conn| {
        conn.execute(WRITE_HALF, ())?;
        let _ = started_tx.send(());
        let _ = release_rx.recv();
        conn.execute(WRITE_REST, ())?;
        Ok(())
    });
    (call, started_rx, release_tx)
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
        "the next transaction must run, not fail inside an abandoned one"
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
    let nested = store
        .raw(|conn| {
            conn.execute_batch("BEGIN")?;
            assert!(!conn.is_autocommit());
            let nested = conn.execute_batch("BEGIN");
            conn.execute_batch("ROLLBACK")?;
            nested
        })
        .await
        .unwrap_err();
    assert!(
        nested.to_string().contains("within a transaction"),
        "unexpected engine answer: {nested}"
    );
}

#[tokio::test]
async fn a_caller_dropped_after_its_job_started_leaves_a_whole_committed_transaction() {
    let store = Store::open_in_memory().await.unwrap();
    let (call, started, release) = paused_transaction(&store);
    {
        // The caller's deadline fires between the two writes and drops the
        // future, exactly as `timeout_at(deadline, capability.execute(..))`
        // does.
        let mut call = pin!(call);
        tokio::select! {
            result = &mut call => panic!("the job must still be paused: {result:?}"),
            entered = started => entered.unwrap(),
        }
    }
    release.send(()).unwrap();

    // The next call waits for the job, which finished without its caller:
    // both writes are there, not one.
    assert_eq!(half_written(&store).await.as_deref(), Some("1"));
    assert_eq!(setting(&store, "rest").await.as_deref(), Some("1"));
    assert!(store.raw(|conn| Ok(conn.is_autocommit())).await.unwrap());
    assert_next_transaction_works(&store, "after_deadline").await;
}

#[tokio::test]
async fn a_caller_dropped_while_waiting_for_the_gate_never_runs_its_job() {
    let store = Store::open_in_memory().await.unwrap();
    let (holder, started, release) = paused_transaction(&store);
    let mut holder = pin!(holder);
    tokio::select! {
        result = &mut holder => panic!("the job must still be paused: {result:?}"),
        entered = started => entered.unwrap(),
    }
    {
        // Queued behind the paused job, then given up on.
        let waiting =
            tokio::time::timeout(Duration::from_millis(20), store.set_setting("queued", "1")).await;
        assert!(waiting.is_err(), "the gate must still be held");
    }
    release.send(()).unwrap();
    holder.await.unwrap();

    assert_eq!(
        setting(&store, "queued").await,
        None,
        "a call abandoned before it started must not run later"
    );
    assert_eq!(setting(&store, "rest").await.as_deref(), Some("1"));
    assert_next_transaction_works(&store, "after_queue").await;
}

#[tokio::test]
async fn a_job_that_ends_inside_a_raw_transaction_is_rolled_back_by_the_gate() {
    let store = Store::open_in_memory().await.unwrap();
    // What no store call does, done through the test seam: BEGIN ran, the
    // job returned, nobody will ever COMMIT.
    store
        .raw(|conn| {
            conn.execute_batch("BEGIN")?;
            conn.execute(WRITE_HALF, ()).map(|_| ())
        })
        .await
        .unwrap();
    assert_eq!(half_written(&store).await, None);
    assert_next_transaction_works(&store, "after_raw_begin").await;
    // The connection is in autocommit again, not inside a second leak.
    assert!(store.raw(|conn| Ok(conn.is_autocommit())).await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_aborted_task_inside_a_transaction_does_not_wedge_the_store() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let task = tokio::spawn({
        let store = Arc::clone(&store);
        async move {
            store
                .transact(move |conn| {
                    conn.execute(WRITE_HALF, ())?;
                    let _ = started_tx.send(());
                    let _ = release_rx.recv();
                    conn.execute(WRITE_REST, ())?;
                    Ok(())
                })
                .await
        }
    });
    started_rx.await.unwrap();
    // `tasks.abort_all()` at shutdown, or a handler task cancelled mid-write.
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    release_tx.send(()).unwrap();

    // All or nothing, never half: the job had started, so it is all.
    let half = half_written(&store).await;
    let rest = setting(&store, "rest").await;
    assert_eq!(half, rest, "half a transaction is visible");
    assert_eq!(half.as_deref(), Some("1"));
    assert_next_transaction_works(&store, "after_abort").await;
}

#[tokio::test]
async fn a_panic_inside_a_transaction_does_not_wedge_the_store() {
    let store = Store::open_in_memory().await.unwrap();
    let error = store
        .transact(|conn| {
            conn.execute(WRITE_HALF, ())?;
            injected_panic()
        })
        .await
        .unwrap_err();
    assert!(
        matches!(&error, StoreError::Unavailable { detail } if detail.contains("injected panic")),
        "{error:?}"
    );

    assert_eq!(half_written(&store).await, None);
    assert!(store.raw(|conn| Ok(conn.is_autocommit())).await.unwrap());
    assert_next_transaction_works(&store, "after_panic").await;
}

#[tokio::test]
async fn a_panic_outside_a_transaction_is_contained_and_keeps_what_already_committed() {
    let store = Store::open_in_memory().await.unwrap();
    let error = store
        .run(|conn| {
            // Autocommit: this write is durable before the panic.
            conn.execute(WRITE_HALF, ())?;
            injected_panic()
        })
        .await
        .unwrap_err();
    assert!(matches!(error, StoreError::Unavailable { .. }), "{error:?}");
    assert_eq!(half_written(&store).await.as_deref(), Some("1"));
    assert_next_transaction_works(&store, "after_plain_panic").await;
}

#[tokio::test]
async fn an_error_inside_a_transaction_rolls_back_and_returns_that_error() {
    // The store methods' own error paths are covered by the injected-failure
    // tests in `store_integrity_test`.
    let store = Store::open_in_memory().await.unwrap();
    let error = store
        .transact(|conn| {
            conn.execute(WRITE_HALF, ())?;
            Err::<(), _>(StoreError::NotFound {
                table: "request",
                id: "injected".to_owned(),
            })
        })
        .await
        .unwrap_err();
    assert!(matches!(error, StoreError::NotFound { .. }));
    // Rolled back by the transaction itself, not left for the gate to find.
    assert!(store.raw(|conn| Ok(conn.is_autocommit())).await.unwrap());
    assert_eq!(half_written(&store).await, None);
    assert_next_transaction_works(&store, "after_error").await;
}

#[tokio::test]
async fn writes_after_an_abandoned_transaction_are_durable_and_its_own_are_not() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    {
        let store = Store::open(&path).await.unwrap();
        let abandoned = store
            .transact(|conn| {
                conn.execute(WRITE_HALF, ())?;
                injected_panic()
            })
            .await;
        assert!(matches!(abandoned, Err(StoreError::Unavailable { .. })));
        // Had the transaction been left open, these writes would have joined
        // it: visible in this process, gone after the restart.
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
    // call is cut, the request is either still in flight with no audit
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_callers_are_served_one_at_a_time() {
    const CALLERS: i64 = 24;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::open(&dir.path().join("state.sqlite3"))
            .await
            .unwrap(),
    );
    store.set_setting("counter", "0").await.unwrap();
    let inside = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..CALLERS {
        let store = Arc::clone(&store);
        let inside = Arc::clone(&inside);
        tasks.push(tokio::spawn(async move {
            // Read, linger, write: a lost update unless the jobs are serial.
            store
                .raw(move |conn| {
                    assert_eq!(
                        inside.fetch_add(1, Ordering::SeqCst),
                        0,
                        "two jobs on the connection at once"
                    );
                    let current: String = conn.query_row(
                        "SELECT value FROM setting WHERE key = 'counter'",
                        (),
                        |row| row.get(0),
                    )?;
                    std::thread::sleep(Duration::from_millis(2));
                    let next = current.parse::<i64>().unwrap() + 1;
                    conn.execute(
                        "UPDATE setting SET value = ?1 WHERE key = 'counter'",
                        params![next.to_string()],
                    )?;
                    inside.fetch_sub(1, Ordering::SeqCst);
                    Ok(())
                })
                .await
                .unwrap();
            // Interleave the store's own reads and writes with the raw jobs.
            store.get_setting("counter").await.unwrap().unwrap()
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(
        store.get_setting("counter").await.unwrap().as_deref(),
        Some(CALLERS.to_string().as_str())
    );
}

/// Polls until `condition` holds; panics if it has not after ten seconds.
async fn eventually(what: &str, condition: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_queue_refuses_the_next_call_before_it_runs_and_recovers() {
    use crate::conn_gate::MAX_QUEUED_CALLS;

    let store = Arc::new(Store::open_in_memory().await.unwrap());
    // A disk that has stopped answering: one job holds the connection.
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let stalled = tokio::spawn({
        let store = Arc::clone(&store);
        async move {
            store
                .raw(move |_| {
                    let _ = started_tx.send(());
                    let _ = release_rx.recv();
                    Ok(())
                })
                .await
        }
    });
    started_rx.await.unwrap();
    assert_eq!(store.queued_calls(), 1);

    // Callers keep arriving until the queue is full.
    let mut waiting = Vec::new();
    for index in 1..MAX_QUEUED_CALLS {
        let store = Arc::clone(&store);
        waiting.push(tokio::spawn(async move {
            store.set_setting(&format!("k{index}"), "1").await
        }));
    }
    eventually("the queue fills", || {
        store.queued_calls() == MAX_QUEUED_CALLS
    })
    .await;

    // The next one is answered at once, with the cause, and is not queued.
    let refused = tokio::time::timeout(Duration::from_secs(5), store.set_setting("over", "1"))
        .await
        .expect("a call past the bound waited instead of being refused")
        .unwrap_err();
    assert!(
        matches!(refused, StoreError::Overloaded { waiting } if waiting == MAX_QUEUED_CALLS),
        "{refused:?}"
    );
    let text = refused.to_string();
    assert!(text.contains("1024 calls waiting"), "{text}");
    assert!(text.contains("refused before it ran"), "{text}");
    assert!(text.contains("disk"), "{text}");
    assert_eq!(store.queued_calls(), MAX_QUEUED_CALLS);

    // A waiter that gives up leaves the queue, and its place can be taken.
    let gave_up = waiting.pop().unwrap();
    gave_up.abort();
    let _ = gave_up.await;
    eventually("the abandoned place is free", || {
        store.queued_calls() == MAX_QUEUED_CALLS - 1
    })
    .await;
    waiting.push(tokio::spawn({
        let store = Arc::clone(&store);
        async move { store.set_setting("took_the_place", "1").await }
    }));
    eventually("the place is taken", || {
        store.queued_calls() == MAX_QUEUED_CALLS
    })
    .await;

    // The disk answers again: everyone who waited is served, in full.
    release_tx.send(()).unwrap();
    stalled.await.unwrap().unwrap();
    for task in waiting {
        task.await.unwrap().unwrap();
    }
    assert_eq!(store.queued_calls(), 0);
    let written: i64 = store
        .raw_scalar("SELECT COUNT(*) FROM setting", ())
        .await
        .unwrap();
    // Every waiter but the one that gave up, plus the one that took its
    // place; the refused call wrote nothing.
    assert_eq!(written, i64::try_from(MAX_QUEUED_CALLS).unwrap() - 2 + 1);
    assert_eq!(store.get_setting("over").await.unwrap(), None);
    assert!(store.get_setting("took_the_place").await.unwrap().is_some());
}
