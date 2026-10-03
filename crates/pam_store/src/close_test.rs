//! Ending a store: what `close` leaves on disk and answers afterwards, and
//! what dropping a store without closing it does and does not do.

use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use tokio::sync::oneshot;

use crate::{Actor, AuditEntry, Decision, MAX_LIST_LIMIT, RequestState, Store, StoreError};

fn entry(action: &str) -> AuditEntry<'_> {
    AuditEntry {
        action,
        decision: Decision::Allow,
        actor: Actor::System,
        detail: None,
    }
}

fn len(path: &Path) -> u64 {
    std::fs::metadata(path).map_or(0, |meta| meta.len())
}

/// Inserts and finishes `count` requests, each with its audit row.
async fn finished_requests(store: &Store, prefix: &str, count: usize) {
    for index in 0..count {
        let id = format!("{prefix}_{index}");
        store
            .insert_request(&id, "echo", "/repo", "agent", "{}", None)
            .await
            .unwrap();
        assert!(
            store
                .finish_request(&id, RequestState::Done, Some("ok"), entry("execute"))
                .await
                .unwrap()
        );
    }
}

async fn request_count(store: &Store) -> usize {
    store
        .list_requests_filtered(Some(MAX_LIST_LIMIT), None, None, None, None, false)
        .await
        .unwrap()
        .len()
}

#[tokio::test]
async fn close_leaves_the_main_file_as_the_whole_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    let log = dir.path().join("state.sqlite3-wal");
    let store = Store::open(&path).await.unwrap();
    finished_requests(&store, "r", 20).await;
    assert!(len(&log) > 0, "the writes should still be in the log");

    store.close().await.unwrap();
    // Nothing is left in a log, and the log and its index are gone.
    assert_eq!(len(&log), 0);
    assert!(!log.exists());
    assert!(!dir.path().join("state.sqlite3-shm").exists());

    // So a plain copy of the main file is a complete backup.
    let elsewhere = tempfile::tempdir().unwrap();
    let copy = elsewhere.path().join("state.sqlite3");
    std::fs::copy(&path, &copy).unwrap();
    let restored = Store::open(&copy).await.unwrap();
    restored.check_integrity().await.unwrap();
    assert_eq!(request_count(&restored).await, 20);
    for index in 0..20 {
        let id = format!("r_{index}");
        let row = restored.get_request(&id).await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Done);
        assert_eq!(restored.audit_for_request(&id).await.unwrap().len(), 1);
    }
    restored.close().await.unwrap();
}

#[tokio::test]
async fn calls_after_close_are_refused_with_the_reason_and_closing_twice_is_harmless() {
    let dir = tempfile::tempdir().unwrap();
    for store in [
        Store::open(&dir.path().join("state.sqlite3"))
            .await
            .unwrap(),
        Store::open_in_memory().await.unwrap(),
    ] {
        store
            .insert_request("r", "echo", "/repo", "agent", "{}", None)
            .await
            .unwrap();
        store.close().await.unwrap();

        // A write, a transaction, a read on each connection, the check.
        let refusals = [
            store.set_setting("k", "v").await.unwrap_err(),
            store
                .finish_request("r", RequestState::Done, None, entry("execute"))
                .await
                .unwrap_err(),
            store.get_request("r").await.unwrap_err(),
            store
                .list_requests_filtered(None, None, None, None, None, false)
                .await
                .unwrap_err(),
            store.audit_for_request("r").await.unwrap_err(),
            store.check_integrity().await.unwrap_err(),
            store.schema_version().await.unwrap_err(),
        ];
        for refusal in refusals {
            assert!(matches!(refusal, StoreError::Closed), "{refusal:?}");
            let text = refusal.to_string();
            assert!(text.contains("the store is closed"), "{text}");
            assert!(text.contains("shutting down"), "{text}");
            assert!(text.contains("nothing was written"), "{text}");
        }
        store.close().await.unwrap();
        store.close().await.unwrap();
    }

    // What was written before the close is there; nothing after it is.
    let store = Store::open(&dir.path().join("state.sqlite3"))
        .await
        .unwrap();
    let row = store.get_request("r").await.unwrap().unwrap();
    assert_eq!(row.state, RequestState::Queued);
    assert_eq!(store.get_setting("k").await.unwrap(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_waits_for_the_call_in_flight_and_nothing_runs_after_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    let store = Arc::new(Store::open(&path).await.unwrap());

    // A transaction that has made its first write and is waiting.
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let in_flight = tokio::spawn({
        let store = Arc::clone(&store);
        async move {
            store
                .transact(move |conn| {
                    conn.execute("INSERT INTO setting(key,value) VALUES('half','1')", ())?;
                    let _ = started_tx.send(());
                    let _ = release_rx.recv();
                    conn.execute("INSERT INTO setting(key,value) VALUES('rest','1')", ())?;
                    Ok(())
                })
                .await
        }
    });
    started_rx.await.unwrap();

    let closing = tokio::spawn({
        let store = Arc::clone(&store);
        async move { store.close().await }
    });
    // Give the close time to reach the writer's queue, then queue a call
    // behind it.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let late = tokio::spawn({
        let store = Arc::clone(&store);
        async move { store.set_setting("late", "1").await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!closing.is_finished(), "close did not wait for the call");
    assert!(!late.is_finished());

    release_tx.send(()).unwrap();
    in_flight.await.unwrap().unwrap();
    closing.await.unwrap().unwrap();
    // The late call was queued behind the close unless the scheduler let it
    // overtake the close on its way to the queue; either way it ran whole
    // before the close or not at all.
    let late = late.await.unwrap();
    assert!(matches!(late, Ok(()) | Err(StoreError::Closed)), "{late:?}");
    // After the close has returned there is only one answer.
    assert!(matches!(
        store.set_setting("later", "1").await,
        Err(StoreError::Closed)
    ));

    // The call in flight committed whole; the late one is there exactly
    // when it was told so.
    let store = Store::open(&path).await.unwrap();
    assert_eq!(
        store.get_setting("half").await.unwrap().as_deref(),
        Some("1")
    );
    assert_eq!(
        store.get_setting("rest").await.unwrap().as_deref(),
        Some("1")
    );
    assert_eq!(
        store.get_setting("late").await.unwrap().is_some(),
        late.is_ok()
    );
    assert_eq!(store.get_setting("later").await.unwrap(), None);
}

#[tokio::test]
async fn dropping_a_store_without_closing_writes_nothing_and_loses_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    let log = dir.path().join("state.sqlite3-wal");
    Store::open(&path).await.unwrap().close().await.unwrap();

    let store = Store::open(&path).await.unwrap();
    finished_requests(&store, "r", 10).await;
    let main_before = std::fs::read(&path).unwrap();
    let log_before = std::fs::read(&log).unwrap();
    assert!(!log_before.is_empty());

    // No close: the destructor must not start folding the log into the main
    // file on whatever thread happens to drop the store.
    drop(store);
    assert_eq!(std::fs::read(&path).unwrap(), main_before);
    assert_eq!(std::fs::read(&log).unwrap(), log_before);

    // Which is what a killed process leaves, and the next open replays it.
    let store = Store::open(&path).await.unwrap();
    assert_eq!(request_count(&store).await, 10);
    assert_eq!(store.audit_for_request("r_9").await.unwrap().len(), 1);
    store.close().await.unwrap();
}

#[tokio::test]
async fn close_with_another_connection_mid_read_still_closes_and_loses_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    let log = dir.path().join("state.sqlite3-wal");
    let store = Store::open(&path).await.unwrap();
    finished_requests(&store, "before", 3).await;

    // An operator's shell in the middle of a read.
    let other = rusqlite::Connection::open(&path).unwrap();
    other.execute_batch("BEGIN").unwrap();
    let seen: i64 = other
        .query_row("SELECT COUNT(*) FROM request", (), |row| row.get(0))
        .unwrap();
    assert_eq!(seen, 3);
    // Written after that read began: the log cannot be folded past it.
    finished_requests(&store, "after", 3).await;
    // Do not sit out the full busy timeout in a test.
    store
        .raw(|conn| conn.busy_timeout(Duration::from_millis(50)))
        .await
        .unwrap();

    store.close().await.unwrap();
    assert!(matches!(
        store.set_setting("k", "v").await,
        Err(StoreError::Closed)
    ));
    assert!(len(&log) > 0, "the log should have stayed");
    // The other connection still reads its snapshot, undisturbed.
    let seen: i64 = other
        .query_row("SELECT COUNT(*) FROM request", (), |row| row.get(0))
        .unwrap();
    assert_eq!(seen, 3);
    other.execute_batch("COMMIT").unwrap();
    drop(other);

    let store = Store::open(&path).await.unwrap();
    assert_eq!(request_count(&store).await, 6);
    store.close().await.unwrap();
}

/// The closing checkpoint is best effort, so a lock that does not clear costs
/// a close a bounded wait (a second and a half of attempts, plus whatever the
/// last attempt's sync takes), never the five-second statement timeout: a
/// daemon's shutdown on Windows used to stall exactly that long.
#[tokio::test]
async fn close_does_not_sit_out_the_statement_busy_timeout_behind_another_reader() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    let store = Store::open(&path).await.unwrap();
    finished_requests(&store, "before", 3).await;

    let other = rusqlite::Connection::open(&path).unwrap();
    other.execute_batch("BEGIN").unwrap();
    let _: i64 = other
        .query_row("SELECT COUNT(*) FROM request", (), |row| row.get(0))
        .unwrap();
    finished_requests(&store, "after", 3).await;

    // The store keeps its own busy timeout: nothing here lowers it.
    let started = std::time::Instant::now();
    store.close().await.unwrap();
    let took = started.elapsed();
    assert!(
        took < Duration::from_millis(4_000),
        "close waited {took:?} behind another connection's read"
    );

    other.execute_batch("COMMIT").unwrap();
    drop(other);
    let store = Store::open(&path).await.unwrap();
    assert_eq!(request_count(&store).await, 6);
    store.close().await.unwrap();
}

/// A lock that clears within the close's bound is waited out, so the log is
/// still folded and the main file alone is the whole database.
#[tokio::test]
async fn close_waits_out_a_brief_read_and_still_folds_the_log() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    let log = dir.path().join("state.sqlite3-wal");
    let store = Store::open(&path).await.unwrap();
    finished_requests(&store, "before", 3).await;

    let (began, began_rx) = mpsc::channel();
    let reader_path = path.clone();
    let reader = std::thread::spawn(move || {
        let other = rusqlite::Connection::open(&reader_path).unwrap();
        other.execute_batch("BEGIN").unwrap();
        let _: i64 = other
            .query_row("SELECT COUNT(*) FROM request", (), |row| row.get(0))
            .unwrap();
        began.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(600));
        other.execute_batch("COMMIT").unwrap();
    });
    began_rx.recv().unwrap();
    finished_requests(&store, "after", 3).await;

    store.close().await.unwrap();
    reader.join().unwrap();
    assert_eq!(len(&log), 0, "the log should have been folded");

    let copy_dir = tempfile::tempdir().unwrap();
    let copy = copy_dir.path().join("state.sqlite3");
    std::fs::copy(&path, &copy).unwrap();
    let restored = Store::open(&copy).await.unwrap();
    assert_eq!(request_count(&restored).await, 6);
    restored.close().await.unwrap();
}
