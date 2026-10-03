//! The read-only second connection: what it may do, what it sees, and that
//! the reads routed to it and the writes on the first connection no longer
//! wait for each other.
//!
//! All on real files: an in-memory store has one connection, which is the
//! control in the last test.

use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use tokio::sync::oneshot;

use crate::{Actor, AuditEntry, Decision, MAX_LIST_LIMIT, RequestState, Store};

/// Long enough that only a call that is really waiting runs into it.
const MUST_NOT_WAIT: Duration = Duration::from_secs(10);

/// Long enough to tell "waiting" from "slow".
const STILL_WAITING: Duration = Duration::from_millis(300);

fn entry(action: &str) -> AuditEntry<'_> {
    AuditEntry {
        action,
        decision: Decision::Allow,
        actor: Actor::System,
        detail: None,
    }
}

async fn file_store(dir: &tempfile::TempDir) -> Arc<Store> {
    Arc::new(
        Store::open(&dir.path().join("state.sqlite3"))
            .await
            .unwrap(),
    )
}

async fn listed(store: &Store, state: Option<RequestState>) -> Vec<String> {
    store
        .list_requests_filtered(Some(MAX_LIST_LIMIT), None, None, state, None, false)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.id)
        .collect()
}

#[tokio::test]
async fn the_read_connection_cannot_write_and_is_hardened_like_the_writer() {
    let dir = tempfile::tempdir().unwrap();
    let store = file_store(&dir).await;
    let pragma = |name: &'static str| {
        let store = Arc::clone(&store);
        async move {
            store
                .raw_read(move |conn| {
                    conn.pragma_query_value(None, name, |row| row.get::<_, i64>(0))
                })
                .await
                .expect("a file store has a read connection")
                .unwrap()
        }
    };
    assert_eq!(pragma("query_only").await, 1);
    assert_eq!(pragma("foreign_keys").await, 1);
    assert_eq!(pragma("trusted_schema").await, 0);
    assert_eq!(pragma("busy_timeout").await, 5000);

    let refused = |sql: &'static str| {
        let store = Arc::clone(&store);
        async move {
            store
                .raw_read(move |conn| conn.execute_batch(sql))
                .await
                .unwrap()
                .unwrap_err()
                .to_string()
        }
    };
    let write = refused("INSERT INTO setting (key, value) VALUES ('k', 'v')").await;
    assert!(write.contains("readonly"), "{write}");
    let schema = refused("CREATE TABLE smuggled (x)").await;
    assert!(schema.contains("readonly"), "{schema}");
    let attach = refused("ATTACH DATABASE ':memory:' AS other").await;
    assert!(attach.contains("too many attached databases"), "{attach}");
    let quoted = refused("SELECT \"nope\"").await;
    assert!(quoted.contains("no such column"), "{quoted}");
    assert_eq!(store.get_setting("k").await.unwrap(), None);

    // An in-memory store has nothing a second connection could open.
    let memory = Store::open_in_memory().await.unwrap();
    assert!(memory.raw_read(|_| Ok(())).await.is_none());
}

#[tokio::test]
async fn a_read_sees_every_write_that_returned_before_it_started() {
    let dir = tempfile::tempdir().unwrap();
    let store = file_store(&dir).await;
    for index in 0..40 {
        let id = format!("r_{index:02}");
        store
            .insert_request(&id, "echo", "/repo", "agent", "{}", None)
            .await
            .unwrap();
        // Listed the moment the insert has returned...
        assert!(listed(&store, None).await.contains(&id), "{id}");
        assert!(
            listed(&store, Some(RequestState::Queued))
                .await
                .contains(&id)
        );

        store
            .insert_evidence(
                &format!("ev_{index}"),
                &id,
                "log.source",
                id.as_bytes(),
                None,
            )
            .await
            .unwrap();
        let evidence = store
            .get_evidence(&format!("ev_{index}"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(evidence.content, id.as_bytes());
        assert_eq!(store.list_evidence(&id).await.unwrap().len(), 1);

        // ...and finished, with its audit row, the moment the finish has.
        assert!(
            store
                .finish_request(&id, RequestState::Done, Some("ok"), entry("execute"))
                .await
                .unwrap()
        );
        assert_eq!(store.audit_for_request(&id).await.unwrap().len(), 1, "{id}");
        assert!(listed(&store, Some(RequestState::Done)).await.contains(&id));
        assert!(
            !listed(&store, Some(RequestState::Queued))
                .await
                .contains(&id)
        );
    }
    let census = store
        .retention_census(Some(i64::MAX), "none", Some(i64::MAX))
        .await
        .unwrap();
    assert_eq!(census.total_rows, 80);
    assert_eq!(census.eligible_rows, 80);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_in_progress_does_not_delay_a_terminal_write() {
    let dir = tempfile::tempdir().unwrap();
    let store = file_store(&dir).await;
    store
        .insert_request("r", "echo", "/repo", "agent", "{}", None)
        .await
        .unwrap();

    // A long read, taking the way every routed list query takes: it has
    // fetched a row and has not finished, so its statement is open and its
    // snapshot is held.
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let reading = tokio::spawn({
        let store = Arc::clone(&store);
        async move {
            store
                .read(move |conn| {
                    let mut stmt = conn.prepare("SELECT state FROM request WHERE id = 'r'")?;
                    let mut rows = stmt.query(())?;
                    let first: String = rows.next()?.expect("the request row").get(0)?;
                    let _ = started_tx.send(());
                    let _ = release_rx.recv();
                    assert!(rows.next()?.is_none());
                    drop(rows);
                    // A second statement of the same read: the same moment.
                    let mut rows = stmt.query(())?;
                    let again: String = rows.next()?.expect("the request row").get(0)?;
                    Ok((first, again))
                })
                .await
        }
    });
    started_rx.await.unwrap();

    // The terminal write and its audit row land while that read is open.
    let finished = tokio::time::timeout(
        MUST_NOT_WAIT,
        store.finish_request("r", RequestState::Done, Some("ok"), entry("execute")),
    )
    .await
    .expect("the terminal write waited for a read");
    assert!(finished.unwrap());
    assert!(!reading.is_finished());
    assert_eq!(
        store.get_request("r").await.unwrap().unwrap().state,
        RequestState::Done
    );

    release_tx.send(()).unwrap();
    // The read saw one moment throughout, the one it began in; a read
    // started after the write sees the write.
    let (first, again) = reading.await.unwrap().unwrap();
    assert_eq!((first.as_str(), again.as_str()), ("queued", "queued"));
    assert_eq!(listed(&store, Some(RequestState::Done)).await, ["r"]);
    assert_eq!(store.audit_for_request("r").await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_routed_reads_answer_while_a_write_transaction_is_held_open() {
    let dir = tempfile::tempdir().unwrap();
    let store = file_store(&dir).await;
    store
        .insert_request("r", "log.compress", "/repo", "agent", "{}", None)
        .await
        .unwrap();
    store
        .insert_evidence("ev", "r", "log.source", b"evidence bytes", None)
        .await
        .unwrap();
    store.upsert_caller("agent", "/repo").await.unwrap();
    store
        .finish_request("r", RequestState::Done, Some("ok"), entry("execute"))
        .await
        .unwrap();

    // A write transaction that has written and is not finishing.
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let writing = tokio::spawn({
        let store = Arc::clone(&store);
        async move {
            store
                .transact(move |conn| {
                    conn.execute("INSERT INTO setting(key,value) VALUES('held','1')", ())?;
                    let _ = started_tx.send(());
                    let _ = release_rx.recv();
                    Ok(())
                })
                .await
        }
    });
    started_rx.await.unwrap();

    // Every routed read answers, with what was committed before.
    let reads = async {
        assert_eq!(listed(&store, None).await, ["r"]);
        assert_eq!(store.audit_for_request("r").await.unwrap().len(), 1);
        assert_eq!(store.list_callers().await.unwrap().len(), 1);
        assert!(store.list_model_jobs(10).await.unwrap().is_empty());
        assert_eq!(store.list_evidence("r").await.unwrap().len(), 1);
        let evidence = store.get_evidence("ev").await.unwrap().unwrap();
        assert_eq!(evidence.content, b"evidence bytes");
        assert_eq!(store.compression_stats(0).await.unwrap().compressions, 0);
        let census = store.retention_census(None, "none", None).await.unwrap();
        assert_eq!(census.total_rows, 2);
        store.check_integrity().await.unwrap();
    };
    tokio::time::timeout(MUST_NOT_WAIT, reads)
        .await
        .expect("a routed read waited for the write transaction");

    // A read that stays on the writing connection does wait, and does not
    // see the uncommitted row from the side.
    assert!(
        tokio::time::timeout(STILL_WAITING, store.get_setting("held"))
            .await
            .is_err(),
        "a read on the writing connection ran inside somebody's transaction"
    );
    assert!(!writing.is_finished());

    release_tx.send(()).unwrap();
    writing.await.unwrap().unwrap();
    assert_eq!(
        store.get_setting("held").await.unwrap().as_deref(),
        Some("1")
    );
}

/// The control. With one connection (an in-memory store) the same two
/// sequences do wait: the tests above pass because of the second connection,
/// not because the calls are fast.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_one_connection_the_same_read_and_write_do_wait_for_each_other() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    store
        .insert_request("r", "echo", "/repo", "agent", "{}", None)
        .await
        .unwrap();

    // A read in progress on the only connection.
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let reading = tokio::spawn({
        let store = Arc::clone(&store);
        async move {
            store
                .raw(move |conn| {
                    let state: String =
                        conn.query_row("SELECT state FROM request WHERE id = 'r'", (), |row| {
                            row.get(0)
                        })?;
                    let _ = started_tx.send(());
                    let _ = release_rx.recv();
                    Ok(state)
                })
                .await
        }
    });
    started_rx.await.unwrap();
    let write = store.finish_request("r", RequestState::Done, Some("ok"), entry("execute"));
    let mut write = std::pin::pin!(write);
    assert!(
        tokio::time::timeout(STILL_WAITING, &mut write)
            .await
            .is_err(),
        "the write did not wait for the read on a single connection"
    );
    release_tx.send(()).unwrap();
    assert!(write.await.unwrap());
    assert_eq!(reading.await.unwrap().unwrap(), "queued");

    // A write transaction in progress on the only connection.
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let writing = tokio::spawn({
        let store = Arc::clone(&store);
        async move {
            store
                .transact(move |conn| {
                    conn.execute("INSERT INTO setting(key,value) VALUES('held','1')", ())?;
                    let _ = started_tx.send(());
                    let _ = release_rx.recv();
                    Ok(())
                })
                .await
        }
    });
    started_rx.await.unwrap();
    let list = listed(&store, None);
    let mut list = std::pin::pin!(list);
    assert!(
        tokio::time::timeout(STILL_WAITING, &mut list)
            .await
            .is_err(),
        "the list did not wait for the write on a single connection"
    );
    release_tx.send(()).unwrap();
    writing.await.unwrap().unwrap();
    assert_eq!(list.await, ["r"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn readers_and_writers_run_together_and_every_count_adds_up() {
    const WRITERS: usize = 8;
    const PER_WRITER: usize = 25;
    let dir = tempfile::tempdir().unwrap();
    let store = file_store(&dir).await;

    let mut tasks = Vec::new();
    for writer in 0..WRITERS {
        let store = Arc::clone(&store);
        tasks.push(tokio::spawn(async move {
            for index in 0..PER_WRITER {
                let id = format!("w{writer}_{index:02}");
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
                // One caller's calls apply in order: its own finished
                // request is there, whole, on both connections.
                assert_eq!(store.audit_for_request(&id).await.unwrap().len(), 1);
                assert_eq!(
                    store.get_request(&id).await.unwrap().unwrap().state,
                    RequestState::Done
                );
            }
        }));
    }
    for _ in 0..4 {
        let store = Arc::clone(&store);
        tasks.push(tokio::spawn(async move {
            let mut last = 0;
            for _ in 0..50 {
                // Never a request without its audit row in a list of
                // finished ones, and the list only ever grows.
                let done = listed(&store, Some(RequestState::Done)).await;
                assert!(done.len() >= last);
                last = done.len();
                if let Some(id) = done.first() {
                    assert_eq!(store.audit_for_request(id).await.unwrap().len(), 1);
                }
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(listed(&store, None).await.len(), WRITERS * PER_WRITER);
    assert_eq!(
        listed(&store, Some(RequestState::Done)).await.len(),
        WRITERS * PER_WRITER
    );
    store.check_integrity().await.unwrap();
    store.close().await.unwrap();
}
