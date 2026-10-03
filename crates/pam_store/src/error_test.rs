//! Engine failures as the store reports them: no engine type in the error,
//! and the kinds a caller can act on told apart.

use std::error::Error as _;
use std::time::Duration;

use rusqlite::{Connection, TransactionBehavior};

use crate::{Actor, Decision, EngineError, Store, StoreError};

fn engine_error(error: StoreError) -> EngineError {
    match error {
        StoreError::Database(engine) => engine,
        other => panic!("expected an engine failure, got: {other:?}"),
    }
}

#[tokio::test]
async fn a_duplicate_key_is_a_constraint_failure_with_the_engines_words() {
    let store = Store::open_in_memory().await.unwrap();
    store
        .insert_request("dup", "echo", "/repo", "agent", "{}", None)
        .await
        .unwrap();
    let error = store
        .insert_request("dup", "echo", "/repo", "agent", "{}", None)
        .await
        .unwrap_err();
    let text = error.to_string();
    assert!(text.starts_with("database error: "), "{text}");
    assert!(text.contains("request.id"), "{text}");
    // The engine's failure is the error's source, as the store's own type.
    assert!(
        error
            .source()
            .is_some_and(<dyn std::error::Error>::is::<EngineError>)
    );
    let engine = engine_error(error);
    assert!(engine.is_constraint());
    assert!(!engine.is_busy());
    assert_ne!(engine.code(), 0);
}

#[tokio::test]
async fn foreign_key_check_and_trigger_refusals_are_constraint_failures() {
    let store = Store::open_in_memory().await.unwrap();
    // Foreign key: an audit row for a request that does not exist.
    let orphan = store
        .append_audit("missing", "execute", Decision::Allow, Actor::System, None)
        .await
        .unwrap_err();
    assert!(engine_error(orphan).is_constraint());

    // CHECK: a model job of a kind the schema does not admit.
    let unchecked = store
        .insert_model_job("job", "transmogrify", "vendor/model", None, None)
        .await
        .unwrap_err();
    assert!(engine_error(unchecked).is_constraint());

    // Trigger: the audit trail is append-only, and says so.
    store
        .insert_request("r", "echo", "/repo", "agent", "{}", None)
        .await
        .unwrap();
    store
        .append_audit("r", "execute", Decision::Allow, Actor::System, None)
        .await
        .unwrap();
    let rewritten = store
        .raw_execute("UPDATE audit SET detail = 'rewritten'", ())
        .await
        .unwrap_err();
    assert!(rewritten.to_string().contains("audit rows are append-only"));
    assert!(engine_error(rewritten).is_constraint());
}

#[tokio::test]
async fn a_database_held_by_another_connection_answers_busy_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    let store = Store::open(&path).await.unwrap();
    // Do not wait the production five seconds for the lock in a test.
    store
        .raw(|conn| conn.busy_timeout(Duration::ZERO))
        .await
        .unwrap();

    // An operator's shell, or a backup tool, in the middle of a write.
    let mut other = Connection::open(&path).unwrap();
    let held = other
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();

    let error = store.set_setting("k", "1").await.unwrap_err();
    let text = error.to_string();
    assert!(text.contains("retry"), "{text}");
    let engine = engine_error(error);
    assert!(engine.is_busy(), "{engine:?}");
    assert!(!engine.is_constraint());
    // A transaction is refused at its start, before any of its statements.
    let error = store
        .set_settings(&[("a", "1"), ("b", "2")])
        .await
        .unwrap_err();
    assert!(engine_error(error).is_busy());

    drop(held);
    drop(other);
    // Nothing was written by the refused calls, and the store is usable.
    assert_eq!(store.get_setting("k").await.unwrap(), None);
    assert_eq!(store.get_setting("a").await.unwrap(), None);
    store.set_setting("k", "1").await.unwrap();
}

#[tokio::test]
async fn a_client_side_failure_carries_no_engine_code() {
    let store = Store::open_in_memory().await.unwrap();
    store.set_setting("k", "text").await.unwrap();
    // Text read as an integer: refused by the client, not by the engine.
    let error = store
        .raw_scalar::<i64, _>("SELECT value FROM setting WHERE key = 'k'", ())
        .await
        .unwrap_err();
    let engine = engine_error(error);
    assert_eq!(engine.code(), 0);
    assert!(!engine.is_constraint());
    assert!(!engine.is_busy());
    assert!(!engine.message().is_empty());
}

/// An engine failure with result code `code`, as the client reports it.
fn failure(code: i32, message: Option<&str>) -> StoreError {
    crate::error::engine(rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(code),
        message.map(str::to_owned),
    ))
}

#[test]
fn corruption_codes_become_the_corrupt_variant_wherever_they_surface() {
    // SQLITE_CORRUPT, two of its extended forms (CORRUPT_VTAB 267,
    // CORRUPT_INDEX 779), and SQLITE_NOTADB.
    for code in [11, 267, 779, 26] {
        match failure(code, Some("database disk image is malformed")) {
            StoreError::Corrupt { detail } => {
                assert_eq!(detail, "database disk image is malformed");
            }
            other => panic!("code {code} must read as corruption, got: {other:?}"),
        }
    }
    // Without a message the engine's description of the code stands in.
    match failure(26, None) {
        StoreError::Corrupt { detail } => assert!(!detail.is_empty()),
        other => panic!("{other:?}"),
    }
    // The detail is bounded.
    let long = "x".repeat(5000);
    match failure(11, Some(&long)) {
        StoreError::Corrupt { detail } => assert_eq!(detail.len(), 200),
        other => panic!("{other:?}"),
    }
}

#[test]
fn busy_and_constraint_codes_are_classified_by_their_primary_code() {
    // SQLITE_BUSY, SQLITE_BUSY_SNAPSHOT (517), SQLITE_LOCKED.
    for code in [5, 517, 6] {
        let engine = engine_error(failure(code, Some("database is locked")));
        assert!(engine.is_busy(), "{code}");
        assert!(!engine.is_constraint(), "{code}");
        assert_eq!(engine.code(), code);
    }
    // SQLITE_CONSTRAINT and its unique (2067), foreign-key (787) and
    // trigger (1811) forms.
    for code in [19, 2067, 787, 1811] {
        let engine = engine_error(failure(code, Some("constraint failed")));
        assert!(engine.is_constraint(), "{code}");
        assert!(!engine.is_busy(), "{code}");
        assert_eq!(engine.to_string(), "constraint failed");
    }
    // Anything else is neither: a full disk, here.
    let engine = engine_error(failure(13, Some("database or disk is full")));
    assert!(!engine.is_busy() && !engine.is_constraint());
    assert_eq!(engine.message(), "database or disk is full");
}
