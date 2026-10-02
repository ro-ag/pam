//! The connection's settings, read back from the engine, and what an open
//! that is refused leaves behind.

use std::path::Path;

use rusqlite::Connection;

use crate::{Store, StoreError};

async fn pragma_i64(store: &Store, name: &'static str) -> i64 {
    store
        .raw_scalar(&format!("PRAGMA {name}"), ())
        .await
        .unwrap()
}

async fn file_store(dir: &Path) -> Store {
    Store::open(&dir.join("state.sqlite3")).await.unwrap()
}

#[tokio::test]
async fn a_file_store_is_durable_and_hardened() {
    let dir = tempfile::tempdir().unwrap();
    let store = file_store(dir.path()).await;

    let mode: String = store.raw_scalar("PRAGMA journal_mode", ()).await.unwrap();
    assert_eq!(mode, "wal");
    // 2 is FULL: every commit is synced before the call returns.
    assert_eq!(pragma_i64(&store, "synchronous").await, 2);
    assert_eq!(pragma_i64(&store, "foreign_keys").await, 1);
    assert_eq!(pragma_i64(&store, "secure_delete").await, 1);
    assert_eq!(pragma_i64(&store, "trusted_schema").await, 0);
    assert_eq!(pragma_i64(&store, "busy_timeout").await, 5000);
    assert_eq!(
        pragma_i64(&store, "journal_size_limit").await,
        16 * 1024 * 1024
    );
}

#[tokio::test]
async fn an_in_memory_store_keeps_the_settings_that_do_not_need_a_file() {
    let store = Store::open_in_memory().await.unwrap();
    let mode: String = store.raw_scalar("PRAGMA journal_mode", ()).await.unwrap();
    assert_eq!(mode, "memory");
    assert_eq!(pragma_i64(&store, "foreign_keys").await, 1);
    assert_eq!(pragma_i64(&store, "secure_delete").await, 1);
    assert_eq!(pragma_i64(&store, "trusted_schema").await, 0);
}

#[tokio::test]
async fn the_engine_is_the_bundled_one() {
    // The version the bindings were generated for is the version that
    // answers at run time: the engine linked in is the one shipped with the
    // client crate, not whatever library the host has installed.
    let store = Store::open_in_memory().await.unwrap();
    let running: String = store
        .raw_scalar("SELECT sqlite_version()", ())
        .await
        .unwrap();
    assert_eq!(
        running,
        rusqlite::ffi::SQLITE_VERSION.to_str().unwrap(),
        "the engine at run time is not the bundled build"
    );
}

#[tokio::test]
async fn a_double_quoted_token_is_never_a_string() {
    let store = Store::open_in_memory().await.unwrap();
    // With the engine's legacy default this would answer the text "nope".
    let error = store
        .raw_scalar::<String, _>("SELECT \"nope\"", ())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("no such column"), "{error}");
    // In a schema statement too: this would index a constant.
    let error = store
        .raw_execute("CREATE INDEX probe ON setting (\"nope\")", ())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("no such column"), "{error}");
    // A quoted identifier still is one.
    let count: i64 = store
        .raw_scalar("SELECT COUNT(*) FROM \"grant\"", ())
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn sql_cannot_reach_outside_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let store = file_store(dir.path()).await;

    // No extension can be loaded from SQL.
    let error = store
        .raw_scalar::<Option<String>, _>("SELECT load_extension('x')", ())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("not authorized"), "{error}");

    // No second database can be attached, on disk or in memory.
    let other = dir.path().join("other.sqlite3");
    for target in [other.to_str().unwrap().to_owned(), ":memory:".to_owned()] {
        let error = store
            .raw_execute("ATTACH DATABASE ?1 AS other", (target,))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("too many attached databases"),
            "{error}"
        );
    }
    assert!(!other.exists());

    // The schema table cannot be edited as data.
    let error = store
        .raw_execute("DELETE FROM sqlite_master", ())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("may not be modified"), "{error}");
}

#[tokio::test]
async fn a_rollback_journal_database_is_switched_to_wal_and_keeps_its_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    // A database another client of the engine made, in the engine's default
    // journal mode, holding a row.
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE elsewhere (note TEXT NOT NULL);
             INSERT INTO elsewhere VALUES ('kept');",
        )
        .unwrap();
        let mode: String = conn
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "delete");
    }

    let store = Store::open(&path).await.unwrap();
    let mode: String = store.raw_scalar("PRAGMA journal_mode", ()).await.unwrap();
    assert_eq!(mode, "wal");
    store.set_setting("after", "1").await.unwrap();
    drop(store);

    // The mode is a property of the file: any later client sees it.
    let conn = Connection::open(&path).unwrap();
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    let kept: String = conn
        .query_row("SELECT note FROM elsewhere", (), |row| row.get(0))
        .unwrap();
    assert_eq!(kept, "kept");
}

#[tokio::test]
async fn a_file_that_is_not_a_database_is_refused_and_left_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    let garbage = b"this is a text file somebody put where the state file goes\n".repeat(200);
    std::fs::write(&path, &garbage).unwrap();

    match Store::open(&path).await {
        Err(StoreError::Corrupt { detail }) => assert!(!detail.is_empty()),
        Err(other) => panic!("a non-database must be reported as corruption, got: {other}"),
        Ok(_) => panic!("a text file opened as a database"),
    }
    assert_eq!(std::fs::read(&path).unwrap(), garbage);
}

#[tokio::test]
async fn a_refused_open_leaves_the_log_and_the_main_file_as_it_found_them() {
    let dir = tempfile::tempdir().unwrap();
    let live = dir.path().join("live");
    let copy = dir.path().join("copy");
    std::fs::create_dir_all(&copy).unwrap();
    // A database whose newest commits are only in its write-ahead log,
    // which is what a killed daemon leaves: copied while the store that
    // wrote it is still open.
    let store = file_store(&live).await;
    store.set_setting("in_the_log", "1").await.unwrap();
    store
        .raw(|conn| conn.execute_batch("PRAGMA user_version = 999"))
        .await
        .unwrap();
    for name in ["state.sqlite3", "state.sqlite3-wal"] {
        std::fs::copy(live.join(name), copy.join(name)).unwrap();
    }
    drop(store);
    let main_before = std::fs::read(copy.join("state.sqlite3")).unwrap();
    let log_before = std::fs::read(copy.join("state.sqlite3-wal")).unwrap();
    assert!(!log_before.is_empty(), "the copy must carry a log");

    // Refused: written by a newer version than this binary knows.
    let error = Store::open(&copy.join("state.sqlite3")).await.unwrap_err();
    assert!(
        matches!(error, StoreError::VersionTooNew { found: 999, .. }),
        "{error:?}"
    );
    // Closing the refused connection did not fold the log into the file.
    assert_eq!(
        std::fs::read(copy.join("state.sqlite3")).unwrap(),
        main_before
    );
    assert_eq!(
        std::fs::read(copy.join("state.sqlite3-wal")).unwrap(),
        log_before
    );
}

#[test]
fn a_path_that_looks_like_a_uri_stays_a_path() {
    assert_eq!(
        crate::open::literal_path("file:state.db"),
        "./file:state.db"
    );
    assert_eq!(
        crate::open::literal_path("file:state.db?mode=memory"),
        "./file:state.db?mode=memory"
    );
    assert_eq!(
        crate::open::literal_path("/home/u/.pam/state.sqlite3"),
        "/home/u/.pam/state.sqlite3"
    );
    assert_eq!(crate::open::literal_path("state.sqlite3"), "state.sqlite3");
}

/// On macOS a plain `fsync` stops at the drive's cache. Checkpoints, where
/// the main file is rewritten and the log recycled, go through to the drive.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn checkpoints_are_synced_through_to_the_drive_on_macos() {
    let dir = tempfile::tempdir().unwrap();
    let store = file_store(dir.path()).await;
    assert_eq!(pragma_i64(&store, "checkpoint_fullfsync").await, 1);
}

#[tokio::test]
async fn every_open_of_a_file_keeps_the_same_settings() {
    let dir = tempfile::tempdir().unwrap();
    // New, reopened after a close, and reopened after a drop.
    for round in 0..3 {
        let store = file_store(dir.path()).await;
        let mode: String = store.raw_scalar("PRAGMA journal_mode", ()).await.unwrap();
        assert_eq!(mode, "wal", "round {round}");
        assert_eq!(pragma_i64(&store, "synchronous").await, 2, "round {round}");
        assert_eq!(pragma_i64(&store, "foreign_keys").await, 1, "round {round}");
        assert_eq!(
            pragma_i64(&store, "secure_delete").await,
            1,
            "round {round}"
        );
        store.check_integrity().await.unwrap();
        if round == 0 {
            store.close().await.unwrap();
        }
    }
    assert!(!dir.path().join("backup").exists());
}
