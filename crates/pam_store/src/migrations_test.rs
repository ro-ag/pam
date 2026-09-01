use turso::Builder;

use crate::{Store, StoreError, migrations};

#[tokio::test]
async fn fresh_open_lands_on_latest_version() {
    let store = Store::open_in_memory().await.unwrap();
    assert_eq!(
        store.schema_version().await.unwrap(),
        migrations::latest_version()
    );
    assert_eq!(store.schema_version().await.unwrap(), 2);
}

#[tokio::test]
async fn all_seven_tables_exist() {
    let store = Store::open_in_memory().await.unwrap();
    for table in [
        "request", "audit", "evidence", "grant", "approval", "caller", "setting",
    ] {
        let mut rows = store
            .conn
            .query(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
            )
            .await
            .unwrap();
        let count: i64 = rows.next().await.unwrap().unwrap().get(0).unwrap();
        assert_eq!(count, 1, "table {table} missing");
    }
}

#[tokio::test]
async fn reopen_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");

    let store = Store::open(&path).await.unwrap();
    let version = store.schema_version().await.unwrap();
    drop(store);

    let store = Store::open(&path).await.unwrap();
    assert_eq!(store.schema_version().await.unwrap(), version);
    // Schema untouched: inserting into an existing table still works.
    store.set_setting("k", "1").await.unwrap();
}

#[tokio::test]
async fn newer_database_version_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    drop(Store::open(&path).await.unwrap());

    let db = Builder::new_local(path.to_str().unwrap())
        .build()
        .await
        .unwrap();
    let conn = db.connect().unwrap();
    conn.execute("PRAGMA user_version = 999", ()).await.unwrap();
    drop((conn, db));

    let err = Store::open(&path).await.unwrap_err();
    assert!(matches!(
        err,
        StoreError::VersionTooNew {
            found: 999,
            supported: 2
        }
    ));
    let message = err.to_string();
    assert!(message.contains("999"), "unhelpful message: {message}");
    assert!(message.contains("newer"), "unhelpful message: {message}");
}

#[tokio::test]
async fn v1_database_upgrades_to_v2() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");

    // Build a genuine v1 database by hand: apply only the first
    // migration and stamp its version.
    let db = Builder::new_local(path.to_str().unwrap())
        .build()
        .await
        .unwrap();
    let conn = db.connect().unwrap();
    conn.execute_batch(migrations::MIGRATIONS[0].sql)
        .await
        .unwrap();
    conn.execute("PRAGMA user_version = 1", ()).await.unwrap();
    drop((conn, db));

    // Opening runs migration 2: the idempotency column exists and the
    // version advances.
    let store = Store::open(&path).await.unwrap();
    assert_eq!(store.schema_version().await.unwrap(), 2);
    store
        .insert_request("req_1", "echo", "ro-ag/pam", "claude", "{}", Some("key-1"))
        .await
        .unwrap();
    let row = store.get_request("req_1").await.unwrap().unwrap();
    assert_eq!(row.idempotency_key.as_deref(), Some("key-1"));
}

#[test]
fn migrations_are_strictly_ordered() {
    let mut previous = 0;
    for migration in migrations::MIGRATIONS {
        assert!(migration.version > previous, "migrations out of order");
        previous = migration.version;
    }
}
