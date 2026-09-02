use turso::Builder;

use crate::{Store, StoreError, migrations};

#[tokio::test]
async fn fresh_open_lands_on_latest_version() {
    let store = Store::open_in_memory().await.unwrap();
    assert_eq!(
        store.schema_version().await.unwrap(),
        migrations::latest_version()
    );
    assert_eq!(store.schema_version().await.unwrap(), 4);
}

#[tokio::test]
async fn all_eight_tables_exist() {
    let store = Store::open_in_memory().await.unwrap();
    for table in [
        "request",
        "audit",
        "evidence",
        "grant",
        "approval",
        "caller",
        "setting",
        "model_job",
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
            supported: 4
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

    // Opening runs migrations 2, 3 and 4: the idempotency column exists,
    // the model job table exists, and the version advances.
    let store = Store::open(&path).await.unwrap();
    assert_eq!(store.schema_version().await.unwrap(), 4);
    store
        .insert_model_job("job_1", "verify", "qwen/tiny", None, None)
        .await
        .unwrap();
    store
        .insert_request("req_1", "echo", "ro-ag/pam", "claude", "{}", Some("key-1"))
        .await
        .unwrap();
    let row = store.get_request("req_1").await.unwrap().unwrap();
    assert_eq!(row.idempotency_key.as_deref(), Some("key-1"));
}

#[tokio::test]
async fn v3_database_gains_meta_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");

    // Build a genuine v3 database by hand: apply migrations 1..=3 and
    // stamp their version, so the evidence table has no `meta_json`.
    let db = Builder::new_local(path.to_str().unwrap())
        .build()
        .await
        .unwrap();
    let conn = db.connect().unwrap();
    for migration in &migrations::MIGRATIONS[..3] {
        conn.execute_batch(migration.sql).await.unwrap();
    }
    conn.execute("PRAGMA user_version = 3", ()).await.unwrap();
    drop((conn, db));

    let store = Store::open(&path).await.unwrap();
    assert_eq!(store.schema_version().await.unwrap(), 4);
    assert!(
        evidence_columns(&store)
            .await
            .contains(&"meta_json".to_owned()),
        "migration 4 did not add evidence.meta_json"
    );

    // The upgraded column is writable, and existing rows read back NULL.
    store
        .insert_request("req_1", "echo", "ro-ag/pam", "claude", "{}", None)
        .await
        .unwrap();
    store
        .insert_evidence("ev_1", "req_1", "log.source", b"hello", None)
        .await
        .unwrap();
    let row = store.get_evidence("ev_1").await.unwrap().unwrap();
    assert_eq!(row.meta_json, None);
}

/// Column names of the `evidence` table, via `PRAGMA table_info`.
async fn evidence_columns(store: &Store) -> Vec<String> {
    let mut rows = store
        .conn
        .query("PRAGMA table_info(evidence)", ())
        .await
        .unwrap();
    let mut names = Vec::new();
    while let Some(row) = rows.next().await.unwrap() {
        names.push(row.get(1).unwrap());
    }
    names
}

#[test]
fn migrations_are_strictly_ordered() {
    let mut previous = 0;
    for migration in migrations::MIGRATIONS {
        assert!(migration.version > previous, "migrations out of order");
        previous = migration.version;
    }
}
