use turso::Builder;

use crate::{Store, StoreError, migrations};

#[tokio::test]
async fn fresh_open_lands_on_latest_version() {
    let store = Store::open_in_memory().await.unwrap();
    assert_eq!(
        store.schema_version().await.unwrap(),
        migrations::latest_version()
    );
    assert_eq!(store.schema_version().await.unwrap(), 12);
}

#[tokio::test]
async fn all_nine_tables_exist() {
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
        "connector",
    ] {
        let mut rows = store
            .lock()
            .await
            .unwrap()
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
            supported: 12
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

    // Opening runs migrations 2 through 6: the idempotency column
    // exists, the model job table exists, the connector table exists,
    // and the version advances.
    let store = Store::open(&path).await.unwrap();
    assert_eq!(store.schema_version().await.unwrap(), 12);
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
    assert_eq!(store.schema_version().await.unwrap(), 12);
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

#[tokio::test]
async fn v4_database_upgrades_to_v5() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");

    // Build a genuine v4 database by hand: apply migrations 1..=4 and
    // stamp their version, so the `connector` table does not exist yet.
    let db = Builder::new_local(path.to_str().unwrap())
        .build()
        .await
        .unwrap();
    let conn = db.connect().unwrap();
    for migration in &migrations::MIGRATIONS[..4] {
        conn.execute_batch(migration.sql).await.unwrap();
    }
    conn.execute("PRAGMA user_version = 4", ()).await.unwrap();
    drop((conn, db));

    let store = Store::open(&path).await.unwrap();
    assert_eq!(store.schema_version().await.unwrap(), 12);

    let mut rows = store
        .lock()
        .await
        .unwrap()
        .query(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'connector'",
            (),
        )
        .await
        .unwrap();
    let count: i64 = rows.next().await.unwrap().unwrap().get(0).unwrap();
    assert_eq!(count, 1, "migration 5 did not create the connector table");

    // `enabled` rejects anything but 0 or 1.
    let err = store
        .lock()
        .await
        .unwrap()
        .execute(
            "INSERT INTO connector (id, enabled, updated_ts) VALUES ('x', 2, 0)",
            (),
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("check"),
        "enabled CHECK not enforced: {err}"
    );

    // `last_test_status` only accepts 'passed' or 'failed'.
    let err = store
        .lock()
        .await
        .unwrap()
        .execute(
            "INSERT INTO connector (id, enabled, last_test_status, updated_ts)
             VALUES ('y', 0, 'maybe', 0)",
            (),
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("check"),
        "last_test_status CHECK not enforced: {err}"
    );
}

/// Column names of the `evidence` table, via `PRAGMA table_info`.
async fn evidence_columns(store: &Store) -> Vec<String> {
    let mut rows = store
        .lock()
        .await
        .unwrap()
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

#[tokio::test]
async fn v5_queued_requests_upgrade_without_authorization_or_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.sqlite3");
    let db = Builder::new_local(path.to_str().unwrap())
        .build()
        .await
        .unwrap();
    let conn = db.connect().unwrap();
    for migration in migrations::MIGRATIONS.iter().take(5) {
        conn.execute_batch(migration.sql).await.unwrap();
    }
    conn.execute("INSERT INTO request(id,capability,repo,caller_agent,args_json,state,created_ts,updated_ts) VALUES ('old','echo','repo','agent','{}','queued',1,1)", ()).await.unwrap();
    conn.execute("PRAGMA user_version = 5", ()).await.unwrap();
    drop((conn, db));
    let store = Store::open(&path).await.unwrap();
    let row = store.get_request("old").await.unwrap().unwrap();
    assert_eq!(row.expires_at_ms, None);
    assert!(!row.queue_authorized);
}

/// A genuine v11 database: every migration up to 11, stamped 11, holding
/// the grants, requests and audit row a daemon of that version leaves behind.
async fn build_v11_database(path: &std::path::Path) {
    let db = Builder::new_local(path.to_str().unwrap())
        .build()
        .await
        .unwrap();
    let conn = db.connect().unwrap();
    for migration in migrations::MIGRATIONS.iter().filter(|m| m.version <= 11) {
        conn.execute_batch(migration.sql).await.unwrap();
    }
    conn.execute("PRAGMA user_version = 11", ()).await.unwrap();
    for (capability, granted, revoked) in [
        // Two revocations inside one second, a later one, and a live grant.
        ("echo", 10, Some(100)),
        ("flow.step:deploy/push", 11, Some(100)),
        ("flow.run", 12, Some(200)),
        ("flow.step:deploy/merge", 13, None::<i64>),
    ] {
        conn.execute(
            "INSERT INTO \"grant\" (capability, scope, granted_ts, revoked_ts)
             VALUES (?1, 'global', ?2, ?3)",
            turso::params![capability, granted, revoked],
        )
        .await
        .unwrap();
    }
    for (id, capability, revision) in [
        // Admitted between the two same-second revocations.
        ("echo_mid", "echo", 1),
        // Admitted after them, before the flow.run revocation.
        ("echo_after", "echo", 2),
        ("flow_before", "flow.run", 2),
        // Admitted after every revocation.
        ("flow_after", "flow.run", 3),
    ] {
        conn.execute(
            "INSERT INTO request (id, capability, repo, caller_agent, args_json, state,
                 created_ts, updated_ts, expires_at_ms, authorization_revision, queue_authorized)
             VALUES (?1, ?2, '/repo', 'agent', '{}', 'done', 1, 1, 9000000000000, ?3, 1)",
            turso::params![id, capability, revision],
        )
        .await
        .unwrap();
    }
    conn.execute(
        "INSERT INTO audit (request_id, action, decision, actor, detail, ts)
         VALUES ('echo_after', 'execute', 'allow', 'policy', 'kept', 5)",
        (),
    )
    .await
    .unwrap();
    drop((conn, db));
}

#[tokio::test]
async fn v11_database_gains_indexes_revocation_order_and_immutability() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");

    build_v11_database(&path).await;

    let store = Store::open(&path).await.unwrap();
    assert_eq!(store.schema_version().await.unwrap(), 12);

    // Revocations are numbered in order; the two that share a second share
    // the higher number, so a request admitted between them is voided
    // rather than trusted.
    let conn = store.lock().await.unwrap();
    let mut rows = conn
        .query(
            "SELECT capability, revoked_seq FROM \"grant\" ORDER BY id",
            (),
        )
        .await
        .unwrap();
    let mut sequence = Vec::new();
    while let Some(row) = rows.next().await.unwrap() {
        sequence.push((
            row.get::<String>(0).unwrap(),
            row.get::<Option<i64>>(1).unwrap(),
        ));
    }
    assert_eq!(
        sequence,
        [
            ("echo".to_owned(), Some(2)),
            ("flow.step:deploy/push".to_owned(), Some(2)),
            ("flow.run".to_owned(), Some(3)),
            ("flow.step:deploy/merge".to_owned(), None),
        ]
    );
    for name in [
        "request_created_idx",
        "request_updated_idx",
        "evidence_ts_idx",
        "evidence_kind_ts_idx",
        "grant_capability_idx",
        "audit_append_only",
        "evidence_view_immutable",
    ] {
        let mut rows = conn
            .query("SELECT COUNT(*) FROM sqlite_master WHERE name = ?1", [name])
            .await
            .unwrap();
        let count: i64 = rows.next().await.unwrap().unwrap().get(0).unwrap();
        assert_eq!(count, 1, "{name} missing after the upgrade");
    }
    // The upgraded trail is append-only too, and kept its rows.
    assert!(
        conn.execute("UPDATE audit SET detail = 'rewritten'", ())
            .await
            .is_err()
    );
    drop(rows);
    drop(conn);
    assert_eq!(
        store.audit_for_request("echo_after").await.unwrap()[0]
            .detail
            .as_deref(),
        Some("kept")
    );

    for (id, current) in [
        ("echo_mid", false),
        ("echo_after", true),
        ("flow_before", false),
        ("flow_after", true),
    ] {
        assert_eq!(
            store.request_authorization_current(id).await.unwrap(),
            current,
            "{id}"
        );
    }
    // The global figure old requests captured still means what it meant.
    assert_eq!(store.grant_revocation_revision().await.unwrap(), 3);
    // A revocation after the upgrade continues the sequence.
    store.revoke_grant("flow.step:deploy/merge").await.unwrap();
    assert!(
        !store
            .request_authorization_current("flow_after")
            .await
            .unwrap()
    );
    assert!(
        store
            .request_authorization_current("echo_after")
            .await
            .unwrap()
    );
}
