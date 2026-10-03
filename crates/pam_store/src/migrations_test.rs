use rusqlite::{Connection, params};

use crate::{Store, StoreError, migrations};

#[tokio::test]
async fn fresh_open_lands_on_latest_version() {
    let store = Store::open_in_memory().await.unwrap();
    assert_eq!(
        store.schema_version().await.unwrap(),
        migrations::latest_version()
    );
    assert_eq!(store.schema_version().await.unwrap(), 15);
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
        let count: i64 = store
            .raw_scalar(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
            )
            .await
            .unwrap();
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

    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA user_version = 999").unwrap();
    drop(conn);

    let err = Store::open(&path).await.unwrap_err();
    assert!(matches!(
        err,
        StoreError::VersionTooNew {
            found: 999,
            supported: 15
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
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(migrations::MIGRATIONS[0].sql).unwrap();
    conn.execute_batch("PRAGMA user_version = 1").unwrap();
    drop(conn);

    // Opening runs migrations 2 through 6: the idempotency column
    // exists, the model job table exists, the connector table exists,
    // and the version advances.
    let store = Store::open(&path).await.unwrap();
    assert_eq!(store.schema_version().await.unwrap(), 15);
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
    let conn = Connection::open(&path).unwrap();
    for migration in &migrations::MIGRATIONS[..3] {
        conn.execute_batch(migration.sql).unwrap();
    }
    conn.execute_batch("PRAGMA user_version = 3").unwrap();
    drop(conn);

    let store = Store::open(&path).await.unwrap();
    assert_eq!(store.schema_version().await.unwrap(), 15);
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
    let conn = Connection::open(&path).unwrap();
    for migration in &migrations::MIGRATIONS[..4] {
        conn.execute_batch(migration.sql).unwrap();
    }
    conn.execute_batch("PRAGMA user_version = 4").unwrap();
    drop(conn);

    let store = Store::open(&path).await.unwrap();
    assert_eq!(store.schema_version().await.unwrap(), 15);

    let count: i64 = store
        .raw_scalar(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'connector'",
            (),
        )
        .await
        .unwrap();
    assert_eq!(count, 1, "migration 5 did not create the connector table");

    // `enabled` rejects anything but 0 or 1.
    let err = store
        .raw_execute(
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
        .raw_execute(
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
    store
        .raw(|conn| {
            let mut stmt = conn.prepare("PRAGMA table_info(evidence)")?;
            let mut rows = stmt.query(())?;
            let mut names = Vec::new();
            while let Some(row) = rows.next()? {
                names.push(row.get(1)?);
            }
            Ok(names)
        })
        .await
        .unwrap()
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
    let conn = Connection::open(&path).unwrap();
    for migration in migrations::MIGRATIONS.iter().take(5) {
        conn.execute_batch(migration.sql).unwrap();
    }
    conn.execute("INSERT INTO request(id,capability,repo,caller_agent,args_json,state,created_ts,updated_ts) VALUES ('old','echo','repo','agent','{}','queued',1,1)", ()).unwrap();
    conn.execute_batch("PRAGMA user_version = 5").unwrap();
    drop(conn);
    let store = Store::open(&path).await.unwrap();
    let row = store.get_request("old").await.unwrap().unwrap();
    assert_eq!(row.expires_at_ms, None);
    assert!(!row.queue_authorized);
}

/// A genuine v11 database: every migration up to 11, stamped 11, holding
/// the grants, requests and audit row a daemon of that version leaves behind.
fn build_v11_database(path: &std::path::Path) {
    let conn = Connection::open(path).unwrap();
    for migration in migrations::MIGRATIONS.iter().filter(|m| m.version <= 11) {
        conn.execute_batch(migration.sql).unwrap();
    }
    conn.execute_batch("PRAGMA user_version = 11").unwrap();
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
            params![capability, granted, revoked],
        )
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
            params![id, capability, revision],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO audit (request_id, action, decision, actor, detail, ts)
         VALUES ('echo_after', 'execute', 'allow', 'policy', 'kept', 5)",
        (),
    )
    .unwrap();
    drop(conn);
}

#[tokio::test]
async fn v11_database_gains_indexes_revocation_order_and_immutability() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");

    build_v11_database(&path);

    let store = Store::open(&path).await.unwrap();
    assert_eq!(store.schema_version().await.unwrap(), 15);

    // Revocations are numbered in order; the two that share a second share
    // the higher number, so a request admitted between them is voided
    // rather than trusted.
    let sequence = store
        .raw(|conn| {
            let mut stmt =
                conn.prepare("SELECT capability, revoked_seq FROM \"grant\" ORDER BY id")?;
            let mut rows = stmt.query(())?;
            let mut sequence = Vec::new();
            while let Some(row) = rows.next()? {
                sequence.push((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?));
            }
            Ok(sequence)
        })
        .await
        .unwrap();
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
        let count: i64 = store
            .raw_scalar("SELECT COUNT(*) FROM sqlite_master WHERE name = ?1", [name])
            .await
            .unwrap();
        assert_eq!(count, 1, "{name} missing after the upgrade");
    }
    // The upgraded trail is append-only too, and kept its rows.
    assert!(
        store
            .raw_execute("UPDATE audit SET detail = 'rewritten'", ())
            .await
            .is_err()
    );
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

/// A genuine v12 database (the version before the origin columns): every
/// migration up to 12, stamped 12, holding rows a daemon of that version
/// left behind in each lifecycle state.
fn build_v12_database(path: &std::path::Path) {
    let conn = Connection::open(path).unwrap();
    for migration in migrations::MIGRATIONS.iter().filter(|m| m.version <= 12) {
        conn.execute_batch(migration.sql).unwrap();
    }
    conn.execute_batch("PRAGMA user_version = 12").unwrap();
    for (id, capability, state) in [
        ("old_queued", "echo", "queued"),
        ("old_done", "flow.run", "done"),
        ("old_admin", "admin.grants.list", "done"),
    ] {
        conn.execute(
            "INSERT INTO request (id, capability, repo, caller_agent, args_json, state,
                 created_ts, updated_ts, expires_at_ms, authorization_revision, queue_authorized)
             VALUES (?1, ?2, '/repo', 'agent', '{}', ?3, 1, 1, 9000000000000, 0, 1)",
            params![id, capability, state],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO audit (request_id, action, decision, actor, detail, ts)
         VALUES ('old_done', 'execute', 'allow', 'system', 'kept', 5)",
        (),
    )
    .unwrap();
    drop(conn);
}

/// The upgrade from the previous version: existing rows survive, read back
/// as public with no recorded peer (nothing is claimed about a connection
/// nobody recorded), and the recovery page — which selects the same columns
/// through its own guarded list — still reads them.
#[tokio::test]
async fn v12_database_gains_the_request_origin_columns() {
    use crate::{RequestIngress, RequestOrigin, RequestState};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    build_v12_database(&path);

    let store = Store::open(&path).await.unwrap();
    assert_eq!(store.schema_version().await.unwrap(), 15);

    for id in ["old_queued", "old_done", "old_admin"] {
        let row = store.get_request(id).await.unwrap().unwrap();
        assert_eq!(row.origin, RequestOrigin::PUBLIC, "{id}");
    }
    // The rows kept everything else they had.
    let done = store.get_request("old_done").await.unwrap().unwrap();
    assert_eq!(done.state, RequestState::Done);
    assert_eq!(done.expires_at_ms, Some(9_000_000_000_000));
    assert!(done.queue_authorized);
    assert_eq!(
        store.audit_for_request("old_done").await.unwrap()[0]
            .detail
            .as_deref(),
        Some("kept")
    );
    let page = store
        .queued_recovery_page(None, 1024 * 1024)
        .await
        .unwrap()
        .expect("no oversized row");
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].id, "old_queued");
    assert_eq!(page[0].origin, RequestOrigin::PUBLIC);

    // A row written after the upgrade carries its origin.
    let origin = RequestOrigin {
        ingress: RequestIngress::Public,
        peer_uid: Some(501),
        peer_pid: Some(4242),
        relayed: true,
    };
    store
        .insert_admitted_request_from(
            "new_public",
            "echo",
            "/repo",
            "agent",
            "{}",
            None,
            9_000_000_000_000,
            &origin,
        )
        .await
        .unwrap();
    let row = store.get_request("new_public").await.unwrap().unwrap();
    assert_eq!(row.origin, origin);

    // The column constraints came with the upgrade: an ingress outside the
    // two planes, or a relayed flag that is not a flag, is refused.
    for (ingress, relayed) in [("gui", 0), ("public", 2)] {
        assert!(
            store
                .raw_execute(
                    "INSERT INTO request (id, capability, repo, caller_agent, args_json, state,
                     created_ts, updated_ts, ingress, relayed)
                 VALUES ('bad', 'echo', '/repo', 'agent', '{}', 'done', 1, 1, ?1, ?2)",
                    (ingress, relayed),
                )
                .await
                .is_err(),
            "ingress {ingress:?} relayed {relayed} was accepted"
        );
    }
}

/// The downgrade answer. A binary only ever knows the migrations compiled
/// into it; handed a database stamped past them it refuses before it reads a
/// row. The boundary migration's version (14) is above every version a
/// binary on the previous engine knows (11 in release 0.4.3, 13 in the last
/// development build), so such a binary is the "older binary" of this test;
/// the database it is handed is at the latest version (15).
#[tokio::test]
async fn a_binary_that_knows_fewer_migrations_refuses_this_database_legibly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    let store = Store::open(&path).await.unwrap();
    store.set_setting("kept", "yes").await.unwrap();
    store.close().await.unwrap();
    assert_eq!(migrations::ENGINE_BOUNDARY, 14);

    let mut conn = Connection::open(&path).unwrap();
    for known in [11, 13] {
        let older = &migrations::MIGRATIONS[..known];
        let error = migrations::run_with(&mut conn, older).unwrap_err();
        assert!(
            matches!(
                error,
                StoreError::VersionTooNew { found: 15, supported } if supported == i64::try_from(known).unwrap()
            ),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            format!(
                "database schema version 15 is newer than this binary supports (max {known}); \
                 upgrade pam instead of downgrading the database"
            )
        );
    }
    // Refusing changed nothing.
    assert_eq!(migrations::current_version(&conn).unwrap(), 15);
    let kept: String = conn
        .query_row("SELECT value FROM setting WHERE key = 'kept'", (), |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(kept, "yes");
}

fn build_v14_database(path: &std::path::Path) {
    let conn = Connection::open(path).unwrap();
    for migration in migrations::MIGRATIONS.iter().filter(|m| m.version <= 14) {
        conn.execute_batch(migration.sql).unwrap();
    }
    conn.execute_batch("PRAGMA user_version = 14").unwrap();
    for (id, kind, model_id, source, state, done, total, detail) in [
        (
            "job_dl",
            "download",
            "qwen/one",
            Some("https://huggingface.co/qwen/one.gguf"),
            "done",
            12,
            Some(12),
            Some(r#"{"sha256":"ab"}"#),
        ),
        (
            "job_vf",
            "verify",
            "qwen/two",
            None,
            "failed",
            3,
            None,
            Some(r#"{"cause":"digest_mismatch"}"#),
        ),
        (
            "job_run",
            "download",
            "qwen/three",
            None,
            "running",
            0,
            Some(99),
            None,
        ),
    ] {
        conn.execute(
            "INSERT INTO model_job (id, kind, model_id, source, state, bytes_done, bytes_total,
                 detail, created_ts, updated_ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 7, 8)",
            params![id, kind, model_id, source, state, done, total, detail],
        )
        .unwrap();
    }
    drop(conn);
}

/// The upgrade from the previous version: `model_job` is rebuilt so its
/// `kind` admits `import`, every row survives with every column, the state
/// index comes back, and the constraint still refuses any other kind.
#[tokio::test]
async fn v14_database_admits_import_jobs_and_keeps_its_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    build_v14_database(&path);

    let store = Store::open(&path).await.unwrap();
    assert_eq!(store.schema_version().await.unwrap(), 15);

    let jobs = store.list_model_jobs(10).await.unwrap();
    let by_id = |id: &str| jobs.iter().find(|job| job.id == id).expect(id).clone();
    let download = by_id("job_dl");
    assert_eq!(download.kind, "download");
    assert_eq!(download.model_id, "qwen/one");
    assert_eq!(
        download.source.as_deref(),
        Some("https://huggingface.co/qwen/one.gguf")
    );
    assert_eq!(download.state, "done");
    assert_eq!(download.bytes_done, 12);
    assert_eq!(download.bytes_total, Some(12));
    assert_eq!(download.detail.as_deref(), Some(r#"{"sha256":"ab"}"#));
    assert_eq!(download.created_ts, 7);
    assert_eq!(download.updated_ts, 8);
    let verify = by_id("job_vf");
    assert_eq!(verify.kind, "verify");
    assert_eq!(verify.state, "failed");
    assert_eq!(verify.bytes_total, None);
    assert_eq!(by_id("job_run").state, "running");
    assert_eq!(jobs.len(), 3);

    // The new kind is accepted and reads back; the index is in place.
    store
        .insert_model_job(
            "job_imp",
            "import",
            "imported/local",
            Some("/srv/local.gguf"),
            Some(5),
        )
        .await
        .unwrap();
    let imported = store
        .list_model_jobs(10)
        .await
        .unwrap()
        .into_iter()
        .find(|job| job.id == "job_imp")
        .unwrap();
    assert_eq!(imported.kind, "import");
    assert_eq!(imported.source.as_deref(), Some("/srv/local.gguf"));
    let index: i64 = store
        .raw_scalar(
            "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'model_job_state_idx'",
            (),
        )
        .await
        .unwrap();
    assert_eq!(index, 1);
    let leftovers: i64 = store
        .raw_scalar(
            "SELECT count(*) FROM sqlite_master WHERE name = 'model_job_v15'",
            (),
        )
        .await
        .unwrap();
    assert_eq!(
        leftovers, 0,
        "the scratch table was renamed, not left behind"
    );

    // The constraint came with the rebuild: a kind outside the three is refused.
    assert!(
        store
            .insert_model_job("job_bad", "upload", "x/y", None, None)
            .await
            .is_err()
    );
}
