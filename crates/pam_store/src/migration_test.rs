use std::fs;

use rusqlite::Connection;

use super::{Store, StoreError};
use crate::store::{
    LATEST_SCHEMA_VERSION, busy_timeout_ms, database_path, migration_versions, open_connection,
};

#[test]
fn migrations_are_ordered_and_database_configuration_survives_reopen() {
    assert_eq!(
        migration_versions(),
        (1..=LATEST_SCHEMA_VERSION).collect::<Vec<_>>()
    );
    let (directory, path) = database_path("migration-config");

    for _ in 0..2 {
        let connection = open_connection(&path).unwrap();
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let foreign_keys: u32 = connection
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .unwrap();
        let journal_mode: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        let busy_timeout: i64 = connection
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .unwrap();

        assert_eq!(version, LATEST_SCHEMA_VERSION);
        assert_eq!(foreign_keys, 1);
        assert_eq!(journal_mode, "wal");
        assert_eq!(u64::try_from(busy_timeout).unwrap(), busy_timeout_ms());
    }

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn migration_upgrades_an_existing_empty_schema_without_replacing_it() {
    let (directory, path) = database_path("migration-upgrade");
    fs::create_dir_all(&directory).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute("CREATE TABLE sentinel(value TEXT NOT NULL)", [])
        .unwrap();
    connection
        .execute("INSERT INTO sentinel(value) VALUES ('preserved')", [])
        .unwrap();
    drop(connection);

    let connection = open_connection(&path).unwrap();
    let sentinel: String = connection
        .query_row("SELECT value FROM sentinel", [], |row| row.get(0))
        .unwrap();
    assert_eq!(sentinel, "preserved");
    assert!(
        connection
            .query_row(
                "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'requests'",
                [],
                |_| Ok(())
            )
            .is_ok()
    );

    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn evidence_migration_upgrades_v1_without_replacing_scheduler_data() {
    let (directory, path) = database_path("migration-v1-evidence");
    fs::create_dir_all(&directory).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(include_str!("../migrations/0001_initial.sql"))
        .unwrap();
    connection.pragma_update(None, "user_version", 1).unwrap();
    connection
        .execute("INSERT INTO projects(project_id) VALUES ('project')", [])
        .unwrap();
    connection
        .execute(
            "INSERT INTO requests(
                request_id, caller_id, project_id, idempotency_key,
                operation_kind, operation, queue_sequence, state, accepted_at_ms
             ) VALUES (
                'request', 'caller', 'project', 'key',
                'test.operation', X'00', 1, 'queued', 10
             )",
            [],
        )
        .unwrap();
    drop(connection);

    let connection = open_connection(&path).unwrap();
    let request_count: u32 = connection
        .query_row("SELECT COUNT(*) FROM requests", [], |row| row.get(0))
        .unwrap();
    let evidence_table_count: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'table' AND name IN ('evidence_blobs', 'evidence_handles')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(request_count, 1);
    assert_eq!(evidence_table_count, 2);
    assert_eq!(version, LATEST_SCHEMA_VERSION);

    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn future_schema_is_refused_without_deleting_the_database() {
    let (directory, path) = database_path("future-schema");
    fs::create_dir_all(&directory).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "user_version", LATEST_SCHEMA_VERSION + 1)
        .unwrap();
    connection
        .execute("CREATE TABLE future_data(value TEXT)", [])
        .unwrap();
    drop(connection);

    let Err(error) = Store::open(&path) else {
        panic!("future database should be refused")
    };
    assert!(matches!(
        error,
        StoreError::FutureSchema {
            found,
            supported: LATEST_SCHEMA_VERSION
        } if found == LATEST_SCHEMA_VERSION + 1
    ));
    let connection = Connection::open(&path).unwrap();
    let future_table_count: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'table' AND name = 'future_data'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(future_table_count, 1);
    assert!(path.exists());

    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn corrupt_database_is_refused_without_rewriting_its_bytes() {
    let (directory, path) = database_path("corrupt");
    fs::create_dir_all(&directory).unwrap();
    let original = b"not a sqlite database\0with retained bytes";
    fs::write(&path, original).unwrap();

    let Err(error) = Store::open(&path) else {
        panic!("corrupt database should be refused")
    };
    assert!(matches!(error, StoreError::Sqlite(_)));
    assert_eq!(fs::read(&path).unwrap(), original);

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn orphaned_foreign_key_is_refused_after_open() {
    let (directory, path) = database_path("foreign-key-orphan");
    drop(open_connection(&path).unwrap());
    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .unwrap();
    connection
        .execute(
            "INSERT INTO requests(
                request_id, caller_id, project_id, idempotency_key,
                operation_kind, operation, queue_sequence, state, accepted_at_ms
             ) VALUES (
                'orphan-request', 'caller', 'missing-project', 'key',
                'test.operation', X'00', 1, 'queued', 10
             )",
            [],
        )
        .unwrap();
    drop(connection);

    let Err(error) = Store::open(&path) else {
        panic!("orphaned database should be refused")
    };
    assert!(matches!(error, StoreError::ForeignKeyCheckFailed(_)));
    let connection = Connection::open(&path).unwrap();
    let orphan_count: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM requests WHERE request_id = 'orphan-request'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(orphan_count, 1);

    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}
