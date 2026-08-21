use std::fs;

use rusqlite::{Connection, params};

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
fn caller_migration_upgrades_v2_without_replacing_scheduler_or_evidence_data() {
    let (directory, path) = database_path("migration-v2-callers");
    fs::create_dir_all(&directory).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(include_str!("../migrations/0001_initial.sql"))
        .unwrap();
    connection
        .execute_batch(include_str!("../migrations/0002_evidence.sql"))
        .unwrap();
    connection.pragma_update(None, "user_version", 2).unwrap();
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
                'test.operation', X'010203', 1, 'queued', 10
             )",
            [],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO events(request_id, sequence, kind, payload, recorded_at_ms)
             VALUES ('request', 1, 'accepted', X'040506', 10)",
            [],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO evidence_blobs(digest, size_bytes)
             VALUES ('sha256:0000000000000000000000000000000000000000000000000000000000000000', 3)",
            [],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO evidence_handles(
                project_id, handle, digest, media_type, retention, redaction, created_at_ms
             ) VALUES (
                'project', 'evidence://preserved',
                'sha256:0000000000000000000000000000000000000000000000000000000000000000',
                'application/octet-stream', 'project', 'redacted', 11
             )",
            [],
        )
        .unwrap();
    drop(connection);

    let connection = open_connection(&path).unwrap();
    let operation: Vec<u8> = connection
        .query_row(
            "SELECT operation FROM requests WHERE request_id = 'request'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let event_payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM events WHERE request_id = 'request' AND sequence = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let evidence: (String, i64) = connection
        .query_row(
            "SELECT handle, size_bytes
             FROM evidence_handles JOIN evidence_blobs USING (digest)
             WHERE project_id = 'project'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let callers_table_count: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'table' AND name = 'callers'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();

    assert_eq!(operation, [1, 2, 3]);
    assert_eq!(event_payload, [4, 5, 6]);
    assert_eq!(evidence, ("evidence://preserved".to_owned(), 3));
    assert_eq!(callers_table_count, 1);
    assert_eq!(version, LATEST_SCHEMA_VERSION);

    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn policy_migration_upgrades_v3_without_replacing_caller_request_or_evidence_data() {
    let (directory, path) = database_path("migration-v3-policy");
    fs::create_dir_all(&directory).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(include_str!("../migrations/0001_initial.sql"))
        .unwrap();
    connection
        .execute_batch(include_str!("../migrations/0002_evidence.sql"))
        .unwrap();
    connection
        .execute_batch(include_str!("../migrations/0003_callers.sql"))
        .unwrap();
    connection.pragma_update(None, "user_version", 3).unwrap();
    connection
        .execute(
            "INSERT INTO callers(
                caller_id, credential_digest, registered_at_ms, revoked_at_ms
             ) VALUES ('preserved-caller', zeroblob(32), 9, NULL)",
            [],
        )
        .unwrap();
    connection
        .execute("INSERT INTO projects(project_id) VALUES ('project')", [])
        .unwrap();
    connection
        .execute(
            "INSERT INTO requests(
                request_id, caller_id, project_id, idempotency_key,
                operation_kind, operation, queue_sequence, state, accepted_at_ms
             ) VALUES (
                'request', 'preserved-caller', 'project', 'key',
                'test.operation', X'010203', 1, 'queued', 10
             )",
            [],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO evidence_blobs(digest, size_bytes)
             VALUES ('sha256:0000000000000000000000000000000000000000000000000000000000000000', 3)",
            [],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO evidence_handles(
                project_id, handle, digest, media_type, retention, redaction, created_at_ms
             ) VALUES (
                'project', 'evidence://preserved',
                'sha256:0000000000000000000000000000000000000000000000000000000000000000',
                'application/octet-stream', 'project', 'redacted', 11
             )",
            [],
        )
        .unwrap();
    drop(connection);

    let connection = open_connection(&path).unwrap();
    let caller: (Vec<u8>, i64, Option<i64>) = connection
        .query_row(
            "SELECT credential_digest, registered_at_ms, revoked_at_ms
             FROM callers WHERE caller_id = 'preserved-caller'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let operation: Vec<u8> = connection
        .query_row(
            "SELECT operation FROM requests WHERE request_id = 'request'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let evidence: (String, i64) = connection
        .query_row(
            "SELECT handle, size_bytes
             FROM evidence_handles JOIN evidence_blobs USING (digest)
             WHERE project_id = 'project'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let policy_table_count: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'table'
               AND name IN ('project_policies', 'capability_grants', 'approvals')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();

    assert_eq!(caller, (vec![0; 32], 9, None));
    assert_eq!(operation, [1, 2, 3]);
    assert_eq!(evidence, ("evidence://preserved".to_owned(), 3));
    assert_eq!(policy_table_count, 3);
    assert_eq!(version, LATEST_SCHEMA_VERSION);

    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn audit_migration_upgrades_v4_without_replacing_policy_data() {
    let (directory, path) = database_path("migration-v4-audit");
    fs::create_dir_all(&directory).unwrap();
    let connection = Connection::open(&path).unwrap();
    for migration in [
        include_str!("../migrations/0001_initial.sql"),
        include_str!("../migrations/0002_evidence.sql"),
        include_str!("../migrations/0003_callers.sql"),
        include_str!("../migrations/0004_policy.sql"),
    ] {
        connection.execute_batch(migration).unwrap();
    }
    connection.pragma_update(None, "user_version", 4).unwrap();
    connection
        .execute_batch(
            "INSERT INTO callers(caller_id, credential_digest, registered_at_ms)
                 VALUES ('preserved-caller', zeroblob(32), 1);
             INSERT INTO projects(project_id) VALUES ('preserved-project');
             INSERT INTO project_policies(project_id, version, default_effect, updated_at_ms)
                 VALUES ('preserved-project', 7, 'deny', 10);
             INSERT INTO capability_grants(
                 grant_id, caller_id, project_id, capability, resource_kind, resource,
                 effect, approval, expires_at_ms, revoked_at_ms, created_at_ms
             ) VALUES (
                 'preserved-grant', 'preserved-caller', 'preserved-project', 'deploy',
                 'exact', 'release', 'allow', 'once', NULL, NULL, 10
             );
             INSERT INTO approvals(
                 approval_id, caller_id, project_id, capability, resource,
                 effect_fingerprint, state, requested_at_ms, expires_at_ms
             ) VALUES (
                 'preserved-approval', 'preserved-caller', 'preserved-project',
                 'deploy', 'release', zeroblob(32), 'requested', 11, 20
             );",
        )
        .unwrap();
    drop(connection);

    let connection = open_connection(&path).unwrap();
    let preserved: (i64, String, String) = connection
        .query_row(
            "SELECT
                 (SELECT version FROM project_policies WHERE project_id = 'preserved-project'),
                 (SELECT effect FROM capability_grants WHERE grant_id = 'preserved-grant'),
                 (SELECT state FROM approvals WHERE approval_id = 'preserved-approval')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let retention_table_count: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'table'
               AND name IN ('audit_events', 'evidence_install_intents', 'evidence_gc_attempts')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let install_intent_columns: Vec<String> = connection
        .prepare("SELECT name FROM pragma_table_info('evidence_install_intents') ORDER BY cid")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(preserved, (7, "allow".to_owned(), "requested".to_owned()));
    assert_eq!(retention_table_count, 3);
    assert_eq!(
        install_intent_columns,
        [
            "attempt_id",
            "digest",
            "temporary_name",
            "size_bytes",
            "started_at_ms",
        ]
    );
    assert_eq!(version, LATEST_SCHEMA_VERSION);

    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn policy_resource_bound_migration_upgrades_v5_without_replacing_policy_data() {
    let (directory, path) = database_path("migration-v5-policy-resource-bound");
    fs::create_dir_all(&directory).unwrap();
    let connection = Connection::open(&path).unwrap();
    for migration in [
        include_str!("../migrations/0001_initial.sql"),
        include_str!("../migrations/0002_evidence.sql"),
        include_str!("../migrations/0003_callers.sql"),
        include_str!("../migrations/0004_policy.sql"),
        include_str!("../migrations/0005_audit.sql"),
    ] {
        connection.execute_batch(migration).unwrap();
    }
    connection.pragma_update(None, "user_version", 5).unwrap();
    connection
        .execute_batch(
            "INSERT INTO callers(caller_id, credential_digest, registered_at_ms)
                 VALUES ('preserved-caller', zeroblob(32), 1);
             INSERT INTO projects(project_id) VALUES ('preserved-project');
             INSERT INTO project_policies(project_id, version, default_effect, updated_at_ms)
                 VALUES ('preserved-project', 7, 'deny', 10);
             INSERT INTO capability_grants(
                 grant_id, caller_id, project_id, capability, resource_kind, resource,
                 effect, approval, expires_at_ms, revoked_at_ms, created_at_ms
             ) VALUES (
                 'preserved-grant', 'preserved-caller', 'preserved-project', 'evidence.read',
                 'exact', 'evidence:short', 'allow', 'once', NULL, NULL, 10
             );
             INSERT INTO approvals(
                 approval_id, caller_id, project_id, capability, resource,
                 effect_fingerprint, state, requested_at_ms, expires_at_ms
             ) VALUES (
                 'preserved-approval', 'preserved-caller', 'preserved-project',
                 'evidence.read', 'evidence:short', zeroblob(32), 'requested', 11, 20
             );",
        )
        .unwrap();
    drop(connection);

    let connection = open_connection(&path).unwrap();
    let preserved: (String, String) = connection
        .query_row(
            "SELECT
                 (SELECT resource FROM capability_grants WHERE grant_id = 'preserved-grant'),
                 (SELECT resource FROM approvals WHERE approval_id = 'preserved-approval')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        preserved,
        ("evidence:short".to_owned(), "evidence:short".to_owned())
    );

    let long_resource = format!("evidence:{}", "a".repeat(600));
    connection
        .execute(
            "INSERT INTO capability_grants(
                 grant_id, caller_id, project_id, capability, resource_kind, resource,
                 effect, approval, expires_at_ms, revoked_at_ms, created_at_ms
             ) VALUES (
                 'long-grant', 'preserved-caller', 'preserved-project', 'evidence.read',
                 'exact', ?1, 'allow', 'none', NULL, NULL, 12
             )",
            params![long_resource],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO approvals(
                 approval_id, caller_id, project_id, capability, resource,
                 effect_fingerprint, state, requested_at_ms, expires_at_ms
             ) VALUES (
                 'long-approval', 'preserved-caller', 'preserved-project',
                 'evidence.read', ?1, zeroblob(32), 'requested', 13, 20
             )",
            params![long_resource],
        )
        .unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, LATEST_SCHEMA_VERSION);

    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn model_registry_migration_upgrades_v6_without_replacing_existing_state() {
    let (directory, path) = database_path("migration-v6-models");
    fs::create_dir_all(&directory).unwrap();
    let connection = Connection::open(&path).unwrap();
    for migration in [
        include_str!("../migrations/0001_initial.sql"),
        include_str!("../migrations/0002_evidence.sql"),
        include_str!("../migrations/0003_callers.sql"),
        include_str!("../migrations/0004_policy.sql"),
        include_str!("../migrations/0005_audit.sql"),
        include_str!("../migrations/0006_policy_resource_bound.sql"),
    ] {
        connection.execute_batch(migration).unwrap();
    }
    connection.pragma_update(None, "user_version", 6).unwrap();
    connection
        .execute("INSERT INTO projects(project_id) VALUES ('preserved')", [])
        .unwrap();
    drop(connection);

    let connection = open_connection(&path).unwrap();
    let project_count: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM projects WHERE project_id = 'preserved'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let model_table_count: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = 'models'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let gguf_count_columns: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('models')
             WHERE name IN ('gguf_tensor_count', 'gguf_metadata_kv_count')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(project_count, 1);
    assert_eq!(model_table_count, 1);
    assert_eq!(gguf_count_columns, 2);
    assert_eq!(version, LATEST_SCHEMA_VERSION);

    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
#[allow(clippy::too_many_lines)] // Every preserved table/column is asserted in one upgrade test.
fn flow_checkpoint_migration_upgrades_v7_without_replacing_existing_state() {
    let (directory, path) = database_path("migration-v7-flows");
    fs::create_dir_all(&directory).unwrap();
    let connection = Connection::open(&path).unwrap();
    for migration in [
        include_str!("../migrations/0001_initial.sql"),
        include_str!("../migrations/0002_evidence.sql"),
        include_str!("../migrations/0003_callers.sql"),
        include_str!("../migrations/0004_policy.sql"),
        include_str!("../migrations/0005_audit.sql"),
        include_str!("../migrations/0006_policy_resource_bound.sql"),
        include_str!("../migrations/0007_models.sql"),
    ] {
        connection.execute_batch(migration).unwrap();
    }
    connection.pragma_update(None, "user_version", 7).unwrap();
    connection
        .execute("INSERT INTO projects(project_id) VALUES ('preserved')", [])
        .unwrap();
    connection
        .execute(
            "INSERT INTO requests(
                 request_id, caller_id, project_id, idempotency_key,
                 operation_kind, operation, queue_sequence, state, accepted_at_ms
             ) VALUES (
                 'preserved-request', 'caller', 'preserved', 'key',
                 'flow_run', X'00', 1, 'queued', 10
             )",
            [],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO events(request_id, sequence, kind, payload, recorded_at_ms)
             VALUES ('preserved-request', 1, 'accepted', X'', 10)",
            [],
        )
        .unwrap();
    drop(connection);

    let connection = open_connection(&path).unwrap();
    let preserved: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM requests WHERE request_id = 'preserved-request'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let event_count: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM events WHERE request_id = 'preserved-request'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let flow_table: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = 'flow_runs'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let terminal_columns: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('flow_runs')
             WHERE name IN (
                 'terminal_outcome', 'terminal_result', 'terminal_cancellation_override'
             )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let flow_authorization_table: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'table' AND name = 'flow_authorizations'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let approval_binding_column: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('approvals')
             WHERE name = 'flow_request_id'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let fabricated_flow_authorizations: u32 = connection
        .query_row("SELECT COUNT(*) FROM flow_authorizations", [], |row| {
            row.get(0)
        })
        .unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(preserved, 1);
    assert_eq!(event_count, 1);
    assert_eq!(flow_table, 1);
    assert_eq!(terminal_columns, 3);
    assert_eq!(flow_authorization_table, 1);
    assert_eq!(approval_binding_column, 1);
    assert_eq!(fabricated_flow_authorizations, 0);
    assert_eq!(version, LATEST_SCHEMA_VERSION);

    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn agent_artifact_migration_upgrades_v9_without_replacing_existing_state() {
    let (directory, path) = database_path("migration-v9-agent-artifacts");
    fs::create_dir_all(&directory).unwrap();
    let connection = Connection::open(&path).unwrap();
    for migration in [
        include_str!("../migrations/0001_initial.sql"),
        include_str!("../migrations/0002_evidence.sql"),
        include_str!("../migrations/0003_callers.sql"),
        include_str!("../migrations/0004_policy.sql"),
        include_str!("../migrations/0005_audit.sql"),
        include_str!("../migrations/0006_policy_resource_bound.sql"),
        include_str!("../migrations/0007_models.sql"),
        include_str!("../migrations/0008_flows.sql"),
        include_str!("../migrations/0009_flow_authorizations.sql"),
    ] {
        connection.execute_batch(migration).unwrap();
    }
    connection.pragma_update(None, "user_version", 9).unwrap();
    connection
        .execute("INSERT INTO projects(project_id) VALUES ('preserved')", [])
        .unwrap();
    drop(connection);

    let connection = open_connection(&path).unwrap();
    let preserved_projects: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM projects WHERE project_id = 'preserved'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let artifact_table: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'table' AND name = 'agent_artifacts'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let artifact_columns: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('agent_artifacts')
             WHERE name IN (
                 'artifact_id', 'name', 'logical_path', 'kind', 'scope', 'origin',
                 'load_semantics', 'content_hash', 'first_seen_at_ms',
                 'last_changed_at_ms', 'removed_at_ms'
             )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let active_index: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'index' AND name = 'agent_artifacts_active_order'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(preserved_projects, 1);
    assert_eq!(artifact_table, 1);
    assert_eq!(artifact_columns, 11);
    assert_eq!(active_index, 1);
    assert_eq!(version, LATEST_SCHEMA_VERSION);

    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn inventory_observation_migration_upgrades_v10_and_seeds_the_watermark() {
    let (directory, path) = database_path("migration-v10-inventory-observation");
    fs::create_dir_all(&directory).unwrap();
    let connection = Connection::open(&path).unwrap();
    for migration in [
        include_str!("../migrations/0001_initial.sql"),
        include_str!("../migrations/0002_evidence.sql"),
        include_str!("../migrations/0003_callers.sql"),
        include_str!("../migrations/0004_policy.sql"),
        include_str!("../migrations/0005_audit.sql"),
        include_str!("../migrations/0006_policy_resource_bound.sql"),
        include_str!("../migrations/0007_models.sql"),
        include_str!("../migrations/0008_flows.sql"),
        include_str!("../migrations/0009_flow_authorizations.sql"),
        include_str!("../migrations/0010_agent_artifacts.sql"),
    ] {
        connection.execute_batch(migration).unwrap();
    }
    connection.pragma_update(None, "user_version", 10).unwrap();
    connection
        .execute("INSERT INTO projects(project_id) VALUES ('preserved')", [])
        .unwrap();
    connection
        .execute(
            "INSERT INTO agent_artifacts(
                 project_id, artifact_id, name, logical_path, kind, scope, origin,
                 load_semantics, content_hash, first_seen_at_ms, last_changed_at_ms,
                 removed_at_ms
             ) VALUES (
                 'preserved', ?1, 'SKILL.md', '.claude/skills/old/SKILL.md',
                 'skill', 'project', 'claude_code', 'model_selected', ?2, 10, 12, 15
             )",
            [
                format!("artifact:sha256:{}", "1".repeat(64)),
                format!("sha256:{}", "2".repeat(64)),
            ],
        )
        .unwrap();
    drop(connection);

    let connection = open_connection(&path).unwrap();
    let observed_at_ms: i64 = connection
        .query_row(
            "SELECT observed_at_ms FROM agent_artifact_inventory
             WHERE project_id = 'preserved'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let preserved_artifacts: u32 = connection
        .query_row("SELECT COUNT(*) FROM agent_artifacts", [], |row| row.get(0))
        .unwrap();
    let removed_index: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'index' AND name = 'agent_artifacts_removed_order'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(observed_at_ms, 15);
    assert_eq!(preserved_artifacts, 1);
    assert_eq!(removed_index, 1);
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
