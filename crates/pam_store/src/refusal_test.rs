//! The refusal table: bounded, coalescing-friendly writes, filters, ordering,
//! the retention bounds and the upgrade from the schema before it.

use rusqlite::Connection;

use crate::{
    MAX_AGENT_BYTES, MAX_CAUSE_BYTES, MAX_DETAIL_BYTES, MAX_REFUSALS, MAX_REPO_BYTES,
    RefusalRecord, RefusalWrite, RequestIngress, Store, bounded, migrations,
};

fn record(cause: &str, ts: i64) -> RefusalRecord {
    RefusalRecord {
        ts,
        last_ts: ts,
        ingress: RequestIngress::Public,
        cause: cause.to_owned(),
        detail: "the daemon said no".to_owned(),
        count: 1,
        peer_uid: Some(501),
        peer_pid: Some(4242),
        peer_exe: Some("/usr/local/bin/pam".to_owned()),
        agent: Some("claude".to_owned()),
        repo: Some("/repo".to_owned()),
        request_id: Some("req_1".to_owned()),
        capability: Some("echo".to_owned()),
    }
}

async fn insert(store: &Store, record: RefusalRecord) -> i64 {
    store
        .write_refusals(vec![RefusalWrite::Insert(record)])
        .await
        .unwrap()[0]
        .expect("an insert always lands")
}

#[tokio::test]
async fn a_refusal_lands_and_reads_back_with_everything_the_daemon_knew() {
    let store = Store::open_in_memory().await.unwrap();
    let id = insert(&store, record("request_capacity_exhausted", 1_000)).await;

    let rows = store.list_refusals(10, None, None, None).await.unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.id, id);
    assert_eq!(row.ts, 1_000);
    assert_eq!(row.last_ts, 1_000);
    assert_eq!(row.ingress, RequestIngress::Public);
    assert_eq!(row.cause, "request_capacity_exhausted");
    assert_eq!(row.detail, "the daemon said no");
    assert_eq!(row.count, 1);
    assert_eq!(row.peer_uid, Some(501));
    assert_eq!(row.peer_pid, Some(4242));
    assert_eq!(row.peer_exe.as_deref(), Some("/usr/local/bin/pam"));
    assert_eq!(row.agent.as_deref(), Some("claude"));
    assert_eq!(row.repo.as_deref(), Some("/repo"));
    assert_eq!(row.request_id.as_deref(), Some("req_1"));
    assert_eq!(row.capability.as_deref(), Some("echo"));
}

#[tokio::test]
async fn a_refusal_with_no_peer_and_no_claims_is_still_recorded() {
    let store = Store::open_in_memory().await.unwrap();
    let mut bare = record("bad_frame", 5);
    bare.ingress = RequestIngress::Admin;
    bare.peer_uid = None;
    bare.peer_pid = None;
    bare.peer_exe = None;
    bare.agent = None;
    bare.repo = None;
    bare.request_id = None;
    bare.capability = None;
    insert(&store, bare).await;
    let row = store
        .list_refusals(10, None, None, None)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(row.ingress, RequestIngress::Admin);
    assert_eq!(
        (
            row.peer_uid,
            row.peer_pid,
            row.peer_exe,
            row.agent,
            row.repo
        ),
        (None, None, None, None, None)
    );
    assert_eq!((row.request_id, row.capability), (None, None));
}

#[tokio::test]
async fn a_bump_adds_to_the_count_and_moves_the_last_attempt() {
    let store = Store::open_in_memory().await.unwrap();
    let id = insert(&store, record("request_rate_exhausted", 100)).await;
    let landed = store
        .write_refusals(vec![RefusalWrite::Bump {
            id,
            count: 999,
            last_ts: 108,
        }])
        .await
        .unwrap();
    assert_eq!(landed, vec![Some(id)]);
    // An older last_ts never moves it back.
    store
        .write_refusals(vec![RefusalWrite::Bump {
            id,
            count: 1,
            last_ts: 50,
        }])
        .await
        .unwrap();
    let row = store
        .list_refusals(10, None, None, None)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(row.count, 1_001);
    assert_eq!(row.ts, 100);
    assert_eq!(row.last_ts, 108);
}

#[tokio::test]
async fn a_bump_of_a_pruned_row_answers_none_and_changes_nothing() {
    let store = Store::open_in_memory().await.unwrap();
    insert(&store, record("bad_frame", 1)).await;
    let landed = store
        .write_refusals(vec![RefusalWrite::Bump {
            id: 9_999,
            count: 5,
            last_ts: 2,
        }])
        .await
        .unwrap();
    assert_eq!(landed, vec![None]);
    assert_eq!(store.refusal_rows().await.unwrap(), 1);
    assert_eq!(
        store.list_refusals(10, None, None, None).await.unwrap()[0].count,
        1
    );
}

#[tokio::test]
async fn one_batch_is_one_transaction_with_inserts_and_bumps_in_order() {
    let store = Store::open_in_memory().await.unwrap();
    let first = insert(&store, record("a", 1)).await;
    let landed = store
        .write_refusals(vec![
            RefusalWrite::Insert(record("b", 2)),
            RefusalWrite::Bump {
                id: first,
                count: 4,
                last_ts: 3,
            },
            RefusalWrite::Insert(record("c", 4)),
        ])
        .await
        .unwrap();
    assert_eq!(landed.len(), 3);
    assert!(landed.iter().all(Option::is_some));
    assert_eq!(store.refusal_rows().await.unwrap(), 3);
    assert!(store.write_refusals(Vec::new()).await.unwrap().is_empty());
}

#[tokio::test]
async fn the_table_keeps_only_the_newest_rows() {
    let store = Store::open_in_memory().await.unwrap();
    let total = i64::from(MAX_REFUSALS) + 150;
    // Written in batches, as the daemon writes them.
    for chunk in (0..total).collect::<Vec<_>>().chunks(100) {
        let writes = chunk
            .iter()
            .map(|n| RefusalWrite::Insert(record(&format!("cause_{n}"), 1_000 + n)))
            .collect();
        store.write_refusals(writes).await.unwrap();
    }
    assert_eq!(store.refusal_rows().await.unwrap(), u64::from(MAX_REFUSALS));
    let rows = store.list_refusals(500, None, None, None).await.unwrap();
    // Newest first, and the oldest 150 are gone.
    assert_eq!(rows[0].cause, format!("cause_{}", total - 1));
    let oldest_kept: i64 = store
        .raw_scalar("SELECT MIN(ts) FROM refusal", ())
        .await
        .unwrap();
    assert_eq!(oldest_kept, 1_000 + 150);
}

#[tokio::test]
async fn the_audit_window_removes_rows_whose_last_attempt_is_older_than_the_cutoff() {
    let store = Store::open_in_memory().await.unwrap();
    insert(&store, record("old", 100)).await;
    // First attempt old, latest attempt recent: still inside the window.
    let mut running = record("running", 100);
    running.last_ts = 10_000;
    insert(&store, running).await;
    insert(&store, record("fresh", 9_000)).await;

    let removed = store.prune_refusals_before(5_000).await.unwrap();
    assert_eq!(removed, 1);
    let mut causes: Vec<String> = store
        .list_refusals(10, None, None, None)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.cause)
        .collect();
    causes.sort();
    assert_eq!(causes, ["fresh", "running"]);
    assert_eq!(store.prune_refusals_before(5_000).await.unwrap(), 0);
}

#[tokio::test]
async fn the_list_is_newest_first_and_filters_on_what_the_client_claimed() {
    let store = Store::open_in_memory().await.unwrap();
    let mut other = record("bad_frame", 20);
    other.agent = Some("codex".to_owned());
    other.repo = Some("/other".to_owned());
    other.capability = Some("flow.run".to_owned());
    let mut unclaimed = record("handshake_timeout", 30);
    unclaimed.agent = None;
    unclaimed.repo = None;
    unclaimed.capability = None;
    insert(&store, record("request_capacity_exhausted", 10)).await;
    insert(&store, other).await;
    insert(&store, unclaimed).await;

    let causes = |rows: Vec<crate::RefusalRow>| -> Vec<String> {
        rows.into_iter().map(|row| row.cause).collect()
    };
    assert_eq!(
        causes(store.list_refusals(10, None, None, None).await.unwrap()),
        [
            "handshake_timeout",
            "bad_frame",
            "request_capacity_exhausted"
        ]
    );
    assert_eq!(
        causes(
            store
                .list_refusals(10, Some("/other"), None, None)
                .await
                .unwrap()
        ),
        ["bad_frame"]
    );
    assert_eq!(
        causes(
            store
                .list_refusals(10, None, Some("claude"), None)
                .await
                .unwrap()
        ),
        ["request_capacity_exhausted"]
    );
    assert_eq!(
        causes(
            store
                .list_refusals(10, None, None, Some("flow.run"))
                .await
                .unwrap()
        ),
        ["bad_frame"]
    );
    // A row that never recorded a claim matches no filter on it.
    assert!(
        store
            .list_refusals(10, Some("/nowhere"), None, None)
            .await
            .unwrap()
            .is_empty()
    );
    // The limit clamps to at least one row.
    assert_eq!(
        store
            .list_refusals(0, None, None, None)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn long_text_is_truncated_on_a_character_boundary_never_refused() {
    let store = Store::open_in_memory().await.unwrap();
    let mut long = record(&"c".repeat(MAX_CAUSE_BYTES * 2), 1);
    long.detail = "é".repeat(MAX_DETAIL_BYTES);
    long.agent = Some("a".repeat(MAX_AGENT_BYTES + 50));
    long.repo = Some("世".repeat(MAX_REPO_BYTES));
    long.request_id = Some("r".repeat(1_000));
    long.capability = Some("k".repeat(1_000));
    long.peer_exe = Some("/".repeat(5_000));
    insert(&store, long).await;
    let row = store
        .list_refusals(1, None, None, None)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(row.cause.len(), MAX_CAUSE_BYTES);
    assert!(row.detail.len() <= MAX_DETAIL_BYTES && row.detail.chars().all(|c| c == 'é'));
    assert_eq!(row.agent.unwrap().len(), MAX_AGENT_BYTES);
    assert!(row.repo.unwrap().len() <= MAX_REPO_BYTES);
    assert_eq!(row.request_id.unwrap().len(), 128);
    assert_eq!(row.capability.unwrap().len(), 128);
    assert_eq!(row.peer_exe.unwrap().len(), 1024);
}

#[tokio::test]
async fn an_empty_cause_is_recorded_as_unknown_rather_than_failing_the_batch() {
    let store = Store::open_in_memory().await.unwrap();
    insert(&store, record("", 1)).await;
    assert_eq!(
        store.list_refusals(1, None, None, None).await.unwrap()[0].cause,
        "unknown"
    );
}

#[test]
fn bounded_never_splits_a_character() {
    assert_eq!(bounded("abc", 5), "abc");
    assert_eq!(bounded("abcdef", 3), "abc");
    assert_eq!(bounded("é", 1), "");
    assert_eq!(bounded("aé", 2), "a");
    assert_eq!(bounded("aé", 3), "aé");
}

#[tokio::test]
async fn a_zero_count_is_stored_as_one_attempt() {
    let store = Store::open_in_memory().await.unwrap();
    let mut zero = record("bad_frame", 1);
    zero.count = 0;
    insert(&store, zero).await;
    assert_eq!(
        store.list_refusals(1, None, None, None).await.unwrap()[0].count,
        1
    );
}

fn build_v16_database(path: &std::path::Path) {
    let conn = Connection::open(path).unwrap();
    for migration in migrations::MIGRATIONS.iter().filter(|m| m.version <= 16) {
        conn.execute_batch(migration.sql).unwrap();
    }
    conn.execute_batch("PRAGMA user_version = 16").unwrap();
    conn.execute(
        "INSERT INTO request (id, capability, repo, caller_agent, args_json, state, created_ts, \
         updated_ts, ingress, peer_uid, peer_pid, relayed)
         VALUES ('old_public', 'echo', '/r', 'claude', '{}', 'refused', 1, 2, 'public', 501, 77, 0)",
        (),
    )
    .unwrap();
    conn.execute(
        "INSERT INTO audit (request_id, ts, action, decision, actor, detail)
         VALUES ('old_public', 2, 'gate_refusal', 'refuse', 'policy', NULL)",
        (),
    )
    .unwrap();
    drop(conn);
}

/// The upgrade from the schema before the refusal table: the table appears
/// empty with its bounds, every existing row reads back unchanged, and the
/// new table takes writes.
#[tokio::test]
async fn a_v16_database_gains_the_refusal_table_and_keeps_its_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    build_v16_database(&path);

    let store = Store::open(&path).await.unwrap();
    assert_eq!(
        store.schema_version().await.unwrap(),
        migrations::latest_version()
    );
    assert!(migrations::latest_version() >= 18);

    let old = store.get_request("old_public").await.unwrap().unwrap();
    assert_eq!(old.origin.peer_pid, Some(77));
    assert_eq!(
        store.audit_for_request("old_public").await.unwrap().len(),
        1
    );
    assert_eq!(store.refusal_rows().await.unwrap(), 0);

    insert(&store, record("client_version_mismatch", 9)).await;
    assert_eq!(store.refusal_rows().await.unwrap(), 1);
    // The bounds came with the table: a cause the CHECK refuses is not
    // something the writer can produce, but the engine still enforces it.
    let refused: Result<i64, _> = store
        .raw_scalar(
            "INSERT INTO refusal (ts, last_ts, ingress, cause, detail, count) \
             VALUES (1, 1, 'elsewhere', 'x', '', 1) RETURNING id",
            (),
        )
        .await;
    assert!(refused.is_err(), "an unknown plane is refused by the table");
}

/// A refusal row has no foreign key to `request`: the request id a client
/// supplied names no request, and recording it must not need one.
#[tokio::test]
async fn a_refusal_can_name_a_request_id_that_does_not_exist() {
    let store = Store::open_in_memory().await.unwrap();
    let mut claimed = record("request_capacity_exhausted", 1);
    claimed.request_id = Some("req_that_was_never_admitted".to_owned());
    insert(&store, claimed).await;
    assert!(
        store
            .get_request("req_that_was_never_admitted")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(store.refusal_rows().await.unwrap(), 1);
}
