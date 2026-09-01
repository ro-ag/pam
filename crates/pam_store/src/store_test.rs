use turso::params;

use crate::{Actor, ApprovalResolution, Decision, RequestState, Store, StoreError};

async fn insert_demo_request(store: &Store, id: &str) {
    store
        .insert_request(id, "release", "ro-ag/pam", "claude", "{}", None)
        .await
        .unwrap();
}

#[tokio::test]
async fn open_creates_parent_dir_schema_and_wal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir
        .path()
        .join("nested")
        .join("deeper")
        .join("state.sqlite3");

    let store = Store::open(&path).await.unwrap();
    assert!(path.exists());
    assert_eq!(store.schema_version().await.unwrap(), 2);

    // WAL is the engine's native journal mode.
    let mut rows = store.conn.query("PRAGMA journal_mode", ()).await.unwrap();
    let mode: String = rows.next().await.unwrap().unwrap().get(0).unwrap();
    assert_eq!(mode.to_lowercase(), "wal");
}

#[tokio::test]
async fn request_insert_and_state_round_trip() {
    let store = Store::open_in_memory().await.unwrap();
    insert_demo_request(&store, "req_1").await;

    let row = store.get_request("req_1").await.unwrap().unwrap();
    assert_eq!(row.id, "req_1");
    assert_eq!(row.capability, "release");
    assert_eq!(row.repo, "ro-ag/pam");
    assert_eq!(row.caller_agent, "claude");
    assert_eq!(row.args_json, "{}");
    assert_eq!(row.state, RequestState::Queued);
    assert_eq!(row.outcome, None);
    assert!(row.created_ts > 0);
    assert_eq!(row.created_ts, row.updated_ts);

    store
        .update_request_state("req_1", RequestState::Done, Some("ok"))
        .await
        .unwrap();
    let row = store.get_request("req_1").await.unwrap().unwrap();
    assert_eq!(row.state, RequestState::Done);
    assert_eq!(row.outcome.as_deref(), Some("ok"));

    assert!(store.get_request("req_missing").await.unwrap().is_none());
}

#[tokio::test]
async fn idempotency_key_round_trips() {
    let store = Store::open_in_memory().await.unwrap();
    store
        .insert_request("req_k", "echo", "ro-ag/pam", "claude", "{}", Some("key-9"))
        .await
        .unwrap();
    let row = store.get_request("req_k").await.unwrap().unwrap();
    assert_eq!(row.idempotency_key.as_deref(), Some("key-9"));

    insert_demo_request(&store, "req_none").await;
    let row = store.get_request("req_none").await.unwrap().unwrap();
    assert_eq!(row.idempotency_key, None);
}

#[tokio::test]
async fn find_inflight_by_key_matches_only_active_states() {
    let store = Store::open_in_memory().await.unwrap();
    assert!(store.find_inflight_by_key("k").await.unwrap().is_none());

    store
        .insert_request("req_1", "echo", "ro-ag/pam", "claude", "{}", Some("k"))
        .await
        .unwrap();
    let row = store.find_inflight_by_key("k").await.unwrap().unwrap();
    assert_eq!(row.id, "req_1");

    // Running and waiting_approval still count as in-flight.
    for state in [RequestState::Running, RequestState::WaitingApproval] {
        store
            .update_request_state("req_1", state, None)
            .await
            .unwrap();
        assert!(store.find_inflight_by_key("k").await.unwrap().is_some());
    }

    // A terminal request stops matching: retries start fresh work.
    store
        .update_request_state("req_1", RequestState::Done, Some("ok"))
        .await
        .unwrap();
    assert!(store.find_inflight_by_key("k").await.unwrap().is_none());
}

#[tokio::test]
async fn find_inflight_by_shape_requires_full_equality() {
    let store = Store::open_in_memory().await.unwrap();
    store
        .insert_request("req_1", "echo", "ro-ag/pam", "claude", r#"{"n":1}"#, None)
        .await
        .unwrap();

    let row = store
        .find_inflight_by_shape("echo", "ro-ag/pam", r#"{"n":1}"#)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.id, "req_1");

    // Any differing component misses.
    for (capability, repo, args) in [
        ("status", "ro-ag/pam", r#"{"n":1}"#),
        ("echo", "other/repo", r#"{"n":1}"#),
        ("echo", "ro-ag/pam", r#"{"n":2}"#),
    ] {
        assert!(
            store
                .find_inflight_by_shape(capability, repo, args)
                .await
                .unwrap()
                .is_none(),
            "unexpected match for {capability}/{repo}/{args}"
        );
    }
}

#[tokio::test]
async fn list_queued_ordered_returns_oldest_first_queued_only() {
    let store = Store::open_in_memory().await.unwrap();
    // Same-second inserts: the id tie-break keeps insertion order.
    insert_demo_request(&store, "req_a").await;
    insert_demo_request(&store, "req_b").await;
    insert_demo_request(&store, "req_c").await;
    store
        .update_request_state("req_b", RequestState::Running, None)
        .await
        .unwrap();

    let queued = store.list_queued_ordered().await.unwrap();
    let ids: Vec<&str> = queued.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, ["req_a", "req_c"]);
}

#[tokio::test]
async fn updating_missing_request_is_an_error() {
    let store = Store::open_in_memory().await.unwrap();
    let err = store
        .update_request_state("nope", RequestState::Failed, None)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        StoreError::NotFound {
            table: "request",
            ..
        }
    ));
}

#[tokio::test]
async fn audit_append_works() {
    let store = Store::open_in_memory().await.unwrap();
    insert_demo_request(&store, "req_1").await;

    store
        .append_audit("req_1", "enqueue", Decision::Allow, Actor::Policy, None)
        .await
        .unwrap();
    store
        .append_audit(
            "req_1",
            "approve",
            Decision::Approve,
            Actor::Human,
            Some("looks fine"),
        )
        .await
        .unwrap();

    let mut rows = store
        .conn
        .query(
            "SELECT count(*) FROM audit WHERE request_id = ?1",
            ["req_1"],
        )
        .await
        .unwrap();
    let count: i64 = rows.next().await.unwrap().unwrap().get(0).unwrap();
    assert_eq!(count, 2);
}

#[tokio::test]
async fn audit_requires_existing_request() {
    let store = Store::open_in_memory().await.unwrap();
    // foreign_keys is ON, so a dangling request_id must be rejected.
    let err = store
        .append_audit("ghost", "enqueue", Decision::Allow, Actor::Policy, None)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::Database(_)));
}

#[tokio::test]
async fn audit_for_request_returns_typed_rows_oldest_first() {
    let store = Store::open_in_memory().await.unwrap();
    insert_demo_request(&store, "req_1").await;
    insert_demo_request(&store, "req_2").await;

    store
        .append_audit("req_1", "enqueue", Decision::Allow, Actor::Policy, None)
        .await
        .unwrap();
    store
        .append_audit(
            "req_1",
            "approve",
            Decision::Approve,
            Actor::Human,
            Some("looks fine"),
        )
        .await
        .unwrap();
    store
        .append_audit("req_2", "enqueue", Decision::Refuse, Actor::Policy, None)
        .await
        .unwrap();

    let rows = store.audit_for_request("req_1").await.unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].request_id, "req_1");
    assert_eq!(rows[0].action, "enqueue");
    assert_eq!(rows[0].decision, Decision::Allow);
    assert_eq!(rows[0].actor, Actor::Policy);
    assert_eq!(rows[0].detail, None);
    assert!(rows[0].ts > 0);
    assert_eq!(rows[1].action, "approve");
    assert_eq!(rows[1].decision, Decision::Approve);
    assert_eq!(rows[1].actor, Actor::Human);
    assert_eq!(rows[1].detail.as_deref(), Some("looks fine"));
    assert!(rows[0].id < rows[1].id);

    assert!(store.audit_for_request("ghost").await.unwrap().is_empty());
}

#[tokio::test]
async fn active_grant_tracks_insert_and_revocation() {
    let store = Store::open_in_memory().await.unwrap();
    assert!(!store.active_grant("release").await.unwrap());

    store.insert_grant("release").await.unwrap();
    assert!(store.active_grant("release").await.unwrap());
    // Grants are per capability.
    assert!(!store.active_grant("echo").await.unwrap());

    // A revoked row (GUI-side administration, no helper yet) stops
    // counting; history stays in the table.
    store
        .conn
        .execute(
            "UPDATE \"grant\" SET revoked_ts = granted_ts WHERE capability = ?1",
            params!["release"],
        )
        .await
        .unwrap();
    assert!(!store.active_grant("release").await.unwrap());

    // Re-grant is a new row, and the old one is preserved.
    store.insert_grant("release").await.unwrap();
    assert!(store.active_grant("release").await.unwrap());
    let mut rows = store
        .conn
        .query(
            "SELECT count(*) FROM \"grant\" WHERE capability = ?1",
            params!["release"],
        )
        .await
        .unwrap();
    let count: i64 = rows.next().await.unwrap().unwrap().get(0).unwrap();
    assert_eq!(count, 2);
}

#[tokio::test]
async fn setting_round_trip() {
    let store = Store::open_in_memory().await.unwrap();
    assert!(store.get_setting("policy").await.unwrap().is_none());

    store
        .set_setting("policy", r#"{"mode":"strict"}"#)
        .await
        .unwrap();
    assert_eq!(
        store.get_setting("policy").await.unwrap().as_deref(),
        Some(r#"{"mode":"strict"}"#)
    );

    store
        .set_setting("policy", r#"{"mode":"open"}"#)
        .await
        .unwrap();
    assert_eq!(
        store.get_setting("policy").await.unwrap().as_deref(),
        Some(r#"{"mode":"open"}"#)
    );
}

#[tokio::test]
async fn grant_table_insert_works_despite_keyword_name() {
    let store = Store::open_in_memory().await.unwrap();
    store
        .conn
        .execute(
            "INSERT INTO \"grant\" (capability, granted_ts) VALUES (?1, ?2)",
            params!["release", 1_756_684_800_i64],
        )
        .await
        .unwrap();

    let mut rows = store
        .conn
        .query("SELECT capability, scope, revoked_ts FROM \"grant\"", ())
        .await
        .unwrap();
    let row = rows.next().await.unwrap().unwrap();
    assert_eq!(row.get::<String>(0).unwrap(), "release");
    assert_eq!(row.get::<String>(1).unwrap(), "global");
    assert_eq!(row.get::<Option<i64>>(2).unwrap(), None);
}

#[tokio::test]
async fn count_inflight_counts_only_non_terminal_states() {
    let store = Store::open_in_memory().await.unwrap();
    assert_eq!(store.count_inflight().await.unwrap(), 0);

    for id in ["req_q", "req_r", "req_w", "req_d", "req_f"] {
        insert_demo_request(&store, id).await;
    }
    store
        .update_request_state("req_r", RequestState::Running, None)
        .await
        .unwrap();
    store
        .update_request_state("req_w", RequestState::WaitingApproval, None)
        .await
        .unwrap();
    store
        .update_request_state("req_d", RequestState::Done, Some("ok"))
        .await
        .unwrap();
    store
        .update_request_state("req_f", RequestState::Failed, Some("boom"))
        .await
        .unwrap();

    // queued + running + waiting_approval; done and failed are terminal.
    assert_eq!(store.count_inflight().await.unwrap(), 3);
}

#[tokio::test]
async fn approval_insert_resolve_round_trip() {
    let store = Store::open_in_memory().await.unwrap();
    insert_demo_request(&store, "req_1").await;
    store.insert_approval("req_1", "release").await.unwrap();

    let row = store.approval_for_request("req_1").await.unwrap().unwrap();
    assert_eq!(row.request_id, "req_1");
    assert_eq!(row.capability, "release");
    assert!(row.requested_ts > 0);
    assert_eq!(row.resolved_ts, None);
    assert_eq!(row.resolution, None);
    assert_eq!(row.note, None);

    store
        .resolve_approval("req_1", ApprovalResolution::Approved, Some("go"))
        .await
        .unwrap();
    let row = store.approval_for_request("req_1").await.unwrap().unwrap();
    assert!(row.resolved_ts.is_some());
    assert_eq!(row.resolution, Some(ApprovalResolution::Approved));
    assert_eq!(row.note.as_deref(), Some("go"));

    assert!(store.approval_for_request("req_2").await.unwrap().is_none());
}

#[tokio::test]
async fn resolve_approval_guards_against_double_resolution() {
    let store = Store::open_in_memory().await.unwrap();
    insert_demo_request(&store, "req_1").await;

    // No pending approval at all.
    assert!(matches!(
        store
            .resolve_approval("req_1", ApprovalResolution::Denied, None)
            .await,
        Err(StoreError::NotFound {
            table: "approval",
            ..
        })
    ));

    store.insert_approval("req_1", "release").await.unwrap();
    store
        .resolve_approval("req_1", ApprovalResolution::Denied, None)
        .await
        .unwrap();

    // A second resolution loses the race guard.
    assert!(matches!(
        store
            .resolve_approval("req_1", ApprovalResolution::Timeout, None)
            .await,
        Err(StoreError::NotFound {
            table: "approval",
            ..
        })
    ));
    let row = store.approval_for_request("req_1").await.unwrap().unwrap();
    assert_eq!(row.resolution, Some(ApprovalResolution::Denied));
}

#[tokio::test]
async fn list_pending_approvals_joins_request_and_skips_resolved() {
    let store = Store::open_in_memory().await.unwrap();
    for id in ["req_1", "req_2"] {
        insert_demo_request(&store, id).await;
        store.insert_approval(id, "release").await.unwrap();
    }
    store
        .resolve_approval("req_1", ApprovalResolution::Approved, None)
        .await
        .unwrap();

    let pending = store.list_pending_approvals().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].request_id, "req_2");
    assert_eq!(pending[0].capability, "release");
    assert_eq!(pending[0].repo, "ro-ag/pam");
    assert_eq!(pending[0].caller_agent, "claude");
    assert!(pending[0].requested_ts > 0);
}
