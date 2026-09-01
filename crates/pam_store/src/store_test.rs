use turso::params;

use crate::{Actor, Decision, RequestState, Store, StoreError};

async fn insert_demo_request(store: &Store, id: &str) {
    store
        .insert_request(id, "release", "ro-ag/pam", "claude", "{}")
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
    assert_eq!(store.schema_version().await.unwrap(), 1);

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
