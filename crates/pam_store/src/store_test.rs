use turso::params;

use crate::{Actor, ApprovalResolution, AuditEntry, Decision, RequestState, Store, StoreError};

async fn insert_demo_request(store: &Store, id: &str) {
    store
        .insert_request(id, "release", "ro-ag/pam", "claude", "{}", None)
        .await
        .unwrap();
}

/// A minimal terminal audit entry for seeding finished requests.
fn entry(action: &str) -> AuditEntry<'_> {
    AuditEntry {
        action,
        decision: Decision::Allow,
        actor: Actor::System,
        detail: None,
    }
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
        .update_request_state("req_1", RequestState::Running, None)
        .await
        .unwrap();
    let row = store.get_request("req_1").await.unwrap().unwrap();
    assert_eq!(row.state, RequestState::Running);

    store
        .finish_request("req_1", RequestState::Done, Some("ok"), entry("execute"))
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
        .finish_request("req_1", RequestState::Done, Some("ok"), entry("execute"))
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
        .update_request_state("nope", RequestState::Running, None)
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
        .finish_request("req_d", RequestState::Done, Some("ok"), entry("execute"))
        .await
        .unwrap();
    store
        .finish_request(
            "req_f",
            RequestState::Failed,
            Some("boom"),
            entry("execute"),
        )
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

#[tokio::test]
async fn finish_request_writes_state_outcome_and_audit_together() {
    let store = Store::open_in_memory().await.unwrap();
    insert_demo_request(&store, "req_1").await;

    let finished = store
        .finish_request(
            "req_1",
            RequestState::Refused,
            Some("not_granted"),
            AuditEntry {
                action: "gate_refusal",
                decision: Decision::Refuse,
                actor: Actor::Policy,
                detail: Some(r#"{"cause":"not_granted"}"#),
            },
        )
        .await
        .unwrap();
    assert!(finished);

    let row = store.get_request("req_1").await.unwrap().unwrap();
    assert_eq!(row.state, RequestState::Refused);
    assert_eq!(row.outcome.as_deref(), Some("not_granted"));

    let audit = store.audit_for_request("req_1").await.unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].action, "gate_refusal");
    assert_eq!(audit[0].decision, Decision::Refuse);
    assert_eq!(audit[0].actor, Actor::Policy);
    assert_eq!(
        audit[0].detail.as_deref(),
        Some(r#"{"cause":"not_granted"}"#)
    );
    assert!(audit[0].ts > 0);
}

#[tokio::test]
async fn finish_request_rejects_non_terminal_states() {
    let store = Store::open_in_memory().await.unwrap();
    insert_demo_request(&store, "req_1").await;

    for state in [
        RequestState::Queued,
        RequestState::Running,
        RequestState::WaitingApproval,
    ] {
        let err = store
            .finish_request("req_1", state, None, entry("execute"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, StoreError::NotTerminal { .. }),
            "{state:?} must be rejected, got {err:?}"
        );
    }
    // The refused states left no trace.
    let row = store.get_request("req_1").await.unwrap().unwrap();
    assert_eq!(row.state, RequestState::Queued);
    assert!(store.audit_for_request("req_1").await.unwrap().is_empty());
}

#[tokio::test]
async fn finish_request_double_finish_no_ops_with_a_single_audit_row() {
    let store = Store::open_in_memory().await.unwrap();
    insert_demo_request(&store, "req_1").await;

    // First finisher wins (executor completing)...
    assert!(
        store
            .finish_request(
                "req_1",
                RequestState::Done,
                Some("solved"),
                entry("execute")
            )
            .await
            .unwrap()
    );
    // ...the second (a racing reaper) no-ops and leaves the row alone.
    assert!(
        !store
            .finish_request(
                "req_1",
                RequestState::Failed,
                Some("lease_expired"),
                entry("lease_reaped"),
            )
            .await
            .unwrap()
    );

    let row = store.get_request("req_1").await.unwrap().unwrap();
    assert_eq!(row.state, RequestState::Done);
    assert_eq!(row.outcome.as_deref(), Some("solved"));
    let audit = store.audit_for_request("req_1").await.unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].action, "execute");
}

#[tokio::test]
async fn finish_request_missing_request_is_not_found() {
    let store = Store::open_in_memory().await.unwrap();
    let err = store
        .finish_request("nope", RequestState::Failed, None, entry("execute"))
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
async fn terminal_requests_missing_audit_flags_only_silent_terminals() {
    let store = Store::open_in_memory().await.unwrap();
    let terminal_actions = ["execute", "cancel"];

    // Terminal with a terminal-action audit row: clean.
    insert_demo_request(&store, "req_ok").await;
    store
        .finish_request(
            "req_ok",
            RequestState::Done,
            Some("solved"),
            entry("execute"),
        )
        .await
        .unwrap();

    // Terminal whose only audit row is a non-terminal action: flagged.
    insert_demo_request(&store, "req_wrong_action").await;
    store
        .append_audit(
            "req_wrong_action",
            "auto_grant",
            Decision::Allow,
            Actor::Policy,
            None,
        )
        .await
        .unwrap();
    store
        .finish_request(
            "req_wrong_action",
            RequestState::Failed,
            None,
            entry("bookkeeping"),
        )
        .await
        .unwrap();

    // Non-terminal without audit: not flagged — it is still in flight.
    insert_demo_request(&store, "req_inflight").await;

    let missing = store
        .terminal_requests_missing_audit(&terminal_actions)
        .await
        .unwrap();
    assert_eq!(missing, ["req_wrong_action"]);

    // An empty action list counts every terminal request as silent.
    let missing = store.terminal_requests_missing_audit(&[]).await.unwrap();
    assert_eq!(missing, ["req_ok", "req_wrong_action"]);
}

#[tokio::test]
async fn list_grants_includes_revoked_history_newest_first() {
    let store = Store::open_in_memory().await.unwrap();
    store.insert_grant("deploy").await.unwrap();
    store.insert_grant("release").await.unwrap();
    store.revoke_grant("deploy").await.unwrap();

    let grants = store.list_grants().await.unwrap();
    assert_eq!(grants.len(), 2, "revoked rows stay listed");
    // Same-second timestamps: id DESC is the newest-first tiebreaker.
    assert_eq!(grants[0].capability, "release");
    assert_eq!(grants[0].revoked_ts, None);
    assert_eq!(grants[1].capability, "deploy");
    assert!(grants[1].revoked_ts.is_some(), "revocation timestamped");
    assert_eq!(grants[1].scope, "global");
}

#[tokio::test]
async fn revoke_grant_errors_without_an_active_grant() {
    let store = Store::open_in_memory().await.unwrap();

    // Never granted.
    assert!(matches!(
        store.revoke_grant("deploy").await,
        Err(StoreError::NotFound { table: "grant", .. })
    ));

    // Already revoked.
    store.insert_grant("deploy").await.unwrap();
    store.revoke_grant("deploy").await.unwrap();
    assert!(matches!(
        store.revoke_grant("deploy").await,
        Err(StoreError::NotFound { table: "grant", .. })
    ));
}

#[tokio::test]
async fn list_requests_filtered_applies_filters_newest_first() {
    let store = Store::open_in_memory().await.unwrap();
    store
        .insert_request("req_1", "echo", "/repo/a", "claude", "{}", None)
        .await
        .unwrap();
    store
        .insert_request("req_2", "echo", "/repo/b", "codex", "{}", None)
        .await
        .unwrap();
    store
        .insert_request("req_3", "status", "/repo/a", "claude", "{}", None)
        .await
        .unwrap();
    store
        .finish_request(
            "req_3",
            RequestState::Done,
            Some("verified"),
            entry("execute"),
        )
        .await
        .unwrap();

    // Unfiltered: everything, newest first (id DESC breaks the
    // same-second tie).
    let all = store
        .list_requests_filtered(None, None, None, None)
        .await
        .unwrap();
    let ids: Vec<&str> = all.iter().map(|row| row.id.as_str()).collect();
    assert_eq!(ids, ["req_3", "req_2", "req_1"]);

    // By repo.
    let repo_a = store
        .list_requests_filtered(None, Some("/repo/a"), None, None)
        .await
        .unwrap();
    assert_eq!(repo_a.len(), 2);

    // By agent and state combined.
    let done_claude = store
        .list_requests_filtered(None, None, Some("claude"), Some(RequestState::Done))
        .await
        .unwrap();
    assert_eq!(done_claude.len(), 1);
    assert_eq!(done_claude[0].id, "req_3");

    // No match.
    let none = store
        .list_requests_filtered(None, Some("/repo/none"), None, None)
        .await
        .unwrap();
    assert!(none.is_empty());
}

#[tokio::test]
async fn list_requests_filtered_bounds_the_limit() {
    let store = Store::open_in_memory().await.unwrap();
    for i in 0..5 {
        store
            .insert_request(&format!("req_{i}"), "echo", "/r", "claude", "{}", None)
            .await
            .unwrap();
    }

    // An explicit limit caps the rows.
    let two = store
        .list_requests_filtered(Some(2), None, None, None)
        .await
        .unwrap();
    assert_eq!(two.len(), 2);

    // Zero is clamped up to one instead of returning nothing.
    let one = store
        .list_requests_filtered(Some(0), None, None, None)
        .await
        .unwrap();
    assert_eq!(one.len(), 1);

    // An absurd limit is clamped to the maximum (observable only as
    // "does not error"; the clamp constant bounds the SQL LIMIT).
    let all = store
        .list_requests_filtered(Some(u64::MAX), None, None, None)
        .await
        .unwrap();
    assert_eq!(all.len(), 5);
}

#[tokio::test]
async fn upsert_caller_inserts_once_and_bumps_last_seen() {
    let store = Store::open_in_memory().await.unwrap();
    store.upsert_caller("claude", "/repo/a").await.unwrap();
    store.upsert_caller("claude", "/repo/a").await.unwrap();
    store.upsert_caller("codex", "/repo/b").await.unwrap();

    let callers = store.list_callers().await.unwrap();
    assert_eq!(callers.len(), 2, "same pair upserts into one row");
    let claude = callers
        .iter()
        .find(|caller| caller.agent == "claude")
        .expect("claude row");
    assert_eq!(claude.repo, "/repo/a");
    assert!(claude.first_seen > 0);
    assert!(claude.last_seen >= claude.first_seen);
}

/// The daemon drives one `Store` from many tokio tasks at once: the
/// executor finishes requests while the dispatcher admits new ones and
/// the reaper sweeps leases. Every statement runs on the same
/// connection, so a `BEGIN` from `finish_request` must never land while
/// another task's statement is mid-flight — that is the interleaving
/// that left requests `running` forever (ptrack issue #2). Hammer the
/// two paths concurrently and require every call to succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_inserts_and_finishes_never_fail() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = std::sync::Arc::new(
        Store::open(&tmp.path().join("state.sqlite3"))
            .await
            .expect("store opens"),
    );
    for round in 0..40 {
        let id = format!("req_{round:04}");
        insert_demo_request(&store, &id).await;
        let finisher = {
            let store = std::sync::Arc::clone(&store);
            let id = id.clone();
            tokio::spawn(async move {
                store
                    .finish_request(&id, RequestState::Done, Some("solved"), entry("execute"))
                    .await
            })
        };
        let inserter = {
            let store = std::sync::Arc::clone(&store);
            tokio::spawn(async move {
                let other = format!("req_side_{round:04}");
                store
                    .insert_request(&other, "query", "/repo", "test", "{}", None)
                    .await?;
                store
                    .update_request_state(&other, RequestState::Running, None)
                    .await?;
                store.upsert_caller("test", "/repo").await?;
                store.get_request(&other).await
            })
        };
        let finish_outcome = finisher.await.expect("finisher joins");
        let side_outcome = inserter.await.expect("inserter joins");
        assert!(
            side_outcome.is_ok(),
            "round {round}: side writes failed: {side_outcome:?}"
        );
        assert!(
            matches!(finish_outcome, Ok(true)),
            "round {round}: finish did not transition: {finish_outcome:?}"
        );
    }
}
