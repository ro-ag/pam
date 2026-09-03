use sha2::{Digest, Sha256};
use turso::params;

use crate::{
    Actor, ApprovalResolution, AuditEntry, CompressionStats, ConnectorPatch, Decision,
    EVIDENCE_KIND_LOG_COMPACT, ModelJobRow, RequestState, Store, StoreError,
};

/// The one model job row with `id`, read back through the bounded list.
async fn one_model_job(store: &Store, id: &str) -> ModelJobRow {
    store
        .list_model_jobs(50)
        .await
        .unwrap()
        .into_iter()
        .find(|job| job.id == id)
        .unwrap_or_else(|| panic!("model job {id} exists"))
}

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
    assert_eq!(store.schema_version().await.unwrap(), 5);

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
        .list_requests_filtered(None, None, None, None, None)
        .await
        .unwrap();
    let ids: Vec<&str> = all.iter().map(|row| row.id.as_str()).collect();
    assert_eq!(ids, ["req_3", "req_2", "req_1"]);

    // By repo.
    let repo_a = store
        .list_requests_filtered(None, Some("/repo/a"), None, None, None)
        .await
        .unwrap();
    assert_eq!(repo_a.len(), 2);

    // By agent and state combined.
    let done_claude = store
        .list_requests_filtered(None, None, Some("claude"), Some(RequestState::Done), None)
        .await
        .unwrap();
    assert_eq!(done_claude.len(), 1);
    assert_eq!(done_claude[0].id, "req_3");

    // No match.
    let none = store
        .list_requests_filtered(None, Some("/repo/none"), None, None, None)
        .await
        .unwrap();
    assert!(none.is_empty());
}

#[tokio::test]
async fn list_requests_filtered_by_capability() {
    let store = Store::open_in_memory().await.unwrap();
    store
        .insert_request("req_1", "flow.run", "/repo/a", "claude", "{}", None)
        .await
        .unwrap();
    store
        .insert_request("req_2", "echo", "/repo/a", "claude", "{}", None)
        .await
        .unwrap();
    store
        .insert_request("req_3", "flow.run", "/repo/b", "codex", "{}", None)
        .await
        .unwrap();

    let flow_runs = store
        .list_requests_filtered(None, None, None, None, Some("flow.run"))
        .await
        .unwrap();
    let ids: Vec<&str> = flow_runs.iter().map(|row| row.id.as_str()).collect();
    assert_eq!(ids, ["req_3", "req_1"]);

    let none = store
        .list_requests_filtered(None, None, None, None, Some("no.such.capability"))
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
        .list_requests_filtered(Some(2), None, None, None, None)
        .await
        .unwrap();
    assert_eq!(two.len(), 2);

    // Zero is clamped up to one instead of returning nothing.
    let one = store
        .list_requests_filtered(Some(0), None, None, None, None)
        .await
        .unwrap();
    assert_eq!(one.len(), 1);

    // An absurd limit is clamped to the maximum (observable only as
    // "does not error"; the clamp constant bounds the SQL LIMIT).
    let all = store
        .list_requests_filtered(Some(u64::MAX), None, None, None, None)
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

#[tokio::test]
async fn model_jobs_list_newest_first() {
    let store = Store::open_in_memory().await.unwrap();
    for id in ["job_a", "job_b", "job_c"] {
        store
            .insert_model_job(
                id,
                "download",
                "qwen/one",
                Some("http://origin/one"),
                Some(10),
            )
            .await
            .unwrap();
    }
    let jobs = store.list_model_jobs(20).await.unwrap();
    // Same second for all three, so the id tiebreaker decides: descending.
    let ids: Vec<&str> = jobs.iter().map(|job| job.id.as_str()).collect();
    assert_eq!(ids, ["job_c", "job_b", "job_a"]);
    assert_eq!(jobs[0].kind, "download");
    assert_eq!(jobs[0].model_id, "qwen/one");
    assert_eq!(jobs[0].source.as_deref(), Some("http://origin/one"));
    assert_eq!(jobs[0].state, "running");
    assert_eq!(jobs[0].bytes_done, 0);
    assert_eq!(jobs[0].bytes_total, Some(10));
    assert_eq!(jobs[0].detail, None);
}

#[tokio::test]
async fn model_job_list_limit_is_clamped_into_range() {
    let store = Store::open_in_memory().await.unwrap();
    for index in 0..3 {
        store
            .insert_model_job(&format!("job_{index}"), "verify", "qwen/one", None, None)
            .await
            .unwrap();
    }
    assert_eq!(store.list_model_jobs(0).await.unwrap().len(), 1);
    assert_eq!(store.list_model_jobs(u64::MAX).await.unwrap().len(), 3);
}

#[tokio::test]
async fn model_job_progress_moves_the_byte_figures() {
    let store = Store::open_in_memory().await.unwrap();
    store
        .insert_model_job("job_p", "download", "qwen/one", None, None)
        .await
        .unwrap();
    store
        .update_model_job_progress("job_p", 512, Some(2048))
        .await
        .unwrap();
    let job = one_model_job(&store, "job_p").await;
    assert_eq!(job.bytes_done, 512);
    assert_eq!(job.bytes_total, Some(2048));
    assert_eq!(job.state, "running");
}

#[tokio::test]
async fn finishing_a_model_job_records_the_verdict_once() {
    let store = Store::open_in_memory().await.unwrap();
    for (id, state) in [
        ("job_done", "done"),
        ("job_failed", "failed"),
        ("job_cancelled", "cancelled"),
    ] {
        store
            .insert_model_job(id, "download", "qwen/one", None, None)
            .await
            .unwrap();
        store
            .finish_model_job(id, state, Some(r#"{"cause":"x"}"#))
            .await
            .unwrap();
        let job = one_model_job(&store, id).await;
        assert_eq!(job.state, state);
        assert_eq!(job.detail.as_deref(), Some(r#"{"cause":"x"}"#));
    }

    // A second verdict, and a late progress poll, both bounce off the
    // terminal row.
    store
        .finish_model_job("job_done", "failed", Some("late"))
        .await
        .unwrap();
    store
        .update_model_job_progress("job_done", 999, Some(999))
        .await
        .unwrap();
    let job = one_model_job(&store, "job_done").await;
    assert_eq!(job.state, "done");
    assert_eq!(job.bytes_done, 0);
}

#[tokio::test]
async fn boot_recovery_fails_only_running_model_jobs() {
    let store = Store::open_in_memory().await.unwrap();
    store
        .insert_model_job("job_running", "download", "qwen/one", None, None)
        .await
        .unwrap();
    store
        .insert_model_job("job_settled", "verify", "qwen/two", None, None)
        .await
        .unwrap();
    store
        .finish_model_job("job_settled", "done", Some("sha"))
        .await
        .unwrap();

    let failed = store
        .fail_running_model_jobs("daemon_restart")
        .await
        .unwrap();
    assert_eq!(failed, 1);
    let running = one_model_job(&store, "job_running").await;
    assert_eq!(running.state, "failed");
    assert_eq!(running.detail.as_deref(), Some("daemon_restart"));
    let settled = one_model_job(&store, "job_settled").await;
    assert_eq!(settled.state, "done");
    assert_eq!(settled.detail.as_deref(), Some("sha"));

    // Idempotent: a second boot finds nothing left to fail.
    assert_eq!(
        store
            .fail_running_model_jobs("daemon_restart")
            .await
            .unwrap(),
        0
    );
}

// ---- evidence -------------------------------------------------------

/// The lowercase hex sha256 of `bytes`, computed independently of the
/// store so the round-trip test proves the column, not the helper.
fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// `meta_json` for a `log.compact` row carrying the compression figures.
fn compact_meta(source_bytes: u64, compact_bytes: u64, tokens_avoided_est: u64) -> String {
    format!(
        r#"{{"source_bytes":{source_bytes},"compact_bytes":{compact_bytes},"tokens_avoided_est":{tokens_avoided_est}}}"#
    )
}

#[tokio::test]
async fn evidence_round_trips_bytes_hash_and_meta() {
    let store = Store::open_in_memory().await.unwrap();
    insert_demo_request(&store, "req_1").await;

    let content: &[u8] = b"\x00\xffraw\nbytes";
    store
        .insert_evidence(
            "ev_1",
            "req_1",
            "log.source",
            content,
            Some(r#"{"name":"build.log"}"#),
        )
        .await
        .unwrap();

    let row = store.get_evidence("ev_1").await.unwrap().unwrap();
    assert_eq!(row.id, "ev_1");
    assert_eq!(row.request_id, "req_1");
    assert_eq!(row.kind, "log.source");
    assert_eq!(row.content, content);
    assert_eq!(row.content_hash, sha256_hex(content));
    assert_eq!(row.meta_json.as_deref(), Some(r#"{"name":"build.log"}"#));
    assert!(row.ts > 0);

    assert_eq!(store.get_evidence("ev_missing").await.unwrap(), None);
}

#[tokio::test]
async fn list_evidence_returns_metadata_without_blobs_in_insertion_order() {
    let store = Store::open_in_memory().await.unwrap();
    insert_demo_request(&store, "req_1").await;
    insert_demo_request(&store, "req_2").await;

    for (id, kind, content) in [
        ("ev_1", "log.source", b"aaaa".as_slice()),
        ("ev_2", "log.compact", b"bb".as_slice()),
        ("ev_3", "log.summary", b"c".as_slice()),
    ] {
        store
            .insert_evidence(id, "req_1", kind, content, None)
            .await
            .unwrap();
    }
    store
        .insert_evidence("ev_9", "req_2", "log.source", b"elsewhere", None)
        .await
        .unwrap();

    let rows = store.list_evidence("req_1").await.unwrap();
    assert_eq!(rows.len(), 3);
    let ids: Vec<&str> = rows.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, ["ev_1", "ev_2", "ev_3"]);
    let kinds: Vec<&str> = rows.iter().map(|r| r.kind.as_str()).collect();
    assert_eq!(kinds, ["log.source", "log.compact", "log.summary"]);
    let sizes: Vec<u64> = rows.iter().map(|r| r.bytes).collect();
    assert_eq!(sizes, [4, 2, 1]);
    assert_eq!(rows[0].content_hash, sha256_hex(b"aaaa"));
    assert!(rows.iter().all(|r| r.request_id == "req_1"));

    assert!(store.list_evidence("req_none").await.unwrap().is_empty());
}

#[tokio::test]
async fn compression_stats_sums_only_compact_rows_in_the_window() {
    let store = Store::open_in_memory().await.unwrap();
    insert_demo_request(&store, "req_1").await;

    for id in ["ev_c1", "ev_c2"] {
        store
            .insert_evidence(
                id,
                "req_1",
                EVIDENCE_KIND_LOG_COMPACT,
                b"report",
                Some(&compact_meta(1000, 100, 225)),
            )
            .await
            .unwrap();
    }
    // Another kind with the same meta must not be counted.
    store
        .insert_evidence(
            "ev_s1",
            "req_1",
            "log.source",
            b"raw",
            Some(&compact_meta(1000, 100, 225)),
        )
        .await
        .unwrap();
    // An unreadable meta still counts as a compression, adding nothing.
    store
        .insert_evidence(
            "ev_c3",
            "req_1",
            EVIDENCE_KIND_LOG_COMPACT,
            b"report",
            Some("not json"),
        )
        .await
        .unwrap();

    let stats = store.compression_stats(0).await.unwrap();
    assert_eq!(stats.compressions, 3);
    assert_eq!(stats.source_bytes, 2000);
    assert_eq!(stats.compact_bytes, 200);
    assert_eq!(stats.tokens_avoided_est, 450);

    // A window that starts in the future sees nothing.
    let future = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
        + 600;
    assert_eq!(
        store.compression_stats(future).await.unwrap(),
        CompressionStats::default()
    );
}

#[tokio::test]
async fn evidence_insert_refuses_an_unknown_request() {
    let store = Store::open_in_memory().await.unwrap();
    // foreign_keys is ON, so a dangling request_id must be rejected.
    let err = store
        .insert_evidence("ev_1", "ghost", "log.source", b"raw", None)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::Database(_)));
}

#[tokio::test]
async fn get_connector_returns_none_when_absent() {
    let store = Store::open_in_memory().await.unwrap();
    assert_eq!(store.get_connector("github").await.unwrap(), None);
}

#[tokio::test]
async fn upsert_connector_creates_then_patches_only_given_fields() {
    let store = Store::open_in_memory().await.unwrap();

    // Creates: unset fields land on their defaults.
    let created = store
        .upsert_connector(
            "github",
            ConnectorPatch {
                enabled: Some(true),
                base_url: Some(Some("https://api.github.com")),
                username: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(created.id, "github");
    assert!(created.enabled);
    assert_eq!(created.base_url.as_deref(), Some("https://api.github.com"));
    assert_eq!(created.username, None);
    assert_eq!(created.last_test_status, None);

    // Patches only `username`: `enabled` and `base_url` are untouched.
    let patched = store
        .upsert_connector(
            "github",
            ConnectorPatch {
                enabled: None,
                base_url: None,
                username: Some(Some("octocat")),
            },
        )
        .await
        .unwrap();
    assert!(patched.enabled);
    assert_eq!(patched.base_url.as_deref(), Some("https://api.github.com"));
    assert_eq!(patched.username.as_deref(), Some("octocat"));
    assert!(patched.updated_ts >= created.updated_ts);

    // `Some(None)` clears `base_url`.
    let cleared = store
        .upsert_connector(
            "github",
            ConnectorPatch {
                enabled: None,
                base_url: Some(None),
                username: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(cleared.base_url, None);
    assert_eq!(cleared.username.as_deref(), Some("octocat"));
    assert!(cleared.enabled);

    // Read back through `get_connector` agrees.
    let fetched = store.get_connector("github").await.unwrap().unwrap();
    assert_eq!(fetched, cleared);
}

#[tokio::test]
async fn list_connectors_is_ordered_by_id() {
    let store = Store::open_in_memory().await.unwrap();
    for id in ["jenkins", "github", "argo"] {
        store
            .upsert_connector(
                id,
                ConnectorPatch {
                    enabled: Some(false),
                    base_url: None,
                    username: None,
                },
            )
            .await
            .unwrap();
    }

    let rows = store.list_connectors().await.unwrap();
    let ids: Vec<&str> = rows.iter().map(|row| row.id.as_str()).collect();
    assert_eq!(ids, ["argo", "github", "jenkins"]);
}

#[tokio::test]
async fn record_connector_test_creates_row_when_absent_and_updates_it() {
    let store = Store::open_in_memory().await.unwrap();

    // No prior row: the test result creates one.
    store
        .record_connector_test("github", true, "reached /user")
        .await
        .unwrap();
    let row = store.get_connector("github").await.unwrap().unwrap();
    assert_eq!(row.last_test_status.as_deref(), Some("passed"));
    assert_eq!(row.last_test_detail.as_deref(), Some("reached /user"));
    assert!(row.last_test_ts.is_some());
    assert!(!row.enabled, "record_connector_test must not enable it");

    // A later failing test overwrites the verdict without touching
    // fields it does not own.
    store
        .upsert_connector(
            "github",
            ConnectorPatch {
                enabled: Some(true),
                base_url: None,
                username: None,
            },
        )
        .await
        .unwrap();
    store
        .record_connector_test("github", false, "401 unauthorized")
        .await
        .unwrap();
    let row = store.get_connector("github").await.unwrap().unwrap();
    assert_eq!(row.last_test_status.as_deref(), Some("failed"));
    assert_eq!(row.last_test_detail.as_deref(), Some("401 unauthorized"));
    assert!(row.enabled, "record_connector_test must not clear enabled");
}
