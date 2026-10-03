//! Invariants the spine's security story leans on: terminal states absorb,
//! a security change commits with its audit row or not at all, a revocation
//! voids only the requests that depended on it, and stranded admissions are
//! finished rather than counted forever.

use crate::{
    Actor, ApprovalResolution, AuditEntry, Decision, EvidenceViewInsert, GrantChange,
    GrantChangeOutcome, OUTCOME_ADMIN_DENIED, RequestState, Store, StoreError,
};

const FAR_FUTURE_MS: i64 = i64::MAX / 2;

fn entry<'a>(action: &'a str, detail: Option<&'a str>) -> AuditEntry<'a> {
    AuditEntry {
        action,
        decision: Decision::Allow,
        actor: Actor::Human,
        detail,
    }
}

async fn admitted(store: &Store, id: &str, capability: &str, expires_at_ms: i64) {
    store
        .insert_admitted_request(id, capability, "/repo", "agent", "{}", None, expires_at_ms)
        .await
        .unwrap();
}

async fn running(store: &Store, id: &str) {
    store
        .insert_running_request(id, "admin.grants.add", "(admin)", "pam-gui", "{}", None)
        .await
        .unwrap();
}

async fn count(store: &Store, sql: &str) -> i64 {
    store.raw_scalar(sql, ()).await.unwrap()
}

/// Makes one statement fail from now on, to prove a multi-statement write
/// rolls back as a whole.
async fn inject_failure(store: &Store, trigger_sql: &str) {
    store.raw_execute(trigger_sql, ()).await.unwrap();
}

// --- terminal states are absorbing -----------------------------------------

#[tokio::test]
async fn a_finished_request_cannot_be_moved_back_to_an_inflight_state() {
    let store = Store::open_in_memory().await.unwrap();
    running(&store, "r").await;
    store
        .finish_request(
            "r",
            RequestState::Failed,
            Some("lease_expired"),
            entry("lease_expired", None),
        )
        .await
        .unwrap();

    // The late approval / wake-up path: both callers pass a non-terminal
    // state for a request that was reaped while they were parked.
    for state in [RequestState::Running, RequestState::WaitingApproval] {
        let error = store
            .update_request_state("r", state, None)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, StoreError::AlreadyTerminal { id } if id == "r"),
            "{error}"
        );
    }
    let row = store.get_request("r").await.unwrap().unwrap();
    assert_eq!(row.state, RequestState::Failed);
    assert_eq!(row.outcome.as_deref(), Some("lease_expired"));
    assert_eq!(store.audit_for_request("r").await.unwrap().len(), 1);

    // An in-flight request still moves, and a missing one still says so.
    running(&store, "live").await;
    store
        .update_request_state("live", RequestState::WaitingApproval, None)
        .await
        .unwrap();
    assert!(matches!(
        store
            .update_request_state("ghost", RequestState::Running, None)
            .await,
        Err(StoreError::NotFound { .. })
    ));
}

#[tokio::test]
async fn parking_on_an_approval_is_atomic_and_refuses_a_finished_request() {
    let store = Store::open_in_memory().await.unwrap();
    running(&store, "r").await;
    store
        .insert_approval_waiting("r", "flow.step:deploy/push")
        .await
        .unwrap();
    assert_eq!(
        store.get_request("r").await.unwrap().unwrap().state,
        RequestState::WaitingApproval
    );
    assert_eq!(store.list_pending_approvals().await.unwrap().len(), 1);

    running(&store, "done").await;
    store
        .finish_request(
            "done",
            RequestState::Failed,
            Some("cancelled"),
            entry("cancel", None),
        )
        .await
        .unwrap();
    assert!(matches!(
        store
            .insert_approval_waiting("done", "flow.step:deploy/push")
            .await,
        Err(StoreError::AlreadyTerminal { .. })
    ));
    assert!(store.approval_for_request("done").await.unwrap().is_none());

    // The approval insert failing takes the state change down with it.
    running(&store, "half").await;
    inject_failure(
        &store,
        "CREATE TRIGGER fail_approval BEFORE INSERT ON approval \
         BEGIN SELECT RAISE(ABORT, 'injected'); END",
    )
    .await;
    assert!(store.insert_approval_waiting("half", "x").await.is_err());
    assert_eq!(
        store.get_request("half").await.unwrap().unwrap().state,
        RequestState::Running
    );
}

#[tokio::test]
async fn the_pending_list_hides_an_approval_whose_request_already_finished() {
    let store = Store::open_in_memory().await.unwrap();
    running(&store, "r").await;
    store
        .insert_approval("r", "flow.step:deploy/push")
        .await
        .unwrap();
    assert_eq!(store.list_pending_approvals().await.unwrap().len(), 1);
    // A crash between the terminal write and the approval's resolution.
    store
        .finish_request(
            "r",
            RequestState::Failed,
            Some("daemon_restart"),
            entry("restart", None),
        )
        .await
        .unwrap();
    assert!(store.list_pending_approvals().await.unwrap().is_empty());
}

// --- a security change commits with its audit row --------------------------

#[tokio::test]
async fn a_grant_change_and_its_audit_row_commit_together_or_not_at_all() {
    let store = Store::open_in_memory().await.unwrap();
    running(&store, "r").await;

    let added = store
        .apply_grant_change_audited(
            "r",
            GrantChange::Add("echo"),
            entry("auto_grant", Some("{\"capability\":\"echo\"}")),
        )
        .await
        .unwrap();
    assert_eq!(added, GrantChangeOutcome::Applied);
    assert!(store.active_grant("echo").await.unwrap());
    assert_eq!(store.audit_for_request("r").await.unwrap().len(), 1);

    // A duplicate grant writes nothing, audit row included.
    let again = store
        .apply_grant_change_audited("r", GrantChange::Add("echo"), entry("auto_grant", None))
        .await
        .unwrap();
    assert_eq!(again, GrantChangeOutcome::Unchanged);
    assert_eq!(count(&store, "SELECT COUNT(*) FROM \"grant\"").await, 1);
    assert_eq!(store.audit_for_request("r").await.unwrap().len(), 1);

    // No request to hang the audit row on: the grant must not survive.
    assert!(
        store
            .apply_grant_change_audited("ghost", GrantChange::Add("flow.run"), entry("x", None))
            .await
            .is_err()
    );
    assert!(!store.active_grant("flow.run").await.unwrap());

    // Same for a revocation whose audit row cannot be written.
    assert!(
        store
            .apply_grant_change_audited("ghost", GrantChange::Revoke("echo"), entry("x", None))
            .await
            .is_err()
    );
    assert!(store.active_grant("echo").await.unwrap());
    assert_eq!(store.grant_revocation_revision().await.unwrap(), 0);
}

#[tokio::test]
async fn an_admin_grant_change_finishes_its_request_in_the_same_transaction() {
    let store = Store::open_in_memory().await.unwrap();
    running(&store, "add").await;
    let outcome = store
        .finish_request_with_grant_change(
            "add",
            GrantChange::Add("flow.run"),
            Some("changed"),
            entry("admin", Some("{\"op\":\"admin.grants.add\"}")),
        )
        .await
        .unwrap();
    assert_eq!(outcome, GrantChangeOutcome::Applied);
    assert!(store.active_grant("flow.run").await.unwrap());
    let row = store.get_request("add").await.unwrap().unwrap();
    assert_eq!(row.state, RequestState::Done);
    assert_eq!(row.outcome.as_deref(), Some("changed"));
    assert_eq!(store.audit_for_request("add").await.unwrap().len(), 1);

    // Nothing to do: nothing written, request still in flight for the
    // caller's own refusal.
    running(&store, "dup").await;
    let outcome = store
        .finish_request_with_grant_change(
            "dup",
            GrantChange::Add("flow.run"),
            Some("changed"),
            entry("admin", None),
        )
        .await
        .unwrap();
    assert_eq!(outcome, GrantChangeOutcome::Unchanged);
    assert_eq!(
        store.get_request("dup").await.unwrap().unwrap().state,
        RequestState::Running
    );
    assert!(store.audit_for_request("dup").await.unwrap().is_empty());

    // The deadline finisher won: the revocation must NOT take effect under
    // a request the trail records as failed.
    running(&store, "late").await;
    store
        .finish_request(
            "late",
            RequestState::Failed,
            Some("deadline_exceeded"),
            entry("deadline_refusal", None),
        )
        .await
        .unwrap();
    let error = store
        .finish_request_with_grant_change(
            "late",
            GrantChange::Revoke("flow.run"),
            Some("changed"),
            entry("admin", None),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, StoreError::AlreadyTerminal { .. }),
        "{error}"
    );
    assert!(store.active_grant("flow.run").await.unwrap());
    assert_eq!(store.audit_for_request("late").await.unwrap().len(), 1);

    // The audit insert failing rolls back the revocation and the terminal state.
    running(&store, "boom").await;
    inject_failure(
        &store,
        "CREATE TRIGGER fail_audit BEFORE INSERT ON audit \
         BEGIN SELECT RAISE(ABORT, 'injected'); END",
    )
    .await;
    assert!(
        store
            .finish_request_with_grant_change(
                "boom",
                GrantChange::Revoke("flow.run"),
                Some("changed"),
                entry("admin", None),
            )
            .await
            .is_err()
    );
    assert!(store.active_grant("flow.run").await.unwrap());
    assert_eq!(
        store.get_request("boom").await.unwrap().unwrap().state,
        RequestState::Running
    );
}

#[tokio::test]
async fn an_approval_resolution_its_grant_and_both_audit_rows_are_one_transaction() {
    let store = Store::open_in_memory().await.unwrap();
    let capability = "flow.step:deploy/push";
    running(&store, "r").await;
    store
        .insert_approval_waiting("r", capability)
        .await
        .unwrap();

    let granted = store
        .resolve_approval_audited(
            "r",
            ApprovalResolution::Approved,
            None,
            entry("approval", Some("{\"resolution\":\"approved\"}")),
            Some((capability, entry("grant_from_approval", None))),
        )
        .await
        .unwrap();
    assert!(granted);
    assert!(store.active_grant(capability).await.unwrap());
    let approval = store.approval_for_request("r").await.unwrap().unwrap();
    assert_eq!(approval.resolution, Some(ApprovalResolution::Approved));
    let actions: Vec<String> = store
        .audit_for_request("r")
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.action)
        .collect();
    assert_eq!(actions, ["approval", "grant_from_approval"]);

    // The race guard: a second resolution finds nothing and writes nothing.
    assert!(matches!(
        store
            .resolve_approval_audited(
                "r",
                ApprovalResolution::Denied,
                None,
                entry("approval", None),
                None
            )
            .await,
        Err(StoreError::NotFound { .. })
    ));
    assert_eq!(store.audit_for_request("r").await.unwrap().len(), 2);

    // The grant insert failing leaves the approval pending and unaudited:
    // no resolved approval without its trail, no trail without the grant.
    running(&store, "half").await;
    store
        .insert_approval_waiting("half", "flow.step:deploy/merge")
        .await
        .unwrap();
    inject_failure(
        &store,
        "CREATE TRIGGER fail_grant BEFORE INSERT ON \"grant\" \
         BEGIN SELECT RAISE(ABORT, 'injected'); END",
    )
    .await;
    assert!(
        store
            .resolve_approval_audited(
                "half",
                ApprovalResolution::Approved,
                None,
                entry("approval", None),
                Some(("flow.step:deploy/merge", entry("grant_from_approval", None))),
            )
            .await
            .is_err()
    );
    let pending = store.approval_for_request("half").await.unwrap().unwrap();
    assert_eq!(pending.resolved_ts, None);
    assert!(store.audit_for_request("half").await.unwrap().is_empty());
    assert!(!store.active_grant("flow.step:deploy/merge").await.unwrap());
}

#[tokio::test]
async fn audit_rows_cannot_be_rewritten() {
    let store = Store::open_in_memory().await.unwrap();
    running(&store, "r").await;
    store
        .append_audit(
            "r",
            "enqueue",
            Decision::Allow,
            Actor::Policy,
            Some("original"),
        )
        .await
        .unwrap();
    let error = store
        .raw_execute("UPDATE audit SET decision='refuse', detail='rewritten'", ())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("append-only"), "{error}");
    let rows = store.audit_for_request("r").await.unwrap();
    assert_eq!(rows[0].detail.as_deref(), Some("original"));
    assert_eq!(rows[0].decision, Decision::Allow);
}

#[tokio::test]
async fn several_settings_are_saved_together_or_not_at_all() {
    let store = Store::open_in_memory().await.unwrap();
    store
        .set_settings(&[
            ("retention.evidence_days", "7"),
            ("retention.audit_days", "30"),
        ])
        .await
        .unwrap();
    assert_eq!(
        store
            .get_setting("retention.audit_days")
            .await
            .unwrap()
            .as_deref(),
        Some("30")
    );
    inject_failure(
        &store,
        "CREATE TRIGGER fail_second BEFORE UPDATE ON setting WHEN NEW.key='retention.audit_days' \
         BEGIN SELECT RAISE(ABORT, 'injected'); END",
    )
    .await;
    assert!(
        store
            .set_settings(&[
                ("retention.evidence_days", "90"),
                ("retention.audit_days", "90")
            ])
            .await
            .is_err()
    );
    // The first key of the failed save did not stick on its own.
    assert_eq!(
        store
            .get_setting("retention.evidence_days")
            .await
            .unwrap()
            .as_deref(),
        Some("7")
    );
}

// --- a revocation voids only what depended on it ---------------------------

#[tokio::test]
async fn a_revocation_voids_only_requests_that_depended_on_the_revoked_grant() {
    let store = Store::open_in_memory().await.unwrap();
    for capability in [
        "echo",
        "flow.run",
        "flow.step:deploy/push",
        "flow.step:other/x",
    ] {
        store.insert_grant(capability).await.unwrap();
    }
    admitted(&store, "echo_ticket", "echo", FAR_FUTURE_MS).await;
    admitted(&store, "flow_ticket", "flow.run", FAR_FUTURE_MS).await;
    for id in ["echo_ticket", "flow_ticket"] {
        assert!(store.request_authorization_current(id).await.unwrap());
    }

    // An unrelated step grant goes: the echo ticket never depended on it.
    store.revoke_grant("flow.step:other/x").await.unwrap();
    assert!(
        store
            .request_authorization_current("echo_ticket")
            .await
            .unwrap()
    );
    // A flow run reaches its steps under `flow.step:` names, so any step
    // revocation after its admission voids it.
    assert!(
        !store
            .request_authorization_current("flow_ticket")
            .await
            .unwrap()
    );

    // The global figure moved for everyone; that is the collateral damage
    // the scoped check exists to avoid.
    let echo = store.get_request("echo_ticket").await.unwrap().unwrap();
    assert_ne!(
        echo.authorization_revision,
        Some(store.grant_revocation_revision().await.unwrap())
    );

    // A flow admitted after that revocation is unaffected by it ...
    admitted(&store, "flow_later", "flow.run", FAR_FUTURE_MS).await;
    assert!(
        store
            .request_authorization_current("flow_later")
            .await
            .unwrap()
    );
    // ... and by an echo revocation, which voids the echo ticket only.
    store.revoke_grant("echo").await.unwrap();
    assert!(
        !store
            .request_authorization_current("echo_ticket")
            .await
            .unwrap()
    );
    assert!(
        store
            .request_authorization_current("flow_later")
            .await
            .unwrap()
    );

    // Re-granting never restores a voided admission.
    store.insert_grant("echo").await.unwrap();
    assert!(
        !store
            .request_authorization_current("echo_ticket")
            .await
            .unwrap()
    );
    // A new admission under the new grant stands.
    admitted(&store, "echo_again", "echo", FAR_FUTURE_MS).await;
    assert!(
        store
            .request_authorization_current("echo_again")
            .await
            .unwrap()
    );

    // Revoking the run capability itself voids the later flow too.
    store.revoke_grant("flow.run").await.unwrap();
    assert!(
        !store
            .request_authorization_current("flow_later")
            .await
            .unwrap()
    );
    assert!(
        store
            .request_authorization_current("echo_again")
            .await
            .unwrap()
    );

    // Fail closed on the edges: no row, or a row admitted without a revision.
    assert!(!store.request_authorization_current("ghost").await.unwrap());
    running(&store, "admin_row").await;
    assert!(
        !store
            .request_authorization_current("admin_row")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn the_store_side_admission_checks_use_the_scoped_rule() {
    let store = Store::open_in_memory().await.unwrap();
    store.insert_grant("echo").await.unwrap();
    store.insert_grant("flow.step:deploy/push").await.unwrap();
    admitted(&store, "kept", "echo", FAR_FUTURE_MS).await;
    admitted(&store, "voided", "echo", FAR_FUTURE_MS).await;

    // Unrelated revocation between admission and the gate's verdict.
    store.revoke_grant("flow.step:deploy/push").await.unwrap();
    assert!(
        store
            .authorize_queued_request("kept", "/repo", 1)
            .await
            .unwrap()
    );
    assert!(store.start_queued_request("kept", 1).await.unwrap());

    // The request's own capability revoked (and re-granted) in that window.
    store.revoke_grant("echo").await.unwrap();
    store.insert_grant("echo").await.unwrap();
    assert!(
        !store
            .authorize_queued_request("voided", "/repo", 1)
            .await
            .unwrap()
    );
    assert_eq!(
        store.get_request("voided").await.unwrap().unwrap().state,
        RequestState::Running,
        "a voided admission must not be queued"
    );
}

#[tokio::test]
async fn evidence_and_status_metadata_report_the_scoped_admission_state() {
    let store = Store::open_in_memory().await.unwrap();
    store.insert_grant("echo").await.unwrap();
    store.insert_grant("flow.step:deploy/push").await.unwrap();
    admitted(&store, "t", "echo", FAR_FUTURE_MS).await;
    store
        .insert_evidence("e", "t", "log", b"source", None)
        .await
        .unwrap();
    let view = EvidenceViewInsert {
        evidence_id: "e".into(),
        request_id: "t".into(),
        repository: "/repo".into(),
        origin_json: "{}".into(),
        identity_json: "{}".into(),
        map_json: "[]".into(),
        view_id: "v".into(),
        view_bytes: b"safe".to_vec(),
    };
    assert!(store.insert_evidence_view(&view).await.unwrap());

    store.revoke_grant("flow.step:deploy/push").await.unwrap();
    let meta = store
        .evidence_view_meta("t", "e", "/repo")
        .await
        .unwrap()
        .unwrap();
    assert!(
        meta.authorization_current,
        "an unrelated revoke orphaned the evidence"
    );
    assert!(
        store
            .request_status_meta("t")
            .await
            .unwrap()
            .unwrap()
            .authorization_current
    );

    store.revoke_grant("echo").await.unwrap();
    let meta = store
        .evidence_view_meta("t", "e", "/repo")
        .await
        .unwrap()
        .unwrap();
    assert!(!meta.authorization_current);
    assert!(
        !store
            .request_status_meta("t")
            .await
            .unwrap()
            .unwrap()
            .authorization_current
    );
}

#[tokio::test]
async fn the_scoped_revocation_counter_moves_only_for_relevant_grants() {
    let store = Store::open_in_memory().await.unwrap();
    for capability in ["echo", "flow.run", "flow.step:deploy/push"] {
        store.insert_grant(capability).await.unwrap();
    }
    store.revoke_grant("echo").await.unwrap();
    assert_eq!(
        store.grant_revocation_revision_for("echo").await.unwrap(),
        1
    );
    assert_eq!(
        store
            .grant_revocation_revision_for("flow.run")
            .await
            .unwrap(),
        0
    );
    store.revoke_grant("flow.step:deploy/push").await.unwrap();
    assert_eq!(
        store.grant_revocation_revision_for("echo").await.unwrap(),
        1
    );
    assert_eq!(
        store
            .grant_revocation_revision_for("flow.run")
            .await
            .unwrap(),
        1
    );
    store.revoke_grant("flow.run").await.unwrap();
    assert_eq!(
        store
            .grant_revocation_revision_for("flow.run")
            .await
            .unwrap(),
        2
    );
    assert_eq!(store.grant_revocation_revision().await.unwrap(), 3);
}

#[tokio::test]
async fn one_revocation_of_duplicate_active_grants_keeps_the_sequence_monotonic() {
    let store = Store::open_in_memory().await.unwrap();
    // Two active rows for one capability (the unaudited insert never dedupes).
    store.insert_grant("echo").await.unwrap();
    store.insert_grant("echo").await.unwrap();
    store.insert_grant("flow.run").await.unwrap();
    admitted(&store, "before", "echo", FAR_FUTURE_MS).await;
    store.revoke_grant("echo").await.unwrap();
    assert_eq!(store.grant_revocation_revision().await.unwrap(), 2);
    // Admitted after: its snapshot (2) covers both revoked rows.
    store.insert_grant("echo").await.unwrap();
    admitted(&store, "after", "echo", FAR_FUTURE_MS).await;
    assert!(!store.request_authorization_current("before").await.unwrap());
    assert!(store.request_authorization_current("after").await.unwrap());
    // The next revocation is numbered past every snapshot taken so far.
    store.revoke_grant("echo").await.unwrap();
    assert!(!store.request_authorization_current("after").await.unwrap());
}

// --- stranded admissions ----------------------------------------------------

#[tokio::test]
async fn expired_admissions_stop_counting_and_are_finished_with_an_audit_row() {
    let store = Store::open_in_memory().await.unwrap();
    admitted(&store, "live", "echo", 10_000).await;
    admitted(&store, "stranded_a", "echo", 1_000).await;
    admitted(&store, "stranded_b", "echo", 2_000).await;
    running(&store, "admin_row").await;

    // The unfiltered figure counts the stranded rows forever.
    assert_eq!(store.admission_usage().await.unwrap().0, 3);
    let (live, bytes) = store.admission_usage_at(5_000).await.unwrap();
    assert_eq!(live, 1);
    assert!(bytes > 0);

    let audit = AuditEntry {
        action: "lease_expired",
        decision: Decision::Timeout,
        actor: Actor::System,
        detail: Some("{\"cause\":\"lease_expired\"}"),
    };
    // Bounded: one row per call when asked for one, oldest deadline first.
    let first = store
        .fail_expired_requests(5_000, 1, "lease_expired", audit)
        .await
        .unwrap();
    assert_eq!(first, ["stranded_a"]);
    let second = store
        .fail_expired_requests(5_000, 64, "lease_expired", audit)
        .await
        .unwrap();
    assert_eq!(second, ["stranded_b"]);
    assert!(
        store
            .fail_expired_requests(5_000, 64, "lease_expired", audit)
            .await
            .unwrap()
            .is_empty()
    );

    for id in ["stranded_a", "stranded_b"] {
        let row = store.get_request(id).await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed);
        assert_eq!(row.outcome.as_deref(), Some("lease_expired"));
        let rows = store.audit_for_request(id).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "lease_expired");
        assert_eq!(rows[0].decision, Decision::Timeout);
    }
    // A live admission and a row without a deadline are left alone.
    for id in ["live", "admin_row"] {
        assert_eq!(
            store.get_request(id).await.unwrap().unwrap().state,
            RequestState::Running
        );
    }
    assert_eq!(store.admission_usage().await.unwrap().0, 1);
    assert!(
        store
            .terminal_requests_missing_audit(&["lease_expired"])
            .await
            .unwrap()
            .is_empty()
    );
}

// --- activity feed ----------------------------------------------------------

#[tokio::test]
async fn hiding_probes_never_hides_a_refused_admin_attempt() {
    let store = Store::open_in_memory().await.unwrap();
    // The GUI's own polls.
    store
        .insert_running_request(
            "poll",
            "admin.approvals.pending",
            "(admin)",
            "pam-gui",
            "{}",
            None,
        )
        .await
        .unwrap();
    store
        .finish_request(
            "poll",
            RequestState::Done,
            Some("verified"),
            entry("admin", None),
        )
        .await
        .unwrap();
    store
        .insert_running_request("status", "status", "/repo", "agent", "{}", None)
        .await
        .unwrap();
    // An agent on the public socket trying to grant itself a capability.
    store
        .insert_running_request(
            "forged",
            "admin.grants.add",
            "(admin)",
            "claude",
            "{}",
            None,
        )
        .await
        .unwrap();
    store
        .finish_request(
            "forged",
            RequestState::Refused,
            Some(OUTCOME_ADMIN_DENIED),
            AuditEntry {
                action: "admin_denied",
                decision: Decision::Refuse,
                actor: Actor::System,
                detail: None,
            },
        )
        .await
        .unwrap();
    // A GUI op refused for an ordinary reason is still the GUI's own traffic.
    store
        .insert_running_request(
            "gui_refused",
            "admin.grants.add",
            "(admin)",
            "pam-gui",
            "{}",
            None,
        )
        .await
        .unwrap();
    store
        .finish_request(
            "gui_refused",
            RequestState::Refused,
            Some("already_granted"),
            entry("admin", None),
        )
        .await
        .unwrap();

    let visible: Vec<String> = store
        .list_requests_filtered(None, None, None, None, None, true)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.id)
        .collect();
    assert_eq!(visible, ["forged"]);
    assert_eq!(
        store
            .list_requests_filtered(None, None, None, None, None, false)
            .await
            .unwrap()
            .len(),
        4
    );
}

#[tokio::test]
async fn like_patterns_ignore_ascii_case_which_only_hides_or_voids_more() {
    // The engine's LIKE ignores ASCII case. The store's two patterns are
    // prefixes of names the daemon writes in lower case, so the difference
    // is only reachable through an oddly spelled capability, and then it
    // errs on the closed side: more is voided, more is treated as a probe.
    let store = Store::open_in_memory().await.unwrap();

    // `flow.step:%`: a step grant spelled in capitals still counts as one a
    // flow.run ticket depends on.
    store.insert_grant("FLOW.STEP:deploy/push").await.unwrap();
    admitted(&store, "ticket", "flow.run", FAR_FUTURE_MS).await;
    assert!(store.request_authorization_current("ticket").await.unwrap());
    store.revoke_grant("FLOW.STEP:deploy/push").await.unwrap();
    assert!(!store.request_authorization_current("ticket").await.unwrap());
    assert_eq!(
        store
            .grant_revocation_revision_for("flow.run")
            .await
            .unwrap(),
        1
    );

    // `admin.%`: an admin op spelled in capitals is hidden with the probes.
    store
        .insert_running_request("probe", "ADMIN.Grants.List", "(admin)", "gui", "{}", None)
        .await
        .unwrap();
    let ids = |rows: Vec<crate::RequestRow>| rows.into_iter().map(|row| row.id).collect::<Vec<_>>();
    let shown = store
        .list_requests_filtered(None, None, None, None, None, true)
        .await
        .unwrap();
    assert_eq!(ids(shown), ["ticket"]);
    let all = store
        .list_requests_filtered(None, None, None, None, None, false)
        .await
        .unwrap();
    assert_eq!(all.len(), 2);
}

#[tokio::test]
async fn the_hot_scans_are_served_by_indexes() {
    let store = Store::open_in_memory().await.unwrap();
    let evidence_prune = Store::evidence_prune_batch_sql()
        .replace("?1", "5")
        .replace("?2", "'flow.result'");
    let request_prune = Store::request_prune_batch_sql().replace("?1", "5");
    for (sql, index) in [
        // The Activity list, with and without the probe filter and a
        // terminal-state filter: newest first off the created index.
        (
            "SELECT id FROM request WHERE capability <> 'status' \
             ORDER BY created_ts DESC, id DESC LIMIT 100",
            "request_created_idx",
        ),
        (
            "SELECT id FROM request WHERE +state = 'done' \
             ORDER BY created_ts DESC, id DESC LIMIT 100",
            "request_created_idx",
        ),
        (request_prune.as_str(), "request_updated_idx"),
        (evidence_prune.as_str(), "evidence_ts_idx"),
        (
            "SELECT id, meta_json FROM evidence WHERE kind = 'log.compact' AND ts >= 5",
            "evidence_kind_ts_idx",
        ),
    ] {
        let explain = format!("EXPLAIN QUERY PLAN {sql}");
        let plan = store
            .raw(move |conn| {
                let mut stmt = conn.prepare(&explain)?;
                let mut rows = stmt.query(())?;
                let mut plan = String::new();
                while let Some(row) = rows.next()? {
                    plan.push_str(&row.get::<_, String>(3)?);
                    plan.push('\n');
                }
                Ok(plan)
            })
            .await
            .unwrap();
        assert!(plan.contains(index), "{sql}\nplan:\n{plan}");
        // The engine names a sort it had to add "USE TEMP B-TREE FOR ORDER
        // BY" (the previous engine said "SORTER").
        assert!(
            !plan.contains("SORTER") && !plan.contains("TEMP B-TREE"),
            "{sql} still sorts:\nplan:\n{plan}"
        );
    }
}

// --- retention --------------------------------------------------------------

#[tokio::test]
async fn pruning_more_than_one_batch_removes_every_old_record_whole() {
    let store = Store::open_in_memory().await.unwrap();
    // More terminal records than one request batch (256) and more evidence
    // rows than one evidence batch (64), plus rows that must survive.
    let old = 300_usize;
    for n in 0..old {
        let id = format!("old_{n:04}");
        running(&store, &id).await;
        store
            .insert_evidence(
                &format!("ev_{n:04}"),
                &id,
                "log.source",
                b"0123456789",
                None,
            )
            .await
            .unwrap();
        store
            .finish_request(
                &id,
                RequestState::Done,
                Some("verified"),
                entry("admin", None),
            )
            .await
            .unwrap();
    }
    running(&store, "inflight").await;
    store
        .insert_evidence("ev_inflight", "inflight", "log.source", b"keep", None)
        .await
        .unwrap();
    store
        .raw_execute("UPDATE request SET updated_ts = 10, created_ts = 10", ())
        .await
        .unwrap();
    store
        .raw_execute("UPDATE evidence SET ts = 10", ())
        .await
        .unwrap();
    running(&store, "recent").await;
    store
        .finish_request(
            "recent",
            RequestState::Done,
            Some("verified"),
            entry("admin", None),
        )
        .await
        .unwrap();

    let evidence = store
        .prune_evidence_before(100, "flow.result")
        .await
        .unwrap();
    assert_eq!(evidence.rows, u64::try_from(old).unwrap());
    assert_eq!(evidence.bytes, u64::try_from(old * 10).unwrap());
    assert!(store.get_evidence("ev_inflight").await.unwrap().is_some());

    let records = store.prune_requests_before(100).await.unwrap();
    assert_eq!(records.requests, u64::try_from(old).unwrap());
    assert_eq!(records.audit_rows, u64::try_from(old).unwrap());
    assert_eq!(count(&store, "SELECT COUNT(*) FROM request").await, 2);
    assert_eq!(count(&store, "SELECT COUNT(*) FROM audit").await, 1);
    assert!(store.get_request("inflight").await.unwrap().is_some());
    assert!(store.get_request("recent").await.unwrap().is_some());
    // A second pass finds nothing: the batches left no remainder behind.
    assert_eq!(store.prune_requests_before(100).await.unwrap().requests, 0);
}

// --- engine health ----------------------------------------------------------

#[tokio::test]
async fn a_structurally_damaged_database_is_refused_legibly_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    {
        let store = Store::open(&path).await.unwrap();
        for n in 0..200 {
            running(&store, &format!("req_{n:03}")).await;
        }
        store.check_integrity().await.unwrap();
    }
    // A healthy file reopens.
    drop(Store::open(&path).await.unwrap());

    // Overwrite everything past the header page, in the main file and in
    // the write-ahead log, the way a torn copy or a failing disk would.
    for name in ["state.sqlite3", "state.sqlite3-wal"] {
        let file = dir.path().join(name);
        let Ok(mut bytes) = std::fs::read(&file) else {
            continue;
        };
        for byte in bytes.iter_mut().skip(4096) {
            *byte = 0xA5;
        }
        std::fs::write(&file, bytes).unwrap();
    }
    match Store::open(&path).await {
        Err(StoreError::Corrupt { detail }) => {
            assert!(!detail.is_empty());
            let message = StoreError::Corrupt { detail }.to_string();
            assert!(message.contains("integrity check failed"), "{message}");
            assert!(message.contains("backup"), "{message}");
        }
        Err(other) => panic!("damage must be reported as corruption, got: {other}"),
        Ok(_) => panic!("a damaged database opened as if it were healthy"),
    }
}

// --- stack budget -------------------------------------------------------------

/// Runs the store's boot and hot-path statements on a runtime whose threads
/// — the one driving the calls and the blocking ones the statements run on —
/// have `stack` bytes each. An overflow aborts the test process, so this
/// either passes or fails loudly.
fn run_hot_statements_on_a_stack_of(stack: usize) {
    std::thread::Builder::new()
        .stack_size(stack)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .thread_stack_size(stack)
                .enable_all()
                .build()
                .unwrap()
                .block_on(hot_statements());
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn hot_statements() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("state.sqlite3"))
        .await
        .unwrap();
    store.insert_grant("echo").await.unwrap();
    admitted(&store, "stuck", "echo", FAR_FUTURE_MS).await;
    admitted(&store, "queued", "echo", FAR_FUTURE_MS).await;
    let authorized = store.authorize_queued_request("queued", "/repo", 1).await;
    assert!(authorized.unwrap());
    // Boot recovery: the two page readers and what follows them.
    let stuck = store.stuck_recovery_page(None, 8 << 20).await.unwrap();
    assert_eq!(stuck.unwrap().len(), 1);
    let queued = store.queued_recovery_page(None, 8 << 20).await.unwrap();
    assert_eq!(queued.unwrap().len(), 1);
    assert_eq!(store.admission_usage_at(1).await.unwrap().0, 2);
    assert!(store.start_queued_request("queued", 1).await.unwrap());
    assert!(store.request_authorization_current("queued").await.unwrap());
    // The terminal write and the feeds the GUI polls.
    let finished = store
        .finish_request("stuck", RequestState::Failed, Some("x"), entry("x", None))
        .await;
    assert!(finished.unwrap());
    let failed = store
        .list_requests_filtered(None, None, None, Some(RequestState::Failed), None, true)
        .await;
    assert_eq!(failed.unwrap().len(), 1);
    assert!(store.list_pending_approvals().await.unwrap().is_empty());
    store.prune_evidence_before(1, "flow.result").await.unwrap();
    store.prune_requests_before(1).await.unwrap();
}

#[test]
fn boot_recovery_and_the_hot_statements_fit_well_inside_a_thread_stack() {
    // The statements run on the runtime's blocking threads, 2 MiB each by
    // default. The previous engine translated expressions recursively with
    // very large frames in a debug build and came within a few kilobytes of
    // that; this one compiles a statement iteratively, and everything here
    // (open, migrate, boot recovery, the terminal write, both prunes) passes
    // on a far smaller stack on the development host. The budget below leaves
    // room for other platforms' frame sizes and still fails if a statement
    // ever needs most of a megabyte.
    run_hot_statements_on_a_stack_of(512 * 1024);
}
