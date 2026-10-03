//! Migration 17: flow step grants bound to what runs, and flow-scoped
//! revocation through `request.flow_id`.

use rusqlite::Connection;

use crate::{
    Actor, AuditEntry, Decision, GrantBinding, GrantChange, GrantChangeOutcome, RequestOrigin,
    SCOPE_REPOSITORY, Store, migrations,
};

fn binding(flow: &str, step: &str, digest: char, repository: Option<&str>) -> GrantBinding {
    GrantBinding {
        flow_id: flow.to_owned(),
        step_id: step.to_owned(),
        effect_digest: digest.to_string().repeat(64),
        effect_class: "destructive".to_owned(),
        repository: repository.map(str::to_owned),
    }
}

const AUDIT: AuditEntry<'static> = AuditEntry {
    action: "grant_bound",
    decision: Decision::Allow,
    actor: Actor::Policy,
    detail: None,
};

async fn admitted_flow(store: &Store, id: &str, args: &str) {
    store
        .insert_admitted_request_from(
            id,
            "flow.run",
            "/r",
            "claude",
            args,
            None,
            i64::MAX,
            &RequestOrigin::PUBLIC,
        )
        .await
        .unwrap();
}

/// A database exactly as the previous version (16) left it: a flow step
/// grant, an `echo` grant and a parked `flow.run` ticket that names its flow.
fn build_v16_database(path: &std::path::Path) {
    let conn = Connection::open(path).unwrap();
    for migration in migrations::MIGRATIONS.iter().filter(|m| m.version <= 16) {
        conn.execute_batch(migration.sql).unwrap();
    }
    conn.execute_batch("PRAGMA user_version = 16").unwrap();
    conn.execute_batch(
        r#"
        INSERT INTO "grant" (capability, scope, granted_ts) VALUES ('flow.step:ship/push', 'global', 5);
        INSERT INTO "grant" (capability, scope, granted_ts) VALUES ('echo', 'global', 6);
        INSERT INTO request (id, capability, repo, caller_agent, args_json, state, created_ts,
            updated_ts, expires_at_ms, authorization_revision, queue_authorized)
            VALUES ('old_parked', 'flow.run', '/r', 'claude', '{"id":"ship"}', 'queued', 1, 2,
            9223372036854775807, 0, 1);
        "#,
    )
    .unwrap();
    drop(conn);
}

/// The upgrade: existing grants read back as unbound legacy rows (they
/// still count as active), the old ticket names no flow and so any flow's
/// step revocation still voids it, and a ticket admitted after the upgrade
/// records its flow.
#[tokio::test]
async fn v16_database_gains_unbound_legacy_grants_and_request_flow_ids() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    build_v16_database(&path);

    let store = Store::open(&path).await.unwrap();
    assert_eq!(
        store.schema_version().await.unwrap(),
        migrations::latest_version()
    );
    let grants = store.list_grants().await.unwrap();
    assert_eq!(grants.len(), 2);
    for grant in &grants {
        assert_eq!(grant.binding, None, "{grant:?}");
        assert_eq!(grant.bound_ts, None);
        assert_eq!(grant.scope, "global");
    }
    assert!(store.active_grant("flow.step:ship/push").await.unwrap());
    let active = store.active_grants("flow.step:ship/push").await.unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].granted_ts, 5);

    assert_eq!(store.request_flow_id("old_parked").await.unwrap(), None);
    admitted_flow(&store, "new_ship", r#"{"id":"ship"}"#).await;
    admitted_flow(&store, "new_other", r#"{"id":"other"}"#).await;
    assert_eq!(
        store.request_flow_id("new_ship").await.unwrap().as_deref(),
        Some("ship")
    );

    // A step grant of a third flow: the old ticket names no flow, so it is
    // voided as it always was; the new tickets name theirs and stand.
    store.insert_grant("flow.step:third/x").await.unwrap();
    store.revoke_grant("flow.step:third/x").await.unwrap();
    assert!(
        !store
            .request_authorization_current("old_parked")
            .await
            .unwrap()
    );
    assert!(
        store
            .request_authorization_current("new_ship")
            .await
            .unwrap()
    );
    assert!(
        store
            .request_authorization_current("new_other")
            .await
            .unwrap()
    );

    // The legacy grant binds once, with its audit row.
    let bound = binding("ship", "push", 'a', Some("/r"));
    assert!(
        store
            .bind_legacy_grant_audited("new_ship", active[0].id, &bound, AUDIT)
            .await
            .unwrap()
    );
    assert!(
        !store
            .bind_legacy_grant_audited("new_ship", active[0].id, &bound, AUDIT)
            .await
            .unwrap(),
        "a bound row is no longer a legacy one"
    );
    let audit = store.audit_for_request("new_ship").await.unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].action, "grant_bound");
    let row = &store.active_grants("flow.step:ship/push").await.unwrap()[0];
    assert_eq!(row.binding.as_ref(), Some(&bound));
    assert_eq!(row.scope, SCOPE_REPOSITORY);
    assert!(row.bound_ts.is_some());
    store.close().await.unwrap();
}

#[tokio::test]
async fn revoking_one_flows_step_grant_voids_only_that_flows_tickets() {
    let store = Store::open_in_memory().await.unwrap();
    admitted_flow(&store, "x", r#"{"id":"x"}"#).await;
    admitted_flow(&store, "xy", r#"{"id":"xy"}"#).await;
    admitted_flow(&store, "y", r#"{"id":"y"}"#).await;
    admitted_flow(&store, "unnamed", "{}").await;
    let before_x = store.grant_revocation_revision_for_flow("x").await.unwrap();
    let before_y = store.grant_revocation_revision_for_flow("y").await.unwrap();

    store.insert_grant("flow.step:x/step").await.unwrap();
    store.revoke_grant("flow.step:x/step").await.unwrap();

    assert!(!store.request_authorization_current("x").await.unwrap());
    // A flow whose id merely starts with `x` is another flow.
    assert!(store.request_authorization_current("xy").await.unwrap());
    assert!(store.request_authorization_current("y").await.unwrap());
    // A run that names no flow depends on every flow's step grants.
    assert!(
        !store
            .request_authorization_current("unnamed")
            .await
            .unwrap()
    );
    assert_eq!(
        store.grant_revocation_revision_for_flow("x").await.unwrap(),
        before_x + 1
    );
    assert_eq!(
        store.grant_revocation_revision_for_flow("y").await.unwrap(),
        before_y
    );
    // Revoking `flow.run` itself voids every run.
    store.insert_grant("flow.run").await.unwrap();
    store.revoke_grant("flow.run").await.unwrap();
    assert!(!store.request_authorization_current("y").await.unwrap());
    assert_eq!(
        store.grant_revocation_revision_for_flow("y").await.unwrap(),
        before_y + 1
    );
}

#[tokio::test]
async fn a_bound_grant_is_re_pointed_per_repository_and_binds_a_legacy_row_first() {
    let store = Store::open_in_memory().await.unwrap();
    let cap = "flow.step:ship/push";
    store
        .insert_request("req", "echo", "/r", "claude", "{}", None)
        .await
        .unwrap();
    let apply = |change| {
        let store = &store;
        async move {
            store
                .apply_grant_change_audited(
                    "req",
                    change,
                    AuditEntry {
                        action: "grant_from_approval",
                        ..AUDIT
                    },
                )
                .await
                .unwrap()
        }
    };

    // A legacy row is bound rather than shadowed by a second row.
    store.insert_grant(cap).await.unwrap();
    let in_a = binding("ship", "push", 'a', Some("/a"));
    assert_eq!(
        apply(GrantChange::Bind(cap, &in_a)).await,
        GrantChangeOutcome::Applied
    );
    assert_eq!(store.active_grants(cap).await.unwrap().len(), 1);
    // The same binding again changes nothing.
    assert_eq!(
        apply(GrantChange::Bind(cap, &in_a)).await,
        GrantChangeOutcome::Unchanged
    );
    // A new definition in the same repository re-points that row.
    let changed = binding("ship", "push", 'b', Some("/a"));
    assert_eq!(
        apply(GrantChange::Bind(cap, &changed)).await,
        GrantChangeOutcome::Applied
    );
    let rows = store.active_grants(cap).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].binding.as_ref(), Some(&changed));
    // Another repository is a row of its own; the first stays.
    let in_b = binding("ship", "push", 'b', Some("/b"));
    assert_eq!(
        apply(GrantChange::Bind(cap, &in_b)).await,
        GrantChangeOutcome::Applied
    );
    let rows = store.active_grants(cap).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].binding.as_ref(), Some(&in_b));
    // Every repository is its own binding too, with the global scope.
    let everywhere = binding("ship", "push", 'b', None);
    assert_eq!(
        apply(GrantChange::Bind(cap, &everywhere)).await,
        GrantChangeOutcome::Applied
    );
    let rows = store.active_grants(cap).await.unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[2].scope, "global");
    // Four audited changes, one audit row each.
    assert_eq!(store.audit_for_request("req").await.unwrap().len(), 4);
    // Revocation still ends every binding of the capability.
    store.revoke_grant(cap).await.unwrap();
    assert!(store.active_grants(cap).await.unwrap().is_empty());
    assert_eq!(store.list_grants().await.unwrap().len(), 3);
}

#[tokio::test]
async fn a_remembered_approval_records_the_binding_with_its_audit_row() {
    let store = Store::open_in_memory().await.unwrap();
    let cap = "flow.step:ship/push";
    admitted_flow(&store, "run", r#"{"id":"ship"}"#).await;
    store.insert_approval_waiting("run", cap).await.unwrap();
    let bound = binding("ship", "push", 'c', Some("/r"));
    let granted = store
        .resolve_approval_with_grant(
            "run",
            crate::ApprovalResolution::Approved,
            None,
            AuditEntry {
                action: "approval",
                decision: Decision::Approve,
                actor: Actor::Human,
                detail: None,
            },
            Some((
                GrantChange::Bind(cap, &bound),
                AuditEntry {
                    action: "grant_from_approval",
                    decision: Decision::Allow,
                    actor: Actor::Human,
                    detail: None,
                },
            )),
        )
        .await
        .unwrap();
    assert!(granted);
    let rows = store.active_grants(cap).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].binding.as_ref(), Some(&bound));
    let actions: Vec<String> = store
        .audit_for_request("run")
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.action)
        .collect();
    assert_eq!(actions, ["approval", "grant_from_approval"]);
}

#[tokio::test]
async fn a_binding_outside_the_schema_bounds_is_refused_by_the_database() {
    let store = Store::open_in_memory().await.unwrap();
    let mut bad = binding("ship", "push", 'a', Some("/r"));
    bad.effect_class = "read_only".to_owned();
    store
        .insert_request("req", "echo", "/r", "claude", "{}", None)
        .await
        .unwrap();
    assert!(
        store
            .apply_grant_change_audited(
                "req",
                GrantChange::Bind("flow.step:ship/push", &bad),
                AUDIT
            )
            .await
            .is_err()
    );
    assert!(store.list_grants().await.unwrap().is_empty());
}
