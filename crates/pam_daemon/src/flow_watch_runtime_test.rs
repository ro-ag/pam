use crate::flow_exec::{StepReport, StepStatus};
use crate::flow_recovery::{Recovery, WatchState};
use pam_flow::Vars;
use pam_store::Store;
use serde_json::json;

fn flow() -> pam_flow::Flow {
    pam_flow::parse("schema: 1\nid: watch-test\nname: Watch\nsteps:\n - id: wait\n   connector: github\n   call: run\n   with: {repo: 'owner/repo', run_id: 1, run_attempt: 1}\n   watch: {}\n   role: observe\n").unwrap()
}

#[tokio::test]
async fn polls_reuse_snapshot_and_completed_cursor_preserves_committed_progress() {
    let store = Store::open_in_memory().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().canonicalize().unwrap();
    store
        .insert_request("r", "flow.run", repo.to_str().unwrap(), "test", "{}", None)
        .await
        .unwrap();
    store
        .set_setting(
            "flows.scope_policy",
            &json!({"version":1,"repositories":[{"root":repo,"connectors":[]}]}).to_string(),
        )
        .await
        .unwrap();
    let flow = flow();
    let (mut recovery, snapshot) = Recovery::open(&store, "r", &flow, &repo, &Vars::new())
        .await
        .unwrap();
    let initial: serde_json::Value = serde_json::from_str(
        &store
            .read_flow_journal("r")
            .await
            .unwrap()
            .unwrap()
            .checkpoint_json,
    )
    .unwrap();
    let mut state = WatchState {
        step: "wait".into(),
        args_fingerprint: "a".repeat(64),
        origin: crate::evidence_service::ConnectorTarget {
            connector: pam_flow::ConnectorId::Github,
            base_url: "https://api.github.com/".into(),
            call: "run_status".into(),
            args: std::collections::BTreeMap::new(),
        },
        profile_stamp: "b".repeat(64),
        authorization_revision: 0,
        polls: 1,
        errors: 0,
        next_poll_ms: 10,
        collecting: false,
        observation: json!({"status":"pending"}),
        pins: serde_json::Value::Null,
        last_digest: "c".repeat(64),
        last_evidence: "ev_poll".into(),
    };
    for poll in 1..=2 {
        recovery
            .prepare(&store, "r", &flow.steps[0], true)
            .await
            .unwrap();
        state.polls = poll;
        recovery
            .settle_watch(&store, "r", state.clone(), &[])
            .await
            .unwrap();
        let row = store.read_flow_journal("r").await.unwrap().unwrap();
        let cursor: serde_json::Value = serde_json::from_str(&row.checkpoint_json).unwrap();
        assert_eq!(cursor["evidence_id"], initial["evidence_id"]);
        assert_eq!(cursor["watch"]["polls"], poll);
        assert_eq!(store.list_evidence("r").await.unwrap().len(), 1);
    }
    // A retained cursor never makes missing or unauthorized poll evidence readable.
    assert!(
        Recovery::open(&store, "r", &flow, &repo, &Vars::new())
            .await
            .is_err()
    );
    recovery
        .prepare(&store, "r", &flow.steps[0], true)
        .await
        .unwrap();
    recovery.settle(&store, "r", &snapshot, true).await.unwrap();
    let row = store.read_flow_journal("r").await.unwrap().unwrap();
    let cursor: serde_json::Value = serde_json::from_str(&row.checkpoint_json).unwrap();
    assert!(cursor["watch"].is_null());
    assert_eq!(cursor["last_watch_evidence"], "ev_poll");
    assert_ne!(cursor["evidence_id"], initial["evidence_id"]);
}

#[test]
fn github_watch_assertion_uses_actual_conclusion_and_never_top_level_success() {
    let mut step = flow().steps.remove(0);
    step.expect_status = Some("success".into());
    let mut report = StepReport::new("wait", "connector", StepStatus::Succeeded);
    super::apply_connector_assertion(
        &step,
        Some(&json!({"status":"success","run":{"conclusion":"failure"}})),
        &mut report,
    );
    assert_eq!(report.status, StepStatus::Failed);
    let mut report = StepReport::new("wait", "connector", StepStatus::Succeeded);
    super::apply_connector_assertion(
        &step,
        Some(&json!({"run":{"conclusion":"success"}})),
        &mut report,
    );
    assert_eq!(report.status, StepStatus::Succeeded);
}

#[tokio::test]
async fn substituted_run_is_committed_as_conflict_without_replacing_valid_pins() {
    let store = Store::open_in_memory().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().canonicalize().unwrap();
    store
        .insert_request("r", "flow.run", repo.to_str().unwrap(), "test", "{}", None)
        .await
        .unwrap();
    store
        .set_setting(
            "flows.scope_policy",
            &json!({"version":1,"repositories":[{"root":repo,"connectors":[]}]}).to_string(),
        )
        .await
        .unwrap();
    let flow = flow();
    let (mut recovery, _) = Recovery::open(&store, "r", &flow, &repo, &Vars::new())
        .await
        .unwrap();
    let pins = json!({"run_id":1,"run_attempt":1});
    let received = crate::flow_watch::Observation {
        state: crate::flow_watch::State::Terminal,
        payload: json!({"run_id":2,"run_attempt":1,"status":"completed","conclusion":"success"}),
        digest: "unused".into(),
    };
    let conflict = super::watch_runtime::conflicting_observation(
        pam_flow::ConnectorId::Github,
        &pins,
        &received,
    )
    .unwrap();
    assert_eq!(conflict.state, crate::flow_watch::State::Unavailable);
    assert_eq!(conflict.payload["cause"], "watch_target_changed");
    assert_eq!(conflict.payload["received"], received.payload);
    let bytes = serde_json::to_vec(&conflict.payload).unwrap();
    store
        .insert_evidence("ev_conflict", "r", "flow.watch", &bytes, None)
        .await
        .unwrap();
    let state = WatchState {
        step: "wait".into(),
        args_fingerprint: "a".repeat(64),
        origin: crate::evidence_service::ConnectorTarget {
            connector: pam_flow::ConnectorId::Github,
            base_url: "https://api.github.com/".into(),
            call: "run_status".into(),
            args: std::collections::BTreeMap::new(),
        },
        profile_stamp: "b".repeat(64),
        authorization_revision: 0,
        polls: 2,
        errors: 0,
        next_poll_ms: 0,
        collecting: false,
        observation: conflict.payload,
        pins: pins.clone(),
        last_digest: conflict.digest,
        last_evidence: "ev_conflict".into(),
    };
    recovery
        .prepare(&store, "r", &flow.steps[0], true)
        .await
        .unwrap();
    recovery
        .settle_watch(&store, "r", state, &[])
        .await
        .unwrap();
    let row = store.read_flow_journal("r").await.unwrap().unwrap();
    let cursor: serde_json::Value = serde_json::from_str(&row.checkpoint_json).unwrap();
    assert_eq!(cursor["watch"]["pins"], pins);
    assert_eq!(
        cursor["watch"]["observation"]["cause"],
        "watch_target_changed"
    );
    assert_eq!(cursor["watch"]["collecting"], false);
    assert_eq!(cursor["watch"]["next_poll_ms"], 0);
    assert_eq!(row.evidence_refs, vec!["ev_conflict"]);
    assert!(
        store
            .list_evidence("r")
            .await
            .unwrap()
            .iter()
            .any(|evidence| evidence.id == "ev_conflict")
    );
}
