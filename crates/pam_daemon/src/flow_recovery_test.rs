use crate::flow_exec::{StepReport, StepStatus};
use crate::flow_recovery::{Recovery, Snapshot, encode};
use pam_flow::Vars;
use pam_store::Store;
use serde_json::json;

async fn fixture() -> (Store, tempfile::TempDir, pam_flow::Flow, Vars) {
    let store = Store::open_in_memory().await.unwrap();
    let repo = tempfile::tempdir().unwrap();
    let root = repo.path().canonicalize().unwrap();
    store
        .insert_request("r", "flow.run", root.to_str().unwrap(), "test", "{}", None)
        .await
        .unwrap();
    store
        .set_setting(
            "flows.scope_policy",
            &json!({"version":1,"repositories":[{"root":root,"connectors":[]}]}).to_string(),
        )
        .await
        .unwrap();
    let flow=pam_flow::parse("schema: 1\nid: recovery\nname: Recovery\nsteps:\n - id: first\n   run: [git, status]\n - id: second\n   run: [git, status]\n").unwrap();
    let mut vars = Vars::new();
    vars.set("repo.path", root.to_str().unwrap());
    (store, repo, flow, vars)
}

#[tokio::test]
async fn settled_prefix_restores_variables_and_refuses_changed_recipe_inputs_or_scope() {
    let (store, repo, flow, vars) = fixture().await;
    let (mut recovery, mut snapshot) = Recovery::open(&store, "r", &flow, repo.path(), &vars)
        .await
        .unwrap();
    recovery
        .prepare(&store, "r", &flow.steps[0], true)
        .await
        .unwrap();
    snapshot
        .vars
        .set_step("first", json!({"result":{"value":"saved"}}));
    snapshot.observed = snapshot.vars.clone();
    snapshot.reports.push(
        serde_json::to_value(StepReport::new("first", "command", StepStatus::Succeeded)).unwrap(),
    );
    recovery
        .settle(&store, "r", &snapshot, false)
        .await
        .unwrap();
    let (_, restored) = Recovery::open(&store, "r", &flow, repo.path(), &vars)
        .await
        .unwrap();
    assert_eq!(restored.restore_reports(&flow).unwrap().len(), 1);
    assert_eq!(
        restored.vars.resolve("steps.first.result.value").as_deref(),
        Some("saved")
    );
    let mut different = vars.clone();
    different.set("repo.origin", "changed");
    assert!(
        Recovery::open(&store, "r", &flow, repo.path(), &different)
            .await
            .is_err()
    );
    let mut changed = flow.clone();
    changed.name = "Changed recipe".to_owned();
    assert!(
        Recovery::open(&store, "r", &changed, repo.path(), &vars)
            .await
            .is_err()
    );
    store
        .set_setting("flows.scope_policy", r#"{"version":1,"repositories":[]}"#)
        .await
        .unwrap();
    assert!(
        Recovery::open(&store, "r", &flow, repo.path(), &vars)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn prepared_effect_never_restores_as_ready() {
    let (store, repo, flow, vars) = fixture().await;
    let (mut recovery, _) = Recovery::open(&store, "r", &flow, repo.path(), &vars)
        .await
        .unwrap();
    let mut effect = flow.steps[0].clone();
    effect.effect = pam_flow::Effect::Stateful;
    recovery.prepare(&store, "r", &effect, true).await.unwrap();
    assert!(
        Recovery::open(&store, "r", &flow, repo.path(), &vars)
            .await
            .is_err()
    );
    let row = store.read_flow_journal("r").await.unwrap().unwrap();
    assert!(row.effectful);
    assert_eq!(row.state, pam_store::FlowJournalState::Prepared);
}

#[test]
fn serialization_and_decode_are_bounded_and_reject_arbitrary_reports() {
    assert!(encode(&"x".repeat(1024 * 1024)).is_err());
    let flow = pam_flow::parse(
        "schema: 1\nid: example\nname: Example\nsteps:\n - id: first\n   run: [git, status]\n",
    )
    .unwrap();
    let snapshot = json!({"fingerprint":"f","vars":{"map":{},"steps":{}},"observed":{"map":{},"steps":{}},"reports":[{"id":"other"}],"evidence":[],"origins":{},"all_origins":[]});
    assert!(Snapshot::decode(&serde_json::to_vec(&snapshot).unwrap(), "f", &flow).is_err());
}

#[tokio::test]
async fn missing_checkpoint_and_changed_connector_configuration_refuse_restore() {
    let (store, repo, flow, vars) = fixture().await;
    let (mut recovery, mut snapshot) = Recovery::open(&store, "r", &flow, repo.path(), &vars)
        .await
        .unwrap();
    let origin = crate::evidence_service::ConnectorTarget {
        connector: pam_flow::ConnectorId::Github,
        base_url: "https://github.test/".to_owned(),
        call: "run".to_owned(),
        args: std::collections::BTreeMap::from([
            (
                "repo".to_owned(),
                pam_flow::ArgValue::Text("team/repo".to_owned()),
            ),
            ("run_id".to_owned(), pam_flow::ArgValue::Int(9)),
        ]),
    };
    snapshot.all_origins.push(origin);
    recovery
        .prepare(&store, "r", &flow.steps[0], true)
        .await
        .unwrap();
    recovery
        .settle(&store, "r", &snapshot, false)
        .await
        .unwrap();
    // No configured connector can authenticate this captured origin.
    assert!(
        Recovery::open(&store, "r", &flow, repo.path(), &vars)
            .await
            .is_err()
    );
    let cursor = json!({"evidence_id":"ev_absent","next_step":0}).to_string();
    let identity = pam_store::FlowJournalIdentity {
        request_id: "missing".to_owned(),
        flow_digest: pam_flow::digest(&flow),
        repository: repo.path().to_string_lossy().into_owned(),
        input_fingerprint: crate::flow_recovery::fingerprint(&flow, repo.path(), &vars).unwrap(),
    };
    store
        .insert_request(
            "missing",
            "flow.run",
            repo.path().to_str().unwrap(),
            "test",
            "{}",
            None,
        )
        .await
        .unwrap();
    store.begin_flow_journal(&identity, &cursor).await.unwrap();
    assert!(
        Recovery::open(&store, "missing", &flow, repo.path(), &vars)
            .await
            .is_err()
    );
}
