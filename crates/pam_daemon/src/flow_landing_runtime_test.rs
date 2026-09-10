use crate::flow_recovery::Recovery;
use pam_flow::Vars;
use pam_store::{FlowJournalState, Store};
use serde_json::{Value, json};

#[tokio::test]
async fn landing_poll_commits_progress_without_copying_or_advancing_protected_snapshot() {
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
    let flow=pam_flow::parse("schema: 1\nid: land\nname: Land\ncorrelation: { repository: 'https://github.com/owner/repo.git', commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa }\nsteps:\n - id: freeze\n   landing: freeze\n").unwrap();
    let (mut recovery, _) = Recovery::open(&store, "r", &flow, &repo, &Vars::new())
        .await
        .unwrap();
    let original = store.read_flow_journal("r").await.unwrap().unwrap();
    let original_cursor: Value = serde_json::from_str(&original.checkpoint_json).unwrap();
    for id in ["poll1", "poll1", "poll2"] {
        recovery
            .prepare(&store, "r", &flow.steps[0], true)
            .await
            .unwrap();
        recovery
            .settle_landing_wait(&store, "r", id, &[])
            .await
            .unwrap();
        let journal = store.read_flow_journal("r").await.unwrap().unwrap();
        assert_eq!(journal.state, FlowJournalState::Ready);
        let cursor: Value = serde_json::from_str(&journal.checkpoint_json).unwrap();
        assert_eq!(cursor["evidence_id"], original_cursor["evidence_id"]);
        assert_eq!(cursor["next_step"], 0);
        assert_eq!(cursor["last_watch_evidence"], id);
        assert_eq!(journal.evidence_refs, [id]);
    }
    assert_eq!(recovery.revision, 6);
    assert_eq!(
        store
            .read_flow_journal("r")
            .await
            .unwrap()
            .unwrap()
            .identity,
        original.identity
    );
}

#[test]
fn landing_availability_blocks_sync_but_preserves_supported_prefix() {
    use pam_flow::LandingOperation;

    for operation in [
        LandingOperation::Freeze,
        LandingOperation::Validate,
        LandingOperation::Push,
        LandingOperation::EnsurePr,
        LandingOperation::VerifyPr,
        LandingOperation::Merge,
        LandingOperation::VerifyMain,
    ] {
        super::landing_runtime::available(operation).unwrap();
    }
    let error = super::landing_runtime::available(LandingOperation::Sync).unwrap_err();
    assert_eq!(error.cause, "landing_sync_unavailable");
}
