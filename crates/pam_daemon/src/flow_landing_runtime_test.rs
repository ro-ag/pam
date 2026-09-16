use super::landing_runtime::{
    EffectPhase, attempted, broker_error, checkout_error, effect_verdict, landing_workspace,
    release_workspace,
};
use super::{Attempt, CapabilityFailure, StepStatus};
use crate::flow_recovery::{Prepare, Recovery};
use crate::landing_checkout::{CANCELLED, CheckoutError};
use crate::landing_git::{PushObservation, PushState, RemoteRef};
use pam_flow::{LandingOperation as Op, Vars};
use pam_store::{FlowJournalState, Store};
use serde_json::{Value, json};
use std::path::Path;

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
            .prepare(&store, "r", &flow.steps[0], Prepare::Run)
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

fn cause(failure: &CapabilityFailure) -> &str {
    match failure {
        CapabilityFailure::Refused { cause, .. } => cause,
        CapabilityFailure::Cancelled => "<cancelled>",
        CapabilityFailure::Failed { .. } => "<failed>",
        CapabilityFailure::Parked { .. } => "<parked>",
    }
}

#[test]
fn the_cancel_signal_ends_a_landing_stage_cancelled_not_blocked() {
    assert_eq!(
        checkout_error(CheckoutError {
            cause: CANCELLED,
            detail: "checkout capture cancelled",
        }),
        CapabilityFailure::Cancelled
    );
    assert_eq!(
        cause(&checkout_error(CheckoutError {
            cause: "landing_checkout_changed",
            detail: "source refs changed during capture",
        })),
        "landing_checkout_changed"
    );
    let cancelled =
        crate::connector_service::InvokeError::Connector(pam_connectors::ConnectorError::Policy {
            cause: CANCELLED,
            detail: "The landing Git operation was cancelled before it started.".to_owned(),
        });
    assert_eq!(broker_error(&cancelled), CapabilityFailure::Cancelled);
    let timeout =
        crate::connector_service::InvokeError::Connector(pam_connectors::ConnectorError::Timeout);
    assert_eq!(cause(&broker_error(&timeout)), "connector_timeout");
    assert!(matches!(attempted(None), Err(CapabilityFailure::Cancelled)));
    assert!(matches!(
        attempted(Some(Attempt::Failed {
            exit_status: Some(1),
            output: Vec::new(),
            result: None,
            status: StepStatus::Failed,
            cause: "exit_status",
            detail: String::new(),
            recovery: String::new(),
            retry_after: None,
        })),
        Ok(Attempt::Failed { .. })
    ));
}

fn prepared(state: PushState) -> PushObservation {
    PushObservation {
        ref_name: "refs/heads/feature/work".into(),
        expected_old: Some("a".repeat(40)),
        requested_commit: "b".repeat(40),
        state,
    }
}
fn observed(oid: Option<&str>) -> RemoteRef {
    RemoteRef {
        ref_name: "refs/heads/feature/work".into(),
        oid: oid.map(str::to_owned),
    }
}

#[test]
fn an_unchanged_ref_after_a_rejected_push_is_a_typed_refusal_never_a_resend() {
    let commit = "b".repeat(40);
    let old = "a".repeat(40);
    effect_verdict(
        &observed(Some(&commit)),
        &prepared(PushState::ReportedSuccess),
        Op::Push,
        EffectPhase::JustRan,
    )
    .unwrap();
    let rejected = effect_verdict(
        &observed(Some(&old)),
        &prepared(PushState::Uncertain),
        Op::Push,
        EffectPhase::JustRan,
    )
    .unwrap_err();
    assert_eq!(cause(&rejected), "landing_push_rejected");
    let contradiction = effect_verdict(
        &observed(Some(&old)),
        &prepared(PushState::ReportedSuccess),
        Op::Push,
        EffectPhase::JustRan,
    )
    .unwrap_err();
    assert_eq!(cause(&contradiction), "landing_effect_uncertain");
    let resumed = effect_verdict(
        &observed(Some(&old)),
        &prepared(PushState::Uncertain),
        Op::Push,
        EffectPhase::Resumed,
    )
    .unwrap_err();
    assert_eq!(cause(&resumed), "landing_effect_uncertain");
    assert!(matches!(
        &resumed,
        CapabilityFailure::Refused { detail, .. } if detail.contains("observed old value")
    ));
    for phase in [EffectPhase::JustRan, EffectPhase::Resumed] {
        let moved = effect_verdict(
            &observed(Some(&"c".repeat(40))),
            &prepared(PushState::Uncertain),
            Op::Push,
            phase,
        )
        .unwrap_err();
        assert_eq!(cause(&moved), "landing_effect_uncertain");
        let gone = effect_verdict(
            &observed(None),
            &prepared(PushState::Uncertain),
            Op::Sync,
            phase,
        )
        .unwrap_err();
        assert_eq!(cause(&gone), "landing_effect_uncertain");
    }
    let sync_unchanged = effect_verdict(
        &observed(Some(&old)),
        &prepared(PushState::Uncertain),
        Op::Sync,
        EffectPhase::Resumed,
    )
    .unwrap_err();
    assert_eq!(cause(&sync_unchanged), "landing_effect_uncertain");
    assert!(matches!(
        sync_unchanged,
        CapabilityFailure::Refused { detail, .. }
            if detail.contains("local base") && detail.contains("observed old value")
    ));
}

#[test]
fn only_a_checktree_of_the_exact_freeze_shape_names_a_removable_workspace() {
    let root = Path::new("/private/workspaces");
    let ulid = ulid::Ulid::new().to_string();
    let good = root.join(format!("landing-{ulid}")).join("tree");
    assert_eq!(
        landing_workspace(&good, root).as_deref(),
        Some(root.join(format!("landing-{ulid}")).as_path())
    );
    for wrong in [
        root.join(format!("landing-{ulid}")),
        root.join(format!("landing-{ulid}")).join("artifacts"),
        root.join("landing-not-a-ulid").join("tree"),
        root.join(format!("other-{ulid}")).join("tree"),
        Path::new("/elsewhere")
            .join(format!("landing-{ulid}"))
            .join("tree"),
        root.join("nested")
            .join(format!("landing-{ulid}"))
            .join("tree"),
    ] {
        assert_eq!(landing_workspace(&wrong, root), None, "{}", wrong.display());
    }
}

#[test]
fn releasing_a_terminal_ticket_removes_its_workspace_and_nothing_else() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let ulid = ulid::Ulid::new().to_string();
    let workspace = root.join(format!("landing-{ulid}"));
    let tree = workspace.join("tree");
    std::fs::create_dir_all(tree.join("src")).unwrap();
    std::fs::create_dir_all(workspace.join("artifacts")).unwrap();
    std::fs::write(tree.join("src/main.rs"), "fn main() {}\n").unwrap();
    let neighbour = root.join(format!("landing-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(neighbour.join("tree")).unwrap();
    let foreign = root.join("keep").join("tree");
    std::fs::create_dir_all(&foreign).unwrap();
    assert!(!release_workspace(&foreign, &root));
    assert!(foreign.is_dir());
    assert!(release_workspace(&tree, &root));
    assert!(!workspace.exists());
    assert!(neighbour.join("tree").is_dir());
    assert!(foreign.is_dir());
    // Releasing again is idempotent: already gone counts as released.
    assert!(release_workspace(&tree, &root));
}
