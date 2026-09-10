use super::landing_git_broker::GitGuard;
use crate::{
    landing_checkout::{CheckoutReceipt, CheckoutRequest},
    landing_git::{GitAuthorization, GitTarget},
};
use pam_store::Store;
use serde_json::json;
use std::{path::PathBuf, sync::Arc};
async fn fixture() -> (tempfile::TempDir, Arc<Store>, GitTarget, String) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let repo = root.join("repo");
    let workspace = root.join("workspace");
    let protected = root.join("pam");
    for directory in [&repo, &workspace, &protected] {
        std::fs::create_dir(directory).unwrap();
    }
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    store.set_setting("flows.scope_policy",&json!({"version":1,"repositories":[{"root":repo,"connectors":[{"connector":"github","base_url":"https://api.github.com/","access":"targets","targets":["org/repo"]}]}]}).to_string()).await.unwrap();
    store.set_setting("flows.landing_policy",&json!({"version":1,"repositories":[{"root":repo,"repository":"https://github.com/org/repo","github_server":"https://api.github.com/","github_repository":"org/repo","base":"main","branches":["feature/work"],"workspace_root":workspace,"checks":[{"name":"test","argv":["cargo","test"],"timeout_seconds":300}],"required_checks":["ci"],"main_checks":["ci"],"permissions":{"push":true,"create_pr":false,"merge":false,"sync":false}}]}).to_string()).await.unwrap();
    store
        .upsert_connector(
            "github",
            pam_store::ConnectorPatch {
                enabled: Some(true),
                base_url: Some(Some("https://api.github.com/")),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    store
        .insert_admitted_request(
            "r",
            "flow.run",
            repo.to_str().unwrap(),
            "test",
            "{}",
            None,
            now + 60_000,
        )
        .await
        .unwrap();
    let request = CheckoutRequest {
        repository: repo.clone(),
        protected_base: protected,
        checkouts_root: workspace,
        git_program: PathBuf::from("/usr/bin/git"),
        expected_commit: "a".repeat(40),
        base_ref: "refs/heads/main".into(),
        remote_url: "https://github.com/org/repo".into(),
    };
    let receipt = CheckoutReceipt {
        repository: repo,
        remote_url: request.remote_url.clone(),
        branch: "feature/work".into(),
        commit: request.expected_commit.clone(),
        base_ref: request.base_ref.clone(),
        base_commit: "b".repeat(40),
        tree: "c".repeat(40),
        manifest: vec![],
        manifest_sha256: "d".repeat(64),
    };
    let revision = crate::landing_policy::Snapshot::load(&store)
        .await
        .unwrap()
        .revision;
    (
        temp,
        store,
        GitTarget {
            request,
            receipt,
            branch: "feature/work".into(),
            expected_old: None,
        },
        revision,
    )
}
fn guard(store: Arc<Store>, target: &GitTarget, revision: &str, push: bool) -> GitGuard {
    GitGuard::new(
        store,
        &target.request.repository,
        "r",
        revision,
        target,
        push,
    )
    .unwrap()
}
#[tokio::test]
async fn owned_network_guard_rechecks_grants_without_capturing_service_or_secrets() {
    let (_temp, store, target, revision) = fixture().await;
    let authorization: Arc<dyn GitAuthorization> =
        Arc::new(guard(store.clone(), &target, &revision, true));
    authorization.authorize().await.unwrap();
    store.insert_grant("flow.run").await.unwrap();
    store.revoke_grant("flow.run").await.unwrap();
    let error = authorization.authorize().await.unwrap_err();
    assert_eq!(error.cause, "landing_git_denied");
}
#[tokio::test]
async fn exact_remote_base_workspace_and_branch_scope_cannot_be_rebound() {
    let (_temp, store, target, revision) = fixture().await;
    assert!(
        guard(store.clone(), &target, "stale", true)
            .authorize_row()
            .await
            .is_err()
    );
    let mut changed = target.clone();
    changed.request.remote_url = "https://github.com/other/repo".into();
    changed.receipt.remote_url = changed.request.remote_url.clone();
    assert!(
        guard(store.clone(), &changed, &revision, true)
            .authorize_row()
            .await
            .is_err()
    );
    let mut changed = target.clone();
    changed.request.base_ref = "main".into();
    changed.receipt.base_ref = "main".into();
    assert!(
        guard(store.clone(), &changed, &revision, true)
            .authorize_row()
            .await
            .is_err()
    );
    let mut base = target.clone();
    base.branch = "main".into();
    guard(store.clone(), &base, &revision, false)
        .authorize_row()
        .await
        .unwrap();
    assert!(
        GitGuard::new(
            store.clone(),
            &base.request.repository,
            "r",
            &revision,
            &base,
            true
        )
        .is_err()
    );
    let mut changed = target.clone();
    changed.request.checkouts_root = changed.request.repository.clone();
    assert!(
        guard(store.clone(), &changed, &revision, true)
            .authorize_row()
            .await
            .is_err()
    );
    store
        .set_setting("flows.scope_policy", r#"{"version":1,"repositories":[]}"#)
        .await
        .unwrap();
    assert!(
        guard(store, &target, &revision, true)
            .authorize_row()
            .await
            .is_err()
    );
}
