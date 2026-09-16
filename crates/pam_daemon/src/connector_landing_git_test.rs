use super::landing_git_broker::{GitGuard, GitRole, check_live, upload_pack_url};
use super::{ConfigurePatch, ConnectorService, CredentialAction};
use crate::{
    landing_checkout::{CheckoutReceipt, CheckoutRequest},
    landing_git::{GitAuthorization, GitTarget, LandingCall},
    request_budget::RequestBudget,
    secrets::{FakeSecretBackend, SecretStore},
};
use pam_connectors::{ConnectorId, HttpRequest, HttpResponse, HttpTransport, TransportError};
use pam_store::Store;
use serde_json::json;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
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
        branch: "refs/heads/feature/work".into(),
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
fn guard(store: Arc<Store>, target: &GitTarget, revision: &str, role: GitRole) -> GitGuard {
    GitGuard::new(
        store,
        &target.request.repository,
        "r",
        revision,
        target,
        role,
    )
    .unwrap()
}
#[tokio::test]
async fn owned_network_guard_rechecks_grants_without_capturing_service_or_secrets() {
    let (_temp, store, target, revision) = fixture().await;
    let authorization: Arc<dyn GitAuthorization> =
        Arc::new(guard(store.clone(), &target, &revision, GitRole::Push));
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
        guard(store.clone(), &target, "stale", GitRole::Push)
            .authorize_row()
            .await
            .is_err()
    );
    let mut changed = target.clone();
    changed.request.remote_url = "https://github.com/other/repo".into();
    changed.receipt.remote_url = changed.request.remote_url.clone();
    assert!(
        guard(store.clone(), &changed, &revision, GitRole::Push)
            .authorize_row()
            .await
            .is_err()
    );
    let mut changed = target.clone();
    changed.request.base_ref = "main".into();
    changed.receipt.base_ref = "main".into();
    assert!(
        guard(store.clone(), &changed, &revision, GitRole::Push)
            .authorize_row()
            .await
            .is_err()
    );
    let mut base = target.clone();
    base.branch = "main".into();
    guard(store.clone(), &base, &revision, GitRole::Observe)
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
            GitRole::Push
        )
        .is_err()
    );
    let mut changed = target.clone();
    changed.request.checkouts_root = changed.request.repository.clone();
    assert!(
        guard(store.clone(), &changed, &revision, GitRole::Push)
            .authorize_row()
            .await
            .is_err()
    );
    store
        .set_setting("flows.scope_policy", r#"{"version":1,"repositories":[]}"#)
        .await
        .unwrap();
    assert!(
        guard(store, &target, &revision, GitRole::Push)
            .authorize_row()
            .await
            .is_err()
    );
}

#[cfg(target_os = "macos")]
fn initialize_captured_repository(target: &mut GitTarget) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        &target.request.checkouts_root,
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    target.request.git_program = PathBuf::from("/Library/Developer/CommandLineTools/usr/bin/git");
    let git = |args: &[&str]| {
        let output = std::process::Command::new(&target.request.git_program)
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(&target.request.repository)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "Fixture")
            .env("GIT_COMMITTER_NAME", "Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "local capture fixture setup failed"
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };
    git(&["init", "-q", "-b", "main"]);
    git(&["remote", "add", "origin", &target.request.remote_url]);
    std::fs::write(target.request.repository.join("tracked"), "fixture\n").unwrap();
    git(&["add", "tracked"]);
    git(&["commit", "-qm", "fixture"]);
    git(&["checkout", "-qb", "feature/work"]);
    target.request.expected_commit = git(&["rev-parse", "HEAD"]);
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn captured_full_branch_receipt_reaches_current_guard_without_network() {
    let (_temp, store, mut target, revision) = fixture().await;
    initialize_captured_repository(&mut target);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let budget = crate::request_budget::RequestBudget::new(deadline);
    let (_sender, mut cancel) = tokio::sync::watch::channel(false);
    let snapshot =
        crate::landing_checkout::capture(&target.request, budget.clone(), &mut cancel, deadline)
            .await
            .unwrap();
    assert_eq!(snapshot.receipt.branch, "refs/heads/feature/work");
    assert_eq!(snapshot.receipt.commit, target.request.expected_commit);
    target.receipt = snapshot.receipt;
    guard(store.clone(), &target, &revision, GitRole::Observe)
        .authorize_row()
        .await
        .unwrap();
    guard(store.clone(), &target, &revision, GitRole::Push)
        .authorize_row()
        .await
        .unwrap();
    assert_eq!(
        budget.usage().http_calls,
        0,
        "capture and authorization are network-free"
    );
    store.insert_grant("flow.run").await.unwrap();
    store.revoke_grant("flow.run").await.unwrap();
    assert!(
        guard(store, &target, &revision, GitRole::Observe)
            .authorize_row()
            .await
            .is_err()
    );
}

#[test]
fn upload_pack_url_accepts_only_the_exact_canonical_https_remote() {
    let url = upload_pack_url("https://github.com/org/repo").unwrap();
    assert_eq!(url.as_str(), "https://github.com/org/repo/git-upload-pack");
    for remote in [
        "http://github.com/org/repo",
        "https://user@github.com/org/repo",
        "https://user:secret@github.com/org/repo",
        "https://github.com/org/repo?service=git-upload-pack",
        "https://github.com/org/repo#main",
        "https://github.com/org/repo/",
        "https://GitHub.com/org/repo",
        "git@github.com:org/repo.git",
        "",
    ] {
        let error = upload_pack_url(remote).unwrap_err();
        assert_eq!(error.cause(), "landing_git_denied", "{remote:?}");
    }
}

#[test]
fn liveness_check_tells_cancellation_apart_from_the_deadline() {
    let budget = RequestBudget::new(Instant::now() + Duration::from_secs(30));
    let (sender, cancel) = tokio::sync::watch::channel(false);
    check_live(&cancel, Instant::now() + Duration::from_secs(5), &budget).unwrap();
    let elapsed = Instant::now();
    std::thread::sleep(Duration::from_millis(2));
    assert_eq!(
        check_live(&cancel, elapsed, &budget).unwrap_err().cause(),
        "connector_timeout"
    );
    sender.send(true).unwrap();
    assert_eq!(
        check_live(&cancel, Instant::now() + Duration::from_secs(5), &budget)
            .unwrap_err()
            .cause(),
        "cancelled"
    );
    let (sender, cancel) = tokio::sync::watch::channel(false);
    drop(sender);
    assert_eq!(
        check_live(&cancel, Instant::now() + Duration::from_secs(5), &budget)
            .unwrap_err()
            .cause(),
        "cancelled"
    );
}

/// A transport that must never be reached; it counts every attempt.
#[derive(Default)]
struct Unreachable {
    sends: AtomicUsize,
}
impl HttpTransport for Unreachable {
    fn send<'a>(
        &'a self,
        _request: HttpRequest,
        _deadline: Instant,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>,
    > {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(TransportError::Network("unexpected send".to_owned())) })
    }
}

#[tokio::test]
async fn a_cancelled_pack_fetch_refuses_as_cancelled_before_any_network_send() {
    let (_temp, store, mut target, _) = fixture().await;
    let repo = target.request.repository.clone();
    let workspace = target.request.checkouts_root.clone();
    store.set_setting("flows.landing_policy",&json!({"version":1,"repositories":[{"root":repo,"repository":"https://github.com/org/repo","github_server":"https://api.github.com/","github_repository":"org/repo","base":"main","branches":["feature/work"],"workspace_root":workspace,"checks":[{"name":"test","argv":["cargo","test"],"timeout_seconds":300}],"required_checks":["ci"],"main_checks":["ci"],"permissions":{"push":true,"create_pr":false,"merge":false,"sync":true}}]}).to_string()).await.unwrap();
    let revision = crate::landing_policy::Snapshot::load(&store)
        .await
        .unwrap()
        .revision;
    target.branch = "main".into();
    target.expected_old = Some("b".repeat(40));
    let transport = Arc::new(Unreachable::default());
    let service = ConnectorService::new(
        Arc::clone(&store),
        Arc::new(SecretStore::new(Arc::new(FakeSecretBackend::default()))),
        Arc::clone(&transport) as Arc<dyn HttpTransport>,
    );
    service
        .configure(
            ConnectorId::Github,
            ConfigurePatch {
                enabled: Some(true),
                base_url: Some(Some("https://api.github.com/".into())),
                credential: Some(CredentialAction::Set(crate::secrets::Secret::new(
                    "private-token".into(),
                ))),
                ..ConfigurePatch::default()
            },
        )
        .await
        .unwrap();
    let budget = RequestBudget::new(Instant::now() + Duration::from_secs(30));
    let (sender, mut cancel) = tokio::sync::watch::channel(false);
    sender.send(true).unwrap();
    let error = service
        .landing_fetch_pack(
            LandingCall {
                repo: &target.request.repository,
                ticket: "r",
                policy_revision: &revision,
                target: &target,
                budget: Arc::clone(&budget),
                cancel: &mut cancel,
                deadline: Instant::now() + Duration::from_secs(10),
            },
            &"c".repeat(40),
            &["b".repeat(40).as_str()],
        )
        .await
        .unwrap_err();
    assert_eq!(error.cause(), "cancelled");
    assert_eq!(transport.sends.load(Ordering::SeqCst), 0);
    assert_eq!(budget.usage().http_calls, 0);
}
