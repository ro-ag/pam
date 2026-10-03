use super::landing::LandingGithubOp;
use super::{ConfigurePatch, ConnectorService, CredentialAction};
use crate::secrets::{FakeSecretBackend, SecretBackend, SecretError, SecretStore};
use pam_connectors::{
    ConnectorId, HttpRequest, HttpResponse, HttpTransport, TransportError,
    github_landing::{MergeMethod, RequiredCheck, Target},
    testing::FakeTransport,
};
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
#[derive(Default)]
struct Secrets {
    inner: FakeSecretBackend,
    reads: AtomicUsize,
}
impl SecretBackend for Secrets {
    fn get(&self, key: &str) -> Result<Option<String>, SecretError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.get(key)
    }
    fn set(&self, key: &str, value: &str) -> Result<(), SecretError> {
        self.inner.set(key, value)
    }
    fn delete(&self, key: &str) -> Result<bool, SecretError> {
        self.inner.delete(key)
    }
}
struct Fixture {
    _repo: tempfile::TempDir,
    _workspace: tempfile::TempDir,
    repo: PathBuf,
    store: Arc<Store>,
    secrets: Arc<Secrets>,
    service: ConnectorService,
    revision: String,
}
async fn fixture(store: Arc<Store>, transport: Arc<dyn HttpTransport>) -> Fixture {
    fixture_under(
        store,
        transport,
        crate::managed_policy_service::PolicyHandle::none(),
    )
    .await
}
async fn fixture_under(
    store: Arc<Store>,
    transport: Arc<dyn HttpTransport>,
    policy: Arc<crate::managed_policy_service::PolicyHandle>,
) -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().canonicalize().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let work = workspace.path().canonicalize().unwrap();
    store.set_setting("flows.scope_policy",&json!({"version":1,"repositories":[{"root":repo,"connectors":[{"connector":"github","base_url":"https://api.github.com/","access":"targets","targets":["org/repo"]}]}]}).to_string()).await.unwrap();
    store.set_setting("flows.landing_policy",&json!({"version":1,"repositories":[{"root":repo,"repository":"https://github.com/org/repo","github_server":"https://api.github.com/","github_repository":"org/repo","base":"main","branches":["feature/work"],"workspace_root":work,"checks":[{"name":"test","argv":["cargo","test"],"timeout_seconds":300}],"required_checks":["ci"],"main_checks":["ci"],"permissions":{"push":false,"create_pr":true,"merge":false,"sync":false}}]}).to_string()).await.unwrap();
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
    let secrets = Arc::new(Secrets::default());
    let service = ConnectorService::new(
        Arc::clone(&store),
        Arc::new(SecretStore::new(secrets.clone())),
        transport,
        policy,
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
    secrets.reads.store(0, Ordering::SeqCst);
    let revision = crate::landing_policy::Snapshot::load(&store)
        .await
        .unwrap()
        .revision;
    Fixture {
        _repo: temp,
        _workspace: workspace,
        repo,
        store,
        secrets,
        service,
        revision,
    }
}
fn target() -> Target {
    Target {
        repository: "org/repo".into(),
        head: "feature/work".into(),
        base: "main".into(),
        head_sha: "a".repeat(40),
    }
}
fn budget() -> Arc<crate::request_budget::RequestBudget> {
    crate::request_budget::RequestBudget::new(Instant::now() + Duration::from_secs(20))
}
async fn call(
    f: &Fixture,
    revision: &str,
    op: &LandingGithubOp,
) -> Result<serde_json::Value, super::InvokeError> {
    f.service
        .landing_github(
            &f.repo,
            "r",
            revision,
            op,
            budget(),
            Instant::now() + Duration::from_secs(10),
        )
        .await
}
#[tokio::test]
async fn bad_revision_target_permission_and_revocation_refuse_before_credentials_or_http() {
    let fake = Arc::new(FakeTransport::new());
    let f = fixture(
        Arc::new(Store::open_in_memory().await.unwrap()),
        fake.clone(),
    )
    .await;
    assert!(
        call(&f, "stale", &LandingGithubOp::FindPr(target()))
            .await
            .is_err()
    );
    let mut wrong = target();
    wrong.base = "other".into();
    assert!(
        call(&f, &f.revision, &LandingGithubOp::FindPr(wrong))
            .await
            .is_err()
    );
    assert!(
        call(
            &f,
            &f.revision,
            &LandingGithubOp::MergePr(target(), 7, MergeMethod::Squash)
        )
        .await
        .is_err()
    );
    f.store.insert_grant("flow.run").await.unwrap();
    f.store.revoke_grant("flow.run").await.unwrap();
    assert!(
        call(&f, &f.revision, &LandingGithubOp::FindPr(target()))
            .await
            .is_err()
    );
    assert_eq!(f.secrets.reads.load(Ordering::SeqCst), 0);
    assert!(fake.requests().is_empty());
}
#[tokio::test]
async fn allowed_creation_uses_exact_json_and_no_generic_mutation_scope() {
    let body = json!({"number":7,"state":"open","merged":false,"head":{"ref":"feature/work","sha":"a".repeat(40),"repo":{"full_name":"org/repo"}},"base":{"ref":"main","sha":"b".repeat(40),"repo":{"full_name":"org/repo"}}});
    let fake = Arc::new(FakeTransport::new().json(201, &body.to_string()));
    let f = fixture(
        Arc::new(Store::open_in_memory().await.unwrap()),
        fake.clone(),
    )
    .await;
    let result = call(
        &f,
        &f.revision,
        &LandingGithubOp::CreatePr(target(), "Title".into()),
    )
    .await
    .unwrap();
    assert_eq!(result["number"], 7);
    assert!(!result.to_string().contains("private-token"));
    let requests = fake.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, pam_connectors::Method::Post);
    assert_eq!(
        requests[0].url.as_str(),
        "https://api.github.com/repos/org/repo/pulls"
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(requests[0].body.as_ref().unwrap()).unwrap(),
        json!({"head":"feature/work","base":"main","title":"Title","maintainer_can_modify":false})
    );
}
struct RevokeAfterFirst {
    store: Arc<Store>,
    calls: AtomicUsize,
}
impl HttpTransport for RevokeAfterFirst {
    fn send<'a>(
        &'a self,
        _request: HttpRequest,
        _deadline: Instant,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.store.insert_grant("flow.run").await.unwrap();
            self.store.revoke_grant("flow.run").await.unwrap();
            Ok(HttpResponse{status:200,headers:vec![],body:json!({"total_count":1,"check_runs":[{"name":"ci","head_sha":"a".repeat(40),"status":"completed","conclusion":"success"}]}).to_string().into_bytes()})
        })
    }
}
#[tokio::test]
async fn every_physical_request_rechecks_revocation_before_second_http() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let transport = Arc::new(RevokeAfterFirst {
        store: store.clone(),
        calls: AtomicUsize::new(0),
    });
    let f = fixture(store, transport.clone()).await;
    let op = LandingGithubOp::Checks {
        repository: "org/repo".into(),
        sha: "a".repeat(40),
        required: vec![RequiredCheck::named("ci")],
    };
    assert!(call(&f, &f.revision, &op).await.is_err());
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
}

/// The connector re-checks the managed landing ceiling itself (defense in
/// depth behind the flow's checks): a pull request the human's landing
/// policy allows but the managed `landing.max_permissions` caps is refused
/// before any credential read or HTTP request.
#[tokio::test]
async fn the_managed_landing_ceiling_is_rechecked_at_the_connector() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let source = crate::policy_test::SwitchablePolicy::new(Some(
        &json!({
            "version": 1,
            "landing": { "max_permissions": { "create_pr": false } },
        })
        .to_string(),
    ));
    let policy = crate::policy_test::managed_handle(&store, &source).await;
    let fake = Arc::new(FakeTransport::new());
    let f = fixture_under(store, fake.clone(), policy).await;
    assert!(
        call(
            &f,
            &f.revision,
            &LandingGithubOp::CreatePr(target(), "Title".into()),
        )
        .await
        .is_err(),
        "the ceiling refuses the pull request"
    );
    assert_eq!(f.secrets.reads.load(Ordering::SeqCst), 0);
    assert!(fake.requests().is_empty());
}

/// Rewrites the fixture's landing recipe with `edit` and returns the new
/// revision.
async fn edit_recipe(f: &Fixture, edit: impl FnOnce(&mut serde_json::Value)) -> String {
    let raw = f
        .store
        .get_setting_bounded("flows.landing_policy", 32_768)
        .await
        .unwrap()
        .unwrap();
    let mut document: serde_json::Value = serde_json::from_str(&raw).unwrap();
    edit(&mut document["repositories"][0]);
    f.store
        .set_setting("flows.landing_policy", &document.to_string())
        .await
        .unwrap();
    crate::landing_policy::Snapshot::load(&f.store)
        .await
        .unwrap()
        .revision
}

/// The merge call carries exactly the recipe's merge method; another method
/// is refused before any credential read or HTTP request.
#[tokio::test]
async fn the_merge_carries_only_the_recipe_merge_method() {
    let fake = Arc::new(FakeTransport::new().json(
        200,
        &json!({"merged":true,"sha":"c".repeat(40)}).to_string(),
    ));
    let f = fixture(
        Arc::new(Store::open_in_memory().await.unwrap()),
        fake.clone(),
    )
    .await;
    let revision = edit_recipe(&f, |recipe| {
        recipe["permissions"]["merge"] = json!(true);
        recipe["merge_method"] = json!("rebase");
    })
    .await;
    assert!(
        call(
            &f,
            &revision,
            &LandingGithubOp::MergePr(target(), 7, MergeMethod::Squash)
        )
        .await
        .is_err()
    );
    assert!(fake.requests().is_empty());
    call(
        &f,
        &revision,
        &LandingGithubOp::MergePr(target(), 7, MergeMethod::Rebase),
    )
    .await
    .unwrap();
    let requests = fake.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(requests[0].body.as_ref().unwrap()).unwrap(),
        json!({"sha":"a".repeat(40),"merge_method":"rebase"})
    );
}

#[tokio::test]
async fn merge_methods_reads_exactly_the_repository() {
    let fake = Arc::new(FakeTransport::new().json(
        200,
        &json!({"full_name":"org/repo","allow_squash_merge":false,"allow_merge_commit":true,"allow_rebase_merge":true}).to_string(),
    ));
    let f = fixture(
        Arc::new(Store::open_in_memory().await.unwrap()),
        fake.clone(),
    )
    .await;
    let methods = call(
        &f,
        &f.revision,
        &LandingGithubOp::MergeMethods("org/repo".into()),
    )
    .await
    .unwrap();
    assert_eq!(methods["squash"], false);
    let requests = fake.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, pam_connectors::Method::Get);
    assert_eq!(
        requests[0].url.as_str(),
        "https://api.github.com/repos/org/repo"
    );
    assert!(
        call(
            &f,
            &f.revision,
            &LandingGithubOp::MergeMethods("org/other".into())
        )
        .await
        .is_err()
    );
}

/// A recipe whose required checks are all pinned reads check runs only;
/// the status read a name-only list needs is not even authorized.
#[tokio::test]
async fn pinned_required_checks_read_check_runs_only() {
    let fake = Arc::new(FakeTransport::new().json(
        200,
        &json!({"total_count":1,"check_runs":[{"name":"ci","head_sha":"a".repeat(40),"status":"completed","conclusion":"success","app":{"id":15368}}]}).to_string(),
    ));
    let f = fixture(
        Arc::new(Store::open_in_memory().await.unwrap()),
        fake.clone(),
    )
    .await;
    let revision = edit_recipe(&f, |recipe| {
        recipe["required_checks"] = json!([{"name":"ci","app_id":15368}]);
    })
    .await;
    let checks = call(
        &f,
        &revision,
        &LandingGithubOp::Checks {
            repository: "org/repo".into(),
            sha: "a".repeat(40),
            required: vec![RequiredCheck::pinned("ci", 15368)],
        },
    )
    .await
    .unwrap();
    assert_eq!(checks["passed"], true);
    assert_eq!(fake.requests().len(), 1);
    // The name-only spelling of the same check is no longer the recipe's.
    assert!(
        call(
            &f,
            &revision,
            &LandingGithubOp::Checks {
                repository: "org/repo".into(),
                sha: "a".repeat(40),
                required: vec![RequiredCheck::named("ci")],
            },
        )
        .await
        .is_err()
    );
}
