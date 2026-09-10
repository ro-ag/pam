//! Scope admission tests include credential/HTTP seams, not only policy parsing.
use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use pam_connectors::testing::FakeTransport;
use pam_connectors::{
    ArgValue, ConnectorId, HttpRequest, HttpResponse, HttpTransport, TransportError,
};
use pam_store::{ConnectorPatch, Store};
use serde_json::json;

use crate::connector_service::ConnectorService;
use crate::scope_policy::{
    CAUSE_SCOPE_DENIED, CAUSE_SCOPE_INVALID, ConnectorScope, RepositoryScope, SETTING_SCOPE_POLICY,
    ScopeAccess, ScopePolicy,
};
use crate::secrets::{SecretBackend, SecretError, SecretStore};

const BASE: &str = "https://api.example.test/";

fn policy(root: &Path, connector: ConnectorId, targets: &[&str]) -> ScopePolicy {
    ScopePolicy {
        version: 1,
        repositories: vec![RepositoryScope {
            root: root.to_path_buf(),
            connectors: vec![ConnectorScope {
                connector,
                base_url: BASE.to_owned(),
                access: ScopeAccess::Targets,
                targets: targets.iter().map(|target| (*target).to_owned()).collect(),
            }],
        }],
    }
    .normalize()
    .expect("valid policy")
}

fn args(name: &str, value: &str) -> BTreeMap<String, ArgValue> {
    BTreeMap::from([(name.to_owned(), ArgValue::Text(value.to_owned()))])
}

#[tokio::test]
async fn missing_and_malformed_policy_never_grant_scope() {
    let store = Store::open_in_memory().await.unwrap();
    let root = tempfile::tempdir().unwrap();
    assert_eq!(
        ScopePolicy::load(&store)
            .await
            .unwrap()
            .authorize_repo(root.path())
            .unwrap_err()
            .cause(),
        CAUSE_SCOPE_DENIED
    );
    for raw in [
        "{",
        "null",
        r#"{"version":2,"repositories":[]}"#,
        r#"{"version":1,"repositories":[],"allow_all":true}"#,
    ] {
        store.set_setting(SETTING_SCOPE_POLICY, raw).await.unwrap();
        assert_eq!(
            ScopePolicy::load(&store).await.unwrap_err().cause(),
            CAUSE_SCOPE_INVALID
        );
        assert_eq!(
            store
                .get_setting(SETTING_SCOPE_POLICY)
                .await
                .unwrap()
                .as_deref(),
            Some(raw)
        );
    }
}

#[test]
fn repository_matching_is_exact_and_rejects_sibling_prefixes() {
    let root = tempfile::tempdir().unwrap();
    let nested = root.path().join("nested");
    std::fs::create_dir(&nested).unwrap();
    let scope = policy(root.path(), ConnectorId::Github, &["team/app"]);
    assert!(scope.authorize_repo(root.path()).is_ok());
    assert!(scope.authorize_repo(&nested).is_err());
    assert!(scope.authorize_repo(Path::new(".")).is_err());
    assert!(
        scope
            .authorize_repo(tempfile::tempdir().unwrap().path())
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn replacing_approved_root_with_symlink_does_not_retarget_approval() {
    let base = tempfile::tempdir().unwrap();
    let root = base.path().join("repo");
    let moved = base.path().join("moved");
    let outside = base.path().join("outside");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&outside).unwrap();
    let scope = policy(&root, ConnectorId::Github, &["team/app"]);
    std::fs::rename(&root, &moved).unwrap();
    std::os::unix::fs::symlink(&outside, &root).unwrap();
    assert!(scope.authorize_repo(&root).is_err());
}

#[test]
fn product_targets_and_broad_searches_have_explicit_boundaries() {
    let root = tempfile::tempdir().unwrap();
    for (connector, call, key, value, target) in [
        (ConnectorId::Github, "run", "repo", "team/app", "team/app"),
        (
            ConnectorId::Sonarqube,
            "analysis",
            "project",
            "team:app",
            "team:app",
        ),
        (
            ConnectorId::Jenkins,
            "node_evidence",
            "job",
            "folder/app",
            "folder/app",
        ),
        (
            ConnectorId::Jenkins,
            "investigate",
            "job",
            "folder/app",
            "folder/app",
        ),
        (
            ConnectorId::Sonarqube,
            "quality_gate",
            "project",
            "team:app",
            "team:app",
        ),
        (ConnectorId::Jira, "issue", "key", "APP-123", "APP"),
        (ConnectorId::Confluence, "page", "id", "123", "123"),
        (
            ConnectorId::Sharepoint,
            "documents",
            "site",
            "site.example,abc,def",
            "site.example,abc,def",
        ),
    ] {
        let scope = policy(root.path(), connector, &[target]);
        assert!(
            scope
                .authorize_connector(root.path(), connector, BASE, call, &args(key, value))
                .is_ok(),
            "{connector}"
        );
        assert!(
            scope
                .authorize_connector(root.path(), connector, BASE, call, &args(key, "other"))
                .is_err(),
            "{connector}"
        );
    }
    for (connector, call, key, value, target) in [
        (
            ConnectorId::Jira,
            "search",
            "jql",
            "project = APP OR project = SECRET",
            "APP",
        ),
        (
            ConnectorId::Confluence,
            "search",
            "cql",
            "id=123 OR id=999",
            "123",
        ),
        (
            ConnectorId::Jenkins,
            "jobs",
            "job",
            "folder/app",
            "folder/app",
        ),
    ] {
        let mut scope = policy(root.path(), connector, &[target]);
        assert!(
            scope
                .authorize_connector(root.path(), connector, BASE, call, &args(key, value))
                .is_err()
        );
        scope.repositories[0].connectors[0].access = ScopeAccess::ConnectorWide;
        scope.repositories[0].connectors[0].targets.clear();
        assert!(
            scope
                .authorize_connector(root.path(), connector, BASE, call, &args(key, value))
                .is_ok()
        );
    }
}

#[test]
fn prefixes_forged_jira_keys_and_changed_service_urls_are_denied() {
    let root = tempfile::tempdir().unwrap();
    let scope = policy(root.path(), ConnectorId::Jenkins, &["team/app"]);
    for job in [
        "team/application",
        "team/app/nested",
        "team/../app",
        "team/%2e%2e/app",
    ] {
        assert!(
            scope
                .authorize_connector(
                    root.path(),
                    ConnectorId::Jenkins,
                    BASE,
                    "builds",
                    &args("job", job)
                )
                .is_err()
        );
    }
    assert!(
        scope
            .authorize_connector(
                root.path(),
                ConnectorId::Jenkins,
                "https://other.example/",
                "builds",
                &args("job", "team/app")
            )
            .is_err()
    );
    let scope = policy(root.path(), ConnectorId::Jira, &["APP"]);
    for key in [
        "APP-1/SECRET-2",
        "APP-1 OR SECRET-2",
        "APP-xyz",
        "APP-1-2",
        "APP-",
    ] {
        assert!(
            scope
                .authorize_connector(
                    root.path(),
                    ConnectorId::Jira,
                    BASE,
                    "issue",
                    &args("key", key)
                )
                .is_err()
        );
    }
}

#[test]
fn duplicate_roots_unknown_fields_and_implicit_wide_access_are_invalid() {
    let root = tempfile::tempdir().unwrap();
    let mut scope = policy(root.path(), ConnectorId::Github, &["team/app"]);
    scope.repositories.push(scope.repositories[0].clone());
    assert!(scope.normalize().is_err());
    let mut scope = policy(root.path(), ConnectorId::Github, &["team/app"]);
    scope.repositories[0].connectors[0].access = ScopeAccess::ConnectorWide;
    assert!(scope.normalize().is_err());
    assert!(serde_json::from_value::<ScopePolicy>(json!({"version":1,"repositories":[{"root":root.path(),"connectors":[],"allow_all":true}]})).is_err());
}

#[derive(Default)]
struct CountingSecrets(AtomicUsize);

impl SecretBackend for CountingSecrets {
    fn get(&self, _account: &str) -> Result<Option<String>, SecretError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Some("test-token".to_owned()))
    }
    fn set(&self, _account: &str, _secret: &str) -> Result<(), SecretError> {
        Ok(())
    }
    fn delete(&self, _account: &str) -> Result<bool, SecretError> {
        Ok(false)
    }
}

async fn configured_store() -> Arc<Store> {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    store
        .upsert_connector(
            "github",
            ConnectorPatch {
                enabled: Some(true),
                base_url: Some(Some(BASE)),
                ..ConnectorPatch::default()
            },
        )
        .await
        .unwrap();
    store
}

fn service(
    store: &Arc<Store>,
    backend: &Arc<CountingSecrets>,
    transport: Arc<dyn HttpTransport>,
) -> ConnectorService {
    ConnectorService::new(
        Arc::clone(store),
        Arc::new(SecretStore::new(Arc::clone(backend) as Arc<_>)),
        transport,
    )
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[tokio::test]
async fn denied_scope_touches_neither_credentials_nor_network() {
    let root = tempfile::tempdir().unwrap();
    let store = configured_store().await;
    let backend = Arc::new(CountingSecrets::default());
    let transport = Arc::new(FakeTransport::new());
    let service = service(&store, &backend, Arc::clone(&transport) as Arc<_>);
    let error = service
        .invoke(
            root.path(),
            ConnectorId::Github,
            "runs",
            &args("repo", "team/app"),
            deadline(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.cause(), CAUSE_SCOPE_DENIED);
    assert_eq!(backend.0.load(Ordering::SeqCst), 0);
    assert!(transport.requests().is_empty());
}

#[tokio::test]
async fn approved_target_runs_and_revocation_applies_to_next_invoke() {
    let root = tempfile::tempdir().unwrap();
    let store = configured_store().await;
    policy(root.path(), ConnectorId::Github, &["team/app"])
        .save(&store)
        .await
        .unwrap();
    let backend = Arc::new(CountingSecrets::default());
    let transport = Arc::new(FakeTransport::new().json(200, r#"{"workflow_runs":[]}"#));
    let service = service(&store, &backend, Arc::clone(&transport) as Arc<_>);
    service
        .invoke(
            root.path(),
            ConnectorId::Github,
            "runs",
            &args("repo", "team/app"),
            deadline(),
        )
        .await
        .unwrap();
    ScopePolicy::default().save(&store).await.unwrap();
    assert_eq!(
        service
            .invoke(
                root.path(),
                ConnectorId::Github,
                "runs",
                &args("repo", "team/app"),
                deadline()
            )
            .await
            .unwrap_err()
            .cause(),
        CAUSE_SCOPE_DENIED
    );
    assert_eq!(backend.0.load(Ordering::SeqCst), 1);
    assert_eq!(transport.requests().len(), 1);
}

struct RevokingTransport {
    store: Arc<Store>,
    inner: FakeTransport,
    calls: AtomicUsize,
    revoke_after: usize,
    change_url: bool,
}

impl HttpTransport for RevokingTransport {
    fn send<'a>(
        &'a self,
        request: HttpRequest,
        deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>> {
        Box::pin(async move {
            let response = self.inner.send(request, deadline).await?;
            if self.calls.fetch_add(1, Ordering::SeqCst) + 1 == self.revoke_after {
                if self.change_url {
                    self.store
                        .upsert_connector(
                            "github",
                            ConnectorPatch {
                                base_url: Some(Some("https://other.example/")),
                                ..ConnectorPatch::default()
                            },
                        )
                        .await
                        .unwrap();
                } else {
                    ScopePolicy::default().save(&self.store).await.unwrap();
                }
            }
            Ok(response)
        })
    }
}

#[tokio::test]
async fn revocation_blocks_a_second_api_read_and_a_signed_log_redirect() {
    for redirect in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let store = configured_store().await;
        policy(root.path(), ConnectorId::Github, &["team/app"])
            .save(&store)
            .await
            .unwrap();
        let mut inner =
            FakeTransport::new().json(200, r#"{"id":41,"run_attempt":1,"conclusion":"failure"}"#);
        if redirect {
            inner = inner.with_headers(
                302,
                &[("Location", "https://storage.example/log?signature=test")],
                "",
            );
        }
        let transport = Arc::new(RevokingTransport {
            store: Arc::clone(&store),
            inner,
            calls: AtomicUsize::new(0),
            revoke_after: if redirect { 2 } else { 1 },
            change_url: false,
        });
        let backend = Arc::new(CountingSecrets::default());
        let service = service(&store, &backend, Arc::clone(&transport) as Arc<_>);
        let mut arguments = args("repo", "team/app");
        arguments.insert(
            if redirect { "job_id" } else { "run_id" }.to_owned(),
            ArgValue::Int(41),
        );
        let error = service
            .invoke(
                root.path(),
                ConnectorId::Github,
                if redirect { "job_log" } else { "run" },
                &arguments,
                deadline(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.cause(), CAUSE_SCOPE_DENIED);
        assert_eq!(
            transport.calls.load(Ordering::SeqCst),
            if redirect { 2 } else { 1 }
        );
    }
}

#[tokio::test]
async fn changing_connector_url_during_read_blocks_next_http_request() {
    let root = tempfile::tempdir().unwrap();
    let store = configured_store().await;
    policy(root.path(), ConnectorId::Github, &["team/app"])
        .save(&store)
        .await
        .unwrap();
    let transport = Arc::new(RevokingTransport {
        store: Arc::clone(&store),
        inner: FakeTransport::new().json(200, r#"{"id":41,"run_attempt":1}"#),
        calls: AtomicUsize::new(0),
        revoke_after: 1,
        change_url: true,
    });
    let backend = Arc::new(CountingSecrets::default());
    let service = service(&store, &backend, Arc::clone(&transport) as Arc<_>);
    let mut arguments = args("repo", "team/app");
    arguments.insert("run_id".to_owned(), ArgValue::Int(41));
    assert_eq!(
        service
            .invoke(
                root.path(),
                ConnectorId::Github,
                "run",
                &arguments,
                deadline()
            )
            .await
            .unwrap_err()
            .cause(),
        CAUSE_SCOPE_DENIED
    );
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn signed_log_redirect_is_one_physical_hop_without_authorization() {
    let root = tempfile::tempdir().unwrap();
    let store = configured_store().await;
    policy(root.path(), ConnectorId::Github, &["team/app"])
        .save(&store)
        .await
        .unwrap();
    let backend = Arc::new(CountingSecrets::default());
    let transport = Arc::new(
        FakeTransport::new()
            .json(200, r#"{"conclusion":"failure"}"#)
            .with_headers(
                302,
                &[("Location", "https://storage.example/log?signature=test")],
                "",
            )
            .bytes(200, b"node failure".to_vec()),
    );
    let service = service(&store, &backend, Arc::clone(&transport) as Arc<_>);
    let mut arguments = args("repo", "team/app");
    arguments.insert("job_id".to_owned(), ArgValue::Int(41));
    service
        .invoke(
            root.path(),
            ConnectorId::Github,
            "job_log",
            &arguments,
            deadline(),
        )
        .await
        .unwrap();
    let requests = transport.requests();
    assert_eq!(requests.len(), 3);
    assert!(
        requests[1]
            .headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("authorization"))
    );
    assert!(
        !requests[2]
            .headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("authorization"))
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.follow_one_https_redirect_without_auth)
    );
}

#[tokio::test]
async fn invalid_redirect_targets_and_a_second_redirect_are_not_followed() {
    for location in [
        "http://storage.example/log",
        "https://user:password@storage.example/log",
        "https://storage.example/log#fragment",
        "https://storage.example/log",
    ] {
        let root = tempfile::tempdir().unwrap();
        let store = configured_store().await;
        policy(root.path(), ConnectorId::Github, &["team/app"])
            .save(&store)
            .await
            .unwrap();
        let transport = Arc::new(
            FakeTransport::new()
                .json(200, "{}")
                .with_headers(302, &[("Location", location)], "")
                .with_headers(302, &[("Location", "https://third.example/log")], ""),
        );
        let backend = Arc::new(CountingSecrets::default());
        let service = service(&store, &backend, Arc::clone(&transport) as Arc<_>);
        let mut arguments = args("repo", "team/app");
        arguments.insert("job_id".to_owned(), ArgValue::Int(41));
        assert!(
            service
                .invoke(
                    root.path(),
                    ConnectorId::Github,
                    "job_log",
                    &arguments,
                    deadline()
                )
                .await
                .is_err()
        );
        assert_eq!(
            transport.requests().len(),
            if location == "https://storage.example/log" {
                3
            } else {
                2
            }
        );
    }
}

#[tokio::test]
async fn sharepoint_scope_revocation_after_membership_blocks_item_download() {
    let root = tempfile::tempdir().unwrap();
    let store = configured_store().await;
    store
        .upsert_connector(
            "sharepoint",
            ConnectorPatch {
                enabled: Some(true),
                base_url: Some(Some(BASE)),
                ..ConnectorPatch::default()
            },
        )
        .await
        .unwrap();
    let site = "tenant.sharepoint.com,site,web";
    policy(root.path(), ConnectorId::Sharepoint, &[site])
        .save(&store)
        .await
        .unwrap();
    let transport = Arc::new(RevokingTransport {
        store: Arc::clone(&store),
        inner: FakeTransport::new()
            .json(200, &serde_json::json!({"id":site,"webUrl":"https://tenant.sharepoint.com/sites/project"}).to_string())
            .json(200, r#"{"value":[{"id":"drive-1"}]}"#),
        calls: AtomicUsize::new(0), revoke_after: 2, change_url: false,
    });
    let backend = Arc::new(CountingSecrets::default());
    let service = service(&store, &backend, Arc::clone(&transport) as Arc<_>);
    let arguments = BTreeMap::from([
        ("site".to_owned(), ArgValue::Text(site.to_owned())),
        ("drive".to_owned(), ArgValue::Text("drive-1".to_owned())),
        ("item".to_owned(), ArgValue::Text("item-1".to_owned())),
    ]);
    let error = service
        .invoke(
            root.path(),
            ConnectorId::Sharepoint,
            "document",
            &arguments,
            deadline(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.cause(), CAUSE_SCOPE_DENIED);
    assert_eq!(transport.inner.requests().len(), 2);
}
