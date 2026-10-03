use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pam_connectors::testing::FakeTransport;
use pam_connectors::{ArgValue, CallResult, ConnectorId};
use pam_store::Store;

use crate::connector_service::{
    CAUSE_BAD_URL, CAUSE_BASE_URL_MISSING, CAUSE_CLI_MISSING, CAUSE_CONNECTOR_DISABLED,
    CAUSE_CREDENTIAL_MISSING, CAUSE_NOT_CONFIGURED, ConfigurePatch, ConnectorService,
    ConnectorSummary, CredentialAction,
};
use crate::secrets::{FakeSecretBackend, SecretBackend, SecretError, SecretStore, account_for};

/// A GitHub personal access token, as a human would paste one in. Every
/// assertion that this string does not appear somewhere is the point of
/// the test it is in.
const TOKEN: &str = "ghp_secret_value_0123456789";

const BASE_URL: &str = "https://api.github.test/";

/// Fixture-only approvals for the concrete services exercised below.
async fn approve_connector_repo(store: &Store, repo: &std::path::Path) {
    let root = repo.canonicalize().expect("real fixture repo");
    store.set_setting("flows.scope_policy", &serde_json::json!({
        "version": 1, "repositories": [{"root": root, "connectors": [
            {"connector":"github", "base_url":BASE_URL, "access":"connector_wide", "targets":[]},
            {"connector":"jenkins", "base_url":"https://ci.example.test/", "access":"connector_wide", "targets":[]}
        ]}]
    }).to_string()).await.expect("explicit test scope");
}

/// A patch can end up in a log line or a panic message; neither may carry
/// the secret.
#[test]
fn a_patch_debug_never_prints_the_credential() {
    let patch = ConfigurePatch {
        credential: Some(CredentialAction::Set(crate::secrets::Secret::new(
            TOKEN.to_owned(),
        ))),
        base_url: Some(Some(BASE_URL.to_owned())),
        ..ConfigurePatch::default()
    };
    let rendered = format!("{patch:?}");
    assert!(!rendered.contains(TOKEN), "{rendered}");
    assert!(rendered.contains("Set([REDACTED])"), "{rendered}");
    assert!(
        rendered.contains(BASE_URL),
        "non-secrets still print: {rendered}"
    );
    assert_eq!(format!("{:?}", CredentialAction::Clear), "Clear");
}

/// A service over an in-memory store, a fake keychain, and a scripted
/// transport — the three seams the real service runs on.
struct Fixture {
    repo: tempfile::TempDir,
    store: Arc<Store>,
    backend: Arc<FakeSecretBackend>,
    transport: Arc<FakeTransport>,
    service: ConnectorService,
}

async fn fixture() -> Fixture {
    fixture_with(FakeTransport::new()).await
}

async fn fixture_with(transport: FakeTransport) -> Fixture {
    let store = Arc::new(Store::open_in_memory().await.expect("store opens"));
    let repo = tempfile::tempdir().expect("repo");
    approve_connector_repo(&store, repo.path()).await;
    let backend = Arc::new(FakeSecretBackend::default());
    let transport = Arc::new(transport);
    let service = ConnectorService::new(
        Arc::clone(&store),
        Arc::new(SecretStore::new(Arc::clone(&backend) as Arc<_>)),
        Arc::clone(&transport) as Arc<_>,
        crate::managed_policy_service::PolicyHandle::none(),
    );
    Fixture {
        repo,
        store,
        backend,
        transport,
        service,
    }
}

impl Fixture {
    /// Configures GitHub the way a human would: base URL, credential,
    /// enabled.
    async fn configure_github(&self) {
        self.service
            .configure(
                ConnectorId::Github,
                ConfigurePatch {
                    enabled: Some(true),
                    base_url: Some(Some(BASE_URL.to_owned())),
                    credential: Some(CredentialAction::Set(crate::secrets::Secret::new(
                        TOKEN.to_owned(),
                    ))),
                    ..ConfigurePatch::default()
                },
            )
            .await
            .expect("configure succeeds");
    }

    fn summary_of(summaries: &[ConnectorSummary], id: ConnectorId) -> &ConnectorSummary {
        summaries
            .iter()
            .find(|summary| summary.id == id.as_str())
            .expect("every connector is listed")
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

#[tokio::test]
async fn list_answers_every_descriptor_merged_with_its_row() {
    let fixture = fixture().await;
    fixture.configure_github().await;

    let summaries = fixture.service.list().await.expect("list ok");
    assert_eq!(summaries.len(), ConnectorId::ALL.len());
    let ids: Vec<&str> = summaries.iter().map(|entry| entry.id.as_str()).collect();
    assert_eq!(
        ids,
        ConnectorId::ALL
            .iter()
            .map(|id| id.as_str())
            .collect::<Vec<_>>()
    );

    let github = Fixture::summary_of(&summaries, ConnectorId::Github);
    assert_eq!(github.name, "GitHub");
    assert_eq!(github.auth, "bearer");
    assert!(github.needs_base_url);
    assert!(github.enabled);
    assert_eq!(github.base_url.as_deref(), Some(BASE_URL));
    assert!(github.credential.present);
    assert!(github.credential.store_available);
    assert!(github.last_test.is_none());

    // Jenkins was never configured: present in the list, empty, and its
    // user-name field is labelled for the GUI.
    let jenkins = Fixture::summary_of(&summaries, ConnectorId::Jenkins);
    assert!(!jenkins.enabled);
    assert!(jenkins.base_url.is_none());
    assert!(!jenkins.credential.present);
    assert_eq!(jenkins.username_label, Some("user"));
}

#[tokio::test]
async fn configure_writes_the_credential_and_normalizes_the_base_url() {
    let fixture = fixture().await;
    let summary = fixture
        .service
        .configure(
            ConnectorId::Jenkins,
            ConfigurePatch {
                enabled: Some(true),
                // No trailing slash: the stored value gets one.
                base_url: Some(Some("https://ci.example.test/jenkins".to_owned())),
                username: Some(Some("builder".to_owned())),
                credential: Some(CredentialAction::Set(crate::secrets::Secret::new(
                    TOKEN.to_owned(),
                ))),
            },
        )
        .await
        .expect("configure ok");

    assert!(summary.enabled);
    assert_eq!(
        summary.base_url.as_deref(),
        Some("https://ci.example.test/jenkins/")
    );
    assert_eq!(summary.username.as_deref(), Some("builder"));
    assert!(summary.credential.present);

    // The secret is in the keychain, under the connector's account, and
    // nowhere in the row.
    let stored = fixture
        .backend
        .get(&account_for("jenkins"))
        .expect("backend ok");
    assert_eq!(stored.as_deref(), Some(TOKEN));
    let row = fixture
        .store
        .get_connector("jenkins")
        .await
        .expect("row query ok")
        .expect("row exists");
    assert!(!format!("{row:?}").contains(TOKEN));
}

#[tokio::test]
async fn configure_refuses_a_bad_base_url_before_writing_anything() {
    let fixture = fixture().await;
    let error = fixture
        .service
        .configure(
            ConnectorId::Github,
            ConfigurePatch {
                enabled: Some(true),
                base_url: Some(Some("http://api.github.test/".to_owned())),
                credential: Some(CredentialAction::Set(crate::secrets::Secret::new(
                    TOKEN.to_owned(),
                ))),
                ..ConfigurePatch::default()
            },
        )
        .await
        .expect_err("a plain-http base URL is refused");

    assert_eq!(error.cause(), CAUSE_BAD_URL);
    assert!(
        error.detail().contains("https"),
        "detail: {}",
        error.detail()
    );
    assert!(
        error
            .recovery(ConnectorId::Github)
            .contains("Settings → Connectors → GitHub")
    );

    // Neither half of the write happened.
    assert!(
        fixture
            .store
            .get_connector("github")
            .await
            .expect("row query ok")
            .is_none()
    );
    assert_eq!(
        fixture
            .backend
            .get(&account_for("github"))
            .expect("backend ok"),
        None
    );
}

#[tokio::test]
async fn configure_clears_the_credential() {
    let fixture = fixture().await;
    fixture.configure_github().await;

    let summary = fixture
        .service
        .configure(
            ConnectorId::Github,
            ConfigurePatch {
                credential: Some(CredentialAction::Clear),
                ..ConfigurePatch::default()
            },
        )
        .await
        .expect("clear ok");

    assert!(!summary.credential.present);
    // The rest of the row survived the credential-only patch.
    assert!(summary.enabled);
    assert_eq!(summary.base_url.as_deref(), Some(BASE_URL));
    assert_eq!(
        fixture
            .backend
            .get(&account_for("github"))
            .expect("backend ok"),
        None
    );
}

#[tokio::test]
async fn an_unreachable_credential_store_refuses_configure_and_still_lists() {
    let fixture = fixture().await;
    *fixture.backend.fail_with.lock().expect("lock") = Some(SecretError::Unavailable);

    let error = fixture
        .service
        .configure(
            ConnectorId::Github,
            ConfigurePatch {
                credential: Some(CredentialAction::Set(crate::secrets::Secret::new(
                    TOKEN.to_owned(),
                ))),
                ..ConfigurePatch::default()
            },
        )
        .await
        .expect_err("an unreachable keychain refuses the write");
    assert_eq!(error.cause(), SecretError::Unavailable.cause());

    // The panel still draws: no credential, and it says why.
    let summaries = fixture.service.list().await.expect("list ok");
    let github = Fixture::summary_of(&summaries, ConnectorId::Github);
    assert!(!github.credential.present);
    assert!(!github.credential.store_available);
}

#[tokio::test]
async fn test_records_a_pass_and_its_detail() {
    let fixture = fixture_with(FakeTransport::new().json(200, r#"{"login":"octocat"}"#)).await;
    fixture.configure_github().await;

    let (passed, detail) = fixture
        .service
        .test(ConnectorId::Github)
        .await
        .expect("test ran");
    assert!(passed);
    assert_eq!(detail, "authenticated as octocat");
    assert_eq!(fixture.transport.url(0), "https://api.github.test/user");

    let summary = fixture
        .service
        .get(ConnectorId::Github)
        .await
        .expect("summary ok");
    let last = summary.last_test.expect("a test was recorded");
    assert_eq!(last.status, "passed");
    assert_eq!(last.detail, "authenticated as octocat");
    assert!(last.ts > 0);
}

#[tokio::test]
async fn test_records_a_failure_rather_than_erroring() {
    let fixture = fixture_with(FakeTransport::new().json(401, "{}")).await;
    fixture.configure_github().await;

    let (passed, detail) = fixture
        .service
        .test(ConnectorId::Github)
        .await
        .expect("test ran");
    assert!(!passed);
    assert!(detail.contains("credential"), "detail: {detail}");

    let summary = fixture
        .service
        .get(ConnectorId::Github)
        .await
        .expect("summary ok");
    assert_eq!(
        summary.last_test.expect("recorded").status.as_str(),
        "failed"
    );
}

#[tokio::test]
async fn invoke_refuses_a_disabled_connector_before_the_transport_sees_anything() {
    let fixture = fixture().await;
    fixture.configure_github().await;
    fixture
        .service
        .configure(
            ConnectorId::Github,
            ConfigurePatch {
                enabled: Some(false),
                ..ConfigurePatch::default()
            },
        )
        .await
        .expect("disable ok");

    let error = fixture
        .service
        .invoke(
            fixture.repo.path(),
            ConnectorId::Github,
            "runs",
            &BTreeMap::from([("repo".to_owned(), ArgValue::Text("octo/repo".to_owned()))]),
            deadline(),
        )
        .await
        .expect_err("a disabled connector is refused");

    assert_eq!(error.cause(), CAUSE_CONNECTOR_DISABLED);
    assert!(
        error
            .recovery(ConnectorId::Github)
            .contains("Settings → Connectors → GitHub")
    );
    assert!(
        fixture.transport.requests().is_empty(),
        "a refused call must never reach the transport"
    );
}

#[tokio::test]
async fn invoke_refuses_an_unreachable_keychain_before_the_transport_sees_anything() {
    let fixture = fixture().await;
    fixture.configure_github().await;
    *fixture.backend.fail_with.lock().expect("lock") = Some(SecretError::Denied);

    let error = fixture
        .service
        .invoke(
            fixture.repo.path(),
            ConnectorId::Github,
            "runs",
            &BTreeMap::from([("repo".to_owned(), ArgValue::Text("octo/repo".to_owned()))]),
            deadline(),
        )
        .await
        .expect_err("a keychain that denies access refuses the call");
    assert_eq!(error.cause(), SecretError::Denied.cause());
    assert_eq!(
        error.recovery_line(ConnectorId::Github),
        SecretError::Denied.recovery()
    );
    assert!(fixture.transport.requests().is_empty());
}

#[tokio::test]
async fn invoke_refuses_a_missing_credential_before_the_transport_sees_anything() {
    let fixture = fixture().await;
    fixture
        .service
        .configure(
            ConnectorId::Github,
            ConfigurePatch {
                enabled: Some(true),
                base_url: Some(Some(BASE_URL.to_owned())),
                ..ConfigurePatch::default()
            },
        )
        .await
        .expect("configure ok");

    let error = fixture
        .service
        .invoke(
            fixture.repo.path(),
            ConnectorId::Github,
            "runs",
            &BTreeMap::from([("repo".to_owned(), ArgValue::Text("octo/repo".to_owned()))]),
            deadline(),
        )
        .await
        .expect_err("a credential-less connector is refused");
    assert_eq!(error.cause(), CAUSE_CREDENTIAL_MISSING);
    assert!(fixture.transport.requests().is_empty());
}

#[tokio::test]
async fn invoke_refuses_a_missing_base_url_before_the_transport_sees_anything() {
    let fixture = fixture().await;
    fixture
        .service
        .configure(
            ConnectorId::Github,
            ConfigurePatch {
                enabled: Some(true),
                credential: Some(CredentialAction::Set(crate::secrets::Secret::new(
                    TOKEN.to_owned(),
                ))),
                ..ConfigurePatch::default()
            },
        )
        .await
        .expect("configure ok");

    let error = fixture
        .service
        .invoke(
            fixture.repo.path(),
            ConnectorId::Github,
            "runs",
            &BTreeMap::from([("repo".to_owned(), ArgValue::Text("octo/repo".to_owned()))]),
            deadline(),
        )
        .await
        .expect_err("a base-URL-less connector is refused");
    assert_eq!(error.cause(), CAUSE_BASE_URL_MISSING);
    assert!(fixture.transport.requests().is_empty());
}

#[tokio::test]
async fn invoke_refuses_a_connector_missing_the_user_name_its_auth_needs() {
    let fixture = fixture().await;
    fixture
        .service
        .configure(
            ConnectorId::Jenkins,
            ConfigurePatch {
                enabled: Some(true),
                base_url: Some(Some("https://ci.example.test/".to_owned())),
                credential: Some(CredentialAction::Set(crate::secrets::Secret::new(
                    TOKEN.to_owned(),
                ))),
                ..ConfigurePatch::default()
            },
        )
        .await
        .expect("configure ok");

    let error = fixture
        .service
        .invoke(
            fixture.repo.path(),
            ConnectorId::Jenkins,
            "jobs",
            &BTreeMap::new(),
            deadline(),
        )
        .await
        .expect_err("Jenkins without a user name is refused");
    assert_eq!(error.cause(), CAUSE_NOT_CONFIGURED);
    assert!(
        error.detail().contains("user"),
        "detail: {}",
        error.detail()
    );
    assert!(fixture.transport.requests().is_empty());
}

#[tokio::test]
async fn invoke_calls_the_connector_and_answers_its_json() {
    let fixture = fixture_with(FakeTransport::new().json(
        200,
        r#"{"workflow_runs":[{"id":7,"conclusion":"failure"}]}"#,
    ))
    .await;
    fixture.configure_github().await;

    let result = fixture
        .service
        .invoke(
            fixture.repo.path(),
            ConnectorId::Github,
            "runs",
            &BTreeMap::from([("repo".to_owned(), ArgValue::Text("octo/repo".to_owned()))]),
            deadline(),
        )
        .await
        .expect("the call runs");

    match result {
        CallResult::Json(body) => assert_eq!(body["runs"][0]["id"], 7),
        CallResult::Log { name, .. } => panic!("expected JSON, got the log {name}"),
    }
    assert!(
        fixture
            .transport
            .url(0)
            .contains("/repos/octo/repo/actions/runs")
    );
    // The credential rode in a header, not in the URL.
    assert!(!fixture.transport.url(0).contains(TOKEN));
    assert_eq!(
        fixture.transport.header(0, "Authorization"),
        Some(format!("Bearer {TOKEN}"))
    );
}

#[tokio::test]
async fn absent_or_invalid_scope_refuses_before_credentials_and_network() {
    for raw in [r#"{"version":1,"repositories":[]}"#, "not-json"] {
        let fixture = fixture().await;
        fixture.configure_github().await;
        fixture
            .store
            .set_setting("flows.scope_policy", raw)
            .await
            .unwrap();
        *fixture.backend.fail_with.lock().unwrap() = Some(SecretError::Denied);
        let error = fixture
            .service
            .invoke(
                fixture.repo.path(),
                ConnectorId::Github,
                "runs",
                &BTreeMap::from([("repo".to_owned(), ArgValue::Text("octo/repo".to_owned()))]),
                deadline(),
            )
            .await
            .expect_err("scope must reject before secret access");
        assert_eq!(
            error.cause(),
            if raw == "not-json" {
                "scope_policy_invalid"
            } else {
                "scope_denied"
            }
        );
        assert!(fixture.transport.requests().is_empty());
    }
}

#[tokio::test]
async fn missing_scope_setting_does_not_inherit_connector_permission() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let repo = tempfile::tempdir().unwrap();
    let transport = Arc::new(FakeTransport::new());
    let service = ConnectorService::from_parts(
        Arc::clone(&store),
        None,
        Some(transport.clone()),
        crate::managed_policy_service::PolicyHandle::none(),
    );
    assert!(
        store
            .get_setting("flows.scope_policy")
            .await
            .unwrap()
            .is_none()
    );
    let error = service
        .invoke(
            repo.path(),
            ConnectorId::Github,
            "runs",
            &BTreeMap::new(),
            deadline(),
        )
        .await
        .expect_err("absent policy must deny before connector or credentials");
    assert_eq!(error.cause(), "scope_denied");
    assert!(transport.requests().is_empty());
}

#[tokio::test]
async fn a_daemon_without_curl_refuses_http_connectors() {
    let store = Arc::new(Store::open_in_memory().await.expect("store opens"));
    let repo = tempfile::tempdir().expect("repo");
    approve_connector_repo(&store, repo.path()).await;
    let backend = Arc::new(FakeSecretBackend::default());
    let service = ConnectorService::from_parts(
        Arc::clone(&store),
        Some(Arc::new(SecretStore::new(Arc::clone(&backend) as Arc<_>))),
        None,
        crate::managed_policy_service::PolicyHandle::none(),
    );
    service
        .configure(
            ConnectorId::Github,
            ConfigurePatch {
                enabled: Some(true),
                base_url: Some(Some(BASE_URL.to_owned())),
                credential: Some(CredentialAction::Set(crate::secrets::Secret::new(
                    TOKEN.to_owned(),
                ))),
                ..ConfigurePatch::default()
            },
        )
        .await
        .expect("configure still works without curl");

    let error = service
        .test(ConnectorId::Github)
        .await
        .expect_err("no curl, no test");
    assert_eq!(error.cause(), CAUSE_CLI_MISSING);
    assert_eq!(
        error.recovery_line(ConnectorId::Github),
        pam_model::download::curl_recovery_line()
    );

    let error = service
        .invoke(
            repo.path(),
            ConnectorId::Github,
            "runs",
            &BTreeMap::from([("repo".to_owned(), ArgValue::Text("octo/repo".to_owned()))]),
            deadline(),
        )
        .await
        .expect_err("no curl, no call");
    assert_eq!(error.cause(), CAUSE_CLI_MISSING);
}

#[tokio::test]
async fn a_daemon_without_a_credential_store_still_lists() {
    let store = Arc::new(Store::open_in_memory().await.expect("store opens"));
    let service = ConnectorService::from_parts(
        Arc::clone(&store),
        None,
        None,
        crate::managed_policy_service::PolicyHandle::none(),
    );

    let summaries = service.list().await.expect("list ok");
    assert_eq!(summaries.len(), ConnectorId::ALL.len());
    let github = Fixture::summary_of(&summaries, ConnectorId::Github);
    assert!(!github.credential.store_available);
    assert!(!github.credential.present);
}

#[tokio::test]
async fn configuration_changes_retire_the_old_verdict_and_test_current_credentials() {
    let fixture = fixture_with(
        FakeTransport::new()
            .json(200, r#"{"login":"octocat"}"#)
            .json(401, "{}"),
    )
    .await;
    fixture.configure_github().await;
    fixture.service.test(ConnectorId::Github).await.unwrap();
    let summary = fixture
        .service
        .configure(
            ConnectorId::Github,
            ConfigurePatch {
                enabled: Some(false),
                base_url: Some(Some(format!("  {BASE_URL}  "))),
                ..ConfigurePatch::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(summary.last_test.unwrap().status, "passed");
    let replacement = "replacement-test-token";
    let summary = fixture
        .service
        .configure(
            ConnectorId::Github,
            ConfigurePatch {
                base_url: Some(Some("https://replacement.github.test/".to_owned())),
                credential: Some(CredentialAction::Set(crate::secrets::Secret::new(
                    replacement.to_owned(),
                ))),
                ..ConfigurePatch::default()
            },
        )
        .await
        .unwrap();
    assert!(summary.last_test.is_none());
    assert!(!summary.enabled, "saving must not enable the connector");
    let (passed, _) = fixture.service.test(ConnectorId::Github).await.unwrap();
    assert!(!passed);
    assert_eq!(
        fixture.transport.url(1),
        "https://replacement.github.test/user"
    );
    assert_eq!(
        fixture.transport.header(1, "Authorization"),
        Some(format!("Bearer {replacement}"))
    );
    let summary = fixture.service.get(ConnectorId::Github).await.unwrap();
    assert_eq!(summary.last_test.unwrap().status, "failed");
    let summary = fixture
        .service
        .configure(
            ConnectorId::Github,
            ConfigurePatch {
                credential: Some(CredentialAction::Clear),
                ..ConfigurePatch::default()
            },
        )
        .await
        .unwrap();
    assert!(summary.last_test.is_none());
    assert!(!summary.credential.present);
}

#[tokio::test]
async fn failed_secret_replacement_retires_proof_without_applying_new_settings() {
    let fixture = fixture_with(FakeTransport::new().json(200, r#"{"login":"octocat"}"#)).await;
    fixture.configure_github().await;
    fixture.service.test(ConnectorId::Github).await.unwrap();
    *fixture.backend.fail_with.lock().unwrap() = Some(SecretError::Unavailable);
    let result = fixture
        .service
        .configure(
            ConnectorId::Github,
            ConfigurePatch {
                enabled: Some(false),
                base_url: Some(Some("https://replacement.github.test/".to_owned())),
                credential: Some(CredentialAction::Set(crate::secrets::Secret::new(
                    "replacement".to_owned(),
                ))),
                ..ConfigurePatch::default()
            },
        )
        .await;
    assert!(result.is_err());
    let summary = fixture.service.get(ConnectorId::Github).await.unwrap();
    assert!(summary.last_test.is_none());
    assert!(summary.enabled);
    assert_eq!(summary.base_url.as_deref(), Some(BASE_URL));
    assert!(!summary.credential.store_available);
}

struct DeferredVerification {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl pam_connectors::HttpTransport for DeferredVerification {
    fn send<'a>(
        &'a self,
        _request: pam_connectors::HttpRequest,
        _deadline: Instant,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<pam_connectors::HttpResponse, pam_connectors::TransportError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(pam_connectors::HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: br#"{"login":"old-identity"}"#.to_vec(),
            })
        })
    }
}

#[tokio::test]
async fn configuration_waits_for_the_old_test_then_retires_its_verdict() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let backend = Arc::new(FakeSecretBackend::default());
    let transport = Arc::new(DeferredVerification {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let service = ConnectorService::new(
        store,
        Arc::new(SecretStore::new(backend)),
        transport.clone(),
        crate::managed_policy_service::PolicyHandle::none(),
    );
    service
        .configure(
            ConnectorId::Github,
            ConfigurePatch {
                base_url: Some(Some(BASE_URL.to_owned())),
                credential: Some(CredentialAction::Set(crate::secrets::Secret::new(
                    TOKEN.to_owned(),
                ))),
                ..ConfigurePatch::default()
            },
        )
        .await
        .unwrap();
    let test = service.test(ConnectorId::Github);
    tokio::pin!(test);
    tokio::select! {
        () = transport.entered.notified() => {},
        result = &mut test => panic!("test completed before release: {result:?}"),
    }
    tokio::time::timeout(
        Duration::from_secs(1),
        service.configure(
            ConnectorId::Jenkins,
            ConfigurePatch {
                enabled: Some(false),
                ..ConfigurePatch::default()
            },
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let configure = service.configure(
        ConnectorId::Github,
        ConfigurePatch {
            credential: Some(CredentialAction::Set(crate::secrets::Secret::new(
                "new-identity".to_owned(),
            ))),
            ..ConfigurePatch::default()
        },
    );
    tokio::pin!(configure);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut configure)
            .await
            .is_err()
    );
    transport.release.notify_one();
    let (tested, configured) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(test, configure)
    })
    .await
    .unwrap();
    assert!(tested.unwrap().0);
    assert!(configured.unwrap().last_test.is_none());
    assert!(
        service
            .get(ConnectorId::Github)
            .await
            .unwrap()
            .last_test
            .is_none()
    );
}

/// An install upgraded from a release that shipped the AWS adapter still has
/// an `aws` connector row. Listing must ignore it (it is not a connector any
/// more), leave it and any keychain item untouched, and never panic.
#[tokio::test]
async fn a_legacy_aws_row_is_ignored_by_the_connector_host() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    store
        .upsert_connector(
            "aws",
            pam_store::ConnectorPatch {
                enabled: Some(true),
                username: Some(Some("default")),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let service = ConnectorService::from_parts(
        Arc::clone(&store),
        None,
        None,
        crate::managed_policy_service::PolicyHandle::none(),
    );

    let summaries = service.list().await.expect("list survives a legacy row");
    assert_eq!(summaries.len(), ConnectorId::ALL.len());
    assert!(summaries.iter().all(|entry| entry.id != "aws"));
    assert!(ConnectorId::parse("aws").is_none());
    // The row is left alone: removal never deletes user data.
    assert!(store.get_connector("aws").await.unwrap().is_some());
}

/// A scope policy saved before the removal can still approve `aws` for a
/// repository. That must not lock out the repository's other approvals.
#[tokio::test]
async fn a_legacy_aws_scope_approval_is_dropped_without_voiding_the_policy() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let repo = tempfile::tempdir().unwrap();
    approve_connector_repo(&store, repo.path()).await;
    let root = repo.path().canonicalize().unwrap();
    store
        .set_setting(
            "flows.scope_policy",
            &serde_json::json!({
                "version": 1, "repositories": [{"root": root, "connectors": [
                    {"connector":"github", "base_url":BASE_URL, "access":"connector_wide", "targets":[]},
                    {"connector":"aws", "base_url":"https://aws.invalid/", "access":"connector_wide", "targets":[]}
                ]}]
            })
            .to_string(),
        )
        .await
        .unwrap();
    let policy = crate::scope_policy::ScopePolicy::load_effective(
        &store,
        &crate::managed_policy::PolicyView::unmanaged(),
    )
    .await
    .expect("a policy naming the removed connector still loads");
    assert_eq!(policy.repositories[0].connectors.len(), 1);
    assert_eq!(
        policy.repositories[0].connectors[0].connector,
        ConnectorId::Github
    );
    policy
        .authorize_connector(
            repo.path(),
            ConnectorId::Github,
            BASE_URL,
            "runs",
            &BTreeMap::new(),
        )
        .expect("the surviving approval still grants");
    // A truly malformed connector name is still invalid, not silently dropped.
    store
        .set_setting(
            "flows.scope_policy",
            &serde_json::json!({
                "version": 1, "repositories": [{"root": root, "connectors": [
                    {"connector":"gitlab", "base_url":BASE_URL, "access":"connector_wide", "targets":[]}
                ]}]
            })
            .to_string(),
        )
        .await
        .unwrap();
    assert_eq!(
        crate::scope_policy::ScopePolicy::load_effective(
            &store,
            &crate::managed_policy::PolicyView::unmanaged(),
        )
        .await
        .unwrap_err()
        .cause(),
        crate::scope_policy::CAUSE_SCOPE_INVALID
    );
}

/// The one redirect hop of a job log goes to a signed storage URL, not wherever a
/// hostile response points.
#[test]
fn a_log_redirect_may_not_target_the_machines_own_network() {
    use crate::connector_service::redirect_target_refusal;
    let url = |raw: &str| pam_connectors::Url::parse(raw).unwrap();
    for refused in [
        "https://10.0.0.5:8443/secret",
        "https://10.0.0.5/secret",
        "https://169.254.169.254/latest/meta-data",
        "https://127.0.0.1/x",
        "https://[::1]/x",
        "https://localhost/x",
        "https://intranet-box/x",
        "https://files.corp.local/x",
        "https://storage.example:8443/log",
        "https://2130706433/x",
    ] {
        assert!(
            redirect_target_refusal(&url(refused)).is_some(),
            "{refused} was allowed"
        );
    }
    for allowed in [
        "https://pipelines.actions.githubusercontent.com/log?sig=abc",
        "https://productionresultssa1.blob.core.windows.net/log",
        "https://storage.example/log?signature=test",
        "https://storage.example:443/log",
    ] {
        assert_eq!(redirect_target_refusal(&url(allowed)), None, "{allowed}");
    }
}

/// The proxy password the fake proxy is given and must never echo.
const PROXY_PASSWORD: &str = "pr0xy-s3cret-\"quoted\"";
const PROXY_USER: &str = "svc-pam";

/// A real connector service over the trusted curl, routed through a fake
/// proxy that refuses [`PROXY_PASSWORD`]; `None` when there is no curl.
async fn service_behind_a_refusing_proxy(
    store: &Arc<Store>,
    origin: std::net::SocketAddr,
) -> Option<(ConnectorService, pam_net::testing::FakeProxy)> {
    use pam_connectors::{CurlTransport, NetSettings};
    use pam_net::testing::{FakeProxy, ProxyMode};
    use pam_net::{Proxy, ProxyAuth, ProxyPassword};
    let proxy = FakeProxy::start(
        ProxyMode::RequireAuth {
            username: PROXY_USER.to_owned(),
            password: "a different password".to_owned(),
            offer: vec!["Basic realm=\"corp\"".to_owned()],
        },
        origin,
    )
    .await;
    let settings = NetSettings::new(
        Some(Proxy::parse(&proxy.url(), ProxyAuth::Basic, Some(PROXY_USER)).unwrap()),
        Some(ProxyPassword::new(PROXY_PASSWORD).unwrap()),
        Vec::new(),
        None,
    )
    .unwrap();
    let transport = match CurlTransport::trusted(Arc::new(Arc::new(settings))) {
        Ok(transport) => transport,
        Err(error) => {
            eprintln!("no trusted operating-system curl ({error}); skipping");
            return None;
        }
    };
    let backend = Arc::new(FakeSecretBackend::default());
    let service = ConnectorService::new(
        Arc::clone(store),
        Arc::new(SecretStore::new(backend as Arc<_>)),
        Arc::new(transport),
        crate::managed_policy_service::PolicyHandle::none(),
    );
    service
        .configure(
            ConnectorId::Github,
            ConfigurePatch {
                enabled: Some(true),
                base_url: Some(Some(BASE_URL.to_owned())),
                credential: Some(CredentialAction::Set(crate::secrets::Secret::new(
                    TOKEN.to_owned(),
                ))),
                ..ConfigurePatch::default()
            },
        )
        .await
        .expect("configure");
    Some((service, proxy))
}

/// A connector test through a proxy that refuses the stored proxy
/// password: the verdict row, the refusal and the log name the proxy and
/// the cause, and never the password, in any encoding.
#[tokio::test]
async fn a_proxy_password_never_reaches_a_verdict_row_a_refusal_or_a_log_line() {
    use pam_net::testing::{Origin, OriginMode, base64};

    let (log, _logging) = crate::test_log::Captured::start();
    let origin = Origin::start(OriginMode::Json).await;
    let store = Arc::new(Store::open_in_memory().await.expect("store opens"));
    let repo = tempfile::tempdir().expect("repo");
    approve_connector_repo(&store, repo.path()).await;
    let Some((service, proxy)) = service_behind_a_refusing_proxy(&store, origin.address()).await
    else {
        return;
    };

    let (passed, detail) = service.test(ConnectorId::Github).await.expect("a verdict");
    assert!(!passed);
    assert!(
        detail.contains(&proxy.address().to_string()),
        "the proxy is named: {detail}"
    );
    assert!(
        detail.contains("refused the stored user name and password"),
        "{detail}"
    );
    assert_eq!(
        proxy.request_lines(),
        vec!["CONNECT api.github.test:443 HTTP/1.1".to_owned()],
        "the connector's host reached the proxy as a tunnel request"
    );

    let error = service
        .invoke(
            repo.path(),
            ConnectorId::Github,
            "runs",
            &BTreeMap::from([("repo".to_owned(), ArgValue::Text("octo/repo".to_owned()))]),
            deadline(),
        )
        .await
        .expect_err("the proxy refuses the call too");
    assert_eq!(error.cause(), "connector_network");

    let row = store
        .get_connector("github")
        .await
        .unwrap()
        .expect("the row");
    let encoded = base64(format!("{PROXY_USER}:{PROXY_PASSWORD}").as_bytes());
    for rendering in [
        detail,
        row.last_test_detail.clone().unwrap_or_default(),
        error.detail(),
        error.recovery(ConnectorId::Github),
        format!("{error:?}"),
        format!("{service:?}"),
        log.text(),
    ] {
        assert!(!rendering.contains(PROXY_PASSWORD), "{rendering}");
        assert!(!rendering.contains(&encoded), "{rendering}");
        assert!(!rendering.contains("s3cret"), "{rendering}");
        assert!(!rendering.contains(TOKEN), "{rendering}");
    }
    assert!(
        origin.requests().is_empty(),
        "nothing passed the proxy: {:?}",
        origin.requests()
    );
}

// ---------------------------------------------------------------------------
// The managed policy: connectors.allowed_base_hosts and connectors.disabled.
// ---------------------------------------------------------------------------

/// A policy that allows only `github.test` as a base host and disables
/// Jenkins.
const MANAGED: &str = r#"{
    "version": 1,
    "revision": "rev-7",
    "contact": "it@example.test",
    "connectors": { "allowed_base_hosts": ["github.test"], "disabled": ["jenkins"] }
}"#;

/// A fixture whose service reads `policy` (a trusted, scripted file), after
/// the human has saved GitHub and Jenkins as `before` the policy says.
async fn managed_fixture(policy: &str, transport: FakeTransport) -> Fixture {
    let mut fixture = fixture_with(transport).await;
    fixture.configure_github().await;
    fixture
        .service
        .configure(
            ConnectorId::Jenkins,
            ConfigurePatch {
                enabled: Some(true),
                base_url: Some(Some("https://ci.example.test/".to_owned())),
                username: Some(Some("builder".to_owned())),
                credential: Some(CredentialAction::Set(crate::secrets::Secret::new(
                    TOKEN.to_owned(),
                ))),
            },
        )
        .await
        .expect("saved before the policy");
    let handle = crate::managed_policy_service::PolicyHandle::load(
        Arc::clone(&fixture.store),
        Arc::new(crate::daemon_test::ScriptedPolicy::new(Some(policy))),
        std::path::Path::new("pam-tests-have-no-base"),
    )
    .await;
    assert!(
        matches!(handle.status().state.as_str(), "active" | "degraded"),
        "{:?}",
        handle.status()
    );
    fixture.service = ConnectorService::new(
        Arc::clone(&fixture.store),
        Arc::new(SecretStore::new(Arc::clone(&fixture.backend) as Arc<_>)),
        Arc::clone(&fixture.transport) as Arc<_>,
        handle,
    );
    fixture
}

fn runs_args() -> BTreeMap<String, ArgValue> {
    BTreeMap::from([("repo".to_owned(), ArgValue::Text("octo/repo".to_owned()))])
}

#[tokio::test]
async fn a_connector_the_policy_disables_refuses_a_call_a_test_and_a_save() {
    let fixture = managed_fixture(MANAGED, FakeTransport::new()).await;
    let repo = fixture.repo.path();

    let error = fixture
        .service
        .invoke(
            repo,
            ConnectorId::Jenkins,
            "jobs",
            &BTreeMap::new(),
            deadline(),
        )
        .await
        .expect_err("a disabled connector is not called");
    assert_eq!(error.cause(), CAUSE_CONNECTOR_DISABLED);
    assert_eq!(
        error.recovery(ConnectorId::Jenkins),
        crate::managed_policy::RECOVERY_MANAGED
    );
    // An agent reads this text through a flow refusal: nothing names the key or the contact.
    let detail = error.detail();
    assert!(!detail.contains("connectors."), "{detail}");
    assert!(!detail.contains("it@example.test"), "{detail}");

    let error = fixture
        .service
        .test(ConnectorId::Jenkins)
        .await
        .expect_err("a test would send the credential");
    assert_eq!(error.cause(), CAUSE_CONNECTOR_DISABLED);

    let (refusal, view) = fixture
        .service
        .check_configure(
            ConnectorId::Jenkins,
            &ConfigurePatch {
                enabled: Some(true),
                ..ConfigurePatch::default()
            },
        )
        .expect_err("enabling it is refused");
    assert_eq!(refusal.cause, crate::managed_policy::CAUSE_SETTING_LOCKED);
    assert!(
        refusal.detail.contains("connectors.disabled"),
        "{}",
        refusal.detail
    );
    assert!(
        refusal.detail.contains("it@example.test"),
        "{}",
        refusal.detail
    );
    assert!(refusal.detail.contains("rev rev-7"), "{}", refusal.detail);
    assert_eq!(refusal.recovery, crate::managed_policy::RECOVERY_MANAGED);
    assert_eq!(view.digest12(), fixture.service.policy().view().digest12());

    // The service enforces it too, for any caller, and writes nothing.
    let before = fixture.store.get_connector("jenkins").await.unwrap();
    let error = fixture
        .service
        .configure(
            ConnectorId::Jenkins,
            ConfigurePatch {
                credential: Some(CredentialAction::Set(crate::secrets::Secret::new(
                    "another".to_owned(),
                ))),
                ..ConfigurePatch::default()
            },
        )
        .await
        .expect_err("a save is refused");
    assert_eq!(error.cause(), crate::managed_policy::CAUSE_SETTING_LOCKED);
    assert_eq!(
        fixture.store.get_connector("jenkins").await.unwrap(),
        before
    );
    assert_eq!(
        fixture
            .backend
            .get(&account_for("jenkins"))
            .unwrap()
            .as_deref(),
        Some(TOKEN),
        "the credential was not replaced"
    );
    assert!(fixture.transport.requests().is_empty());

    // Switching it off, or clearing what is saved, only ever tightens.
    fixture
        .service
        .configure(
            ConnectorId::Jenkins,
            ConfigurePatch {
                enabled: Some(false),
                credential: Some(CredentialAction::Clear),
                ..ConfigurePatch::default()
            },
        )
        .await
        .expect("less configured is allowed");
}

#[tokio::test]
async fn the_summary_says_what_the_policy_did_and_the_row_is_untouched() {
    let fixture = managed_fixture(MANAGED, FakeTransport::new()).await;
    let summaries = fixture.service.list().await.unwrap();

    let jenkins = Fixture::summary_of(&summaries, ConnectorId::Jenkins);
    assert!(!jenkins.enabled, "a flow step may not call it");
    assert_eq!(jenkins.effective["enabled"]["source"], "policy");
    assert_eq!(jenkins.effective["enabled"]["locked"], true);
    assert_eq!(jenkins.effective["enabled"]["state"], "applied");
    assert!(
        fixture
            .store
            .get_connector("jenkins")
            .await
            .unwrap()
            .unwrap()
            .enabled,
        "the human's row keeps what they saved"
    );
    // Jenkins's saved host is outside the allowlist too.
    assert_eq!(jenkins.effective["base_url"]["source"], "policy");
    assert_eq!(
        jenkins.effective["base_url"]["constraint"],
        serde_json::json!({ "allow": ["github.test"] })
    );

    let github = Fixture::summary_of(&summaries, ConnectorId::Github);
    assert!(github.enabled);
    assert_eq!(github.effective["enabled"]["source"], "user");
    assert_eq!(github.effective["enabled"]["locked"], false);
    assert_eq!(github.effective["base_url"]["source"], "user");
    assert_eq!(github.effective["base_url"]["locked"], false);

    // An untouched service: exactly `{ source, locked }`.
    let plain = fixture_without_policy_summary().await;
    assert_eq!(
        plain.effective["enabled"],
        serde_json::json!({ "source": "user", "locked": false })
    );
}

async fn fixture_without_policy_summary() -> ConnectorSummary {
    let fixture = fixture().await;
    fixture.configure_github().await;
    fixture.service.get(ConnectorId::Github).await.unwrap()
}

#[tokio::test]
async fn a_base_url_outside_the_allowed_hosts_cannot_be_saved_or_used() {
    let fixture = managed_fixture(MANAGED, FakeTransport::new()).await;
    let repo = fixture.repo.path();

    // Saving: refused with the policy cause, before the credential store is touched.
    let outside = ConfigurePatch {
        base_url: Some(Some("https://evil.example.org/".to_owned())),
        ..ConfigurePatch::default()
    };
    let (refusal, _) = fixture
        .service
        .check_configure(ConnectorId::Github, &outside)
        .expect_err("the host is not allowed");
    assert_eq!(
        refusal.cause,
        crate::managed_policy::CAUSE_POLICY_NOT_ALLOWED
    );
    assert!(
        refusal.detail.contains("evil.example.org"),
        "{}",
        refusal.detail
    );
    let before = fixture.store.get_connector("github").await.unwrap();
    let error = fixture
        .service
        .configure(ConnectorId::Github, outside)
        .await
        .expect_err("saving is refused");
    assert_eq!(
        error.cause(),
        crate::managed_policy::CAUSE_POLICY_NOT_ALLOWED
    );
    assert_eq!(fixture.store.get_connector("github").await.unwrap(), before);

    // A subdomain of an allowed host is inside the rule, and an invalid
    // address is the save's own bad_url, not a policy refusal.
    fixture
        .service
        .check_configure(
            ConnectorId::Github,
            &ConfigurePatch {
                base_url: Some(Some("https://api.github.test/".to_owned())),
                ..ConfigurePatch::default()
            },
        )
        .expect("inside the allowlist");
    fixture
        .service
        .check_configure(
            ConnectorId::Github,
            &ConfigurePatch {
                base_url: Some(Some("not a url".to_owned())),
                ..ConfigurePatch::default()
            },
        )
        .expect("the save reports a bad url itself");

    // Using: a row saved before the policy existed is not called either.
    fixture
        .store
        .upsert_connector(
            "github",
            pam_store::ConnectorPatch {
                base_url: Some(Some("https://evil.example.org/")),
                ..pam_store::ConnectorPatch::default()
            },
        )
        .await
        .unwrap();
    let error = fixture
        .service
        .invoke(repo, ConnectorId::Github, "runs", &runs_args(), deadline())
        .await
        .expect_err("outside the allowlist");
    assert_eq!(
        error.cause(),
        crate::managed_policy::CAUSE_POLICY_NOT_ALLOWED
    );
    assert_eq!(
        error.recovery(ConnectorId::Github),
        crate::managed_policy::RECOVERY_MANAGED
    );
    let error = fixture
        .service
        .test(ConnectorId::Github)
        .await
        .expect_err("the credential does not go there");
    assert_eq!(
        error.cause(),
        crate::managed_policy::CAUSE_POLICY_NOT_ALLOWED
    );
    assert!(fixture.transport.requests().is_empty(), "nothing was sent");
}

#[tokio::test]
async fn a_connector_inside_the_policy_still_works_and_removing_it_restores_everything() {
    let fixture = managed_fixture(
        MANAGED,
        FakeTransport::new().json(200, r#"{"workflow_runs":[]}"#),
    )
    .await;
    let repo = fixture.repo.path();
    fixture
        .service
        .invoke(repo, ConnectorId::Github, "runs", &runs_args(), deadline())
        .await
        .expect("github.test is allowed");

    // The policy goes away: Jenkins reads as the human saved it.
    let plain = ConnectorService::new(
        Arc::clone(&fixture.store),
        Arc::new(SecretStore::new(Arc::clone(&fixture.backend) as Arc<_>)),
        Arc::clone(&fixture.transport) as Arc<_>,
        crate::managed_policy_service::PolicyHandle::none(),
    );
    let jenkins = plain.get(ConnectorId::Jenkins).await.unwrap();
    assert!(jenkins.enabled);
    assert_eq!(
        jenkins.base_url.as_deref(),
        Some("https://ci.example.test/")
    );
}

#[tokio::test]
async fn a_policy_that_cannot_be_read_pauses_the_save_and_never_the_call() {
    // `connectors.disabled` of the wrong type: the leaf is rejected, and with
    // no last-known-good copy a Tier A key is held.
    let bad = r#"{ "version": 1, "connectors": { "disabled": "jenkins" } }"#;
    let fixture = managed_fixture(
        bad,
        FakeTransport::new().json(200, r#"{"workflow_runs":[]}"#),
    )
    .await;
    let repo = fixture.repo.path();
    let (refusal, _) = fixture
        .service
        .check_configure(
            ConnectorId::Github,
            &ConfigurePatch {
                enabled: Some(true),
                ..ConfigurePatch::default()
            },
        )
        .expect_err("held key");
    assert_eq!(refusal.cause, crate::managed_policy::CAUSE_POLICY_FROZEN);

    fixture
        .service
        .invoke(repo, ConnectorId::Github, "runs", &runs_args(), deadline())
        .await
        .expect("a held policy never stops a call");
}
