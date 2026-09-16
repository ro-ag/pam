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
            {"connector":"jenkins", "base_url":"https://ci.example.test/", "access":"connector_wide", "targets":[]},
            {"connector":"aws", "base_url":"https://aws.invalid/", "access":"connector_wide", "targets":[]}
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

    // AWS keeps no credential at all, so the keychain is never asked.
    let aws = Fixture::summary_of(&summaries, ConnectorId::Aws);
    assert_eq!(aws.auth, "aws_profile");
    assert!(!aws.needs_base_url);
    assert!(!aws.credential.present);
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
    let service = ConnectorService::from_parts(Arc::clone(&store), None, Some(transport.clone()));
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
async fn a_daemon_without_curl_refuses_http_and_uncontained_aws() {
    let store = Arc::new(Store::open_in_memory().await.expect("store opens"));
    let repo = tempfile::tempdir().expect("repo");
    approve_connector_repo(&store, repo.path()).await;
    let backend = Arc::new(FakeSecretBackend::default());
    let service = ConnectorService::from_parts(
        Arc::clone(&store),
        Some(Arc::new(SecretStore::new(Arc::clone(&backend) as Arc<_>))),
        None,
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

    // AWS's separate CLI bridge is refused until its descendants are contained,
    // including the local allowlist call so discovery never implies readiness.
    service
        .configure(
            ConnectorId::Aws,
            ConfigurePatch {
                enabled: Some(true),
                ..ConfigurePatch::default()
            },
        )
        .await
        .expect("aws needs no base URL and no credential");
    let error = service
        .invoke(
            repo.path(),
            ConnectorId::Aws,
            "commands",
            &BTreeMap::new(),
            deadline(),
        )
        .await
        .expect_err("AWS CLI containment is unavailable");
    assert_eq!(error.cause(), "command_containment_unavailable");
}

#[tokio::test]
async fn a_daemon_without_a_credential_store_still_lists() {
    let store = Arc::new(Store::open_in_memory().await.expect("store opens"));
    let service = ConnectorService::from_parts(Arc::clone(&store), None, None);

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
            ConnectorId::Aws,
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

#[derive(Default)]
struct UntouchedSecrets(std::sync::atomic::AtomicUsize);

impl SecretBackend for UntouchedSecrets {
    fn get(&self, _account: &str) -> Result<Option<String>, SecretError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(SecretError::Unavailable)
    }
    fn set(&self, _account: &str, _secret: &str) -> Result<(), SecretError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(SecretError::Unavailable)
    }
    fn delete(&self, _account: &str) -> Result<bool, SecretError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(SecretError::Unavailable)
    }
}

#[tokio::test]
async fn aws_containment_refusal_precedes_credentials_transport_and_cli_validation() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let repo = tempfile::tempdir().unwrap();
    approve_connector_repo(&store, repo.path()).await;
    // Defense in depth for the fixture: even if the containment guard regresses,
    // this invalid profile fails adapter validation before any real CLI spawn.
    store
        .upsert_connector(
            "aws",
            pam_store::ConnectorPatch {
                enabled: Some(true),
                username: Some(Some("--fixture-no-process")),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let secrets = Arc::new(UntouchedSecrets::default());
    let transport = Arc::new(FakeTransport::new());
    let service = ConnectorService::new(
        store,
        Arc::new(SecretStore::new(secrets.clone())),
        transport.clone(),
    );
    let args = BTreeMap::from([
        ("service".to_owned(), ArgValue::Text("sts".to_owned())),
        (
            "command".to_owned(),
            ArgValue::Text("get-caller-identity".to_owned()),
        ),
    ]);
    for call in ["commands", "cli"] {
        let error = service
            .invoke(repo.path(), ConnectorId::Aws, call, &args, deadline())
            .await
            .unwrap_err();
        assert_eq!(error.cause(), "command_containment_unavailable");
    }
    let error = service.test(ConnectorId::Aws).await.unwrap_err();
    assert_eq!(error.cause(), "command_containment_unavailable");
    assert_eq!(secrets.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(transport.requests().is_empty());
}
