use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use pam_connectors::testing::FakeTransport;
use pam_net::NetFailure;
use pam_net::testing::{FakeProxy, Origin, OriginMode, ProxyMode, TlsCert, TlsOrigin, base64};
use pam_proto::{Caller, Envelope, Outcome, PROTOCOL_VERSION, Response};
use pam_store::{ConnectorPatch, RequestState, Store};
use serde_json::{Value, json};

use crate::admin::{ACTION_ADMIN, ADMIN_CALLER_AGENT, AdminService, CAUSE_INVALID_ADMIN_ARGS};
use crate::admin_network::{
    ACTION_NETWORK_CONFIGURE, CAUSE_CA_IMPORT_REFUSED, CAUSE_NETWORK_INVALID, CAUSE_SETTING_LOCKED,
    NETWORK_ADMIN_OPS, OP_NETWORK_GET, OP_NETWORK_SET, OP_NETWORK_TEST,
};
use crate::approval::ApprovalService;
use crate::connector_service::ConnectorService;
use crate::daemon::TERMINAL_ACTIONS;
use crate::log_service::LogService;
use crate::model_service::ModelService;
use crate::network_service::{
    FixedManagedNetwork, ManagedNetwork, NetworkService, PROXY_CREDENTIAL_ID, ProxyEntry,
    SETTING_KEY,
};
use crate::secrets::{FakeSecretBackend, SecretBackend, SecretStore, account_for};
use crate::test_log::Captured;
use crate::transport::EventPublisher;

/// The proxy password the human types. No reply, audit row, request row or
/// log line may contain it, in any encoding.
const PROXY_PASSWORD: &str = "pr0xy-s3cret-\"quoted\"";
const PROXY_USER: &str = "svc-pam";
const PROXY_URL: &str = "http://proxy.corp.example:3128";

const LONG_TIMEOUT: Duration = Duration::from_mins(10);

struct Fixture {
    store: Arc<Store>,
    admin: AdminService,
    backend: Arc<FakeSecretBackend>,
    network: Arc<NetworkService>,
    models: Arc<ModelService>,
    base: tempfile::TempDir,
    next: AtomicU32,
}

async fn fixture() -> Fixture {
    fixture_with(None).await
}

/// An admin service wired the way the daemon wires it: one network
/// service for the ops, the model downloads and (here) the probes, over a
/// fake keychain and a temp base.
async fn fixture_with(managed: Option<ManagedNetwork>) -> Fixture {
    let store = Arc::new(Store::open_in_memory().await.expect("store opens"));
    let (events, _rx) = EventPublisher::for_tests();
    let approvals = Arc::new(ApprovalService::new(
        Arc::clone(&store),
        events,
        LONG_TIMEOUT,
    ));
    let base = tempfile::tempdir().expect("tempdir");
    let models = ModelService::new(Arc::clone(&store))
        .await
        .expect("model service");
    models.set_engine_base(base.path().to_path_buf());
    let logs = LogService::new(Arc::clone(&store), Arc::clone(&models));
    let backend = Arc::new(FakeSecretBackend::default());
    let secrets = Arc::new(SecretStore::new(Arc::clone(&backend) as Arc<_>));
    let network = Arc::new(
        NetworkService::new(
            Arc::clone(&store),
            Some(Arc::clone(&secrets)),
            base.path().to_path_buf(),
        )
        .with_managed(Arc::new(FixedManagedNetwork::new(managed))),
    );
    network.allow_plain_http_probes_for_tests();
    models.set_network_service(Arc::clone(&network));
    let connectors = Arc::new(ConnectorService::new(
        Arc::clone(&store),
        secrets,
        Arc::new(FakeTransport::new()),
    ));
    let flows = crate::flow_service_test::flows_for_tests(
        std::path::Path::new("pam-tests-have-no-flow-library"),
        &store,
        &approvals,
        &connectors,
        &logs,
    )
    .await;
    let admin = AdminService::new(
        Arc::clone(&store),
        approvals,
        Arc::clone(&models),
        logs,
        connectors,
        flows,
        crate::flow_service_test::closed_submit(),
    )
    .with_network(Arc::clone(&network));
    Fixture {
        store,
        admin,
        backend,
        network,
        models,
        base,
        next: AtomicU32::new(0),
    }
}

impl Fixture {
    async fn run(&self, op: &str, args: Value) -> (String, Response) {
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        let id = format!("req_net_{index:03}");
        let envelope = Envelope {
            v: PROTOCOL_VERSION,
            id: id.clone(),
            capability: op.to_owned(),
            client_version: env!("CARGO_PKG_VERSION").to_owned(),
            caller: Caller {
                agent: ADMIN_CALLER_AGENT.to_owned(),
                repo: "/repo/anywhere".to_owned(),
                pid: 4242,
            },
            args,
            idempotency_key: None,
            deadline_ms: 30_000,
            wait: true,
        };
        let response = self.admin.handle(&envelope).await;
        (id, response)
    }

    async fn get(&self) -> Value {
        let (_, response) = self.run(OP_NETWORK_GET, json!({})).await;
        body_of(response, Outcome::Verified)
    }

    async fn set(&self, patch: Value) -> (String, Value) {
        let (id, response) = self.run(OP_NETWORK_SET, patch).await;
        (id, body_of(response, Outcome::Changed))
    }

    async fn refuse(&self, op: &str, args: Value) -> (String, String, String) {
        let (_, response) = self.run(op, args).await;
        refusal_of(response)
    }

    async fn audit(&self, id: &str) -> Vec<pam_store::AuditRow> {
        self.store.audit_for_request(id).await.expect("audit query")
    }

    async fn configure_row(&self, id: &str) -> Value {
        let rows = self.audit(id).await;
        let row = rows
            .iter()
            .find(|row| row.action == ACTION_NETWORK_CONFIGURE)
            .expect("one network.configure row");
        serde_json::from_str(row.detail.as_deref().unwrap()).unwrap()
    }

    async fn terminal_actions(&self, id: &str) -> Vec<String> {
        self.audit(id)
            .await
            .into_iter()
            .filter(|row| TERMINAL_ACTIONS.contains(&row.action.as_str()))
            .map(|row| row.action)
            .collect()
    }

    /// Everything the daemon wrote for `id`, as text, for secret scans.
    async fn everything_recorded(&self, id: &str) -> String {
        let mut text = String::new();
        for row in self.audit(id).await {
            text.push_str(&row.action);
            text.push_str(row.detail.as_deref().unwrap_or_default());
            text.push('\n');
        }
        let request = self.store.get_request(id).await.unwrap().unwrap();
        text.push_str(&request.args_json);
        text.push_str(request.outcome.as_deref().unwrap_or_default());
        text.push_str(
            &self
                .store
                .get_setting(SETTING_KEY)
                .await
                .unwrap()
                .unwrap_or_default(),
        );
        text
    }

    /// Plants a connector row with any base URL, bypassing the https rule
    /// a save applies, so a loopback fixture can be a probe target.
    async fn plant_connector(&self, id: &str, base_url: &str) {
        self.store
            .upsert_connector(
                id,
                ConnectorPatch {
                    invalidate_test: false,
                    enabled: Some(true),
                    base_url: Some(Some(base_url)),
                    username: None,
                },
            )
            .await
            .expect("row");
    }

    fn ca_source(&self) -> std::path::PathBuf {
        let source = self.base.path().join("corp-ca.pem");
        std::fs::copy(pam_net::testing::test_ca(), &source).expect("copy");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        source
    }
}

fn body_of(response: Response, outcome: Outcome) -> Value {
    match response {
        Response::Result {
            outcome: got, body, ..
        } => {
            assert_eq!(got, outcome);
            body
        }
        other => panic!("expected a result, got {other:?}"),
    }
}

fn refusal_of(response: Response) -> (String, String, String) {
    match response {
        Response::Refusal {
            cause,
            detail,
            recovery,
            ..
        } => (cause, detail, recovery),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn proxy_patch(auth: &str) -> Value {
    json!({ "url": PROXY_URL, "auth": auth, "username": PROXY_USER })
}

fn assert_no_secret(text: &str) {
    let encoded = base64(format!("{PROXY_USER}:{PROXY_PASSWORD}").as_bytes());
    assert!(!text.contains(PROXY_PASSWORD), "{text}");
    assert!(!text.contains(&encoded), "{text}");
    assert!(!text.contains("s3cret"), "{text}");
}

#[test]
fn the_three_ops_are_the_whole_surface() {
    assert_eq!(
        NETWORK_ADMIN_OPS,
        [OP_NETWORK_GET, OP_NETWORK_SET, OP_NETWORK_TEST]
    );
}

#[tokio::test]
async fn get_answers_the_defaults_in_the_shape_the_screen_reads() {
    let fixture = fixture().await;
    let (id, response) = fixture.run(OP_NETWORK_GET, json!({})).await;
    let body = body_of(response, Outcome::Verified);
    assert_eq!(
        body["settings"],
        json!({
            "proxy": null,
            "no_proxy": [],
            "ca_bundle": null,
            "engine_mirror": null,
            "models_mirror": null,
            "credential": { "present": false, "store_available": true },
            "mirror_allowed_hosts": null,
        })
    );
    for field in [
        "proxy",
        "credential",
        "no_proxy",
        "ca_bundle",
        "engine_mirror",
        "models_mirror",
    ] {
        assert_eq!(
            body["effective"][field],
            json!({ "source": "default", "locked": false }),
            "{field}"
        );
    }
    assert!(body["ignored_env"].is_array());
    assert!(
        body.get("document").is_none(),
        "a valid document has no notice"
    );
    if !body["curl"].is_null() {
        assert!(body["curl"]["version"].is_string());
        assert!(body["curl"]["backend"].is_string());
        assert!(body["curl"]["supports_proxy"].is_boolean());
        assert!(body["curl"]["supports_cidr_no_proxy"].is_boolean());
    }
    assert_eq!(fixture.terminal_actions(&id).await, [ACTION_ADMIN]);
    let (cause, detail, _) = fixture
        .refuse(OP_NETWORK_GET, json!({ "target": "github" }))
        .await;
    assert_eq!(cause, CAUSE_INVALID_ADMIN_ARGS);
    assert!(detail.contains("target"), "{detail}");
}

/// A save applies exactly the fields sent, the password reaches the
/// keychain and nothing else, and every reply and row names what changed
/// without the secret.
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one sequence of saves over one fixture; splitting it hides what each save left"
)]
async fn set_applies_exactly_the_fields_sent_and_the_password_reaches_only_the_keychain() {
    let (log, logging) = Captured::start();
    let fixture = fixture().await;

    let (id, body) = fixture
        .set(json!({
            "proxy": proxy_patch("basic"),
            "credential": { "set": format!("  {PROXY_PASSWORD}\n") },
            "no_proxy": ["Corp.Example", "10.0.0.0/8", "corp.example"],
        }))
        .await;
    assert_eq!(
        body["settings"]["proxy"],
        json!({ "url": PROXY_URL, "auth": "basic", "username": PROXY_USER })
    );
    assert_eq!(
        body["settings"]["no_proxy"],
        json!(["Corp.Example", "10.0.0.0/8", "corp.example"])
    );
    assert_eq!(body["settings"]["credential"]["present"], true);
    assert_eq!(body["effective"]["proxy"]["source"], "user");
    assert_eq!(body["effective"]["engine_mirror"]["source"], "default");
    assert_eq!(
        fixture
            .backend
            .get(&account_for(PROXY_CREDENTIAL_ID))
            .unwrap()
            .as_deref(),
        Some(PROXY_PASSWORD),
        "trimmed, stored once"
    );
    let configure = fixture.configure_row(&id).await;
    assert_eq!(
        configure["changed"],
        json!(["proxy", "credential", "no_proxy"])
    );
    assert_eq!(
        configure["proxy"],
        json!({ "host": "proxy.corp.example", "port": 3128, "scheme": "http", "auth": "basic", "username": PROXY_USER })
    );
    assert_eq!(configure["credential"], "set");
    assert_eq!(configure["ca_bundle"], Value::Null);
    assert_eq!(configure["engine_mirror_host"], Value::Null);
    assert_eq!(configure["locked_by_policy"], json!([]));
    assert_eq!(fixture.terminal_actions(&id).await, [ACTION_ADMIN]);
    let terminal = fixture.audit(&id).await;
    let terminal = terminal
        .iter()
        .find(|row| row.action == ACTION_ADMIN)
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(terminal.detail.as_deref().unwrap()).unwrap(),
        json!({ "op": OP_NETWORK_SET, "changed": ["proxy", "credential", "no_proxy"] })
    );

    // The profile the transport and the downloads read is the saved one,
    // password included — from the keychain, read now.
    let settings = fixture.models.network_settings().await.expect("resolved");
    assert_eq!(
        settings.proxy().unwrap().authority(),
        "proxy.corp.example:3128"
    );
    assert!(settings.sends_proxy_credential());
    assert_eq!(
        settings.no_proxy().len(),
        2,
        "deduplicated case-insensitively"
    );

    // A second patch touches only what it names.
    let (id2, body) = fixture
        .set(json!({ "engine_mirror": "https://Artifacts.corp.example/llama" }))
        .await;
    assert_eq!(
        body["settings"]["engine_mirror"],
        "https://artifacts.corp.example/llama/"
    );
    assert_eq!(body["settings"]["proxy"]["url"], PROXY_URL);
    assert_eq!(body["settings"]["credential"]["present"], true);
    let configure = fixture.configure_row(&id2).await;
    assert_eq!(configure["changed"], json!(["engine_mirror"]));
    assert_eq!(configure["credential"], "unchanged");
    assert_eq!(configure["engine_mirror_host"], "artifacts.corp.example");
    assert_eq!(configure["proxy"]["host"], "proxy.corp.example");
    let (engine, models) = fixture.models.mirrors().await.expect("mirrors");
    assert_eq!(
        engine.unwrap().as_str(),
        "https://artifacts.corp.example/llama/"
    );
    assert!(models.is_none());

    // Clears: the proxy goes, the password is cleared on request only.
    let (id3, body) = fixture.set(json!({ "proxy": null })).await;
    assert_eq!(body["settings"]["proxy"], Value::Null);
    assert_eq!(body["settings"]["credential"]["present"], true);
    assert_eq!(
        fixture.configure_row(&id3).await["changed"],
        json!(["proxy"])
    );
    let (id4, body) = fixture
        .set(json!({ "credential": { "clear": true } }))
        .await;
    assert_eq!(body["settings"]["credential"]["present"], false);
    assert_eq!(fixture.configure_row(&id4).await["credential"], "cleared");
    assert!(
        fixture
            .backend
            .get(&account_for(PROXY_CREDENTIAL_ID))
            .unwrap()
            .is_none()
    );
    let (_, body) = fixture
        .set(json!({ "engine_mirror": null, "no_proxy": [] }))
        .await;
    assert_eq!(body["settings"]["engine_mirror"], Value::Null);
    assert_eq!(body["settings"]["no_proxy"], json!([]));

    drop(logging);
    for id in [&id, &id2, &id3, &id4] {
        assert_no_secret(&fixture.everything_recorded(id).await);
    }
    assert_no_secret(&log.text());
    assert_no_secret(&format!("{:?}", fixture.admin));
    assert_no_secret(&fixture.get().await.to_string());
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one refusal table; splitting it hides what is compared"
)]
async fn malformed_patches_are_refused_before_any_effect() {
    let fixture = fixture().await;
    let before = fixture.get().await;
    for (args, cause, needle) in [
        (json!({}), CAUSE_INVALID_ADMIN_ARGS, "nothing to change"),
        (
            json!({ "insecure": true }),
            CAUSE_INVALID_ADMIN_ARGS,
            "insecure",
        ),
        (
            json!({ "proxy": { "url": PROXY_URL, "auth": "basic", "password": "x" } }),
            CAUSE_INVALID_ADMIN_ARGS,
            "password",
        ),
        (
            json!({ "proxy": "http://p:1" }),
            CAUSE_INVALID_ADMIN_ARGS,
            "proxy",
        ),
        (
            json!({ "proxy": { "url": PROXY_URL, "auth": "ntlm" } }),
            CAUSE_INVALID_ADMIN_ARGS,
            "ntlm",
        ),
        (
            json!({ "proxy": { "url": "socks5://p:1080", "auth": "none" } }),
            CAUSE_NETWORK_INVALID,
            "SOCKS",
        ),
        (
            json!({ "proxy": { "url": "proxy.corp.example:3128", "auth": "none" } }),
            CAUSE_NETWORK_INVALID,
            "did you mean http://",
        ),
        (
            json!({ "proxy": { "url": "http://svc:pw@proxy.corp.example:3128", "auth": "none" } }),
            CAUSE_NETWORK_INVALID,
            "keychain",
        ),
        (
            json!({ "credential": { "set": "" } }),
            CAUSE_INVALID_ADMIN_ARGS,
            "credential",
        ),
        (
            json!({ "credential": { "set": "a\nb" } }),
            CAUSE_INVALID_ADMIN_ARGS,
            "control",
        ),
        (
            json!({ "credential": { "clear": false } }),
            CAUSE_INVALID_ADMIN_ARGS,
            "credential",
        ),
        (
            json!({ "credential": "x" }),
            CAUSE_INVALID_ADMIN_ARGS,
            "credential",
        ),
        (
            json!({ "no_proxy": "corp.example" }),
            CAUSE_INVALID_ADMIN_ARGS,
            "no_proxy",
        ),
        (
            json!({ "no_proxy": [1] }),
            CAUSE_INVALID_ADMIN_ARGS,
            "no_proxy",
        ),
        (
            json!({ "no_proxy": ["corp.example:8080"] }),
            CAUSE_NETWORK_INVALID,
            "no_proxy",
        ),
        (
            json!({ "ca_bundle": "/etc/ca.pem" }),
            CAUSE_INVALID_ADMIN_ARGS,
            "ca_bundle",
        ),
        (
            json!({ "ca_bundle": { "path": "/etc/ca.pem", "sha256": "x" } }),
            CAUSE_INVALID_ADMIN_ARGS,
            "ca_bundle",
        ),
        (
            json!({ "engine_mirror": 7 }),
            CAUSE_INVALID_ADMIN_ARGS,
            "engine_mirror",
        ),
        (
            json!({ "engine_mirror": "http://mirror.corp.example/" }),
            CAUSE_NETWORK_INVALID,
            "https://",
        ),
        (
            json!({ "models_mirror": "https://localhost/hf/" }),
            CAUSE_NETWORK_INVALID,
            "localhost",
        ),
        (
            json!({ "models_mirror": "https://169.254.169.254/" }),
            CAUSE_NETWORK_INVALID,
            "link-local",
        ),
        // One bad field refuses the whole patch.
        (
            json!({ "no_proxy": ["corp.example"], "engine_mirror": "ftp://x/" }),
            CAUSE_NETWORK_INVALID,
            "https://",
        ),
    ] {
        let (got, detail, recovery) = fixture.refuse(OP_NETWORK_SET, args.clone()).await;
        assert_eq!(got, cause, "{args}: {detail}");
        assert!(detail.contains(needle), "{args}: {detail}");
        assert!(!recovery.is_empty());
    }
    assert_eq!(fixture.get().await, before, "nothing was applied");
    assert!(
        fixture
            .backend
            .get(&account_for(PROXY_CREDENTIAL_ID))
            .unwrap()
            .is_none()
    );
    assert!(
        fixture
            .store
            .get_setting(SETTING_KEY)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_field_the_policy_owns_refuses_the_whole_patch_and_is_reported_locked() {
    let fixture = fixture_with(Some(ManagedNetwork {
        proxy: Some(Some(ProxyEntry {
            url: "http://managed.corp.example:8080".to_owned(),
            auth: "none".to_owned(),
            username: None,
        })),
        mirror_allowed_hosts: vec!["artifacts.corp.example".to_owned()],
        ..ManagedNetwork::default()
    }))
    .await;
    let body = fixture.get().await;
    assert_eq!(
        body["settings"]["proxy"]["url"],
        "http://managed.corp.example:8080"
    );
    assert_eq!(
        body["effective"]["proxy"],
        json!({ "source": "policy", "locked": true })
    );
    assert_eq!(
        body["effective"]["credential"],
        json!({ "source": "policy", "locked": true })
    );
    assert_eq!(body["effective"]["no_proxy"]["locked"], false);
    assert_eq!(
        body["settings"]["mirror_allowed_hosts"],
        json!(["artifacts.corp.example"])
    );

    for args in [
        json!({ "proxy": proxy_patch("basic"), "no_proxy": ["corp.example"] }),
        json!({ "proxy": null }),
        json!({ "credential": { "set": "x" } }),
    ] {
        let (cause, detail, recovery) = fixture.refuse(OP_NETWORK_SET, args.clone()).await;
        assert_eq!(cause, CAUSE_SETTING_LOCKED, "{args}");
        assert!(detail.contains("proxy"), "{detail}");
        assert!(recovery.contains("administrator"), "{recovery}");
    }
    assert_eq!(
        fixture.get().await["settings"]["no_proxy"],
        json!([]),
        "whole patch refused"
    );
    assert!(
        fixture
            .backend
            .get(&account_for(PROXY_CREDENTIAL_ID))
            .unwrap()
            .is_none()
    );

    // Unlocked fields still save, and a mirror outside the allowlist is
    // refused by the policy's rule.
    let (_, body) = fixture
        .set(json!({ "no_proxy": ["corp.example"], "engine_mirror": "https://artifacts.corp.example/llama/" }))
        .await;
    assert_eq!(body["settings"]["no_proxy"], json!(["corp.example"]));
    assert_eq!(
        body["settings"]["proxy"]["url"],
        "http://managed.corp.example:8080"
    );
    let (cause, detail, _) = fixture
        .refuse(
            OP_NETWORK_SET,
            json!({ "models_mirror": "https://elsewhere.example/" }),
        )
        .await;
    assert_eq!(cause, CAUSE_NETWORK_INVALID);
    assert!(detail.contains("allowed list"), "{detail}");

    // The user's own proxy is kept under the policy and returns when the
    // policy goes.
    fixture
        .store
        .set_setting(
            SETTING_KEY,
            &json!({ "version": 1, "proxy": proxy_patch("none"), "no_proxy": ["corp.example"] })
                .to_string(),
        )
        .await
        .unwrap();
    fixture.network.invalidate();
    assert_eq!(
        fixture.get().await["settings"]["proxy"]["url"],
        "http://managed.corp.example:8080"
    );
    let settings = fixture.network.resolve_settings().await.unwrap();
    assert_eq!(settings.proxy().unwrap().host(), "managed.corp.example");
}

#[tokio::test]
async fn a_ca_bundle_is_imported_as_a_private_copy_and_removed_with_it() {
    let fixture = fixture().await;
    let source = fixture.ca_source();

    let (id, body) = fixture
        .set(json!({ "ca_bundle": { "path": source.to_str().unwrap() } }))
        .await;
    let bundle = &body["settings"]["ca_bundle"];
    let sha256 = bundle["sha256"].as_str().unwrap().to_owned();
    assert_eq!(sha256.len(), 64);
    assert_eq!(bundle["certificates"], 1);
    assert_eq!(bundle["source_path"], source.to_str().unwrap());
    assert!(bundle["imported_ts"].as_i64().unwrap() > 0);
    assert_eq!(bundle["source_changed"], false);
    let copy = fixture.network.copy_path(&sha256);
    assert!(copy.exists());
    let configure = fixture.configure_row(&id).await;
    assert_eq!(configure["changed"], json!(["ca_bundle"]));
    assert_eq!(configure["ca_bundle"]["sha256"], sha256);
    assert_eq!(configure["ca_bundle"]["certificates"], 1);
    let settings = fixture.network.resolve_settings().await.unwrap();
    assert_eq!(settings.ca_bundle(), Some(copy.as_path()));

    // The source changing afterwards is reported, not acted on.
    std::fs::write(
        &source,
        std::fs::read(pam_net::testing::unrelated_ca()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        fixture.get().await["settings"]["ca_bundle"]["source_changed"],
        true
    );
    assert_eq!(
        fixture
            .network
            .resolve_settings()
            .await
            .unwrap()
            .ca_bundle(),
        Some(copy.as_path())
    );

    // Importing another bundle replaces the record and prunes the old copy.
    let (_, body) = fixture
        .set(json!({ "ca_bundle": { "path": source.to_str().unwrap() } }))
        .await;
    let replaced = body["settings"]["ca_bundle"]["sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(replaced, sha256);
    assert!(!copy.exists(), "the unreferenced copy is gone");
    assert!(fixture.network.copy_path(&replaced).exists());

    // Removal deletes the private copy; the default trust is back.
    let (id2, body) = fixture.set(json!({ "ca_bundle": null })).await;
    assert_eq!(body["settings"]["ca_bundle"], Value::Null);
    assert!(!fixture.network.copy_path(&replaced).exists());
    assert_eq!(fixture.configure_row(&id2).await["ca_bundle"], Value::Null);
    assert!(
        fixture
            .network
            .resolve_settings()
            .await
            .unwrap()
            .ca_bundle()
            .is_none()
    );
}

#[tokio::test]
async fn a_ca_bundle_that_cannot_be_trusted_is_refused_and_the_old_one_stays() {
    let fixture = fixture().await;
    let source = fixture.ca_source();
    let (_, body) = fixture
        .set(json!({ "ca_bundle": { "path": source.to_str().unwrap() } }))
        .await;
    let kept = body["settings"]["ca_bundle"].clone();

    let key_file = fixture.base.path().join("with-key.pem");
    std::fs::write(
        &key_file,
        format!(
            "{}{}",
            std::fs::read_to_string(pam_net::testing::test_ca()).unwrap(),
            std::fs::read_to_string(pam_net::testing::fixture("leaf.key")).unwrap()
        ),
    )
    .unwrap();
    let notes = fixture.base.path().join("notes.txt");
    std::fs::write(&notes, "nothing").unwrap();
    let absent = fixture.base.path().join("absent.pem");
    for (path, needle) in [
        (key_file.to_str().unwrap(), "private key"),
        (notes.to_str().unwrap(), "no -----BEGIN CERTIFICATE-----"),
        (absent.to_str().unwrap(), "cannot be opened"),
        ("relative.pem", "absolute"),
    ] {
        let (cause, detail, recovery) = fixture
            .refuse(
                OP_NETWORK_SET,
                json!({ "ca_bundle": { "path": path }, "no_proxy": ["x.example"] }),
            )
            .await;
        assert_eq!(cause, CAUSE_CA_IMPORT_REFUSED, "{path}: {detail}");
        assert!(detail.contains(needle), "{path}: {detail}");
        assert!(recovery.contains("PEM"), "{recovery}");
    }
    let body = fixture.get().await;
    assert_eq!(body["settings"]["ca_bundle"], kept, "the old import stays");
    assert_eq!(
        body["settings"]["no_proxy"],
        json!([]),
        "the whole patch was refused"
    );
    let copies = std::fs::read_dir(fixture.network.net_dir())
        .unwrap()
        .flatten()
        .count();
    assert_eq!(copies, 1, "no refusal left a copy behind");
}

/// A stored document nothing can read refuses connector calls, downloads
/// and the Test — never a direct connection — while `get` still draws
/// the defaults with a notice and a save replaces the document.
#[tokio::test]
async fn a_corrupt_document_refuses_every_consumer_closed_until_it_is_saved_again() {
    let fixture = fixture().await;
    fixture
        .store
        .set_setting(
            SETTING_KEY,
            r#"{"version":1,"proxy":{"url":"socks5://p:1080","auth":"none"}}"#,
        )
        .await
        .unwrap();
    fixture.network.invalidate();

    let body = fixture.get().await;
    assert_eq!(
        body["settings"]["proxy"],
        Value::Null,
        "defaults are drawn, not used"
    );
    assert_eq!(body["document"]["valid"], false);
    assert_eq!(body["document"]["cause"], CAUSE_NETWORK_INVALID);
    assert!(
        body["document"]["detail"]
            .as_str()
            .unwrap()
            .contains("SOCKS")
    );
    assert!(
        body["document"]["recovery"]
            .as_str()
            .unwrap()
            .contains("save")
    );

    // The connector transport over the same source refuses closed.
    let source: Arc<dyn pam_net::NetworkSource> = Arc::clone(&fixture.network) as Arc<_>;
    if let Ok(transport) = pam_connectors::CurlTransport::trusted(source) {
        use pam_connectors::HttpTransport as _;
        let request = pam_connectors::HttpRequest {
            method: pam_connectors::Method::Get,
            url: pam_net::Url::parse("https://api.github.test/user").unwrap(),
            headers: Vec::new(),
            body: None,
            max_bytes: 1024,
            follow_one_https_redirect_without_auth: false,
        };
        let error = transport
            .send(request, std::time::Instant::now() + Duration::from_secs(5))
            .await
            .expect_err("refused before any process starts");
        let text = format!("{error:?}");
        assert!(text.contains("network_settings_invalid"), "{text}");
    }

    // A download is refused before any job row exists.
    let dest = fixture.base.path().join("models").join("x").join("y.gguf");
    let error = fixture
        .models
        .start_download(
            pam_model::DownloadRequest {
                url: "https://huggingface.co/x/y/resolve/main/y.gguf".to_owned(),
                dest,
                expected_size: None,
                expected_sha256: None,
                license_id: None,
            },
            "x/y",
        )
        .await
        .expect_err("refused");
    let text = error.to_string();
    assert!(text.contains("SOCKS"), "{text}");
    assert!(fixture.store.list_model_jobs(10).await.unwrap().is_empty());

    // The Test has no profile to probe under.
    let (cause, _, _) = fixture
        .refuse(OP_NETWORK_TEST, json!({ "target": "github" }))
        .await;
    assert_eq!(cause, CAUSE_NETWORK_INVALID);

    // A save replaces the document and everything answers again.
    let (_, body) = fixture.set(json!({ "proxy": null })).await;
    assert!(body.get("document").is_none());
    assert!(
        fixture
            .network
            .resolve_settings()
            .await
            .unwrap()
            .proxy()
            .is_none()
    );
}

#[tokio::test]
async fn test_refuses_what_it_cannot_probe_and_names_targets_only_from_configuration() {
    let fixture = fixture().await;
    for (args, needle) in [
        (json!({ "target": "nowhere" }), "not a connector"),
        (json!({ "target": 7 }), "target"),
        (json!({ "url": "https://evil.example/" }), "url"),
        (json!({ "target": "github" }), "no base URL"),
    ] {
        let (cause, detail, _) = fixture.refuse(OP_NETWORK_TEST, args.clone()).await;
        assert_eq!(cause, CAUSE_INVALID_ADMIN_ARGS, "{args}: {detail}");
        assert!(detail.contains(needle), "{args}: {detail}");
    }
}

/// A target that nothing listens on. With no proxy the first connection
/// is to the target itself, so the stage is `connect`, never `proxy`; the
/// same holds for a loopback target that bypasses a configured proxy.
#[tokio::test]
async fn a_refused_first_connection_is_reported_at_the_connect_stage() {
    let Some(_) = pam_net::testing::trusted_curl_or_skip() else {
        return;
    };
    let fixture = fixture().await;
    // A port the kernel just handed out and that nothing listens on now.
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    fixture
        .plant_connector("jenkins", &format!("http://127.0.0.1:{closed}/"))
        .await;

    let (_, response) = fixture
        .run(OP_NETWORK_TEST, json!({ "target": "jenkins" }))
        .await;
    let results = body_of(response, Outcome::Verified)["results"].clone();
    assert_eq!(results[0]["ok"], false, "{results}");
    assert_eq!(results[0]["route"], "direct", "{results}");
    assert_eq!(results[0]["stage"], "connect", "{results}");
    assert_eq!(results[0]["cause"], "connect_failed", "{results}");
    assert_eq!(results[0]["host"], "127.0.0.1");

    // A proxy is configured, but loopback never goes through it.
    fixture
        .set(json!({ "proxy": { "url": PROXY_URL, "auth": "none", "username": null } }))
        .await;
    let (_, response) = fixture
        .run(OP_NETWORK_TEST, json!({ "target": "jenkins" }))
        .await;
    let results = body_of(response, Outcome::Verified)["results"].clone();
    assert_eq!(results[0]["ok"], false, "{results}");
    assert_eq!(results[0]["route"], "bypass", "{results}");
    assert_eq!(results[0]["stage"], "connect", "{results}");
    assert_eq!(results[0]["cause"], "connect_failed", "{results}");
}

/// The stage of a failure that happens before any connection is the first
/// stage the route has; target-side resolution and connection failures are
/// `connect` whatever the route says.
#[test]
fn failure_stage_names_the_first_stage_of_the_route() {
    use crate::admin_network::failure_stage;
    use pam_net::Route;

    let proxied = Route::Proxy {
        host: "proxy.corp.example".to_owned(),
        port: 3128,
    };
    let before_any_connection = NetFailure::CurlUnavailable;
    assert_eq!(
        failure_stage(&before_any_connection, &Route::Direct),
        "connect"
    );
    assert_eq!(
        failure_stage(&before_any_connection, &Route::Bypass),
        "connect"
    );
    assert_eq!(failure_stage(&before_any_connection, &proxied), "proxy");

    let target_unresolved = NetFailure::DnsFailed {
        host: "jenkins.corp.example".to_owned(),
    };
    assert_eq!(failure_stage(&target_unresolved, &Route::Direct), "connect");
    assert_eq!(failure_stage(&target_unresolved, &proxied), "connect");
    let proxy_unresolved = NetFailure::ProxyDnsFailed {
        proxy: "proxy.corp.example:3128".to_owned(),
    };
    assert_eq!(failure_stage(&proxy_unresolved, &proxied), "proxy");
    let handshake = NetFailure::CaBundleTampered;
    assert_eq!(failure_stage(&handshake, &Route::Direct), "tls");
    assert_eq!(failure_stage(&NetFailure::Timeout, &proxied), "http");
}

/// The real trusted curl against the fixtures: a direct origin, the fake
/// proxy with and without the stored password, and a private TLS issuer
/// before and after its CA is imported.
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one fixture set driven through every route; splitting it would start the origins twice"
)]
async fn test_probes_the_configured_targets_through_the_saved_settings() {
    let Some(_) = pam_net::testing::trusted_curl_or_skip() else {
        return;
    };
    let (log, logging) = Captured::start();
    let fixture = fixture().await;
    let origin = Origin::start(OriginMode::Json).await;
    fixture
        .plant_connector("github", &format!("http://{}/", origin.address()))
        .await;

    // Direct.
    let (id, response) = fixture
        .run(OP_NETWORK_TEST, json!({ "target": "github" }))
        .await;
    let body = body_of(response, Outcome::Verified);
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["target"], "github");
    assert_eq!(results[0]["host"], "127.0.0.1");
    assert_eq!(results[0]["route"], "direct");
    assert_eq!(results[0]["stage"], "http");
    assert_eq!(results[0]["ok"], true);
    assert_eq!(results[0]["http_status"], 200);
    assert!(results[0].get("cause").is_none());
    let requests = origin.requests();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].starts_with("HEAD / HTTP/1.1"),
        "{}",
        requests[0]
    );
    assert!(
        !requests[0].contains("Authorization"),
        "no credentials: {}",
        requests[0]
    );
    let rows = fixture.audit(&id).await;
    let terminal = rows.iter().find(|row| row.action == ACTION_ADMIN).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(terminal.detail.as_deref().unwrap()).unwrap(),
        json!({ "op": OP_NETWORK_TEST, "targets": ["github"], "failed": [] })
    );
    assert_eq!(fixture.terminal_actions(&id).await, [ACTION_ADMIN]);

    // Through the proxy, which wants the stored password.
    let proxy = FakeProxy::start(
        ProxyMode::RequireAuth {
            username: PROXY_USER.to_owned(),
            password: PROXY_PASSWORD.to_owned(),
            offer: vec!["Basic realm=\"corp\"".to_owned(), "NTLM".to_owned()],
        },
        origin.address(),
    )
    .await;
    fixture
        .plant_connector(
            "jenkins",
            &format!("http://{}/", pam_net::testing::TEST_HOST),
        )
        .await;
    fixture
        .set(json!({
            "proxy": { "url": proxy.url(), "auth": "basic", "username": PROXY_USER },
            "credential": { "set": PROXY_PASSWORD },
        }))
        .await;
    let (_, response) = fixture
        .run(OP_NETWORK_TEST, json!({ "target": "jenkins" }))
        .await;
    let results = body_of(response, Outcome::Verified)["results"].clone();
    assert_eq!(results[0]["route"], "proxy", "{results}");
    assert_eq!(results[0]["ok"], true, "{results}");
    assert_eq!(results[0]["host"], pam_net::testing::TEST_HOST);
    assert_eq!(results[0]["http_status"], 200);
    assert_eq!(
        proxy.request_lines(),
        vec![format!(
            "CONNECT {}:80 HTTP/1.1",
            pam_net::testing::TEST_HOST
        )]
    );
    assert_eq!(
        proxy.authorizations().len(),
        1,
        "the password went to the proxy"
    );

    // Without the password the proxy says 407, and the offer is named.
    fixture
        .set(json!({ "credential": { "clear": true } }))
        .await;
    let (id, response) = fixture
        .run(OP_NETWORK_TEST, json!({ "target": "jenkins" }))
        .await;
    let results = body_of(response, Outcome::Verified)["results"].clone();
    assert_eq!(results[0]["ok"], false, "{results}");
    assert_eq!(results[0]["stage"], "proxy");
    assert_eq!(results[0]["route"], "proxy");
    assert_eq!(results[0]["cause"], "proxy_auth_required");
    assert_eq!(results[0]["http_status"], Value::Null);
    let detail = results[0]["detail"].as_str().unwrap();
    assert!(
        detail.contains("Basic") && detail.contains("NTLM"),
        "{detail}"
    );
    assert!(!results[0]["recovery"].as_str().unwrap().is_empty());
    let rows = fixture.audit(&id).await;
    let terminal = rows.iter().find(|row| row.action == ACTION_ADMIN).unwrap();
    assert!(
        terminal
            .detail
            .as_deref()
            .unwrap()
            .contains("jenkins:proxy_auth_required"),
        "{:?}",
        terminal.detail
    );
    // A bypassed host goes direct, and says so.
    fixture.set(json!({ "no_proxy": ["127.0.0.1"] })).await;
    let (_, response) = fixture
        .run(OP_NETWORK_TEST, json!({ "target": "github" }))
        .await;
    let results = body_of(response, Outcome::Verified)["results"].clone();
    assert_eq!(results[0]["route"], "bypass");
    assert_eq!(results[0]["ok"], true, "{results}");
    fixture.set(json!({ "proxy": null, "no_proxy": [] })).await;

    // A private TLS issuer: untrusted until its CA is imported.
    if let Some(tls) = TlsOrigin::start(TlsCert::Valid).await {
        fixture
            .plant_connector("jira", tls.local_url().as_str())
            .await;
        let (_, response) = fixture
            .run(OP_NETWORK_TEST, json!({ "target": "jira" }))
            .await;
        let results = body_of(response, Outcome::Verified)["results"].clone();
        assert_eq!(results[0]["ok"], false, "{results}");
        assert_eq!(results[0]["stage"], "tls");
        assert_eq!(results[0]["cause"], "tls_untrusted_issuer");
        assert!(
            results[0]["recovery"]
                .as_str()
                .unwrap()
                .contains("Settings › Network"),
            "{results}"
        );
        let source = fixture.ca_source();
        fixture
            .set(json!({ "ca_bundle": { "path": source.to_str().unwrap() } }))
            .await;
        // `openssl s_server -www` never answers a HEAD, so the probe ends on
        // curl's own clock — after the handshake verified, which is what the
        // bundle is for.
        let (_, response) = fixture
            .run(OP_NETWORK_TEST, json!({ "target": "jira" }))
            .await;
        let results = body_of(response, Outcome::Verified)["results"].clone();
        assert_ne!(results[0]["stage"], "tls", "{results}");
        assert_ne!(results[0]["cause"], "tls_untrusted_issuer", "{results}");
    } else {
        eprintln!("no openssl for the TLS origin; skipping the issuer probes");
        assert!(!pam_net::testing::tls_fixture_required());
    }

    drop(logging);
    assert_no_secret(&log.text());
    for index in 0..fixture.next.load(Ordering::Relaxed) {
        assert_no_secret(
            &fixture
                .everything_recorded(&format!("req_net_{index:03}"))
                .await,
        );
    }
}

#[tokio::test]
async fn the_request_row_never_carries_the_arguments() {
    let fixture = fixture().await;
    let (id, _) = fixture
        .set(json!({ "proxy": proxy_patch("basic"), "credential": { "set": PROXY_PASSWORD } }))
        .await;
    let row = fixture.store.get_request(&id).await.unwrap().unwrap();
    assert_eq!(row.args_json, "{}");
    assert_eq!(row.state, RequestState::Done);
    assert_eq!(row.capability, OP_NETWORK_SET);
}
