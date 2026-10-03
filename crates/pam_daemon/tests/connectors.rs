//! The connector admin surface, end to end: a real daemon on a temp base
//! dir, real sockets, a real `SQLite` store — with the OS keychain and the
//! network replaced by the harness's fakes ([`FakeSecretBackend`],
//! [`FakeTransport`]), which is the only thing about this that is not
//! production.
//!
//! Admin envelopes are built by hand here (caller agent `pam-gui`), because
//! the production path to them is the GUI's `pam::client::send_admin`, not
//! the agent-shaped [`pam_testkit::envelope`].

use std::sync::Arc;

use pam_daemon::admin::{ADMIN_CALLER_AGENT, ADMIN_REPO, CAUSE_ADMIN_DENIED};
use pam_daemon::admin_connectors::{
    ACTION_CONNECTOR_CONFIGURE, CONNECTOR_ADMIN_OPS, OP_CONNECTORS_CONFIGURE, OP_CONNECTORS_LIST,
    OP_CONNECTORS_TEST,
};
use pam_daemon::connector_service::CAUSE_CREDENTIAL_MISSING;
use pam_daemon::daemon::DAEMON_VERSION;
use pam_daemon::secrets::{SecretBackend, SecretError, account_for};
use pam_proto::{Caller, Envelope, Outcome, PROTOCOL_VERSION, Response};
use pam_store::RequestState;
use pam_testkit::{FakeSecretBackend, FakeTransport, ScriptedPolicy, TestDaemon, with_deadline};

/// The credential a human types into the Connectors screen.
const TOKEN: &str = "ghp_socket_secret_13572468";

const BASE_URL: &str = "https://api.github.test/";

/// An `admin.*` envelope carrying the GUI tripwire identity.
fn admin_envelope(id: &str, op: &str, args: serde_json::Value) -> Envelope {
    envelope_from(ADMIN_CALLER_AGENT, id, op, args)
}

fn envelope_from(agent: &str, id: &str, op: &str, args: serde_json::Value) -> Envelope {
    Envelope {
        v: PROTOCOL_VERSION,
        id: id.to_owned(),
        capability: op.to_owned(),
        client_version: DAEMON_VERSION.to_owned(),
        caller: Caller {
            agent: agent.to_owned(),
            repo: ADMIN_REPO.to_owned(),
            pid: 4242,
        },
        args,
        idempotency_key: None,
        deadline_ms: 15_000,
        wait: true,
    }
}

/// Unwraps a result body, asserting the outcome.
fn body_of(response: Response, outcome: Outcome) -> serde_json::Value {
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

/// Unwraps a refusal's cause.
fn cause_of(response: Response) -> String {
    match response {
        Response::Refusal { cause, .. } => cause,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn configure_then_test_then_list_agree_over_the_real_socket() {
    with_deadline(async {
        let backend = Arc::new(FakeSecretBackend::default());
        let transport = Arc::new(FakeTransport::new().json(200, r#"{"login":"octocat"}"#));
        let daemon =
            TestDaemon::spawn_with_connectors(Arc::clone(&backend), Arc::clone(&transport)).await;
        let mut client = daemon.client().await;

        let response = client
            .request(&admin_envelope(
                "req_conf",
                OP_CONNECTORS_CONFIGURE,
                serde_json::json!({
                    "id": "github",
                    "enabled": true,
                    "base_url": BASE_URL,
                    "credential": { "set": TOKEN },
                }),
            ))
            .await;
        let body = body_of(response, Outcome::Changed);
        assert_eq!(body["id"], "github");
        assert_eq!(body["credential_present"], true);
        daemon
            .assert_row_state("req_conf", RequestState::Done)
            .await;

        // The secret went to the keychain; the audit row says only that
        // one was set.
        assert_eq!(
            backend.get(&account_for("github")).expect("backend ok"),
            Some(TOKEN.to_owned())
        );
        let rows = daemon.audit_rows("req_conf").await;
        let configure: Vec<_> = rows
            .iter()
            .filter(|row| row.action == ACTION_CONNECTOR_CONFIGURE)
            .collect();
        assert_eq!(configure.len(), 1);
        let detail: serde_json::Value =
            serde_json::from_str(configure[0].detail.as_deref().expect("detail"))
                .expect("detail JSON");
        assert_eq!(detail["credential"], "set");
        assert_eq!(detail["base_url"], BASE_URL);
        for row in &rows {
            assert!(
                !row.detail.as_deref().unwrap_or_default().contains(TOKEN),
                "an audit row carries the secret: {row:?}"
            );
        }

        let response = client
            .request(&admin_envelope(
                "req_test",
                OP_CONNECTORS_TEST,
                serde_json::json!({ "id": "github" }),
            ))
            .await;
        let body = body_of(response, Outcome::Verified);
        assert_eq!(body["status"], "passed");
        assert_eq!(body["detail"], "authenticated as octocat");
        assert!(body["ts"].as_i64().expect("a timestamp") > 0);
        // The call really went out, with the credential in a header.
        assert_eq!(transport.url(0), "https://api.github.test/user");
        assert_eq!(
            transport.header(0, "Authorization"),
            Some(format!("Bearer {TOKEN}"))
        );

        let response = client
            .request(&admin_envelope(
                "req_list",
                OP_CONNECTORS_LIST,
                serde_json::json!({}),
            ))
            .await;
        let body = body_of(response, Outcome::Verified);
        let connectors = body["connectors"].as_array().expect("connectors array");
        assert_eq!(connectors.len(), 6);
        assert_eq!(connectors[0]["id"], "github");
        assert_eq!(connectors[0]["enabled"], true);
        assert_eq!(connectors[0]["base_url"], BASE_URL);
        assert_eq!(connectors[0]["credential_present"], true);
        assert_eq!(connectors[0]["store_available"], true);
        assert_eq!(connectors[0]["last_test"]["status"], "passed");

        // Every op is a real request row with exactly one terminal audit
        // row.
        for id in ["req_conf", "req_test", "req_list"] {
            daemon.assert_row_state(id, RequestState::Done).await;
            daemon.assert_single_terminal_audit(id).await;
        }
        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn a_connector_admin_op_from_an_agent_trips_the_wire() {
    with_deadline(async {
        let backend = Arc::new(FakeSecretBackend::default());
        let transport = Arc::new(FakeTransport::new());
        let daemon =
            TestDaemon::spawn_with_connectors(Arc::clone(&backend), Arc::clone(&transport)).await;
        let mut client = daemon.client().await;

        for (index, op) in CONNECTOR_ADMIN_OPS.iter().enumerate() {
            let id = format!("req_trip_{index}");
            let response = client
                .request(&envelope_from(
                    "claude",
                    &id,
                    op,
                    serde_json::json!({ "id": "github", "credential": { "set": TOKEN } }),
                ))
                .await;
            assert_eq!(cause_of(response), CAUSE_ADMIN_DENIED, "op {op}");
            daemon.assert_row_state(&id, RequestState::Refused).await;
            daemon.assert_single_terminal_audit(&id).await;
        }

        // Nothing an agent asked for reached the keychain or the network.
        assert_eq!(
            backend.get(&account_for("github")).expect("backend ok"),
            None
        );
        assert!(transport.requests().is_empty());

        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn test_refuses_before_the_network_when_no_credential_is_stored() {
    with_deadline(async {
        let backend = Arc::new(FakeSecretBackend::default());
        let transport = Arc::new(FakeTransport::new());
        let daemon =
            TestDaemon::spawn_with_connectors(Arc::clone(&backend), Arc::clone(&transport)).await;
        let mut client = daemon.client().await;

        let response = client
            .request(&admin_envelope(
                "req_conf",
                OP_CONNECTORS_CONFIGURE,
                serde_json::json!({ "id": "github", "enabled": true, "base_url": BASE_URL }),
            ))
            .await;
        body_of(response, Outcome::Changed);

        let response = client
            .request(&admin_envelope(
                "req_test",
                OP_CONNECTORS_TEST,
                serde_json::json!({ "id": "github" }),
            ))
            .await;
        assert_eq!(cause_of(response), CAUSE_CREDENTIAL_MISSING);
        assert!(
            transport.requests().is_empty(),
            "a refused test must never reach the transport"
        );
        daemon
            .assert_row_state("req_test", RequestState::Refused)
            .await;
        daemon.assert_single_terminal_audit("req_test").await;

        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn an_unreachable_keychain_refuses_configure_and_still_lists() {
    with_deadline(async {
        let backend = Arc::new(FakeSecretBackend::default());
        *backend.fail_with.lock().expect("lock") = Some(SecretError::Unavailable);
        let transport = Arc::new(FakeTransport::new());
        let daemon =
            TestDaemon::spawn_with_connectors(Arc::clone(&backend), Arc::clone(&transport)).await;
        let mut client = daemon.client().await;

        let response = client
            .request(&admin_envelope(
                "req_conf",
                OP_CONNECTORS_CONFIGURE,
                serde_json::json!({ "id": "github", "credential": { "set": TOKEN } }),
            ))
            .await;
        let (cause, recovery) = match response {
            Response::Refusal {
                cause, recovery, ..
            } => (cause, recovery),
            other => panic!("expected a refusal, got {other:?}"),
        };
        assert_eq!(cause, SecretError::Unavailable.cause());
        assert!(
            recovery.contains("Settings → Connectors"),
            "recovery: {recovery}"
        );

        // The panel still draws, and says the store is the problem.
        let response = client
            .request(&admin_envelope(
                "req_list",
                OP_CONNECTORS_LIST,
                serde_json::json!({}),
            ))
            .await;
        let body = body_of(response, Outcome::Verified);
        assert_eq!(body["connectors"][0]["store_available"], false);
        assert_eq!(body["connectors"][0]["credential_present"], false);

        daemon
            .assert_row_state("req_conf", RequestState::Refused)
            .await;
        daemon
            .assert_row_state("req_list", RequestState::Done)
            .await;
        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}

/// Only this fixture rewrites the fixed HTTPS test origin to loopback HTTP.
/// Production URL validation and curl's HTTPS-only defaults remain in use.
struct LocalConnectorTransport {
    origin: String,
    curl: pam_connectors::CurlTransport,
}

impl pam_connectors::HttpTransport for LocalConnectorTransport {
    fn send<'a>(
        &'a self,
        mut request: pam_connectors::HttpRequest,
        deadline: std::time::Instant,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<pam_connectors::HttpResponse, pam_connectors::TransportError>,
                > + Send
                + 'a,
        >,
    > {
        assert_eq!(request.url.host_str(), Some("api.github.test"));
        request.url = format!("{}{}", self.origin, request.url.path())
            .parse()
            .unwrap();
        self.curl.send(request, deadline)
    }
}

async fn connector_http_origin() -> (String, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        for (token, status, body) in [
            (TOKEN, "200 OK", r#"{"login":"octocat"}"#),
            ("replacement", "401 Unauthorized", "{}"),
        ] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
                assert!(request.len() < 8192);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET /user HTTP/1.1\r\n"));
            assert!(request.contains(&format!("Authorization: Bearer {token}\r\n")));
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    (origin, task)
}

#[tokio::test]
async fn save_and_test_uses_current_credentials_against_a_local_http_service() {
    with_deadline(async {
        let (origin, server) = connector_http_origin().await;
        let backend = Arc::new(FakeSecretBackend::default());
        let daemon = TestDaemon::spawn_with(move |config| {
            config.secret_backend = Some(backend);
            config.http_transport = Some(Arc::new(LocalConnectorTransport {
                origin,
                curl: pam_connectors::CurlTransport::trusted(Arc::new(Arc::new(
                    pam_connectors::NetSettings::direct(),
                )))
                .expect("the trusted OS curl")
                .allow_http_for_tests(),
            }));
        })
        .await;
        let mut client = daemon.client().await;
        for (index, token, expected) in [(0, TOKEN, "passed"), (1, "replacement", "failed")] {
            let saved = body_of(
                client
                    .request(&admin_envelope(
                        &format!("save{index}"),
                        OP_CONNECTORS_CONFIGURE,
                        serde_json::json!({"id":"github", "enabled":false,
                    "base_url":BASE_URL, "credential":{"set":token}}),
                    ))
                    .await,
                Outcome::Changed,
            );
            assert!(saved["last_test"].is_null());
            assert_eq!(saved["enabled"], false);
            let tested = body_of(
                client
                    .request(&admin_envelope(
                        &format!("test{index}"),
                        OP_CONNECTORS_TEST,
                        serde_json::json!({"id":"github"}),
                    ))
                    .await,
                Outcome::Verified,
            );
            assert_eq!(
                tested["status"],
                expected,
                "connector test body: {}",
                serde_json::to_string(&tested).unwrap()
            );
            let listed = body_of(
                client
                    .request(&admin_envelope(
                        &format!("list{index}"),
                        OP_CONNECTORS_LIST,
                        serde_json::json!({}),
                    ))
                    .await,
                Outcome::Verified,
            );
            assert_eq!(listed["connectors"][0]["last_test"]["status"], expected);
            assert_eq!(listed["connectors"][0]["credential_present"], true);
            assert!(!listed.to_string().contains(token));
        }
        server.await.unwrap();
        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}

/// A trusted managed policy a real daemon reads at boot: GitHub may only
/// use `github.test`, and Jenkins is switched off. Models and retention are
/// governed too, so one daemon shows every surface this change touches.
const MANAGED_POLICY: &str = r#"{
    "version": 1,
    "revision": "2026-10-02.7",
    "organization": "Example Corp",
    "contact": "it@example.test",
    "connectors": { "allowed_base_hosts": ["github.test"], "disabled": ["jenkins"] },
    "models": {
        "engine_source": "import_only",
        "allowed_sources": ["catalog"],
        "idle_unload_min": { "max": 60 }
    },
    "retention": { "audit_days": { "max": 90 } }
}"#;

/// One admin op over the daemon's socket.
async fn call(
    client: &mut pam_testkit::TestClient,
    id: &str,
    op: &str,
    args: serde_json::Value,
) -> Response {
    client.request(&admin_envelope(id, op, args)).await
}

/// The refused op's request carries the terminal `admin`/`refuse` row and
/// the policy's `policy.locked_write` row, with the full digest.
async fn assert_locked_write(daemon: &TestDaemon, id: &str, op: &str, cause: &str, key: &str) {
    let rows = daemon.audit_rows(id).await;
    let row = rows
        .iter()
        .find(|row| row.action == "policy.locked_write")
        .unwrap_or_else(|| panic!("{id}: no policy.locked_write row in {rows:?}"));
    let detail: serde_json::Value =
        serde_json::from_str(row.detail.as_deref().expect("detail")).expect("detail JSON");
    assert_eq!(detail["op"], op);
    assert_eq!(detail["cause"], cause);
    assert_eq!(detail["keys"], serde_json::json!([key]));
    assert_eq!(detail["digest"].as_str().map(str::len), Some(64));
    assert_eq!(detail["revision"], "2026-10-02.7");
    daemon.assert_row_state(id, RequestState::Refused).await;
    daemon.assert_single_terminal_audit(id).await;
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one daemon, every governed surface, in the order a person meets them"
)]
async fn a_managed_policy_governs_connectors_models_and_retention_over_the_real_socket() {
    with_deadline(async {
        let backend = Arc::new(FakeSecretBackend::default());
        let transport = Arc::new(FakeTransport::new());
        let daemon = TestDaemon::spawn_with({
            let backend = Arc::clone(&backend);
            let transport = Arc::clone(&transport);
            move |config| {
                config.secret_backend = Some(backend as Arc<dyn SecretBackend>);
                config.http_transport = Some(transport);
                config.policy_source = Some(ScriptedPolicy::trusted(MANAGED_POLICY));
            }
        })
        .await;
        let mut client = daemon.client().await;
        // Connectors: Jenkins is off for good, and GitHub is held to its hosts.
        let response = call(
            &mut client,
            "req_jenkins",
            OP_CONNECTORS_CONFIGURE,
            serde_json::json!({ "id": "jenkins", "enabled": true }),
        )
        .await;
        assert_eq!(cause_of(response), "setting_locked");
        assert_locked_write(
            &daemon,
            "req_jenkins",
            OP_CONNECTORS_CONFIGURE,
            "setting_locked",
            "connectors.disabled",
        )
        .await;
        let response = call(
            &mut client,
            "req_host",
            OP_CONNECTORS_CONFIGURE,
            serde_json::json!({
                "id": "github", "base_url": "https://evil.example.org/",
                "credential": { "set": TOKEN },
            }),
        )
        .await;
        assert_eq!(cause_of(response), "policy_not_allowed");
        assert_locked_write(
            &daemon,
            "req_host",
            OP_CONNECTORS_CONFIGURE,
            "policy_not_allowed",
            "connectors.allowed_base_hosts",
        )
        .await;
        assert_eq!(
            backend.get(&account_for("github")).expect("backend ok"),
            None,
            "a refused save never reaches the keychain"
        );
        let response = call(
            &mut client,
            "req_ok",
            OP_CONNECTORS_CONFIGURE,
            serde_json::json!({
                "id": "github", "enabled": true, "base_url": BASE_URL,
                "credential": { "set": TOKEN },
            }),
        )
        .await;
        body_of(response, Outcome::Changed);
        let body = body_of(
            call(
                &mut client,
                "req_list",
                OP_CONNECTORS_LIST,
                serde_json::json!({}),
            )
            .await,
            Outcome::Verified,
        );
        let connectors = body["connectors"].as_array().expect("connectors array");
        let jenkins = connectors.iter().find(|c| c["id"] == "jenkins").unwrap();
        assert_eq!(jenkins["enabled"], false);
        assert_eq!(jenkins["effective"]["enabled"]["source"], "policy");
        assert_eq!(jenkins["effective"]["enabled"]["locked"], true);

        // Models: the engine only from an imported file; weights only from the catalog.
        let response = call(
            &mut client,
            "req_engine",
            "admin.models.engine.install",
            serde_json::json!({ "confirm": true }),
        )
        .await;
        assert_eq!(cause_of(response), "policy_not_allowed");
        assert_locked_write(
            &daemon,
            "req_engine",
            "admin.models.engine.install",
            "policy_not_allowed",
            "models.engine_source",
        )
        .await;
        let response = call(
            &mut client,
            "req_url",
            "admin.models.download",
            serde_json::json!({ "url": "http://127.0.0.1:9/w.gguf", "vendor": "v" }),
        )
        .await;
        assert_eq!(cause_of(response), "policy_not_allowed");
        assert_locked_write(
            &daemon,
            "req_url",
            "admin.models.download",
            "policy_not_allowed",
            "models.allowed_sources",
        )
        .await;
        let response = call(
            &mut client,
            "req_idle",
            "admin.models.settings.set",
            serde_json::json!({ "idle_unload_min": 0 }),
        )
        .await;
        assert_eq!(cause_of(response), "policy_not_allowed");
        assert_locked_write(
            &daemon,
            "req_idle",
            "admin.models.settings.set",
            "policy_not_allowed",
            "models.idle_unload_min",
        )
        .await;

        // Retention: a ceiling refuses forever and is the window in force.
        let response = call(
            &mut client,
            "req_forever",
            "admin.retention.set",
            serde_json::json!({ "audit_days": null }),
        )
        .await;
        assert_eq!(cause_of(response), "policy_not_allowed");
        assert_locked_write(
            &daemon,
            "req_forever",
            "admin.retention.set",
            "policy_not_allowed",
            "retention.audit_days",
        )
        .await;
        let body = body_of(
            call(
                &mut client,
                "req_ret",
                "admin.retention.get",
                serde_json::json!({}),
            )
            .await,
            Outcome::Verified,
        );
        assert_eq!(body["audit_days"], 90);
        assert_eq!(body["effective"]["audit_days"]["source"], "policy");

        assert!(
            transport.requests().is_empty(),
            "nothing reached the network"
        );
        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}
