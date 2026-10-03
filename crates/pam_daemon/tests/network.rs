//! The network settings, end to end: a real daemon on a temp base dir, real
//! sockets, the real trusted `curl` — with the OS keychain replaced by the
//! harness's fake and the network by `pam_net`'s loopback fixtures. What
//! this proves is the boot wiring: the proxy a human saves through
//! `admin.network.set` is the proxy the connector transport spawns curl
//! with on the next call, and the password it stored is sent to that proxy
//! and never written anywhere the daemon keeps.

use std::sync::Arc;

use pam_daemon::admin::{ADMIN_CALLER_AGENT, ADMIN_REPO};
use pam_daemon::admin_connectors::{OP_CONNECTORS_CONFIGURE, OP_CONNECTORS_TEST};
use pam_daemon::admin_network::{
    ACTION_NETWORK_CONFIGURE, OP_NETWORK_GET, OP_NETWORK_SET, OP_NETWORK_TEST,
};
use pam_daemon::daemon::DAEMON_VERSION;
use pam_daemon::network_service::{PROXY_CREDENTIAL_ID, SETTING_KEY};
use pam_daemon::secrets::{SecretBackend, account_for};
use pam_net::testing::{FakeProxy, Origin, OriginMode, ProxyMode, base64, trusted_curl_or_skip};
use pam_proto::{Caller, Envelope, Outcome, PROTOCOL_VERSION, Response};
use pam_testkit::{FakeSecretBackend, TestDaemon, with_deadline};

const TOKEN: &str = "ghp_socket_secret_13572468";
const PROXY_PASSWORD: &str = "pr0xy-s3cret-\"quoted\"";
const PROXY_USER: &str = "svc-pam";
const BASE_URL: &str = "https://api.github.test/";

fn admin_envelope(id: &str, op: &str, args: serde_json::Value) -> Envelope {
    Envelope {
        v: PROTOCOL_VERSION,
        id: id.to_owned(),
        capability: op.to_owned(),
        client_version: DAEMON_VERSION.to_owned(),
        caller: Caller {
            agent: ADMIN_CALLER_AGENT.to_owned(),
            repo: ADMIN_REPO.to_owned(),
            pid: 4242,
        },
        args,
        idempotency_key: None,
        deadline_ms: 25_000,
        wait: true,
    }
}

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

/// A proxy saved through the admin op is what the connector transport
/// spawns curl with; the password it stored reaches only the proxy.
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one scenario: configure, save, call, probe, read back; splitting it hides the order"
)]
async fn a_saved_proxy_is_the_one_connector_calls_go_through() {
    if trusted_curl_or_skip().is_none() {
        return;
    }
    with_deadline(async {
        let origin = Origin::start(OriginMode::Json).await;
        // The proxy wants a password other than the one the human saves,
        // so the tunnel is refused and nothing reaches the origin — which
        // is what makes the proxy's refusal, not the origin's answer, the
        // verdict.
        let proxy = FakeProxy::start(
            ProxyMode::RequireAuth {
                username: PROXY_USER.to_owned(),
                password: "a different password".to_owned(),
                offer: vec!["Basic realm=\"corp\"".to_owned()],
            },
            origin.address(),
        )
        .await;
        let backend = Arc::new(FakeSecretBackend::default());
        let daemon = TestDaemon::spawn_with({
            let backend = Arc::clone(&backend);
            move |config| {
                config.secret_backend = Some(backend as Arc<dyn SecretBackend>);
            }
        })
        .await;
        let mut client = daemon.client().await;

        body_of(
            client
                .request(&admin_envelope(
                    "configure",
                    OP_CONNECTORS_CONFIGURE,
                    serde_json::json!({ "id": "github", "enabled": true, "base_url": BASE_URL,
                        "credential": { "set": TOKEN } }),
                ))
                .await,
            Outcome::Changed,
        );
        let saved = body_of(
            client
                .request(&admin_envelope(
                    "network_set",
                    OP_NETWORK_SET,
                    serde_json::json!({
                        "proxy": { "url": proxy.url(), "auth": "basic", "username": PROXY_USER },
                        "credential": { "set": PROXY_PASSWORD },
                    }),
                ))
                .await,
            Outcome::Changed,
        );
        assert_eq!(saved["settings"]["proxy"]["username"], PROXY_USER);
        assert_eq!(saved["settings"]["credential"]["present"], true);
        assert_eq!(
            backend
                .get(&account_for(PROXY_CREDENTIAL_ID))
                .unwrap()
                .as_deref(),
            Some(PROXY_PASSWORD),
            "the password went to the keychain"
        );

        // The connector's own test now goes through the proxy the human
        // saved: the verdict names the proxy, the origin saw nothing.
        let tested = body_of(
            client
                .request(&admin_envelope(
                    "connector_test",
                    OP_CONNECTORS_TEST,
                    serde_json::json!({ "id": "github" }),
                ))
                .await,
            Outcome::Verified,
        );
        assert_eq!(tested["status"], "failed");
        let detail = tested["detail"].as_str().unwrap();
        assert!(detail.contains(&proxy.address().to_string()), "{detail}");
        assert!(
            detail.contains("refused the stored user name and password"),
            "{detail}"
        );
        assert_eq!(
            proxy.request_lines(),
            vec!["CONNECT api.github.test:443 HTTP/1.1".to_owned()]
        );
        assert_eq!(proxy.authorizations().len(), 1);
        assert!(origin.requests().is_empty());

        // The Test action says the same, under its own shape.
        let probed = body_of(
            client
                .request(&admin_envelope(
                    "network_test",
                    OP_NETWORK_TEST,
                    serde_json::json!({ "target": "github" }),
                ))
                .await,
            Outcome::Verified,
        );
        let result = &probed["results"][0];
        assert_eq!(result["target"], "github");
        assert_eq!(result["route"], "proxy");
        assert_eq!(result["ok"], false);
        assert_eq!(result["cause"], "proxy_auth_rejected");

        // `get` never carries the password, and neither does anything the
        // daemon wrote.
        let read = body_of(
            client
                .request(&admin_envelope(
                    "network_get",
                    OP_NETWORK_GET,
                    serde_json::json!({}),
                ))
                .await,
            Outcome::Verified,
        );
        assert_eq!(read["settings"]["credential"]["present"], true);
        let recorded = everything_recorded(&daemon, &read).await;
        assert_no_secret(&recorded);
        assert!(recorded.contains(r#""credential":"set""#), "{recorded}");

        let tmp = daemon.stop().await;
        let log = std::fs::read_to_string(
            pam_testkit::base_of(&tmp)
                .join(pam_daemon::lifecycle::LOG_DIR)
                .join(pam_daemon::lifecycle::LOG_FILE),
        )
        .unwrap_or_default();
        assert_no_secret(&log);
    })
    .await;
}

/// The `get` body, the stored document, and every audit row and request
/// row of the requests above, as one text for the secret scan.
async fn everything_recorded(daemon: &TestDaemon, read: &serde_json::Value) -> String {
    let store = daemon.store();
    let mut recorded = read.to_string();
    recorded.push_str(&store.get_setting(SETTING_KEY).await.unwrap().unwrap());
    for id in [
        "network_set",
        "connector_test",
        "network_test",
        "network_get",
    ] {
        for row in store.audit_for_request(id).await.unwrap() {
            recorded.push_str(&row.action);
            recorded.push_str(row.detail.as_deref().unwrap_or_default());
        }
        recorded.push_str(&store.get_request(id).await.unwrap().unwrap().args_json);
    }
    let configure = store
        .audit_for_request("network_set")
        .await
        .unwrap()
        .into_iter()
        .find(|row| row.action == ACTION_NETWORK_CONFIGURE)
        .expect("the configure row");
    recorded.push_str(configure.detail.as_deref().unwrap());
    recorded
}

/// Neither password nor token, in any encoding.
fn assert_no_secret(text: &str) {
    let encoded = base64(format!("{PROXY_USER}:{PROXY_PASSWORD}").as_bytes());
    assert!(!text.contains(PROXY_PASSWORD), "{text}");
    assert!(!text.contains(&encoded), "{text}");
    assert!(!text.contains("s3cret"), "{text}");
    assert!(!text.contains(TOKEN), "{text}");
}
