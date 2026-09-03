//! The connector admin surface, end to end: a real daemon on a temp base
//! dir, real zmq, a real `SQLite` store — with the OS keychain and the
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
use pam_testkit::{FakeSecretBackend, FakeTransport, TestDaemon, with_deadline};

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
        assert_eq!(connectors.len(), 7);
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
