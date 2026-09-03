use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use pam_connectors::testing::FakeTransport;
use pam_proto::{Caller, Envelope, Outcome, PROTOCOL_VERSION, Response};
use pam_store::{Decision, RequestState, Store};
use serde_json::{Value, json};

use crate::admin::{
    ACTION_ADMIN, ADMIN_CALLER_AGENT, AdminService, CAUSE_ADMIN_DENIED, CAUSE_INVALID_ADMIN_ARGS,
};
use crate::admin_connectors::{
    ACTION_CONNECTOR_CONFIGURE, CONNECTOR_ADMIN_OPS, OP_CONNECTORS_CONFIGURE, OP_CONNECTORS_LIST,
    OP_CONNECTORS_TEST,
};
use crate::approval::ApprovalService;
use crate::connector_service::{CAUSE_BAD_URL, ConnectorService};
use crate::daemon::TERMINAL_ACTIONS;
use crate::log_service::LogService;
use crate::model_service::ModelService;
use crate::secrets::{FakeSecretBackend, SecretBackend, SecretStore, account_for};
use crate::transport::EventPublisher;

/// The credential a human pastes into the Connectors screen. No audit
/// row, no request row, and no daemon log line may contain it.
const TOKEN: &str = "ghp_admin_secret_9876543210";

const BASE_URL: &str = "https://api.github.test/";

/// Approval timeout long enough never to fire here.
const LONG_TIMEOUT: Duration = Duration::from_mins(10);

/// An admin service whose connector host runs on a fake keychain and a
/// scripted transport.
struct Fixture {
    store: Arc<Store>,
    admin: AdminService,
    backend: Arc<FakeSecretBackend>,
    next: AtomicU32,
}

async fn fixture() -> Fixture {
    fixture_with(FakeTransport::new()).await
}

async fn fixture_with(transport: FakeTransport) -> Fixture {
    let store = Arc::new(Store::open_in_memory().await.expect("store opens"));
    let (events, _rx) = EventPublisher::for_tests();
    let approvals = Arc::new(ApprovalService::new(
        Arc::clone(&store),
        events,
        LONG_TIMEOUT,
    ));
    let models = ModelService::new(Arc::clone(&store))
        .await
        .expect("model service");
    let logs = LogService::new(Arc::clone(&store), Arc::clone(&models));
    let backend = Arc::new(FakeSecretBackend::default());
    let connectors = Arc::new(ConnectorService::new(
        Arc::clone(&store),
        Arc::new(SecretStore::new(Arc::clone(&backend) as Arc<_>)),
        Arc::new(transport),
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
        models,
        logs,
        connectors,
        flows,
        crate::flow_service_test::closed_submit(),
    );
    Fixture {
        store,
        admin,
        backend,
        next: AtomicU32::new(0),
    }
}

impl Fixture {
    /// Runs one admin op end to end (row, tripwire, deadline, audit),
    /// answering the request id it ran under and the response.
    async fn run(&self, op: &str, args: Value) -> (String, Response) {
        self.run_as(ADMIN_CALLER_AGENT, op, args).await
    }

    async fn run_as(&self, agent: &str, op: &str, args: Value) -> (String, Response) {
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        let id = format!("req_conn_{index:03}");
        let envelope = Envelope {
            v: PROTOCOL_VERSION,
            id: id.clone(),
            capability: op.to_owned(),
            client_version: env!("CARGO_PKG_VERSION").to_owned(),
            caller: Caller {
                agent: agent.to_owned(),
                repo: "/repo/anywhere".to_owned(),
                pid: 4242,
            },
            args,
            idempotency_key: None,
            deadline_ms: 15_000,
            wait: true,
        };
        let response = self.admin.handle(&envelope).await;
        (id, response)
    }

    /// Every audit row of one request.
    async fn audit(&self, id: &str) -> Vec<pam_store::AuditRow> {
        self.store.audit_for_request(id).await.expect("audit query")
    }

    /// The request's terminal audit actions — exactly one is the
    /// invariant every admin op holds.
    async fn terminal_actions(&self, id: &str) -> Vec<String> {
        self.audit(id)
            .await
            .into_iter()
            .filter(|row| TERMINAL_ACTIONS.contains(&row.action.as_str()))
            .map(|row| row.action)
            .collect()
    }
}

/// Unwraps a successful body, asserting the outcome.
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

/// Unwraps a refusal.
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

#[tokio::test]
async fn list_answers_every_connector_and_finishes_the_request() {
    let fixture = fixture().await;
    let (id, response) = fixture.run(OP_CONNECTORS_LIST, json!({})).await;
    let body = body_of(response, Outcome::Verified);

    let connectors = body["connectors"].as_array().expect("connectors array");
    assert_eq!(connectors.len(), 7);
    assert_eq!(connectors[0]["id"], "github");
    assert_eq!(connectors[0]["name"], "GitHub");
    assert_eq!(connectors[0]["auth"], "bearer");
    assert_eq!(connectors[0]["credential_present"], false);
    assert_eq!(connectors[0]["store_available"], true);
    assert!(connectors[0]["last_test"].is_null());

    assert_eq!(
        fixture
            .store
            .get_request(&id)
            .await
            .expect("row query")
            .expect("row")
            .state,
        RequestState::Done
    );
    assert_eq!(fixture.terminal_actions(&id).await, [ACTION_ADMIN]);
}

#[tokio::test]
async fn configure_writes_one_connector_configure_row_that_carries_no_secret() {
    let fixture = fixture().await;
    let log_dir = tempfile::tempdir().expect("tempdir");
    let (writer, guard) = crate::lifecycle::daemon_log_writer(log_dir.path()).expect("log writer");
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .finish();
    // `#[tokio::test]` runs on one thread, so the default subscriber
    // covers every await of the op — including the ones that log.
    let logging = tracing::subscriber::set_default(subscriber);

    let (id, response) = fixture
        .run(
            OP_CONNECTORS_CONFIGURE,
            json!({
                "id": "github",
                "enabled": true,
                "base_url": BASE_URL,
                "credential": { "set": TOKEN },
            }),
        )
        .await;
    drop(logging);
    drop(guard);

    let body = body_of(response, Outcome::Changed);
    assert_eq!(body["id"], "github");
    assert_eq!(body["enabled"], true);
    assert_eq!(body["base_url"], BASE_URL);
    assert_eq!(body["credential_present"], true);

    // The secret reached the keychain and nothing else.
    assert_eq!(
        fixture
            .backend
            .get(&account_for("github"))
            .expect("backend ok")
            .as_deref(),
        Some(TOKEN)
    );

    let rows = fixture.audit(&id).await;
    let configure: Vec<&pam_store::AuditRow> = rows
        .iter()
        .filter(|row| row.action == ACTION_CONNECTOR_CONFIGURE)
        .collect();
    assert_eq!(configure.len(), 1, "exactly one connector.configure row");
    assert_eq!(configure[0].decision, Decision::Allow);
    let detail: Value =
        serde_json::from_str(configure[0].detail.as_deref().expect("detail")).expect("detail JSON");
    assert_eq!(detail["id"], "github");
    assert_eq!(detail["enabled"], true);
    assert_eq!(detail["base_url"], BASE_URL);
    assert_eq!(detail["credential"], "set");

    for row in &rows {
        assert!(
            !row.detail.as_deref().unwrap_or_default().contains(TOKEN),
            "an audit row carries the secret: {row:?}"
        );
    }
    // The request row keeps the envelope's args verbatim, so the GUI must
    // never put a credential where the row can see it — this asserts the
    // op's own bookkeeping, not the envelope.
    assert_eq!(fixture.terminal_actions(&id).await, [ACTION_ADMIN]);

    let mut logged = String::new();
    for entry in std::fs::read_dir(log_dir.path().join(crate::lifecycle::LOG_DIR))
        .expect("the daemon log dir exists")
    {
        let path = entry.expect("dir entry").path();
        logged.push_str(&std::fs::read_to_string(path).expect("log readable"));
    }
    assert!(
        !logged.contains(TOKEN),
        "the daemon log carries the secret: {logged}"
    );
}

#[tokio::test]
async fn configure_clears_a_credential_and_says_so_in_the_audit_row() {
    let fixture = fixture().await;
    let (_, response) = fixture
        .run(
            OP_CONNECTORS_CONFIGURE,
            json!({ "id": "github", "credential": { "set": TOKEN } }),
        )
        .await;
    body_of(response, Outcome::Changed);

    let (id, response) = fixture
        .run(
            OP_CONNECTORS_CONFIGURE,
            json!({ "id": "github", "credential": { "clear": true } }),
        )
        .await;
    let body = body_of(response, Outcome::Changed);
    assert_eq!(body["credential_present"], false);

    let row = fixture
        .audit(&id)
        .await
        .into_iter()
        .find(|row| row.action == ACTION_CONNECTOR_CONFIGURE)
        .expect("a configure row");
    let detail: Value =
        serde_json::from_str(row.detail.as_deref().expect("detail")).expect("detail JSON");
    assert_eq!(detail["credential"], "cleared");
    assert_eq!(
        fixture
            .backend
            .get(&account_for("github"))
            .expect("backend ok"),
        None
    );
}

#[tokio::test]
async fn configure_refuses_an_unknown_connector_id() {
    let fixture = fixture().await;
    let (id, response) = fixture
        .run(OP_CONNECTORS_CONFIGURE, json!({ "id": "gitlab" }))
        .await;
    let (cause, detail, _) = refusal_of(response);
    assert_eq!(cause, CAUSE_INVALID_ADMIN_ARGS);
    assert!(detail.contains("github"), "detail: {detail}");
    assert_eq!(
        fixture
            .store
            .get_request(&id)
            .await
            .expect("row query")
            .expect("row")
            .state,
        RequestState::Refused
    );
    assert_eq!(fixture.terminal_actions(&id).await, [ACTION_ADMIN]);
}

#[tokio::test]
async fn configure_refuses_a_malformed_credential() {
    let fixture = fixture().await;
    for credential in [
        json!("just-a-string"),
        json!({ "set": 7 }),
        json!({ "clear": false }),
        json!({}),
    ] {
        let (_, response) = fixture
            .run(
                OP_CONNECTORS_CONFIGURE,
                json!({ "id": "github", "credential": credential }),
            )
            .await;
        let (cause, _, _) = refusal_of(response);
        assert_eq!(cause, CAUSE_INVALID_ADMIN_ARGS);
    }
    // Nothing was written by any of them.
    assert_eq!(
        fixture
            .backend
            .get(&account_for("github"))
            .expect("backend ok"),
        None
    );
}

#[tokio::test]
async fn configure_refuses_a_base_url_that_is_not_a_service_root() {
    let fixture = fixture().await;
    let (_, response) = fixture
        .run(
            OP_CONNECTORS_CONFIGURE,
            json!({ "id": "github", "base_url": "http://api.github.test/" }),
        )
        .await;
    let (cause, _, recovery) = refusal_of(response);
    assert_eq!(cause, CAUSE_BAD_URL);
    assert!(
        recovery.contains("Settings → Connectors → GitHub"),
        "recovery: {recovery}"
    );
}

#[tokio::test]
async fn test_answers_the_status_detail_and_timestamp_it_recorded() {
    let fixture = fixture_with(FakeTransport::new().json(200, r#"{"login":"octocat"}"#)).await;
    let (_, response) = fixture
        .run(
            OP_CONNECTORS_CONFIGURE,
            json!({ "id": "github", "enabled": true, "base_url": BASE_URL, "credential": { "set": TOKEN } }),
        )
        .await;
    body_of(response, Outcome::Changed);

    let (id, response) = fixture
        .run(OP_CONNECTORS_TEST, json!({ "id": "github" }))
        .await;
    let body = body_of(response, Outcome::Verified);
    assert_eq!(body["status"], "passed");
    assert_eq!(body["detail"], "authenticated as octocat");
    assert!(body["ts"].as_i64().expect("a timestamp") > 0);
    assert_eq!(fixture.terminal_actions(&id).await, [ACTION_ADMIN]);

    // The verdict is on the row, so the next list shows it.
    let (_, response) = fixture.run(OP_CONNECTORS_LIST, json!({})).await;
    let body = body_of(response, Outcome::Verified);
    let github = &body["connectors"][0];
    assert_eq!(github["id"], "github");
    assert_eq!(github["enabled"], true);
    assert_eq!(github["last_test"]["status"], "passed");
    assert_eq!(github["last_test"]["detail"], "authenticated as octocat");
}

#[tokio::test]
async fn test_records_a_failure_as_a_verdict_not_a_refusal() {
    let fixture = fixture_with(FakeTransport::new().json(401, "{}")).await;
    let (_, response) = fixture
        .run(
            OP_CONNECTORS_CONFIGURE,
            json!({ "id": "github", "base_url": BASE_URL, "credential": { "set": TOKEN } }),
        )
        .await;
    body_of(response, Outcome::Changed);

    let (_, response) = fixture
        .run(OP_CONNECTORS_TEST, json!({ "id": "github" }))
        .await;
    let body = body_of(response, Outcome::Verified);
    assert_eq!(body["status"], "failed");
    assert!(
        body["detail"]
            .as_str()
            .expect("detail")
            .contains("credential")
    );
}

#[tokio::test]
async fn every_connector_op_is_behind_the_gui_tripwire() {
    let fixture = fixture().await;
    for op in CONNECTOR_ADMIN_OPS {
        let (id, response) = fixture
            .run_as("claude", op, json!({ "id": "github" }))
            .await;
        let (cause, _, _) = refusal_of(response);
        assert_eq!(cause, CAUSE_ADMIN_DENIED, "op {op}");
        assert_eq!(
            fixture
                .store
                .get_request(&id)
                .await
                .expect("row query")
                .expect("row")
                .state,
            RequestState::Refused
        );
    }
    // Nothing an agent asked for touched the keychain.
    assert_eq!(
        fixture
            .backend
            .get(&account_for("github"))
            .expect("backend ok"),
        None
    );
}

#[test]
fn the_op_list_names_every_connector_op() {
    assert_eq!(
        CONNECTOR_ADMIN_OPS,
        [
            OP_CONNECTORS_LIST,
            OP_CONNECTORS_CONFIGURE,
            OP_CONNECTORS_TEST
        ]
    );
    for op in CONNECTOR_ADMIN_OPS {
        assert!(op.starts_with("admin.connectors."), "op {op}");
    }
}
