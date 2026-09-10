//! Real `FlowService`, journal, lifecycle and evidence paths; only HTTP/keychain fake.
use crate::{
    approval::ApprovalService,
    connector_service::{ConfigurePatch, ConnectorService, CredentialAction},
    daemon::CompletionRouter,
    executor::{CapabilityFailure, ExecContext},
    flow_service::{FlowService, RunArgs},
    log_service::LogService,
    model_service::ModelService,
    policy::PolicyGate,
    queue::QueueManager,
    secrets::{FakeSecretBackend, SecretStore},
    transport::EventPublisher,
};
use pam_connectors::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use pam_proto::{Caller, Outcome};
use pam_store::{Actor, AuditEntry, Decision, RequestState, Store};
use serde_json::json;
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const SHA: &str = "abcdef1234567890abcdef1234567890abcdef12";
const SOURCE: &str = "https://git.example/team/repo.git";
const FLOW: &str = r"schema: 1
id: watched
name: Watched
correlation:
  repository: https://git.example/team/repo.git
  commit: abcdef1234567890abcdef1234567890abcdef12
steps:
 - id: wait
   connector: github
   call: run
   with: {repo: team/repo, run_id: 9, run_attempt: 1}
   watch: {max_polls: 5, interval: 5s, max_interval: 5s}
   role: verify
   expect_status: success
   output: compact
";
const ORDINARY: &str = r"schema: 1
id: ordinary
name: Ordinary
steps:
 - id: inspect
   connector: github
   call: run
   with: {repo: team/repo, run_id: 10, run_attempt: 1}
   output: compact
";
#[derive(Default)]
struct Reads {
    watched: AtomicUsize,
    watched_jobs: AtomicUsize,
    ordinary: AtomicUsize,
}
impl HttpTransport for Reads {
    fn send<'a>(
        &'a self,
        request: HttpRequest,
        _deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>> {
        Box::pin(async move {
            let path = request.url.path();
            let body = if path.ends_with("/jobs") {
                if path.contains("/runs/9/") {
                    self.watched_jobs.fetch_add(1, Ordering::SeqCst);
                }
                json!({"total_count":0,"jobs":[]})
            } else {
                let (id, pending) = if path == "/repos/team/repo/actions/runs/9/attempts/1" {
                    (9, self.watched.fetch_add(1, Ordering::SeqCst) < 2)
                } else {
                    assert_eq!(path, "/repos/team/repo/actions/runs/10/attempts/1");
                    self.ordinary.fetch_add(1, Ordering::SeqCst);
                    (10, false)
                };
                json!({"id":id,"run_attempt":1,"head_sha":SHA,"status":if pending {"queued"}else{"completed"},"conclusion":if pending {serde_json::Value::Null}else{json!("success")},"repository":{"full_name":"team/repo","clone_url":SOURCE},"head_repository":{"full_name":"team/repo","clone_url":SOURCE}})
            };
            Ok(HttpResponse {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&body).unwrap(),
            })
        })
    }
}
fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}
fn args(id: &str) -> RunArgs {
    RunArgs {
        id: id.to_owned(),
        inputs: BTreeMap::new(),
    }
}
fn entry() -> AuditEntry<'static> {
    AuditEntry {
        action: "execute",
        decision: Decision::Allow,
        actor: Actor::System,
        detail: None,
    }
}
async fn watch_count(store: &Store) -> usize {
    store
        .list_evidence("watch")
        .await
        .unwrap()
        .iter()
        .filter(|row| row.kind == "flow.watch")
        .count()
}

#[tokio::test]
async fn pending_watch_releases_lane_reuses_evidence_and_collects_only_at_terminal() {
    tokio::time::timeout(
        Duration::from_secs(30),
        Box::pin(run_pending_watch_fixture()),
    )
    .await
    .expect("watch fixture completes within bounded deadline");
}

async fn run_pending_watch_fixture() {
    let base = tempfile::tempdir().unwrap();
    let repo = tempfile::tempdir().unwrap();
    let root = repo.path().canonicalize().unwrap();
    std::fs::create_dir(base.path().join("flows")).unwrap();
    std::fs::write(base.path().join("flows/watched.yaml"), FLOW).unwrap();
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    store
        .set_setting("policy.profile", "\"relaxed\"")
        .await
        .unwrap();
    store.set_setting("flows.scope_policy",&json!({"version":1,"repositories":[{"root":root,"connectors":[{"connector":"github","base_url":"https://github.test/","access":"targets","targets":["team/repo"]}]}]}).to_string()).await.unwrap();
    let (events, mut receiver) = EventPublisher::for_tests();

    let approvals = Arc::new(ApprovalService::new(
        store.clone(),
        events.clone(),
        Duration::from_secs(10),
    ));
    let models = ModelService::new(store.clone()).await.unwrap();
    let logs = LogService::new(store.clone(), models.clone());
    let secrets = Arc::new(SecretStore::new(Arc::new(FakeSecretBackend::default())));
    let reads = Arc::new(Reads::default());
    let connectors = Arc::new(ConnectorService::new(
        store.clone(),
        secrets.clone(),
        reads.clone(),
    ));
    connectors
        .configure(
            pam_flow::ConnectorId::Github,
            ConfigurePatch {
                enabled: Some(true),
                base_url: Some(Some("https://github.test/".to_owned())),
                credential: Some(CredentialAction::Set("fixture-only".to_owned())),
                ..ConfigurePatch::default()
            },
        )
        .await
        .unwrap();
    let gate = Arc::new(PolicyGate::new(store.clone()).await.unwrap());
    let flows = Arc::new(FlowService::new(
        base.path(),
        store.clone(),
        approvals.clone(),
        connectors,
        logs,
        gate,
    ));
    let queue = Arc::new(QueueManager::new(store.clone()));
    for step in ["wait"] {
        store
            .insert_grant(&crate::flow_service::step_capability("watched", step))
            .await
            .unwrap();
    }
    std::fs::write(base.path().join("flows/ordinary.yaml"), ORDINARY).unwrap();
    store
        .insert_grant(&crate::flow_service::step_capability("ordinary", "inspect"))
        .await
        .unwrap();

    let expiry = now() + 25_000;
    let deadline = Instant::now() + Duration::from_secs(25);
    store
        .insert_admitted_request(
            "watch",
            "flow.run",
            root.to_str().unwrap(),
            "fixture",
            r#"{"id":"watched"}"#,
            None,
            expiry,
        )
        .await
        .unwrap();
    queue
        .place_in_lane("watch", root.to_str().unwrap(), 25_000)
        .await
        .unwrap();
    let lease = queue
        .take_next(root.to_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    let budget =
        crate::request_budget::RequestBudget::load_persistent(store.clone(), "watch", deadline)
            .await
            .unwrap();
    let mut ctx = ExecContext {
        budget,
        request_id: "watch".into(),
        args: json!({"id":"watched"}),
        cancel: lease.cancel,
        events: events.clone(),
        store: store.clone(),
        queue: queue.clone(),
        models: models.clone(),
        router: CompletionRouter::new(),
        approvals: approvals.clone(),
        flows: flows.clone(),
        secrets: secrets.clone(),
        caller: Caller {
            agent: "fixture".into(),
            repo: root.to_string_lossy().into_owned(),
            pid: std::process::id(),
        },
        capability: "flow.run".into(),
        started_at: Instant::now(),
    };
    let first = flows.run(&ctx, args("watched")).await.unwrap_err();
    let CapabilityFailure::Parked {
        resume_at_ms: first_due,
    } = first
    else {
        panic!("expected pending lease: {first:?}")
    };
    assert!(queue.park("watch", first_due).await.unwrap());
    assert_eq!(watch_count(&store).await, 1);
    assert_eq!(reads.watched_jobs.load(Ordering::SeqCst), 0);
    let progress: serde_json::Value = serde_json::from_str(
        &store
            .flow_watch_progress("watch", root.to_str().unwrap())
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(progress["watch_state"], "pending");
    assert_eq!(progress["polls"], 1);
    let first_evidence = progress["evidence_id"].clone();
    let charged = ctx.budget.usage();
    // Another real flow acquires the same repository lane during the parked interval.
    store
        .insert_admitted_request(
            "ordinary",
            "flow.run",
            root.to_str().unwrap(),
            "fixture",
            r#"{"id":"ordinary"}"#,
            None,
            expiry,
        )
        .await
        .unwrap();
    queue
        .place_in_lane("ordinary", root.to_str().unwrap(), 25_000)
        .await
        .unwrap();
    let ordinary = queue
        .take_next(root.to_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ordinary.request_id, "ordinary");
    let mut other = ExecContext {
        budget: crate::request_budget::RequestBudget::load_persistent(
            store.clone(),
            "ordinary",
            deadline,
        )
        .await
        .unwrap(),
        request_id: "ordinary".into(),
        args: json!({"id":"ordinary"}),
        cancel: ordinary.cancel,
        events: events.clone(),
        store: store.clone(),
        queue: queue.clone(),
        models: models.clone(),
        router: CompletionRouter::new(),
        approvals,
        flows: flows.clone(),
        secrets,
        caller: ctx.caller.clone(),
        capability: "flow.run".into(),
        started_at: Instant::now(),
    };
    let ordinary_output = flows.run(&other, args("ordinary")).await.unwrap();
    assert_eq!(ordinary_output.outcome, Outcome::Solved);
    assert!(
        queue
            .complete("ordinary", RequestState::Done, Some("solved"), entry())
            .await
            .unwrap()
    );
    assert_eq!(reads.ordinary.load(Ordering::SeqCst), 1);
    while receiver.try_recv().is_ok() {}
    tokio::time::sleep(Duration::from_millis(
        u64::try_from(first_due.saturating_sub(now()).max(0)).unwrap() + 1,
    ))
    .await;
    assert_eq!(
        queue
            .wake_due(tokio::time::Instant::now(), now())
            .await
            .unwrap(),
        1
    );
    let lease = queue
        .take_next(root.to_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    ctx.cancel = lease.cancel;
    ctx.budget =
        crate::request_budget::RequestBudget::load_persistent(store.clone(), "watch", deadline)
            .await
            .unwrap();
    assert_eq!(ctx.budget.usage().http_calls, charged.http_calls);
    assert_eq!(ctx.budget.usage().http_bytes, charged.http_bytes);
    let second = flows.run(&ctx, args("watched")).await.unwrap_err();
    let CapabilityFailure::Parked {
        resume_at_ms: second_due,
    } = second
    else {
        panic!("expected unchanged pending lease: {second:?}")
    };
    assert!(queue.park("watch", second_due).await.unwrap());
    assert_eq!(watch_count(&store).await, 1);
    while let Ok((ticket, event)) = receiver.try_recv() {
        if ticket == "watch"
            && let pam_proto::Event::Progress { note, .. } = event
        {
            assert!(
                !note.contains("watch pending"),
                "unchanged poll must not announce: {note}"
            );
        }
    }
    let progress: serde_json::Value = serde_json::from_str(
        &store
            .flow_watch_progress("watch", root.to_str().unwrap())
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(progress["polls"], 2);
    assert_eq!(progress["evidence_id"], first_evidence);
    assert_eq!(
        store
            .get_request("watch")
            .await
            .unwrap()
            .unwrap()
            .expires_at_ms,
        Some(expiry)
    );
    tokio::time::sleep(Duration::from_millis(
        u64::try_from(second_due.saturating_sub(now()).max(0)).unwrap() + 1,
    ))
    .await;
    assert_eq!(
        queue
            .wake_due(tokio::time::Instant::now(), now())
            .await
            .unwrap(),
        1
    );
    let lease = queue
        .take_next(root.to_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    ctx.cancel = lease.cancel;
    ctx.budget =
        crate::request_budget::RequestBudget::load_persistent(store.clone(), "watch", deadline)
            .await
            .unwrap();
    let output = flows.run(&ctx, args("watched")).await.unwrap();
    assert_eq!(output.outcome, Outcome::Verified);
    assert_eq!(reads.watched.load(Ordering::SeqCst), 4);
    assert_eq!(reads.watched_jobs.load(Ordering::SeqCst), 1);
    assert_eq!(watch_count(&store).await, 2);
    assert_eq!(
        ctx.budget.usage().http_calls,
        5,
        "three cheap polls then one metadata and jobs collector"
    );
    assert!(
        queue
            .complete("watch", RequestState::Done, Some("verified"), entry())
            .await
            .unwrap()
    );
    assert!(matches!(
        models.runtime().snapshot().state,
        pam_model::RuntimeState::Idle
    ));
    other.args = json!({"ticket":"watch"});
    let durable = crate::flow_result_service::result(&other).await.unwrap();
    assert_eq!(
        durable.body["agent_result"]["workflow"]["outcome"],
        "verified"
    );
}
