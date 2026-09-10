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

struct Harness {
    _base: tempfile::TempDir,
    _repo: tempfile::TempDir,
    root: std::path::PathBuf,
    store: Arc<Store>,
    events: EventPublisher,
    approvals: Arc<ApprovalService>,
    models: Arc<ModelService>,
    flows: Arc<FlowService>,
    queue: Arc<QueueManager>,
    secrets: Arc<SecretStore>,
    reads: Arc<Reads>,
    expiry: i64,
    deadline: Instant,
}

impl Harness {
    async fn new() -> (
        Self,
        tokio::sync::mpsc::Receiver<(String, pam_proto::Event)>,
    ) {
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
        let (events, receiver) = EventPublisher::for_tests();

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
        store
            .insert_grant(&crate::flow_service::step_capability("watched", "wait"))
            .await
            .unwrap();
        std::fs::write(base.path().join("flows/ordinary.yaml"), ORDINARY).unwrap();
        store
            .insert_grant(&crate::flow_service::step_capability("ordinary", "inspect"))
            .await
            .unwrap();

        let harness = Self {
            _base: base,
            _repo: repo,
            root,
            store,
            events,
            approvals,
            models,
            flows,
            queue,
            secrets,
            reads,
            expiry: now() + 25_000,
            deadline: Instant::now() + Duration::from_secs(25),
        };
        (harness, receiver)
    }

    async fn admit(&self, ticket: &str, flow: &str) -> ExecContext {
        self.store
            .insert_admitted_request(
                ticket,
                "flow.run",
                self.root.to_str().unwrap(),
                "fixture",
                &json!({"id":flow}).to_string(),
                None,
                self.expiry,
            )
            .await
            .unwrap();
        self.queue
            .place_in_lane(ticket, self.root.to_str().unwrap(), 25_000)
            .await
            .unwrap();
        let lease = self
            .queue
            .take_next(self.root.to_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(lease.request_id, ticket);
        ExecContext {
            budget: crate::request_budget::RequestBudget::load_persistent(
                self.store.clone(),
                ticket,
                self.deadline,
            )
            .await
            .unwrap(),
            request_id: ticket.into(),
            args: json!({"id":flow}),
            cancel: lease.cancel,
            events: self.events.clone(),
            store: self.store.clone(),
            queue: self.queue.clone(),
            models: self.models.clone(),
            router: CompletionRouter::new(),
            approvals: self.approvals.clone(),
            flows: self.flows.clone(),
            secrets: self.secrets.clone(),
            caller: Caller {
                agent: "fixture".into(),
                repo: self.root.to_string_lossy().into_owned(),
                pid: std::process::id(),
            },
            capability: "flow.run".into(),
            started_at: Instant::now(),
        }
    }

    async fn resume(&self, ctx: &mut ExecContext, due: i64) {
        tokio::time::sleep(Duration::from_millis(
            u64::try_from(due.saturating_sub(now()).max(0)).unwrap() + 1,
        ))
        .await;
        assert_eq!(
            self.queue
                .wake_due(tokio::time::Instant::now(), now())
                .await
                .unwrap(),
            1
        );
        let lease = self
            .queue
            .take_next(self.root.to_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(lease.request_id, "watch");
        ctx.cancel = lease.cancel;
        ctx.budget = crate::request_budget::RequestBudget::load_persistent(
            self.store.clone(),
            "watch",
            self.deadline,
        )
        .await
        .unwrap();
    }
}

async fn run_pending_watch_fixture() {
    let (h, mut receiver) = Harness::new().await;
    let mut ctx = h.admit("watch", "watched").await;
    let (first_due, first_evidence) = observe_first_pending(&h, &ctx).await;
    let charged = ctx.budget.usage();
    let mut other = run_ordinary_while_parked(&h).await;
    while receiver.try_recv().is_ok() {}
    h.resume(&mut ctx, first_due).await;
    assert_eq!(ctx.budget.usage().http_calls, charged.http_calls);
    assert_eq!(ctx.budget.usage().http_bytes, charged.http_bytes);
    let second_due = observe_unchanged_pending(&h, &ctx, &mut receiver, &first_evidence).await;
    h.resume(&mut ctx, second_due).await;
    observe_terminal_collection(&h, &ctx, &mut other).await;
}

async fn observe_first_pending(h: &Harness, ctx: &ExecContext) -> (i64, serde_json::Value) {
    let Harness {
        flows,
        queue,
        store,
        reads,
        root,
        ..
    } = h;
    let first = flows.run(ctx, args("watched")).await.unwrap_err();
    let CapabilityFailure::Parked {
        resume_at_ms: first_due,
    } = first
    else {
        panic!("expected pending lease: {first:?}")
    };
    assert!(queue.park("watch", first_due).await.unwrap());
    assert_eq!(watch_count(store).await, 1);
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
    (first_due, first_evidence)
}

async fn run_ordinary_while_parked(h: &Harness) -> ExecContext {
    // Another real flow acquires the same repository lane during the parked interval.
    let other = h.admit("ordinary", "ordinary").await;
    let ordinary_output = h.flows.run(&other, args("ordinary")).await.unwrap();
    assert_eq!(ordinary_output.outcome, Outcome::Solved);
    assert!(
        h.queue
            .complete("ordinary", RequestState::Done, Some("solved"), entry())
            .await
            .unwrap()
    );
    assert_eq!(h.reads.ordinary.load(Ordering::SeqCst), 1);
    other
}

async fn observe_unchanged_pending(
    h: &Harness,
    ctx: &ExecContext,
    receiver: &mut tokio::sync::mpsc::Receiver<(String, pam_proto::Event)>,
    first_evidence: &serde_json::Value,
) -> i64 {
    let Harness {
        flows,
        queue,
        store,
        root,
        ..
    } = h;
    let second = flows.run(ctx, args("watched")).await.unwrap_err();
    let CapabilityFailure::Parked {
        resume_at_ms: second_due,
    } = second
    else {
        panic!("expected unchanged pending lease: {second:?}")
    };
    assert!(queue.park("watch", second_due).await.unwrap());
    assert_eq!(watch_count(store).await, 1);
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
    assert_eq!(&progress["evidence_id"], first_evidence);
    assert_eq!(
        store
            .get_request("watch")
            .await
            .unwrap()
            .unwrap()
            .expires_at_ms,
        Some(h.expiry)
    );
    second_due
}

async fn observe_terminal_collection(h: &Harness, ctx: &ExecContext, other: &mut ExecContext) {
    let Harness {
        flows,
        queue,
        store,
        reads,
        ..
    } = h;
    let output = flows.run(ctx, args("watched")).await.unwrap();
    assert_eq!(output.outcome, Outcome::Verified);
    assert_eq!(reads.watched.load(Ordering::SeqCst), 4);
    assert_eq!(reads.watched_jobs.load(Ordering::SeqCst), 1);
    assert_eq!(watch_count(store).await, 2);
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
        h.models.runtime().snapshot().state,
        pam_model::RuntimeState::Idle
    ));
    other.args = json!({"ticket":"watch"});
    let durable = crate::flow_result_service::result(other).await.unwrap();
    assert_eq!(
        durable.body["agent_result"]["workflow"]["outcome"],
        "verified"
    );
}
