use super::{ExecContext, FlowService, FlowSettings, RunState};
use crate::flow_exec::{StepReport, StepStatus};
use crate::flow_recovery::{Prepare, Recovery, WatchState};
use crate::{
    approval::ApprovalService,
    connector_service::{ConfigurePatch, ConnectorService, CredentialAction},
    daemon::CompletionRouter,
    executor::CapabilityFailure,
    log_service::LogService,
    model_service::ModelService,
    queue::QueueManager,
    request_budget::{Limits, RequestBudget},
    secrets::{FakeSecretBackend, SecretStore},
    transport::EventPublisher,
};
use pam_connectors::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use pam_flow::{Action, Flow, Vars};
use pam_proto::Caller;
use pam_store::Store;
use serde_json::json;
use std::{
    collections::BTreeMap,
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

fn flow() -> pam_flow::Flow {
    pam_flow::parse("schema: 1\nid: watch-test\nname: Watch\nsteps:\n - id: wait\n   connector: github\n   call: run\n   with: {repo: 'owner/repo', run_id: 1, run_attempt: 1}\n   watch: {}\n   role: observe\n").unwrap()
}

#[tokio::test]
async fn polls_reuse_snapshot_and_completed_cursor_preserves_committed_progress() {
    let store = Store::open_in_memory().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().canonicalize().unwrap();
    store
        .insert_request("r", "flow.run", repo.to_str().unwrap(), "test", "{}", None)
        .await
        .unwrap();
    store
        .set_setting(
            "flows.scope_policy",
            &json!({"version":1,"repositories":[{"root":repo,"connectors":[]}]}).to_string(),
        )
        .await
        .unwrap();
    let flow = flow();
    let (mut recovery, snapshot) = Recovery::open(&store, "r", &flow, &repo, &Vars::new())
        .await
        .unwrap();
    let initial: serde_json::Value = serde_json::from_str(
        &store
            .read_flow_journal("r")
            .await
            .unwrap()
            .unwrap()
            .checkpoint_json,
    )
    .unwrap();
    let mut state = WatchState {
        step: "wait".into(),
        args_fingerprint: "a".repeat(64),
        origin: crate::evidence_service::ConnectorTarget {
            connector: pam_flow::ConnectorId::Github,
            base_url: "https://api.github.com/".into(),
            call: "run_status".into(),
            args: std::collections::BTreeMap::new(),
        },
        profile_stamp: "b".repeat(64),
        authorization_revision: 0,
        polls: 1,
        errors: 0,
        next_poll_ms: 10,
        collecting: false,
        observation: json!({"status":"pending"}),
        pins: serde_json::Value::Null,
        last_digest: "c".repeat(64),
        last_evidence: "ev_poll".into(),
    };
    for poll in 1..=2 {
        recovery
            .prepare(&store, "r", &flow.steps[0], Prepare::Run)
            .await
            .unwrap();
        state.polls = poll;
        recovery
            .settle_watch(&store, "r", state.clone(), &[])
            .await
            .unwrap();
        let row = store.read_flow_journal("r").await.unwrap().unwrap();
        let cursor: serde_json::Value = serde_json::from_str(&row.checkpoint_json).unwrap();
        assert_eq!(cursor["evidence_id"], initial["evidence_id"]);
        assert_eq!(cursor["watch"]["polls"], poll);
        assert_eq!(store.list_evidence("r").await.unwrap().len(), 1);
    }
    // A retained cursor never makes missing or unauthorized poll evidence readable.
    assert!(
        Recovery::open(&store, "r", &flow, &repo, &Vars::new())
            .await
            .is_err()
    );
    recovery
        .prepare(&store, "r", &flow.steps[0], Prepare::Run)
        .await
        .unwrap();
    recovery.settle(&store, "r", &snapshot, true).await.unwrap();
    let row = store.read_flow_journal("r").await.unwrap().unwrap();
    let cursor: serde_json::Value = serde_json::from_str(&row.checkpoint_json).unwrap();
    assert!(cursor["watch"].is_null());
    assert_eq!(cursor["last_watch_evidence"], "ev_poll");
    assert_ne!(cursor["evidence_id"], initial["evidence_id"]);
}

#[test]
fn github_watch_assertion_uses_actual_conclusion_and_never_top_level_success() {
    let mut step = flow().steps.remove(0);
    step.expect_status = Some("success".into());
    let mut report = StepReport::new("wait", "connector", StepStatus::Succeeded);
    super::apply_connector_assertion(
        &step,
        Some(&json!({"status":"success","run":{"conclusion":"failure"}})),
        &mut report,
    );
    assert_eq!(report.status, StepStatus::Failed);
    let mut report = StepReport::new("wait", "connector", StepStatus::Succeeded);
    super::apply_connector_assertion(
        &step,
        Some(&json!({"run":{"conclusion":"success"}})),
        &mut report,
    );
    assert_eq!(report.status, StepStatus::Succeeded);
}

#[tokio::test]
async fn substituted_run_is_committed_as_conflict_without_replacing_valid_pins() {
    let store = Store::open_in_memory().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().canonicalize().unwrap();
    store
        .insert_request("r", "flow.run", repo.to_str().unwrap(), "test", "{}", None)
        .await
        .unwrap();
    store
        .set_setting(
            "flows.scope_policy",
            &json!({"version":1,"repositories":[{"root":repo,"connectors":[]}]}).to_string(),
        )
        .await
        .unwrap();
    let flow = flow();
    let (mut recovery, _) = Recovery::open(&store, "r", &flow, &repo, &Vars::new())
        .await
        .unwrap();
    let pins = json!({"run_id":1,"run_attempt":1});
    let received = crate::flow_watch::Observation {
        state: crate::flow_watch::State::Terminal,
        payload: json!({"run_id":2,"run_attempt":1,"status":"completed","conclusion":"success"}),
        digest: "unused".into(),
    };
    let conflict = super::watch_runtime::conflicting_observation(
        pam_flow::ConnectorId::Github,
        &pins,
        &received,
    )
    .unwrap();
    assert_eq!(conflict.state, crate::flow_watch::State::Unavailable);
    assert_eq!(conflict.payload["cause"], "watch_target_changed");
    assert_eq!(conflict.payload["received"], received.payload);
    let bytes = serde_json::to_vec(&conflict.payload).unwrap();
    store
        .insert_evidence("ev_conflict", "r", "flow.watch", &bytes, None)
        .await
        .unwrap();
    let state = WatchState {
        step: "wait".into(),
        args_fingerprint: "a".repeat(64),
        origin: crate::evidence_service::ConnectorTarget {
            connector: pam_flow::ConnectorId::Github,
            base_url: "https://api.github.com/".into(),
            call: "run_status".into(),
            args: std::collections::BTreeMap::new(),
        },
        profile_stamp: "b".repeat(64),
        authorization_revision: 0,
        polls: 2,
        errors: 0,
        next_poll_ms: 0,
        collecting: false,
        observation: conflict.payload,
        pins: pins.clone(),
        last_digest: conflict.digest,
        last_evidence: "ev_conflict".into(),
    };
    recovery
        .prepare(&store, "r", &flow.steps[0], Prepare::Run)
        .await
        .unwrap();
    recovery
        .settle_watch(&store, "r", state, &[])
        .await
        .unwrap();
    let row = store.read_flow_journal("r").await.unwrap().unwrap();
    let cursor: serde_json::Value = serde_json::from_str(&row.checkpoint_json).unwrap();
    assert_eq!(cursor["watch"]["pins"], pins);
    assert_eq!(
        cursor["watch"]["observation"]["cause"],
        "watch_target_changed"
    );
    assert_eq!(cursor["watch"]["collecting"], false);
    assert_eq!(cursor["watch"]["next_poll_ms"], 0);
    assert_eq!(row.evidence_refs, vec!["ev_conflict"]);
    assert!(
        store
            .list_evidence("r")
            .await
            .unwrap()
            .iter()
            .any(|evidence| evidence.id == "ev_conflict")
    );
}

#[test]
fn only_transient_connector_errors_consume_watch_outage_allowance() {
    use crate::connector_service::InvokeError;
    use pam_connectors::ConnectorError;
    for error in [
        ConnectorError::Auth,
        ConnectorError::Forbidden,
        ConnectorError::NotFound,
        ConnectorError::BadArgs("bad selector".into()),
        ConnectorError::BadResponse("wrong identity".into()),
        ConnectorError::Certificate,
        ConnectorError::TooLarge {
            bytes: 2,
            maximum: 1,
        },
    ] {
        assert!(!super::watch_runtime::watch_retryable(
            &InvokeError::Connector(error)
        ));
    }
    for error in [
        ConnectorError::Timeout,
        ConnectorError::Network("offline".into()),
        ConnectorError::RateLimited { retry_after: None },
        ConnectorError::Remote { status: 503 },
    ] {
        assert!(super::watch_runtime::watch_retryable(
            &InvokeError::Connector(error)
        ));
    }
    assert!(!super::watch_runtime::watch_retryable(
        &InvokeError::CredentialMissing
    ));
}

#[test]
fn only_connectors_with_a_status_call_can_be_watched() {
    use super::watch_runtime::status_call;
    assert_eq!(
        status_call(pam_flow::ConnectorId::Github),
        Some("run_status")
    );
    assert_eq!(
        status_call(pam_flow::ConnectorId::Jenkins),
        Some("build_status")
    );
    assert_eq!(
        status_call(pam_flow::ConnectorId::Sonarqube),
        Some("ce_status")
    );
    assert_eq!(status_call(pam_flow::ConnectorId::Jira), None);
}

// --- watch admission through the runtime ---------------------------------

const SERVER: &str = "https://github.test/";
const SHA: &str = "abcdef1234567890abcdef1234567890abcdef12";
const SOURCE: &str = "https://git.example/team/repo.git";
/// A watched GitHub run: five polls at a fixed five-second cadence.
const WATCHED: &str = r"schema: 1
id: watched
name: Watched
steps:
 - id: wait
   connector: github
   call: run
   with: {repo: team/repo, run_id: 9, run_attempt: 1}
   watch: {max_polls: 5, interval: 5s, max_interval: 5s}
   role: observe
";

/// How the fake GitHub answers the one status read a watch makes.
#[derive(Clone, Copy)]
enum Answer {
    /// The run is still queued.
    Pending,
    /// `429` with this many seconds of `Retry-After`.
    RateLimited(u64),
}

struct Github {
    answer: Mutex<Answer>,
    reads: AtomicUsize,
}

impl HttpTransport for Github {
    fn send<'a>(
        &'a self,
        request: HttpRequest,
        _deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>> {
        Box::pin(async move {
            assert_eq!(
                request.url.path(),
                "/repos/team/repo/actions/runs/9/attempts/1",
                "a watch polls the exact run attempt and nothing else"
            );
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(match *self.answer.lock().unwrap() {
                Answer::Pending => HttpResponse {
                    status: 200,
                    headers: vec![],
                    body: serde_json::to_vec(&json!({"id":9,"run_attempt":1,"head_sha":SHA,"status":"queued","conclusion":null,
                        "repository":{"full_name":"team/repo","clone_url":SOURCE},"head_repository":{"full_name":"team/repo","clone_url":SOURCE}})).unwrap(),
                },
                Answer::RateLimited(seconds) => HttpResponse {
                    status: 429,
                    headers: vec![("Retry-After".to_owned(), seconds.to_string())],
                    body: b"{\"message\":\"slow down\"}".to_vec(),
                },
            })
        })
    }
}

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// The GitHub connector enabled on [`SERVER`] with a fixture credential.
async fn connectors(
    store: &Arc<Store>,
    secrets: &Arc<SecretStore>,
    transport: Arc<Github>,
) -> Arc<ConnectorService> {
    let connectors = Arc::new(ConnectorService::new(
        store.clone(),
        secrets.clone(),
        transport,
    ));
    connectors
        .configure(
            pam_flow::ConnectorId::Github,
            ConfigurePatch {
                enabled: Some(true),
                base_url: Some(Some(SERVER.to_owned())),
                credential: Some(CredentialAction::Set(crate::secrets::Secret::new(
                    "fixture-only".to_owned(),
                ))),
                ..ConfigurePatch::default()
            },
        )
        .await
        .unwrap();
    connectors
}

/// Admits, authorizes and starts the `watch` ticket on `root`, the state a
/// leased `flow.run` request is in when the engine runs it.
async fn admit(store: &Store, root: &std::path::Path) {
    store
        .insert_admitted_request(
            "watch",
            "flow.run",
            root.to_str().unwrap(),
            "fixture",
            r#"{"id":"watched"}"#,
            None,
            now_ms() + 120_000,
        )
        .await
        .unwrap();
    assert!(
        store
            .authorize_queued_request("watch", root.to_str().unwrap(), now_ms())
            .await
            .unwrap()
    );
    assert!(store.start_queued_request("watch", now_ms()).await.unwrap());
}

/// A real flow service, store, journal and GitHub scope around one admitted
/// `flow.run` ticket, with only the HTTP transport and keychain faked. The
/// budget is injected so a test can exhaust one allowance at a time.
struct Fixture {
    _base: tempfile::TempDir,
    _repo: tempfile::TempDir,
    root: PathBuf,
    store: Arc<Store>,
    github: Arc<Github>,
    flow: Flow,
    settings: FlowSettings,
    ctx: ExecContext,
}

impl Fixture {
    async fn new(answer: Answer, budget: Arc<RequestBudget>) -> Self {
        let base = tempfile::tempdir().unwrap();
        let repo = tempfile::tempdir().unwrap();
        let root = repo.path().canonicalize().unwrap();
        let store = Arc::new(Store::open_in_memory().await.unwrap());
        store
            .set_setting("policy.profile", "\"relaxed\"")
            .await
            .unwrap();
        store.set_setting("flows.scope_policy",&json!({"version":1,"repositories":[{"root":root,"connectors":[{"connector":"github","base_url":SERVER,"access":"targets","targets":["team/repo"]}]}]}).to_string()).await.unwrap();
        let (events, mut receiver) = EventPublisher::for_tests();
        tokio::spawn(async move { while receiver.recv().await.is_some() {} });
        let approvals = Arc::new(ApprovalService::new(
            store.clone(),
            events.clone(),
            Duration::from_secs(10),
        ));
        let models = ModelService::new(store.clone()).await.unwrap();
        let logs = LogService::new(store.clone(), models.clone());
        let secrets = Arc::new(SecretStore::new(Arc::new(FakeSecretBackend::default())));
        let github = Arc::new(Github {
            answer: Mutex::new(answer),
            reads: AtomicUsize::new(0),
        });
        let connectors = connectors(&store, &secrets, github.clone()).await;
        let flows = crate::flow_service_test::flows_for_tests(
            base.path(),
            &store,
            &approvals,
            &connectors,
            &logs,
        )
        .await;
        let settings = flows.settings().await.unwrap();
        admit(&store, &root).await;
        let (keep, cancel) = tokio::sync::watch::channel(false);
        // The sender lives as long as the store does; a closed channel would
        // read as cancellation.
        std::mem::forget(keep);
        let ctx = ExecContext {
            budget,
            request_id: "watch".into(),
            args: json!({"id":"watched"}),
            cancel,
            events,
            store: store.clone(),
            queue: Arc::new(QueueManager::new(store.clone())),
            models,
            router: CompletionRouter::new(),
            approvals,
            flows,
            secrets,
            caller: Caller {
                agent: "fixture".into(),
                repo: root.to_string_lossy().into_owned(),
                pid: std::process::id(),
            },
            capability: "flow.run".into(),
            started_at: Instant::now(),
        };
        Self {
            _base: base,
            _repo: repo,
            root,
            store,
            github,
            flow: pam_flow::parse(WATCHED).unwrap(),
            settings,
            ctx,
        }
    }

    fn service(&self) -> &FlowService {
        &self.ctx.flows
    }

    /// A run over the ticket's journal, stamped the way `run_step` stamps a
    /// watched step before it advances the watch.
    async fn state(&self) -> RunState<'_> {
        let mut state = RunState::restore(
            self.service(),
            &self.ctx,
            &self.flow,
            &self.settings,
            self.root.clone(),
            Vars::new(),
            self.ctx.cancel.clone(),
        )
        .await
        .unwrap();
        state.watch_grant_stamp = Some(state.watch_stamp().await.unwrap());
        state
    }

    /// Journals a pending watch that already made `polls` samples, exactly
    /// as an earlier run of this ticket would have left it.
    async fn seed_polls(&self, state: &mut RunState<'_>, polls: u32) {
        let step = &self.flow.steps[0];
        let Action::Connector { with, .. } = &step.action else {
            panic!("the watched step is a connector call");
        };
        let args = state.substitute_args(with).unwrap();
        let fingerprint = pam_compact::sha256_hex(&crate::flow_recovery::encode(&args).unwrap());
        let (profile_stamp, authorization_revision) = state.watch_stamp().await.unwrap();
        state
            .recovery
            .prepare(&self.store, "watch", step, Prepare::Run)
            .await
            .unwrap();
        state
            .recovery
            .settle_watch(
                &self.store,
                "watch",
                WatchState {
                    step: step.id.clone(),
                    args_fingerprint: fingerprint,
                    origin: crate::evidence_service::ConnectorTarget {
                        connector: pam_flow::ConnectorId::Github,
                        base_url: SERVER.into(),
                        call: "run_status".into(),
                        args: BTreeMap::new(),
                    },
                    profile_stamp,
                    authorization_revision,
                    polls,
                    errors: 0,
                    next_poll_ms: 0,
                    collecting: false,
                    observation: json!({"status":"queued","watch_state":"pending"}),
                    pins: serde_json::Value::Null,
                    last_digest: "c".repeat(64),
                    last_evidence: "ev_seed".into(),
                },
                &[],
            )
            .await
            .unwrap();
    }

    async fn journal_watch(&self) -> serde_json::Value {
        let row = self
            .store
            .read_flow_journal("watch")
            .await
            .unwrap()
            .unwrap();
        let cursor: serde_json::Value = serde_json::from_str(&row.checkpoint_json).unwrap();
        cursor["watch"].clone()
    }

    fn reads(&self) -> usize {
        self.github.reads.load(Ordering::SeqCst)
    }

    /// Commits the attempt and advances the watch, the order `run_step`
    /// keeps: intent is journalled before any poll.
    async fn advance(
        &self,
        state: &mut RunState<'_>,
    ) -> Result<Option<StepReport>, CapabilityFailure> {
        let step = &self.flow.steps[0];
        state
            .recovery
            .prepare(&self.store, "watch", step, Prepare::Run)
            .await
            .unwrap();
        state.advance_watch(step).await
    }
}

fn budget(deadline: Duration, http_calls: u64) -> Arc<RequestBudget> {
    RequestBudget::with_limits(
        Instant::now() + deadline,
        Limits {
            http_calls,
            ..Limits::default()
        },
    )
}

/// The blocked report `advance_watch` settles a refused admission with.
fn blocked(outcome: Result<Option<StepReport>, CapabilityFailure>) -> StepReport {
    match outcome {
        Ok(Some(report)) => {
            assert_eq!(report.status, StepStatus::Blocked);
            report
        }
        other => panic!("expected a blocked report, got {other:?}"),
    }
}

#[tokio::test]
async fn a_watch_that_spent_its_polls_is_blocked_before_polling_again() {
    let fx = Fixture::new(Answer::Pending, budget(Duration::from_secs(3600), 128)).await;
    let mut state = fx.state().await;
    fx.seed_polls(&mut state, 5).await;
    let report = blocked(fx.advance(&mut state).await);
    let error = report.error.unwrap();
    assert_eq!(error.cause, "watch_poll_limit");
    assert!(error.detail.contains("poll allowance"), "{}", error.detail);
    // The retained poll evidence is what the reader is pointed at.
    assert_eq!(report.evidence, ["ev_seed"]);
    assert_eq!(fx.reads(), 0, "no further status read is made");
    assert_eq!(fx.journal_watch().await["polls"], 5);
}

#[tokio::test]
async fn a_watch_without_http_headroom_for_collection_is_blocked_before_polling() {
    // GitHub's terminal collection needs two calls plus the poll: three.
    let fx = Fixture::new(Answer::Pending, budget(Duration::from_secs(3600), 2)).await;
    let mut state = fx.state().await;
    let error = blocked(fx.advance(&mut state).await).error.unwrap();
    assert_eq!(error.cause, "watch_collection_budget");
    assert!(error.detail.contains("HTTP allowance"), "{}", error.detail);
    assert_eq!(fx.reads(), 0);
    assert!(fx.journal_watch().await.is_null(), "nothing was committed");
}

#[tokio::test]
async fn a_watch_whose_request_deadline_has_passed_is_blocked_before_polling() {
    let fx = Fixture::new(Answer::Pending, budget(Duration::ZERO, 128)).await;
    let mut state = fx.state().await;
    let error = blocked(fx.advance(&mut state).await).error.unwrap();
    assert_eq!(error.cause, "watch_deadline");
    assert!(
        error.detail.contains("original request deadline"),
        "{}",
        error.detail
    );
    assert_eq!(fx.reads(), 0);
}

#[tokio::test]
async fn a_pending_poll_parks_at_the_policy_interval() {
    let fx = Fixture::new(Answer::Pending, budget(Duration::from_secs(3600), 128)).await;
    let mut state = fx.state().await;
    let before = now_ms();
    let parked = fx.advance(&mut state).await;
    let after = now_ms();
    let Err(CapabilityFailure::Parked { resume_at_ms }) = parked else {
        panic!("a pending run parks the lease, got {parked:?}");
    };
    assert!(
        (before + 5_000..=after + 5_000).contains(&resume_at_ms),
        "five-second interval: {resume_at_ms} not within [{before}, {after}] + 5000"
    );
    assert_eq!(fx.reads(), 1);
    let watch = fx.journal_watch().await;
    assert_eq!(watch["polls"], 1);
    assert_eq!(watch["errors"], 0);
    assert_eq!(watch["next_poll_ms"], resume_at_ms);
    assert_eq!(watch["observation"]["watch_state"], "pending");
}

#[tokio::test]
async fn a_retry_after_beyond_max_interval_stretches_the_park_and_counts_an_outage() {
    // The policy caps backoff at five seconds; the service asks for ten
    // minutes, and the service wins because the request has an hour left.
    let fx = Fixture::new(
        Answer::RateLimited(600),
        budget(Duration::from_secs(3600), 128),
    )
    .await;
    let mut state = fx.state().await;
    let before = now_ms();
    let parked = fx.advance(&mut state).await;
    let after = now_ms();
    let Err(CapabilityFailure::Parked { resume_at_ms }) = parked else {
        panic!("a throttled poll parks the lease, got {parked:?}");
    };
    assert!(
        (before + 600_000..=after + 600_000).contains(&resume_at_ms),
        "Retry-After floors the delay: {resume_at_ms} not within [{before}, {after}] + 600000"
    );
    assert_eq!(fx.reads(), 1);
    let watch = fx.journal_watch().await;
    assert_eq!(watch["polls"], 1);
    assert_eq!(watch["errors"], 1, "a throttled read is one outage");
    assert_eq!(watch["next_poll_ms"], resume_at_ms);
    assert_eq!(watch["observation"]["watch_state"], "unavailable");
    let evidence = fx.store.list_evidence("watch").await.unwrap();
    assert_eq!(
        evidence
            .iter()
            .filter(|row| row.kind == "flow.watch")
            .count(),
        1,
        "the unavailable observation is filed as watch evidence"
    );
}

#[tokio::test]
async fn a_retry_after_beyond_the_request_deadline_blocks_after_committing_the_poll() {
    // Thirty seconds left; the service asks for ten minutes: the next poll
    // can never happen inside the admission, so the watch is blocked — after
    // the throttled sample is committed, so nothing is repeated on resume.
    let fx = Fixture::new(
        Answer::RateLimited(600),
        budget(Duration::from_secs(30), 128),
    )
    .await;
    let mut state = fx.state().await;
    let report = blocked(fx.advance(&mut state).await);
    let error = report.error.unwrap();
    assert_eq!(error.cause, "watch_deadline");
    assert_eq!(fx.reads(), 1);
    let watch = fx.journal_watch().await;
    assert_eq!(watch["polls"], 1);
    assert_eq!(watch["errors"], 1);
    assert!(
        watch["next_poll_ms"].as_i64().unwrap() >= now_ms() + 599_000,
        "{watch}"
    );
    assert_eq!(
        report.evidence,
        [watch["last_evidence"].as_str().unwrap()],
        "the blocked report cites the committed sample"
    );
}
