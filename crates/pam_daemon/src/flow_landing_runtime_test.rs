use super::landing_runtime::{
    EffectPhase, attempted, broker_error, checkout_error, effect_verdict, landing_workspace,
    release_workspace,
};
use super::{Attempt, CapabilityFailure, StepStatus};
use crate::flow_recovery::{Prepare, Recovery};
use crate::landing_checkout::{CANCELLED, CheckoutError};
use crate::landing_git::{PushObservation, PushState, RemoteRef};
use pam_flow::{LandingOperation as Op, Vars};
use pam_store::{FlowJournalState, Store};
use serde_json::{Value, json};
use std::path::Path;

#[tokio::test]
async fn landing_poll_commits_progress_without_copying_or_advancing_protected_snapshot() {
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
    let flow=pam_flow::parse("schema: 1\nid: land\nname: Land\ncorrelation: { repository: 'https://github.com/owner/repo.git', commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa }\nsteps:\n - id: freeze\n   landing: freeze\n").unwrap();
    let (mut recovery, _) = Recovery::open(&store, "r", &flow, &repo, &Vars::new())
        .await
        .unwrap();
    let original = store.read_flow_journal("r").await.unwrap().unwrap();
    let original_cursor: Value = serde_json::from_str(&original.checkpoint_json).unwrap();
    for id in ["poll1", "poll1", "poll2"] {
        recovery
            .prepare(&store, "r", &flow.steps[0], Prepare::Run)
            .await
            .unwrap();
        recovery
            .settle_landing_wait(&store, "r", id, &[])
            .await
            .unwrap();
        let journal = store.read_flow_journal("r").await.unwrap().unwrap();
        assert_eq!(journal.state, FlowJournalState::Ready);
        let cursor: Value = serde_json::from_str(&journal.checkpoint_json).unwrap();
        assert_eq!(cursor["evidence_id"], original_cursor["evidence_id"]);
        assert_eq!(cursor["next_step"], 0);
        assert_eq!(cursor["last_watch_evidence"], id);
        assert_eq!(journal.evidence_refs, [id]);
    }
    assert_eq!(recovery.revision, 6);
    assert_eq!(
        store
            .read_flow_journal("r")
            .await
            .unwrap()
            .unwrap()
            .identity,
        original.identity
    );
}

fn cause(failure: &CapabilityFailure) -> &str {
    match failure {
        CapabilityFailure::Refused { cause, .. } => cause,
        CapabilityFailure::Cancelled => "<cancelled>",
        CapabilityFailure::Failed { .. } => "<failed>",
        CapabilityFailure::Parked { .. } => "<parked>",
    }
}

#[test]
fn the_cancel_signal_ends_a_landing_stage_cancelled_not_blocked() {
    assert_eq!(
        checkout_error(CheckoutError {
            cause: CANCELLED,
            detail: "checkout capture cancelled",
        }),
        CapabilityFailure::Cancelled
    );
    assert_eq!(
        cause(&checkout_error(CheckoutError {
            cause: "landing_checkout_changed",
            detail: "source refs changed during capture",
        })),
        "landing_checkout_changed"
    );
    let cancelled =
        crate::connector_service::InvokeError::Connector(pam_connectors::ConnectorError::Policy {
            cause: CANCELLED,
            detail: "The landing Git operation was cancelled before it started.".to_owned(),
        });
    assert_eq!(broker_error(&cancelled), CapabilityFailure::Cancelled);
    let timeout =
        crate::connector_service::InvokeError::Connector(pam_connectors::ConnectorError::Timeout);
    assert_eq!(cause(&broker_error(&timeout)), "connector_timeout");
    assert!(matches!(attempted(None), Err(CapabilityFailure::Cancelled)));
    assert!(matches!(
        attempted(Some(Attempt::Failed {
            exit_status: Some(1),
            output: Vec::new(),
            result: None,
            status: StepStatus::Failed,
            cause: "exit_status",
            detail: String::new(),
            recovery: String::new(),
            retry_after: None,
        })),
        Ok(Attempt::Failed { .. })
    ));
}

fn prepared(state: PushState) -> PushObservation {
    PushObservation {
        ref_name: "refs/heads/feature/work".into(),
        expected_old: Some("a".repeat(40)),
        requested_commit: "b".repeat(40),
        state,
    }
}
fn observed(oid: Option<&str>) -> RemoteRef {
    RemoteRef {
        ref_name: "refs/heads/feature/work".into(),
        oid: oid.map(str::to_owned),
    }
}

#[test]
fn an_unchanged_ref_after_a_rejected_push_is_a_typed_refusal_never_a_resend() {
    let commit = "b".repeat(40);
    let old = "a".repeat(40);
    effect_verdict(
        &observed(Some(&commit)),
        &prepared(PushState::ReportedSuccess),
        Op::Push,
        EffectPhase::JustRan,
    )
    .unwrap();
    let rejected = effect_verdict(
        &observed(Some(&old)),
        &prepared(PushState::Uncertain),
        Op::Push,
        EffectPhase::JustRan,
    )
    .unwrap_err();
    assert_eq!(cause(&rejected), "landing_push_rejected");
    let contradiction = effect_verdict(
        &observed(Some(&old)),
        &prepared(PushState::ReportedSuccess),
        Op::Push,
        EffectPhase::JustRan,
    )
    .unwrap_err();
    assert_eq!(cause(&contradiction), "landing_effect_uncertain");
    let resumed = effect_verdict(
        &observed(Some(&old)),
        &prepared(PushState::Uncertain),
        Op::Push,
        EffectPhase::Resumed,
    )
    .unwrap_err();
    assert_eq!(cause(&resumed), "landing_effect_uncertain");
    assert!(matches!(
        &resumed,
        CapabilityFailure::Refused { detail, .. } if detail.contains("observed old value")
    ));
    for phase in [EffectPhase::JustRan, EffectPhase::Resumed] {
        let moved = effect_verdict(
            &observed(Some(&"c".repeat(40))),
            &prepared(PushState::Uncertain),
            Op::Push,
            phase,
        )
        .unwrap_err();
        assert_eq!(cause(&moved), "landing_effect_uncertain");
        let gone = effect_verdict(
            &observed(None),
            &prepared(PushState::Uncertain),
            Op::Sync,
            phase,
        )
        .unwrap_err();
        assert_eq!(cause(&gone), "landing_effect_uncertain");
    }
    let sync_unchanged = effect_verdict(
        &observed(Some(&old)),
        &prepared(PushState::Uncertain),
        Op::Sync,
        EffectPhase::Resumed,
    )
    .unwrap_err();
    assert_eq!(cause(&sync_unchanged), "landing_effect_uncertain");
    assert!(matches!(
        sync_unchanged,
        CapabilityFailure::Refused { detail, .. }
            if detail.contains("local base") && detail.contains("observed old value")
    ));
}

#[test]
fn only_a_checktree_of_the_exact_freeze_shape_names_a_removable_workspace() {
    let root = Path::new("/private/workspaces");
    let ulid = ulid::Ulid::new().to_string();
    let good = root.join(format!("landing-{ulid}")).join("tree");
    assert_eq!(
        landing_workspace(&good, root).as_deref(),
        Some(root.join(format!("landing-{ulid}")).as_path())
    );
    for wrong in [
        root.join(format!("landing-{ulid}")),
        root.join(format!("landing-{ulid}")).join("artifacts"),
        root.join("landing-not-a-ulid").join("tree"),
        root.join(format!("other-{ulid}")).join("tree"),
        Path::new("/elsewhere")
            .join(format!("landing-{ulid}"))
            .join("tree"),
        root.join("nested")
            .join(format!("landing-{ulid}"))
            .join("tree"),
    ] {
        assert_eq!(landing_workspace(&wrong, root), None, "{}", wrong.display());
    }
}

#[test]
fn releasing_a_terminal_ticket_removes_its_workspace_and_nothing_else() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let ulid = ulid::Ulid::new().to_string();
    let workspace = root.join(format!("landing-{ulid}"));
    let tree = workspace.join("tree");
    std::fs::create_dir_all(tree.join("src")).unwrap();
    std::fs::create_dir_all(workspace.join("artifacts")).unwrap();
    std::fs::write(tree.join("src/main.rs"), "fn main() {}\n").unwrap();
    let neighbour = root.join(format!("landing-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(neighbour.join("tree")).unwrap();
    let foreign = root.join("keep").join("tree");
    std::fs::create_dir_all(&foreign).unwrap();
    assert!(!release_workspace(&foreign, &root));
    assert!(foreign.is_dir());
    assert!(release_workspace(&tree, &root));
    assert!(!workspace.exists());
    assert!(neighbour.join("tree").is_dir());
    assert!(foreign.is_dir());
    // Releasing again is idempotent: already gone counts as released.
    assert!(release_workspace(&tree, &root));
}

/// A push whose process verdict was journalled as rejected is a rejection
/// whether the verdict is fresh or read back after a crash; only a resumed
/// intent with no verdict at all stays uncertain.
#[test]
fn a_journalled_rejection_stays_a_rejection_on_resume() {
    let old = "a".repeat(40);
    for phase in [EffectPhase::JustRan, EffectPhase::Resumed] {
        let rejected = effect_verdict(
            &observed(Some(&old)),
            &prepared(PushState::Rejected),
            Op::Push,
            phase,
        )
        .unwrap_err();
        assert_eq!(cause(&rejected), "landing_push_rejected");
        assert!(matches!(
            &rejected,
            CapabilityFailure::Refused { detail, .. }
                if detail.contains("rejected the push") && detail.contains("will not resend")
        ));
    }
    let uncertain = effect_verdict(
        &observed(Some(&old)),
        &prepared(PushState::Uncertain),
        Op::Push,
        EffectPhase::Resumed,
    )
    .unwrap_err();
    assert_eq!(cause(&uncertain), "landing_effect_uncertain");
    // A rejected verdict never rescues a ref that did move: that is still
    // an unconfirmed effect, not a clean rejection.
    let moved = effect_verdict(
        &observed(Some(&"c".repeat(40))),
        &prepared(PushState::Rejected),
        Op::Push,
        EffectPhase::Resumed,
    )
    .unwrap_err();
    assert_eq!(cause(&moved), "landing_effect_uncertain");
}

/// Typed landing stages driven over a seeded session — the private
/// document freeze leaves behind — with a fake GitHub and no Git at all.
/// Every refusal here is reached before the stage's live checkout
/// revalidation, so nothing needs a real repository. (`has_intent`'s
/// operation mismatch sits behind that revalidation and stays with the
/// macOS integration harness.) Landing workspaces are Unix-only.
#[cfg(unix)]
mod seeded {
    use super::super::{ExecContext, FlowSettings, RunState};
    use crate::{
        approval::ApprovalService,
        connector_service::{ConfigurePatch, ConnectorService, CredentialAction},
        daemon::CompletionRouter,
        evidence_service::{self, CaptureScope, ConnectorTarget, EvidenceOrigin},
        executor::CapabilityFailure,
        flow_exec::{StepReport, StepStatus},
        flow_recovery::KIND,
        landing_checkout::CheckoutReceipt,
        log_service::LogService,
        model_service::ModelService,
        queue::QueueManager,
        request_budget::{Limits, RequestBudget},
        secrets::{FakeSecretBackend, SecretStore},
        transport::EventPublisher,
    };
    use pam_connectors::{HttpRequest, HttpResponse, HttpTransport, Method, TransportError};
    use pam_flow::{Action, ArgValue, ConnectorId, Flow, Vars};
    use pam_proto::Caller;
    use pam_store::Store;
    use serde_json::{Value, json};
    use std::{
        collections::BTreeMap,
        fmt::Write as _,
        future::Future,
        path::PathBuf,
        pin::Pin,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    const SOURCE: &str = "https://github.test/team/repo.git";
    const SERVER: &str = "https://api.github.test/";
    const TICKET: &str = "landing-ticket";

    fn sha() -> String {
        "a".repeat(40)
    }
    fn base_sha() -> String {
        "b".repeat(40)
    }
    fn now() -> i64 {
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
    }

    /// The complete landing recipe, one step per operation.
    fn recipe() -> String {
        let mut yaml = format!(
            "schema: 1\nid: landing\nname: Landing\ncorrelation: {{ repository: '{SOURCE}', commit: '{}' }}\nsteps:\n",
            sha()
        );
        let mut previous = None;
        for operation in [
            "freeze",
            "validate",
            "push",
            "ensure_pr",
            "verify_pr",
            "merge",
            "verify_main",
        ] {
            let id = operation.replace('_', "-");
            writeln!(yaml, " - id: {id}\n   landing: {operation}").unwrap();
            if let Some(prior) = previous {
                writeln!(yaml, "   needs: [{prior}]").unwrap();
            }
            if matches!(operation, "validate" | "verify_pr" | "verify_main") {
                yaml.push_str("   role: verify\n");
            }
            previous = Some(id);
        }
        yaml
    }

    /// The relaxed profile plus the GUI's connector scope and landing
    /// policy for `repo`, as the integration harness seeds them.
    async fn configure(store: &Store, repo: &std::path::Path, workspace: &std::path::Path) {
        store
            .set_setting("policy.profile", "\"relaxed\"")
            .await
            .unwrap();
        store.set_setting("flows.scope_policy",&json!({"version":1,"repositories":[{"root":repo,"connectors":[{"connector":"github","base_url":SERVER,"access":"targets","targets":["team/repo"]}]}]}).to_string()).await.unwrap();
        store.set_setting("flows.landing_policy",&json!({"version":1,"repositories":[{"root":repo,"repository":SOURCE,"github_server":SERVER,"github_repository":"team/repo","base":"main","branches":["feature/work"],"workspace_root":workspace,"checks":[{"name":"local","argv":["true"],"timeout_seconds":10}],"required_checks":["ci"],"main_checks":["ci"],"permissions":{"push":true,"create_pr":true,"merge":true,"sync":true}}]}).to_string()).await.unwrap();
    }

    /// Admits, authorizes and starts the landing ticket on `repo`.
    async fn admit(store: &Store, repo: &std::path::Path) {
        store
            .insert_admitted_request(
                TICKET,
                "flow.run",
                repo.to_str().unwrap(),
                "fixture",
                r#"{"id":"landing"}"#,
                None,
                now() + 120_000,
            )
            .await
            .unwrap();
        assert!(
            store
                .authorize_queued_request(TICKET, repo.to_str().unwrap(), now())
                .await
                .unwrap()
        );
        assert!(store.start_queued_request(TICKET, now()).await.unwrap());
    }

    /// A GitHub that answers the exact reads a landing stage may make:
    /// the required checks of the frozen commit and the PR's state.
    struct Github {
        /// `success`, `failure`, or a pending status such as `in_progress`.
        checks: &'static str,
        /// `open` or `closed`.
        pr_state: &'static str,
        requests: Mutex<Vec<String>>,
    }

    impl HttpTransport for Github {
        fn send<'a>(
            &'a self,
            request: HttpRequest,
            _deadline: Instant,
        ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>>
        {
            Box::pin(async move {
                assert_eq!(request.method, Method::Get, "landing stages only read here");
                let path = request.url.path().to_owned();
                self.requests.lock().unwrap().push(path.clone());
                let body = if path.ends_with("/check-runs") {
                    assert_eq!(path.split('/').rev().nth(1), Some(sha().as_str()));
                    let (status, conclusion) = match self.checks {
                        "success" | "failure" => ("completed", json!(self.checks)),
                        pending => (pending, Value::Null),
                    };
                    json!({"total_count":1,"check_runs":[{"name":"ci","head_sha":sha(),"status":status,"conclusion":conclusion}]})
                } else if path.ends_with("/status") {
                    json!({"sha":sha(),"total_count":0,"statuses":[]})
                } else if path.ends_with("/pulls/7") {
                    json!({"number":7,"state":self.pr_state,"merged":false,"merge_commit_sha":null,
                        "head":{"ref":"feature/work","sha":sha(),"repo":{"full_name":"team/repo"}},
                        "base":{"ref":"main","sha":base_sha(),"repo":{"full_name":"team/repo"}}})
                } else {
                    panic!("unexpected landing read {path}")
                };
                Ok(HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: serde_json::to_vec(&body).unwrap(),
                })
            })
        }
    }

    struct Fixture {
        _dirs: tempfile::TempDir,
        repo: PathBuf,
        workspace: PathBuf,
        store: Arc<Store>,
        github: Arc<Github>,
        flow: Flow,
        settings: FlowSettings,
        ctx: ExecContext,
        cancel: tokio::sync::watch::Sender<bool>,
    }

    impl Fixture {
        async fn new(checks: &'static str, pr_state: &'static str, http_calls: u64) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let dirs = tempfile::tempdir().unwrap();
            let root = dirs.path().canonicalize().unwrap();
            let repo = root.join("repo");
            let base = root.join("private");
            let workspace = root.join("workspaces");
            for path in [&repo, &base, &workspace] {
                std::fs::create_dir(path).unwrap();
            }
            std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o700)).unwrap();
            let store = Arc::new(Store::open_in_memory().await.unwrap());
            configure(&store, &repo, &workspace).await;
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
                checks,
                pr_state,
                requests: Mutex::new(Vec::new()),
            });
            let connectors = Arc::new(ConnectorService::new(
                store.clone(),
                secrets.clone(),
                github.clone(),
            ));
            connectors
                .configure(
                    ConnectorId::Github,
                    ConfigurePatch {
                        enabled: Some(true),
                        base_url: Some(Some(SERVER.into())),
                        credential: Some(CredentialAction::Set(crate::secrets::Secret::new(
                            "fixture-token".into(),
                        ))),
                        ..ConfigurePatch::default()
                    },
                )
                .await
                .unwrap();
            let flows = crate::flow_service_test::flows_for_tests(
                &base,
                &store,
                &approvals,
                &connectors,
                &logs,
            )
            .await;
            let settings = flows.settings().await.unwrap();
            admit(&store, &repo).await;
            let (cancel, rx) = tokio::sync::watch::channel(false);
            let ctx = ExecContext {
                budget: RequestBudget::with_limits(
                    Instant::now() + Duration::from_mins(2),
                    Limits {
                        http_calls,
                        ..Limits::default()
                    },
                ),
                request_id: TICKET.into(),
                args: json!({"id":"landing"}),
                cancel: rx,
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
                    repo: repo.to_string_lossy().into_owned(),
                    pid: std::process::id(),
                },
                capability: "flow.run".into(),
                started_at: Instant::now(),
            };
            Self {
                _dirs: dirs,
                repo,
                workspace,
                store,
                github,
                flow: pam_flow::parse(&recipe()).unwrap(),
                settings,
                ctx,
                cancel,
            }
        }

        /// The receipts a session holds once every stage up to `through`
        /// (an operation key) has confirmed, with the PR numbered 7.
        fn receipts(through: &str) -> Value {
            let mut receipts = serde_json::Map::new();
            for key in [
                "freeze",
                "validate",
                "push",
                "ensure_pr",
                "verify_pr",
                "merge",
            ] {
                receipts.insert(
                    key.into(),
                    match key {
                        "ensure_pr" => json!({"number":7,"head_sha":sha()}),
                        "merge" => json!({"number":7,"sha":"c".repeat(40)}),
                        _ => json!({"commit":sha()}),
                    },
                );
                if key == through {
                    break;
                }
            }
            Value::Object(receipts)
        }

        /// Files the frozen manifest and saves the private session freeze
        /// would have left, then lets `mutate` bend it.
        async fn seed_session(&self, receipts: Value, mutate: impl FnOnce(&mut Value)) {
            let receipt = CheckoutReceipt {
                repository: self.repo.clone(),
                remote_url: SOURCE.into(),
                branch: "refs/heads/feature/work".into(),
                commit: sha(),
                base_ref: "refs/heads/main".into(),
                base_commit: base_sha(),
                tree: "d".repeat(40),
                manifest: Vec::new(),
                manifest_sha256: "e".repeat(64),
            };
            let bytes = crate::flow_recovery::encode(&receipt).unwrap();
            self.store
                .insert_evidence("ev_manifest", TICKET, KIND, &bytes, None)
                .await
                .unwrap();
            let policy = crate::landing_policy::Snapshot::load(&self.store)
                .await
                .unwrap();
            let checktree = self
                .workspace
                .join(format!("landing-{}", ulid::Ulid::new()))
                .join("tree");
            let mut document = json!({
                "version": 1,
                "flow_digest": pam_flow::digest(&self.flow),
                "repository": self.repo.to_string_lossy(),
                "policy_revision": policy.revision,
                "manifest_evidence": "ev_manifest",
                "manifest_digest": pam_compact::sha256_hex(&bytes),
                "checktree": checktree,
                "target": {"repository": SOURCE, "commit": sha()},
                "receipts": receipts,
                "intent": null,
                "poll": null,
            });
            mutate(&mut document);
            assert!(
                self.store
                    .save_landing_session(TICKET, None, &document.to_string(), now())
                    .await
                    .unwrap()
            );
        }

        /// Files and publishes one retained poll observation, the evidence a
        /// parked verify stage points its session at.
        async fn published_progress(&self) -> String {
            let bytes = crate::flow_recovery::encode(&json!({"sha":sha(),"passed":false})).unwrap();
            self.store
                .insert_evidence("ev_progress", TICKET, "flow.watch", &bytes, None)
                .await
                .unwrap();
            let view = evidence_service::prepare(bytes).await.unwrap();
            let scope = CaptureScope {
                repository: self.repo.to_string_lossy().into_owned(),
                origin: EvidenceOrigin {
                    targets: vec![ConnectorTarget {
                        connector: ConnectorId::Github,
                        base_url: SERVER.into(),
                        call: "runs".into(),
                        args: BTreeMap::from([("repo".into(), ArgValue::Text("team/repo".into()))]),
                    }],
                },
            };
            evidence_service::publish(
                &self.store,
                &scope,
                TICKET,
                "ev_progress",
                view,
                json!({"kind":"landing_checks"}),
            )
            .await
            .unwrap();
            "ev_progress".into()
        }

        /// Runs the landing step at `index` over a freshly restored run,
        /// stamped the way `run_step` stamps a landing step.
        async fn run(&self, index: usize) -> (StepReport, Result<(), CapabilityFailure>) {
            let step = &self.flow.steps[index];
            let Action::Landing { operation } = &step.action else {
                panic!("{} is a landing step", step.id);
            };
            let mut state = RunState::restore(
                &self.ctx.flows,
                &self.ctx,
                &self.flow,
                &self.settings,
                self.repo.clone(),
                Vars::new(),
                self.ctx.cancel.clone(),
            )
            .await
            .unwrap();
            state.watch_grant_stamp = Some(state.watch_stamp().await.unwrap());
            let mut report = StepReport::new(&step.id, step.kind(), StepStatus::Succeeded);
            let result = state.run_landing_step(step, *operation, &mut report).await;
            (report, result)
        }

        async fn session(&self) -> Value {
            serde_json::from_str(
                &self
                    .store
                    .read_landing_session(TICKET)
                    .await
                    .unwrap()
                    .unwrap()
                    .document,
            )
            .unwrap()
        }

        fn requests(&self) -> Vec<String> {
            self.github.requests.lock().unwrap().clone()
        }
    }

    /// The typed refusal a blocked stage settled the report with.
    fn blocked(outcome: (StepReport, Result<(), CapabilityFailure>)) -> StepReport {
        let (report, result) = outcome;
        assert!(result.is_ok(), "a refusal settles the step: {result:?}");
        assert_eq!(report.status, StepStatus::Blocked, "{report:?}");
        report
    }

    #[tokio::test]
    async fn a_missing_prior_receipt_blocks_the_stage_before_any_remote_call() {
        let fx = Fixture::new("success", "open", 128).await;
        fx.seed_session(Fixture::receipts("freeze"), |_| {}).await;
        // push needs validate's receipt, which the session does not hold.
        let report = blocked(fx.run(2).await);
        assert_eq!(report.error.unwrap().cause, "landing_predecessor_missing");
        assert!(fx.requests().is_empty());
        let session = fx.session().await;
        assert!(session["receipts"].get("validate").is_none());
        assert!(session["receipts"].get("push").is_none());
    }

    #[tokio::test]
    async fn an_explicitly_failed_required_check_blocks_verify_pr_and_files_the_evidence() {
        let fx = Fixture::new("failure", "open", 128).await;
        fx.seed_session(Fixture::receipts("ensure_pr"), |_| {})
            .await;
        let report = blocked(fx.run(4).await);
        let error = report.error.clone().unwrap();
        assert_eq!(error.cause, "landing_checks_failed");
        assert!(
            error.detail.contains("explicitly failed"),
            "{}",
            error.detail
        );
        // Exactly the two reads a check verification makes, no PR read.
        let requests = fx.requests();
        assert_eq!(requests.len(), 2, "{requests:?}");
        assert!(requests[0].ends_with(&format!("/commits/{}/check-runs", sha())));
        assert!(requests[1].ends_with(&format!("/commits/{}/status", sha())));
        // The failing verdict is retained as landing evidence on the report.
        assert_eq!(report.evidence.len(), 1, "{report:?}");
        let filed = fx.store.list_evidence(TICKET).await.unwrap();
        assert!(
            filed
                .iter()
                .any(|row| row.id == report.evidence[0] && row.kind == "landing.result"),
            "{filed:?}"
        );
        let session = fx.session().await;
        assert!(session["receipts"].get("verify_pr").is_none());
        assert!(session["poll"].is_null(), "a failure never parks");
    }

    #[tokio::test]
    async fn a_verified_pr_that_is_no_longer_open_is_a_pr_conflict() {
        let fx = Fixture::new("success", "closed", 128).await;
        fx.seed_session(Fixture::receipts("ensure_pr"), |_| {})
            .await;
        let report = blocked(fx.run(4).await);
        let error = report.error.unwrap();
        assert_eq!(error.cause, "landing_pr_conflict");
        assert!(error.detail.contains("no longer open"), "{}", error.detail);
        let requests = fx.requests();
        assert_eq!(requests.len(), 3, "{requests:?}");
        assert!(requests[2].ends_with("/pulls/7"));
        assert!(fx.session().await["receipts"].get("verify_pr").is_none());
    }

    #[tokio::test]
    async fn an_exhausted_persisted_poll_budget_refuses_before_polling_again() {
        let fx = Fixture::new("in_progress", "open", 128).await;
        let evidence = fx.published_progress().await;
        fx.seed_session(Fixture::receipts("ensure_pr"), |document| {
            document["poll"] = json!({"step":"verify-pr","polls":20,"next_poll_ms":0,
                "profile_stamp":"f".repeat(64),"authorization_revision":0,
                "last_digest":"g".repeat(64),"last_evidence":evidence});
        })
        .await;
        let report = blocked(fx.run(4).await);
        let error = report.error.unwrap();
        assert_eq!(error.cause, "landing_poll_budget_exhausted");
        assert!(error.detail.contains("polling budget"), "{}", error.detail);
        assert!(
            fx.requests().is_empty(),
            "the twenty-first poll is never sent"
        );
        assert_eq!(report.evidence, ["ev_progress"], "the last sample is cited");
        assert_eq!(fx.session().await["poll"]["polls"], 20);
    }

    #[tokio::test]
    async fn insufficient_http_headroom_refuses_to_park_another_poll() {
        // Thirteen calls: the two check reads leave eleven, under the twelve
        // a further poll plus exact landing verification needs.
        let fx = Fixture::new("in_progress", "open", 13).await;
        fx.seed_session(Fixture::receipts("ensure_pr"), |_| {})
            .await;
        let report = blocked(fx.run(4).await);
        let error = report.error.unwrap();
        assert_eq!(error.cause, "landing_poll_budget_exhausted");
        assert!(error.detail.contains("HTTP headroom"), "{}", error.detail);
        assert_eq!(fx.requests().len(), 2);
        let session = fx.session().await;
        assert!(session["poll"].is_null(), "nothing was parked");
        assert!(session["receipts"].get("verify_pr").is_none());
    }

    #[tokio::test]
    async fn a_checktree_outside_the_workspace_root_is_a_changed_target() {
        let fx = Fixture::new("success", "open", 128).await;
        fx.seed_session(Fixture::receipts("freeze"), |document| {
            document["checktree"] = json!("/elsewhere/landing-x/tree");
        })
        .await;
        let report = blocked(fx.run(1).await);
        let error = report.error.unwrap();
        assert_eq!(error.cause, "landing_target_changed");
        assert!(fx.requests().is_empty());
        assert!(fx.session().await["receipts"].get("validate").is_none());
    }

    #[tokio::test]
    async fn a_stale_policy_revision_blocks_every_later_stage() {
        let fx = Fixture::new("success", "open", 128).await;
        fx.seed_session(Fixture::receipts("ensure_pr"), |document| {
            document["policy_revision"] = json!("0".repeat(64));
        })
        .await;
        for index in [1, 4] {
            let report = blocked(fx.run(index).await);
            assert_eq!(report.error.unwrap().cause, "landing_policy_changed");
        }
        assert!(fx.requests().is_empty());
    }

    #[tokio::test]
    async fn cancellation_during_validate_ends_the_run_cancelled_not_blocked() {
        let fx = Fixture::new("success", "open", 128).await;
        fx.seed_session(Fixture::receipts("freeze"), |_| {}).await;
        fx.cancel.send(true).unwrap();
        let (report, result) = fx.run(1).await;
        assert!(
            matches!(result, Err(CapabilityFailure::Cancelled)),
            "{result:?}"
        );
        assert!(
            report.error.is_none(),
            "cancellation is not a settled refusal"
        );
        assert!(fx.requests().is_empty());
        let session = fx.session().await;
        assert!(session["receipts"].get("validate").is_none());
        assert!(session["intent"].is_null());
    }
}
