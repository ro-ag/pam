use super::landing_runtime::{
    EffectPhase, POLL_CAP, POLL_FIRST, POLL_HEADROOM, POLL_MIN, attempted, broker_error,
    checkout_error, effect_verdict, inspect_policy, landing_workspace, mutation_refused,
    poll_delay, release_workspace,
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
        /// `open`, `closed` (without a merge) or `merged`.
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
                    let merged = self.pr_state == "merged";
                    json!({"number":7,"state":if merged {"closed"} else {self.pr_state},"merged":merged,
                        "merge_commit_sha":merged.then(|| "c".repeat(40)),
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
        #[allow(
            clippy::too_many_lines,
            reason = "one fixture wires every service a flow run reaches, in boot order"
        )]
        async fn new(checks: &'static str, pr_state: &'static str, http_calls: u64) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let policy = crate::managed_policy_service::PolicyHandle::none();
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
                policy.clone(),
            ));
            let models = ModelService::new(store.clone(), policy.clone())
                .await
                .unwrap();
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
                policy.clone(),
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
                origin: crate::ingress::Origin::Public,
                peer: pam_store::RequestOrigin::PUBLIC,
                status: crate::status_cache::StatusCache::new(models.clone(), secrets.clone()),
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

    /// The stranded-ticket case: an earlier ticket (or a human) already
    /// merged the exact frozen head, and `merge` will observe that. The PR
    /// checks are still verified for that head; only the "still open" demand
    /// is dropped.
    #[tokio::test]
    async fn a_verified_pr_already_merged_at_the_frozen_head_is_accepted() {
        let fx = Fixture::new("success", "merged", 128).await;
        fx.seed_session(Fixture::receipts("ensure_pr"), |_| {})
            .await;
        let (report, result) = fx.run(4).await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(report.status, StepStatus::Succeeded, "{report:?}");
        let requests = fx.requests();
        assert_eq!(requests.len(), 3, "{requests:?}");
        assert!(requests[2].ends_with("/pulls/7"));
        assert_eq!(fx.session().await["receipts"]["verify_pr"]["passed"], true);
    }

    #[tokio::test]
    async fn a_merged_pr_whose_checks_failed_is_not_reported_as_verified() {
        let fx = Fixture::new("failure", "merged", 128).await;
        fx.seed_session(Fixture::receipts("ensure_pr"), |_| {})
            .await;
        let report = blocked(fx.run(4).await);
        assert_eq!(report.error.unwrap().cause, "landing_checks_failed");
        assert!(fx.session().await["receipts"].get("verify_pr").is_none());
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

    /// The fixed twenty-poll budget is gone: a landing that has already
    /// polled twenty times polls again while the request has time, and only
    /// the request deadline ends it.
    #[tokio::test]
    async fn twenty_polls_no_longer_end_the_landing_only_the_deadline_does() {
        let mut fx = Fixture::new("in_progress", "open", 128).await;
        let evidence = fx.published_progress().await;
        fx.seed_session(Fixture::receipts("ensure_pr"), |document| {
            document["poll"] = json!({"step":"verify-pr","polls":20,"next_poll_ms":0,
                "profile_stamp":"f".repeat(64),"authorization_revision":0,
                "last_digest":"g".repeat(64),"last_evidence":evidence});
        })
        .await;
        // Less than the headroom plus the shortest wait remains.
        fx.ctx.budget = RequestBudget::with_limits(
            Instant::now() + super::POLL_HEADROOM + super::POLL_MIN / 2,
            Limits::default(),
        );
        let report = blocked(fx.run(4).await);
        let error = report.error.unwrap();
        assert_eq!(error.cause, "request_deadline_exhausted");
        assert!(error.detail.contains("after 21 polls"), "{}", error.detail);
        assert!(
            error.recovery.contains("new landing ticket"),
            "{}",
            error.recovery
        );
        let requests = fx.requests();
        assert_eq!(
            requests.len(),
            2,
            "the twenty-first poll is sent: {requests:?}"
        );
        assert_eq!(
            fx.session().await["poll"]["polls"],
            20,
            "nothing new was parked"
        );
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

/// A landing step the managed ceiling caps off is refused before it runs
/// with the policy's cause and recovery; one the human withheld keeps the
/// landing refusal.
#[tokio::test]
async fn a_landing_operation_above_the_policy_ceiling_is_refused_with_the_policy_cause() {
    let store = Store::open_in_memory().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let (repo, workspace) = (root.join("repo"), root.join("work"));
    std::fs::create_dir(&repo).unwrap();
    std::fs::create_dir(&workspace).unwrap();
    store.set_setting("flows.landing_policy",&json!({"version":1,"repositories":[{"root":repo,"repository":"https://github.com/org/repo","github_server":"https://api.github.com/","github_repository":"org/repo","base":"main","branches":["feature/work"],"workspace_root":workspace,"checks":[{"name":"test","argv":["cargo","test"],"timeout_seconds":300}],"required_checks":["ci"],"main_checks":["ci"],"permissions":{"push":true,"create_pr":true,"merge":true,"sync":false}}]}).to_string()).await.unwrap();
    let view = crate::scope_policy_test::view(&json!({
        "version": 1, "landing": { "max_permissions": { "merge": false } }
    }));
    let refusal = inspect_policy(&store, &view, &repo, Op::Merge)
        .await
        .unwrap_err();
    assert_eq!(refusal.cause, crate::managed_policy::CAUSE_POLICY_DENIED);
    assert_eq!(refusal.recovery, crate::managed_policy::RECOVERY_MANAGED);
    assert!(
        refusal.detail.contains("landing.max_permissions"),
        "{}",
        refusal.detail
    );
    inspect_policy(&store, &view, &repo, Op::Push)
        .await
        .unwrap();
    let withheld = inspect_policy(&store, &view, &repo, Op::Sync)
        .await
        .unwrap_err();
    assert_eq!(withheld.cause, "landing_permission_missing");
    let unmanaged = crate::managed_policy::PolicyView::unmanaged();
    inspect_policy(&store, &unmanaged, &repo, Op::Merge)
        .await
        .unwrap();
}

/// The poll schedule on a simulated clock: five seconds doubling to the
/// sixty-second cap, each wait jittered down by at most a fifth, polling
/// until the request deadline and never past it, with the number of polls
/// bounded by the deadline.
#[test]
fn required_check_polls_back_off_to_the_cap_and_stop_only_at_the_deadline() {
    use std::time::Duration;
    let roomy = Duration::from_hours(1);
    let expected = [5u64, 10, 20, 40, 60, 60, 60];
    for (index, base) in expected.iter().enumerate() {
        let polls = u32::try_from(index + 1).unwrap();
        let wait = poll_delay(polls, "ticket/verify-pr", roomy).unwrap();
        let base = Duration::from_secs(*base);
        assert!(
            wait <= base && wait >= base * 4 / 5,
            "poll {polls}: {wait:?}"
        );
    }
    assert!(poll_delay(1, "t/s", roomy).unwrap() <= POLL_FIRST);
    assert!(poll_delay(400, "t/s", roomy).unwrap() <= POLL_CAP);
    // Jitter differs by seed and is deterministic for one.
    let one = poll_delay(6, "ticket-a/verify-pr", roomy).unwrap();
    assert_eq!(one, poll_delay(6, "ticket-a/verify-pr", roomy).unwrap());
    assert!(
        (0..16).any(|n| poll_delay(6, &format!("ticket-{n}/verify-pr"), roomy).unwrap() != one),
        "jitter spreads tickets"
    );
    // Near the deadline the wait shrinks to what is left; then it stops.
    let tight = POLL_HEADROOM + Duration::from_secs(3);
    assert_eq!(poll_delay(5, "t/s", tight), Some(Duration::from_secs(3)));
    assert_eq!(poll_delay(1, "t/s", POLL_HEADROOM + POLL_MIN / 2), None);
    assert_eq!(poll_delay(1, "t/s", Duration::ZERO), None);
    // A whole request on the simulated clock: it keeps polling until the
    // deadline (never giving up while a poll fits) and the count is bounded
    // by the deadline, not by a fixed budget.
    for deadline in [
        Duration::from_secs(90),
        Duration::from_mins(30),
        Duration::from_hours(1),
    ] {
        let mut elapsed = Duration::ZERO;
        let mut polls = 0u32;
        let left = |elapsed: Duration| deadline.saturating_sub(elapsed);
        while let Some(wait) = poll_delay(polls + 1, "ticket/verify-pr", left(elapsed)) {
            elapsed += wait;
            polls += 1;
            assert!(
                elapsed + POLL_HEADROOM <= deadline,
                "never past the deadline"
            );
        }
        assert!(
            left(elapsed) < POLL_HEADROOM + POLL_MIN,
            "stopped with time left: {:?} of {deadline:?}",
            left(elapsed)
        );
        let bound = u32::try_from(deadline.as_secs() / 4 + 2).unwrap();
        assert!(polls <= bound, "{polls} polls in {deadline:?}");
        if deadline == Duration::from_hours(1) {
            assert!(
                polls > 20,
                "an hour admits more than the old twenty polls: {polls}"
            );
            assert!(
                polls < 80,
                "the cap keeps an hour to a bounded count: {polls}"
            );
        }
    }
}

/// Which failed GitHub mutations are definite: a typed GitHub refusal and
/// anything refused before the request left; a lost answer or a server
/// error stays uncertain.
#[test]
fn only_a_lost_or_ambiguous_mutation_answer_stays_uncertain() {
    use crate::connector_service::InvokeError;
    use pam_connectors::ConnectorError;
    for definite in [
        InvokeError::Connector(ConnectorError::Rejected {
            cause: "landing_merge_conflict",
            detail: "conflict",
            recovery: "resolve",
        }),
        InvokeError::Connector(ConnectorError::Forbidden),
        InvokeError::Connector(ConnectorError::NotFound),
        InvokeError::CredentialMissing,
        InvokeError::Disabled,
    ] {
        assert!(mutation_refused(&definite), "{definite:?}");
    }
    for uncertain in [
        InvokeError::Connector(ConnectorError::Network("reset".into())),
        InvokeError::Connector(ConnectorError::Timeout),
        InvokeError::Connector(ConnectorError::Remote { status: 502 }),
        InvokeError::Connector(ConnectorError::BadResponse("odd".into())),
        InvokeError::Connector(ConnectorError::Policy {
            cause: "mutation_redirect_refused",
            detail: "redirect".into(),
        }),
    ] {
        assert!(!mutation_refused(&uncertain), "{uncertain:?}");
    }
}
