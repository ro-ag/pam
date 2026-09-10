//! Real flow/gate/checkpoint/contained-check paths; remote GitHub reads are fixtures.
//! Native push receipts are seeded only as completed work from a prior process.
use super::{
    ApprovalService, Arc, BTreeMap, CapabilityOutput, ConnectorId, ConnectorService, Duration,
    ExecContext, Flow, FlowService, Instant, LogService, Outcome, Path, PathBuf, PolicyGate,
    RunArgs, RunState, StepStatus, Store, Value, json, step_capability, watch,
};
use crate::{
    connector_service::{ConfigurePatch, CredentialAction},
    daemon::CompletionRouter,
    model_service::ModelService,
    queue::QueueManager,
    secrets::{FakeSecretBackend, SecretStore},
    transport::EventPublisher,
};
use pam_connectors::{HttpRequest, HttpResponse, HttpTransport, Method, TransportError};
use pam_proto::Caller;
use std::{
    fmt::Write,
    future::Future,
    pin::Pin,
    sync::Mutex,
    sync::atomic::{AtomicBool, Ordering},
};

const SOURCE: &str = "https://github.test/team/repo.git";
const SERVER: &str = "https://api.github.test/";
const MERGED: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const GIT: &str = "/Library/Developer/CommandLineTools/usr/bin/git";

struct Github {
    sha: String,
    base: String,
    existing: AtomicBool,
    merged: AtomicBool,
    requests: Mutex<Vec<(Method, String)>>,
}
impl Github {
    fn pr(&self) -> Value {
        let merged = self.merged.load(Ordering::SeqCst);
        json!({"number":7,"state":if merged{"closed"}else{"open"},"merged":merged,"merge_commit_sha":if merged{Some(MERGED)}else{None},
            "head":{"ref":"feature/work","sha":self.sha,"repo":{"full_name":"team/repo"}},
            "base":{"ref":"main","sha":self.base,"repo":{"full_name":"team/repo"}}})
    }
    fn count(&self, method: Method) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, _)| *m == method)
            .count()
    }
}
impl HttpTransport for Github {
    fn send<'a>(
        &'a self,
        request: HttpRequest,
        _deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>> {
        Box::pin(async move {
            let path = request.url.path().to_owned();
            self.requests
                .lock()
                .unwrap()
                .push((request.method, path.clone()));
            let body = if path.ends_with("/pulls") && request.method == Method::Get {
                if self.existing.load(Ordering::SeqCst) {
                    json!([self.pr()])
                } else {
                    json!([])
                }
            } else if path.ends_with("/pulls") && request.method == Method::Post {
                assert!(
                    !self.existing.swap(true, Ordering::SeqCst),
                    "PR creation must occur once"
                );
                self.pr()
            } else if path.ends_with("/pulls/7/merge") {
                assert_eq!(request.method, Method::Put);
                let body: Value = serde_json::from_slice(request.body.as_deref().unwrap()).unwrap();
                assert_eq!(
                    body["sha"], self.sha,
                    "mutation must carry original head guard"
                );
                self.merged.store(true, Ordering::SeqCst);
                json!({"merged":true,"sha":MERGED})
            } else if path.ends_with("/pulls/7") {
                assert_eq!(request.method, Method::Get);
                self.pr()
            } else if path.ends_with("/check-runs") {
                let sha = path.split('/').rev().nth(1).unwrap();
                assert!(
                    sha == self.sha || sha == MERGED,
                    "checks cannot query a substituted SHA"
                );
                json!({"total_count":1,"check_runs":[{"name":"ci","head_sha":sha,"status":"completed","conclusion":"success"}]})
            } else if path.ends_with("/status") {
                let sha = path.split('/').rev().nth(1).unwrap();
                assert!(sha == self.sha || sha == MERGED);
                json!({"sha":sha,"total_count":0,"statuses":[]})
            } else {
                panic!("unexpected request {:?} {path}", request.method)
            };
            Ok(HttpResponse {
                status: if request.method == Method::Post {
                    201
                } else {
                    200
                },
                headers: Vec::new(),
                body: serde_json::to_vec(&body).unwrap(),
            })
        })
    }
}
struct Fixture {
    _dirs: tempfile::TempDir,
    ctx: ExecContext,
    flow: Flow,
    repo: PathBuf,
    sha: String,
    github: Arc<Github>,
    _cancel: watch::Sender<bool>,
    drain: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.drain.abort();
    }
}
fn git(repo: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new(GIT)
        .args(args)
        .current_dir(repo)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
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
fn recipe(sha: &str) -> String {
    let mut yaml = format!(
        "schema: 1\nid: landing\nname: Landing integration\ncorrelation: {{ repository: '{SOURCE}', commit: '{sha}' }}\nsteps:\n"
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
impl Fixture {
    async fn new(failing_check: bool) -> Self {
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
        let (base_sha, sha) = initialize_repo(&repo);
        let yaml = recipe(&sha);
        let flow = pam_flow::parse(&yaml).unwrap();
        std::fs::create_dir(base.join("flows")).unwrap();
        std::fs::write(base.join("flows/landing.yaml"), yaml).unwrap();
        let store = Arc::new(Store::open_in_memory().await.unwrap());
        configure(&store, &repo, &workspace, failing_check).await;
        let (events, mut receiver) = EventPublisher::for_tests();
        let drain = tokio::spawn(async move { while receiver.recv().await.is_some() {} });
        let approvals = Arc::new(ApprovalService::new(
            store.clone(),
            events.clone(),
            Duration::from_secs(10),
        ));
        let models = ModelService::new(store.clone()).await.unwrap();
        let logs = LogService::new(store.clone(), models.clone());
        let secrets = Arc::new(SecretStore::new(Arc::new(FakeSecretBackend::default())));
        let github = Arc::new(Github {
            sha: sha.clone(),
            base: base_sha,
            existing: AtomicBool::new(false),
            merged: AtomicBool::new(false),
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
                    credential: Some(CredentialAction::Set("fixture-token".into())),
                    ..ConfigurePatch::default()
                },
            )
            .await
            .unwrap();
        let gate = Arc::new(PolicyGate::new(store.clone()).await.unwrap());
        let flows = Arc::new(FlowService::new(
            &base,
            store.clone(),
            approvals.clone(),
            connectors,
            logs,
            gate,
        ));
        let budget = admitted_budget(&store, &repo, &flow).await;
        let (cancel, rx) = watch::channel(false);
        let ctx = ExecContext {
            budget,
            request_id: "landing-ticket".into(),
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
            ctx,
            flow,
            repo,
            sha,
            github,
            _cancel: cancel,
            drain,
        }
    }
    async fn session(&self) -> (i64, Value) {
        let row = self
            .ctx
            .store
            .read_landing_session(&self.ctx.request_id)
            .await
            .unwrap()
            .unwrap();
        (row.revision, serde_json::from_str(&row.document).unwrap())
    }
    async fn save(&self, revision: i64, value: Value) {
        assert!(
            self.ctx
                .store
                .save_landing_session(
                    &self.ctx.request_id,
                    Some(revision),
                    &value.to_string(),
                    now()
                )
                .await
                .unwrap()
        );
    }
    /// Executes the actual gated prefix then simulates a private, confirmed native
    /// push from the prior process. No GitHub response or local check is fabricated.
    async fn prefix(&self, count: usize) {
        let service = &self.ctx.flows;
        let settings = service.settings().await.unwrap();
        let mut cancel = self.ctx.cancel.clone();
        let (vars, _) = service
            .resolve_vars(
                &self.flow,
                &BTreeMap::new(),
                &self.repo,
                &settings,
                &mut cancel,
                &self.ctx.budget,
            )
            .await
            .unwrap();
        let mut state = RunState::restore(
            service,
            &self.ctx,
            &self.flow,
            &settings,
            self.repo.clone(),
            vars,
            cancel,
        )
        .await
        .unwrap();
        for (index, step) in self.flow.steps.iter().enumerate().take(count) {
            if step.id == "push" {
                let (revision, mut session) = self.session().await;
                session["receipts"]["push"] = json!({"ref_name":"refs/heads/feature/work","commit":self.sha,"confirmed_by":"exact_remote_ref"});
                self.save(revision, session).await;
            }
            state
                .recovery
                .prepare(&self.ctx.store, &self.ctx.request_id, step, true)
                .await
                .unwrap();
            let report = state.run_step(step).await.unwrap();
            assert_eq!(
                report.status,
                StepStatus::Succeeded,
                "step {index}: {report:?}"
            );
            state.reports.push(report);
            state.checkpoint(false).await.unwrap();
        }
    }
    async fn interrupt_effect(&self, step: &str, operation: &str, expected: Value) {
        let (revision, mut session) = self.session().await;
        session["intent"] =
            json!({"step_id":step,"operation":operation,"state":"prepared","expected":expected});
        self.save(revision, session).await;
        let journal = self
            .ctx
            .store
            .read_flow_journal(&self.ctx.request_id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            self.ctx
                .store
                .prepare_flow_attempt(&self.ctx.request_id, journal.revision, step, 1, true)
                .await
                .unwrap()
        );
        assert_eq!(
            crate::lifecycle::recover_stuck_rows(&self.ctx.store)
                .await
                .unwrap(),
            1
        );
        assert!(
            self.ctx
                .store
                .start_queued_request(&self.ctx.request_id, now())
                .await
                .unwrap()
        );
    }
    async fn run(&self) -> CapabilityOutput {
        self.ctx
            .flows
            .run(
                &self.ctx,
                RunArgs {
                    id: "landing".into(),
                    inputs: BTreeMap::new(),
                },
            )
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn full_landing_refuses_unavailable_sync_before_any_work() {
    tokio::time::timeout(
        Duration::from_secs(90),
        Box::pin(async {
            let fixture = Fixture::new(false).await;
            let yaml = format!(
                "{} - id: sync\n   landing: sync\n   needs: [verify-main]\n",
                recipe(&fixture.sha)
            );
            pam_flow::parse(&yaml).unwrap();
            std::fs::write(
                fixture
                    .ctx
                    .flows
                    .protected_base()
                    .join("flows/landing.yaml"),
                yaml,
            )
            .unwrap();
            let inspection = fixture
                .ctx
                .flows
                .inspect(&fixture.ctx, &json!({"id":"landing"}))
                .await
                .unwrap();
            assert_eq!(inspection.body["readiness"], "blocked");
            assert!(
                inspection.body["blockers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|blocker| blocker["step"] == "sync"
                        && blocker["cause"] == "landing_sync_unavailable")
            );
            let result = fixture
                .ctx
                .flows
                .run(
                    &fixture.ctx,
                    RunArgs {
                        id: "landing".into(),
                        inputs: BTreeMap::new(),
                    },
                )
                .await;
            assert!(
                matches!(
                    result,
                    Err(super::CapabilityFailure::Refused { ref cause, .. })
                        if cause == "landing_sync_unavailable"
                ),
                "{result:?}"
            );
            assert!(fixture.github.requests.lock().unwrap().is_empty());
            let usage = fixture.ctx.budget.usage();
            assert_eq!(usage.attempts, 0);
            assert_eq!(usage.command_bytes, 0);
            assert_eq!(usage.http_calls, 0);
            assert!(
                fixture
                    .ctx
                    .store
                    .read_flow_journal(&fixture.ctx.request_id)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                fixture
                    .ctx
                    .store
                    .read_landing_session(&fixture.ctx.request_id)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                std::fs::read_dir(fixture._dirs.path().join("workspaces"))
                    .unwrap()
                    .next()
                    .is_none()
            );
        }),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn gated_local_prefix_and_fake_github_land_verify_the_exact_merge_sha() {
    tokio::time::timeout(
        Duration::from_secs(90),
        Box::pin(async {
            let fixture = Fixture::new(false).await;
            fixture.prefix(3).await;
            let output = fixture.run().await;
            assert_eq!(output.outcome, Outcome::Changed);
            assert_eq!(output.body["correlation"]["status"], "matched");
            assert_eq!(fixture.github.count(Method::Post), 1);
            assert_eq!(fixture.github.count(Method::Put), 1);
            let (_, session) = fixture.session().await;
            assert_eq!(session["receipts"]["merge"]["sha"], MERGED);
            assert_eq!(session["receipts"]["verify_main"]["sha"], MERGED);
            assert!(
                session["receipts"].get("sync").is_none(),
                "prefix must not claim local synchronization"
            );
            let requests = fixture.github.requests.lock().unwrap();
            assert!(
                requests
                    .iter()
                    .any(|(_, path)| path
                        == &format!("/repos/team/repo/commits/{MERGED}/check-runs"))
            );
            assert!(
                !requests
                    .iter()
                    .any(|(_, path)| path.contains("/commits/main/"))
            );
        }),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn failed_local_check_stops_before_any_remote_operation() {
    tokio::time::timeout(
        Duration::from_secs(90),
        Box::pin(async {
            let fixture = Fixture::new(true).await;
            let output = fixture.run().await;
            assert_eq!(output.outcome, Outcome::Unresolved);
            assert!(fixture.github.requests.lock().unwrap().is_empty());
            let (_, session) = fixture.session().await;
            assert!(session["receipts"].get("freeze").is_some());
            assert!(session["receipts"].get("validate").is_none());
            assert!(session["receipts"].get("push").is_none());
        }),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn prepared_pr_creation_recovers_by_reading_without_reposting() {
    tokio::time::timeout(
        Duration::from_secs(90),
        Box::pin(async {
            let fixture = Fixture::new(false).await;
            fixture.prefix(3).await;
            fixture.github.existing.store(true, Ordering::SeqCst);
            fixture
                .interrupt_effect("ensure-pr", "ensure_pr", json!({"head_sha":fixture.sha}))
                .await;
            let output = fixture.run().await;
            assert_eq!(output.outcome, Outcome::Changed);
            assert_eq!(fixture.github.count(Method::Post), 0);
            assert_eq!(fixture.github.count(Method::Put), 1);
            assert_eq!(
                fixture.session().await.1["receipts"]["ensure_pr"]["number"],
                7
            );
        }),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn prepared_merge_recovers_exact_result_without_second_put() {
    tokio::time::timeout(
        Duration::from_secs(90),
        Box::pin(async {
            let fixture = Fixture::new(false).await;
            fixture.prefix(5).await;
            fixture.github.merged.store(true, Ordering::SeqCst);
            fixture
                .interrupt_effect("merge", "merge", json!({"number":7,"head_sha":fixture.sha}))
                .await;
            let output = fixture.run().await;
            assert_eq!(output.outcome, Outcome::Changed);
            assert_eq!(fixture.github.count(Method::Post), 1);
            assert_eq!(fixture.github.count(Method::Put), 0);
            assert_eq!(
                fixture.session().await.1["receipts"]["verify_main"]["sha"],
                MERGED
            );
        }),
    )
    .await
    .unwrap();
}

/// Executed only by the configured contained check process, never by the parent
/// test runner. Both synchronization files stay in the approved artifact root.
#[test]
fn barrier_check_child() {
    let Some(artifacts) = std::env::var_os("PAM_ARTIFACTS") else {
        return;
    };
    let root = PathBuf::from(artifacts);
    std::fs::write(root.join("first_ready"), "ready").unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !root.join("release_first").exists() {
        assert!(
            Instant::now() < deadline,
            "parent never released the first check"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
#[test]
fn forbidden_second_check_child() {
    let Some(artifacts) = std::env::var_os("PAM_ARTIFACTS") else {
        return;
    };
    std::fs::write(
        PathBuf::from(artifacts).join("second_started"),
        "unexpected",
    )
    .unwrap();
}

#[tokio::test]
async fn revocation_during_first_check_prevents_second_check_spawn() {
    let executable = std::env::current_exe().unwrap();
    // Warm the actual child image outside the operation's deadline.
    assert!(
        std::process::Command::new(&executable)
            .arg("--list")
            .output()
            .unwrap()
            .status
            .success()
    );
    tokio::time::timeout(Duration::from_secs(90),Box::pin(async {
        let fixture=Fixture::new(false).await;
        let program=executable.file_name().unwrap().to_str().unwrap();
        fixture.ctx.store.set_setting("flows.allowed_programs",&json!(["git",program]).to_string()).await.unwrap();
        fixture.ctx.store.set_setting("flows.extra_path",&json!([executable.parent().unwrap(),Path::new(GIT).parent().unwrap(),Path::new("/usr/bin")]).to_string()).await.unwrap();
        let mut policy:Value=serde_json::from_str(&fixture.ctx.store.get_setting("flows.landing_policy").await.unwrap().unwrap()).unwrap();
        policy["repositories"][0]["checks"]=json!([
            {"name":"first","argv":[program,"--exact","flow_service::landing_integration_test::barrier_check_child","--nocapture"],"timeout_seconds":40},
            {"name":"second","argv":[program,"--exact","flow_service::landing_integration_test::forbidden_second_check_child","--nocapture"],"timeout_seconds":10}
        ]);
        fixture.ctx.store.set_setting("flows.landing_policy",&policy.to_string()).await.unwrap();
        let running=fixture.ctx.flows.run(&fixture.ctx,RunArgs{id:"landing".into(),inputs:BTreeMap::new()});tokio::pin!(running);
        let waiting=async {
            loop {
                if let Some(row)=fixture.ctx.store.read_landing_session(&fixture.ctx.request_id).await.unwrap() {
                    let session:Value=serde_json::from_str(&row.document).unwrap();
                    if let Some(tree)=session["checktree"].as_str() {
                        let artifacts=Path::new(tree).parent().unwrap().join("artifacts");
                        if artifacts.join("first_ready").exists(){break artifacts;}
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        let artifacts=tokio::select!{result=&mut running=>panic!("first check did not reach barrier: {result:?}"),path=waiting=>path};
        fixture.ctx.store.revoke_grant(&step_capability("landing","validate")).await.unwrap();
        std::fs::write(artifacts.join("release_first"),"release").unwrap();
        let output=running.await;
        assert!(output.is_err() || output.as_ref().is_ok_and(|value|value.outcome==Outcome::Blocked),"{output:?}");
        assert!(!artifacts.join("second_started").exists());
        assert!(fixture.github.requests.lock().unwrap().is_empty());
        assert!(fixture.session().await.1["receipts"].get("validate").is_none());
    })).await.unwrap();
}

fn initialize_repo(repo: &Path) -> (String, String) {
    git(repo, &["init", "-q", "-b", "main"]);
    git(repo, &["config", "user.name", "Fixture"]);
    git(repo, &["config", "user.email", "fixture@example.invalid"]);
    git(repo, &["config", "commit.gpgsign", "false"]);
    git(repo, &["remote", "add", "origin", SOURCE]);
    std::fs::write(repo.join("file"), "base\n").unwrap();
    git(repo, &["add", "file"]);
    git(repo, &["commit", "-q", "-m", "base"]);
    let base_sha = git(repo, &["rev-parse", "HEAD"]);
    git(repo, &["checkout", "-q", "-b", "feature/work"]);
    std::fs::write(repo.join("file"), "feature\n").unwrap();
    git(repo, &["add", "file"]);
    git(repo, &["commit", "-q", "-m", "feature"]);
    let sha = git(repo, &["rev-parse", "HEAD"]);
    (base_sha, sha)
}

async fn configure(store: &Store, repo: &Path, workspace: &Path, failing_check: bool) {
    store
        .set_setting("policy.profile", "\"relaxed\"")
        .await
        .unwrap();
    store
        .set_setting("flows.allowed_programs", r#"["git","true","false"]"#)
        .await
        .unwrap();
    store
        .set_setting(
            "flows.extra_path",
            r#"["/Library/Developer/CommandLineTools/usr/bin","/usr/bin","/bin"]"#,
        )
        .await
        .unwrap();
    store.set_setting("flows.scope_policy",&json!({"version":1,"repositories":[{"root":repo,"connectors":[{"connector":"github","base_url":SERVER,"access":"targets","targets":["team/repo"]}]}]}).to_string()).await.unwrap();
    store.set_setting("flows.landing_policy",&json!({"version":1,"repositories":[{"root":repo,"repository":SOURCE,"github_server":SERVER,"github_repository":"team/repo","base":"main","branches":["feature/work"],"workspace_root":workspace,"checks":[{"name":"local","argv":[if failing_check{"false"}else{"true"}],"timeout_seconds":10}],"required_checks":["ci"],"main_checks":["ci"],"permissions":{"push":true,"create_pr":true,"merge":true,"sync":true}}]}).to_string()).await.unwrap();
}

async fn admitted_budget(
    store: &Arc<Store>,
    repo: &Path,
    flow: &Flow,
) -> Arc<crate::request_budget::RequestBudget> {
    for step in &flow.steps {
        store
            .insert_grant(&step_capability("landing", &step.id))
            .await
            .unwrap();
    }
    store
        .insert_admitted_request(
            "landing-ticket",
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
            .authorize_queued_request("landing-ticket", repo.to_str().unwrap(), now())
            .await
            .unwrap()
    );
    assert!(
        store
            .start_queued_request("landing-ticket", now())
            .await
            .unwrap()
    );
    crate::request_budget::RequestBudget::load_persistent(
        store.clone(),
        "landing-ticket",
        Instant::now() + Duration::from_mins(2),
    )
    .await
    .unwrap()
}
