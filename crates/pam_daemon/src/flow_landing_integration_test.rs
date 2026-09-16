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
    flow_recovery::Prepare,
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
const GIT: &str = "/Library/Developer/CommandLineTools/usr/bin/git";

/// One HTTP call the fixture answered, kept in full so a test can assert on
/// headers and body, not just method and path.
#[derive(Clone, Debug)]
struct Recorded {
    method: Method,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

struct Github {
    sha: String,
    base: String,
    /// The real squash-merge commit: same tree as `sha`, one parent `base`,
    /// built once on `remote`'s `main` and served everywhere GitHub would
    /// report a merge SHA.
    merge: String,
    /// A local bare clone of the fixture repository that plays the GitHub
    /// remote: it holds the merge commit and answers `git-upload-pack`.
    remote: PathBuf,
    existing: AtomicBool,
    merged: AtomicBool,
    requests: Mutex<Vec<Recorded>>,
}
impl Github {
    /// Clones `repo` (bare) into `root/remote.git`, then builds the
    /// squash-merge commit on `main` there. The source repository's own
    /// `main` never moves except through a real `sync`.
    fn new(root: &Path, repo: &Path, base: &str, sha: &str) -> Self {
        let remote = root.join("remote.git");
        git(
            root,
            &[
                "-c",
                "protocol.file.allow=always",
                "clone",
                "--bare",
                "-q",
                repo.to_str().unwrap(),
                remote.to_str().unwrap(),
            ],
        );
        git(&remote, &["config", "user.name", "Fixture"]);
        git(
            &remote,
            &["config", "user.email", "fixture@example.invalid"],
        );
        git(&remote, &["config", "commit.gpgsign", "false"]);
        let tree = git(repo, &["rev-parse", &format!("{sha}^{{tree}}")]);
        let merge = git(&remote, &["commit-tree", &tree, "-p", base, "-m", "squash"]);
        git(&remote, &["update-ref", "refs/heads/main", &merge]);
        Self {
            sha: sha.to_owned(),
            base: base.to_owned(),
            merge,
            remote,
            existing: AtomicBool::new(false),
            merged: AtomicBool::new(false),
            requests: Mutex::new(Vec::new()),
        }
    }
    fn pr(&self) -> Value {
        let merged = self.merged.load(Ordering::SeqCst);
        json!({"number":7,"state":if merged{"closed"}else{"open"},"merged":merged,"merge_commit_sha":if merged{Some(self.merge.as_str())}else{None},
            "head":{"ref":"feature/work","sha":self.sha,"repo":{"full_name":"team/repo"}},
            "base":{"ref":"main","sha":self.base,"repo":{"full_name":"team/repo"}}})
    }
    fn count(&self, method: Method) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.method == method)
            .count()
    }
    /// Every recorded call whose path names the upload-pack service.
    fn upload_pack_calls(&self) -> Vec<Recorded> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.path.ends_with("/git-upload-pack"))
            .cloned()
            .collect()
    }
}
/// Runs `git pack-objects --revs --thin --stdout` against `remote` with
/// `revs` (one positive tip then negative haves) as stdin, and returns the
/// raw pack bytes it writes to stdout.
fn pack_objects(remote: &Path, revs: &str) -> Vec<u8> {
    use std::io::Write as _;
    let mut child = std::process::Command::new(GIT)
        .args([
            "-C",
            remote.to_str().unwrap(),
            "pack-objects",
            "--revs",
            "--thin",
            "--stdout",
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(revs.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
impl HttpTransport for Github {
    fn send<'a>(
        &'a self,
        request: HttpRequest,
        _deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>> {
        Box::pin(async move {
            let path = request.url.path().to_owned();
            self.requests.lock().unwrap().push(Recorded {
                method: request.method,
                path: path.clone(),
                headers: request.headers.clone(),
                body: request.body.clone().unwrap_or_default(),
            });
            if path.ends_with("/git-upload-pack") {
                assert_eq!(request.method, Method::Post);
                let pack = pack_objects(
                    &self.remote,
                    &format!("{}\n^{}\n^{}\n", self.merge, self.base, self.sha),
                );
                let mut body = b"0008NAK\n".to_vec();
                body.extend_from_slice(&pack);
                return Ok(HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body,
                });
            }
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
                json!({"merged":true,"sha":self.merge})
            } else if path.ends_with("/pulls/7") {
                assert_eq!(request.method, Method::Get);
                self.pr()
            } else if path.ends_with("/check-runs") {
                let sha = path.split('/').rev().nth(1).unwrap();
                assert!(
                    sha == self.sha || sha == self.merge,
                    "checks cannot query a substituted SHA"
                );
                json!({"total_count":1,"check_runs":[{"name":"ci","head_sha":sha,"status":"completed","conclusion":"success"}]})
            } else if path.ends_with("/status") {
                let sha = path.split('/').rev().nth(1).unwrap();
                assert!(sha == self.sha || sha == self.merge);
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
/// Runs a git command for its exit status alone (`merge-base --is-ancestor`
/// and the like, which carry no stdout worth reading).
fn git_ok(repo: &Path, args: &[&str]) -> bool {
    std::process::Command::new(GIT)
        .args(args)
        .current_dir(repo)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap()
        .status
        .success()
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
fn recipe(sha: &str, sync: bool) -> String {
    let mut yaml = format!(
        "schema: 1\nid: landing\nname: Landing integration\ncorrelation: {{ repository: '{SOURCE}', commit: '{sha}' }}\nsteps:\n"
    );
    let mut operations = vec![
        "freeze",
        "validate",
        "push",
        "ensure_pr",
        "verify_pr",
        "merge",
        "verify_main",
    ];
    if sync {
        operations.push("sync");
    }
    let mut previous = None;
    for operation in operations {
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
    async fn new(failing_check: bool, sync: bool) -> Self {
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
        let yaml = recipe(&sha, sync);
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
        let github = Arc::new(Github::new(&root, &repo, &base_sha, &sha));
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
    /// Flips the landing policy's `sync` permission, mirroring how a GUI
    /// edit to the policy would land.
    async fn set_sync_permission(&self, enabled: bool) {
        let raw = self
            .ctx
            .store
            .get_setting("flows.landing_policy")
            .await
            .unwrap()
            .unwrap();
        let mut policy: Value = serde_json::from_str(&raw).unwrap();
        policy["repositories"][0]["permissions"]["sync"] = json!(enabled);
        self.ctx
            .store
            .set_setting("flows.landing_policy", &policy.to_string())
            .await
            .unwrap();
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
                .prepare(&self.ctx.store, &self.ctx.request_id, step, Prepare::Run)
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
async fn full_landing_syncs_the_base_branch_after_verify_main() {
    tokio::time::timeout(
        Duration::from_secs(90),
        Box::pin(async {
            let fixture = Fixture::new(false, true).await;
            fixture.prefix(7).await;
            let output = fixture.run().await;
            assert_eq!(output.outcome, Outcome::Changed);
            let (_, session) = fixture.session().await;
            let receipt = session["receipts"]["sync"].clone();
            assert_eq!(receipt["ref_name"], "refs/heads/main");
            assert_eq!(receipt["commit"], fixture.github.merge.as_str());
            let pack = receipt["pack"].as_str().unwrap();
            assert!(pack.starts_with("pack-"), "{pack}");
            assert!(receipt["bounds"]["objects"].as_u64().unwrap() > 0);
            assert_eq!(receipt["confirmed_by"], "exact_local_ref");
            let intent = &session["intent"];
            assert!(!intent.is_null(), "the sync intent is retained");
            assert_eq!(intent["operation"], "sync");
            assert_eq!(
                intent["expected"]["requested_commit"],
                fixture.github.merge.as_str()
            );

            // The base branch fast-forwarded to the merge commit...
            let main = git(&fixture.repo, &["rev-parse", "refs/heads/main"]);
            assert_eq!(main, fixture.github.merge);
            let kind = git(&fixture.repo, &["cat-file", "-t", &fixture.github.merge]);
            assert_eq!(kind, "commit");
            assert!(git_ok(
                &fixture.repo,
                &[
                    "merge-base",
                    "--is-ancestor",
                    &fixture.github.base,
                    &fixture.github.merge
                ]
            ));
            let mut saw_pack = false;
            let mut saw_idx = false;
            for entry in std::fs::read_dir(fixture.repo.join(".git/objects/pack")).unwrap() {
                let name = entry.unwrap().file_name().into_string().unwrap();
                let extension = Path::new(&name).extension().and_then(|ext| ext.to_str());
                saw_pack |= name.starts_with("pack-") && extension == Some("pack");
                saw_idx |= name.starts_with("pack-") && extension == Some("idx");
            }
            assert!(saw_pack && saw_idx, "expected an installed pack and index");

            // ...and nothing else in the repository moved.
            let head = git(&fixture.repo, &["symbolic-ref", "HEAD"]);
            assert_eq!(head, "refs/heads/feature/work");
            let content = std::fs::read_to_string(fixture.repo.join("file")).unwrap();
            assert_eq!(content, "feature\n");
            let status = git(&fixture.repo, &["status", "--porcelain"]);
            assert!(status.is_empty(), "{status}");

            // Exactly one upload-pack request, shaped exactly as the contract says.
            let calls = fixture.github.upload_pack_calls();
            assert_eq!(calls.len(), 1, "{calls:?}");
            let call = &calls[0];
            assert_eq!(call.method, Method::Post);
            assert!(call.path.ends_with("/git-upload-pack"), "{}", call.path);
            let content_type = call
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                .map(|(_, value)| value.as_str());
            assert_eq!(content_type, Some("application/x-git-upload-pack-request"));
            let authorization = call
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                .map(|(_, value)| value.as_str());
            assert!(
                authorization.is_some_and(|value| value.starts_with("Basic ")),
                "{authorization:?}"
            );
            let expected_body = format!(
                "0033want {} \n00000032have {}\n0032have {}\n0009done\n",
                fixture.github.merge, fixture.github.base, fixture.sha
            );
            assert_eq!(call.body, expected_body.into_bytes());
        }),
    )
    .await
    .unwrap();
}

// A checked-out base branch cannot reach the sync-specific refusal through
// the orchestrator: every stage's live check first requires HEAD to remain
// the frozen feature branch (`landing_checkout_changed`), and a policy never
// lists the base branch as a feature branch. The broker-level guard is
// covered directly in landing_git_test.
#[tokio::test]
async fn sync_inspection_reports_permission_then_readiness() {
    tokio::time::timeout(
        Duration::from_secs(90),
        Box::pin(async {
            let fixture = Fixture::new(false, true).await;
            fixture.set_sync_permission(false).await;
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
                        && blocker["cause"] == "landing_permission_missing")
            );
            fixture.set_sync_permission(true).await;
            let inspection = fixture
                .ctx
                .flows
                .inspect(&fixture.ctx, &json!({"id":"landing"}))
                .await
                .unwrap();
            assert_eq!(inspection.body["readiness"], "admission_required");
            assert!(
                inspection.body["blockers"].as_array().unwrap().is_empty(),
                "{:?}",
                inspection.body["blockers"]
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
            let fixture = Fixture::new(false, false).await;
            fixture.prefix(3).await;
            let output = fixture.run().await;
            assert_eq!(output.outcome, Outcome::Changed);
            assert_eq!(output.body["correlation"]["status"], "matched");
            assert_eq!(fixture.github.count(Method::Post), 1);
            assert_eq!(fixture.github.count(Method::Put), 1);
            let (_, session) = fixture.session().await;
            assert_eq!(
                session["receipts"]["merge"]["sha"],
                fixture.github.merge.as_str()
            );
            assert_eq!(
                session["receipts"]["verify_main"]["sha"],
                fixture.github.merge.as_str()
            );
            assert!(
                session["receipts"].get("sync").is_none(),
                "prefix must not claim local synchronization"
            );
            let requests = fixture.github.requests.lock().unwrap();
            assert!(requests.iter().any(|call| call.path
                == format!(
                    "/repos/team/repo/commits/{}/check-runs",
                    fixture.github.merge
                )));
            assert!(
                !requests
                    .iter()
                    .any(|call| call.path.contains("/commits/main/"))
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
            let fixture = Fixture::new(true, false).await;
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
            let fixture = Fixture::new(false, false).await;
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
            let fixture = Fixture::new(false, false).await;
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
                fixture.github.merge.as_str()
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
        let fixture=Fixture::new(false, false).await;
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

/// Runs the recipe expecting a refusal and returns its cause.
async fn run_refused(fixture: &Fixture) -> String {
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
    match result {
        Err(super::CapabilityFailure::Refused { cause, .. }) => cause,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn sync_intent(fixture: &Fixture) -> Value {
    json!({
        "ref_name": "refs/heads/main",
        "expected_old": fixture.github.base,
        "requested_commit": fixture.github.merge,
        "state": "uncertain",
        "bounds": {"objects": 3, "deltas": 1, "compressed_bytes": 300, "decoded_bytes": 200, "expanded_bytes": 250},
    })
}

#[tokio::test]
async fn prepared_sync_recovers_from_the_exact_local_ref_without_a_second_fetch() {
    tokio::time::timeout(
        Duration::from_secs(90),
        Box::pin(async {
            let fixture = Fixture::new(false, true).await;
            fixture.prefix(7).await;
            // The effect happened before the crash: main already names the
            // merge commit (objects arrived through the remote clone).
            git(
                &fixture.repo,
                &[
                    "-c",
                    "protocol.file.allow=always",
                    "fetch",
                    "-q",
                    fixture.github.remote.to_str().unwrap(),
                    &fixture.github.merge,
                ],
            );
            git(
                &fixture.repo,
                &[
                    "update-ref",
                    "refs/heads/main",
                    &fixture.github.merge,
                    &fixture.github.base,
                ],
            );
            fixture
                .interrupt_effect("sync", "sync", sync_intent(&fixture))
                .await;
            let output = fixture.run().await;
            assert_eq!(output.outcome, Outcome::Changed);
            assert!(
                fixture.github.upload_pack_calls().is_empty(),
                "a prepared sync is reconciled by reading, never re-fetched"
            );
            let (_, session) = fixture.session().await;
            assert_eq!(
                session["receipts"]["sync"]["commit"],
                fixture.github.merge.as_str()
            );
            assert_eq!(
                session["receipts"]["sync"]["confirmed_by"],
                "exact_local_ref"
            );
            assert_eq!(
                git(&fixture.repo, &["rev-parse", "refs/heads/main"]),
                fixture.github.merge
            );
        }),
    )
    .await
    .unwrap();
}

/// A prepared intent whose journalled process verdict is still `uncertain`
/// (the daemon died before the process reported) is a truly unknown
/// outcome: resume reads the ref, finds it unchanged, and refuses as
/// `landing_effect_uncertain`. Only a journalled `rejected` verdict earns
/// the typed `landing_push_rejected` cause on resume.
#[tokio::test]
async fn prepared_sync_whose_effect_never_landed_stays_uncertain_without_replay() {
    tokio::time::timeout(
        Duration::from_secs(90),
        Box::pin(async {
            let fixture = Fixture::new(false, true).await;
            fixture.prefix(7).await;
            fixture
                .interrupt_effect("sync", "sync", sync_intent(&fixture))
                .await;
            assert_eq!(run_refused(&fixture).await, "landing_effect_uncertain");
            assert!(fixture.github.upload_pack_calls().is_empty());
            assert_eq!(
                git(&fixture.repo, &["rev-parse", "refs/heads/main"]),
                fixture.github.base,
                "an unconfirmed sync is never repeated automatically"
            );
            assert!(
                !fixture.repo.join(".git/objects/pack").exists()
                    || std::fs::read_dir(fixture.repo.join(".git/objects/pack"))
                        .unwrap()
                        .all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".idx"))
            );
            let (_, session) = fixture.session().await;
            assert!(session["receipts"].get("sync").is_none());
        }),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn sync_refuses_a_moved_base_before_fetching() {
    tokio::time::timeout(
        Duration::from_secs(90),
        Box::pin(async {
            let fixture = Fixture::new(false, true).await;
            fixture.prefix(7).await;
            // Local main moved to a commit the merge does not descend from.
            git(
                &fixture.repo,
                &[
                    "update-ref",
                    "refs/heads/main",
                    &fixture.sha,
                    &fixture.github.base,
                ],
            );
            // The live identity check blocks the step before any transfer:
            // only the frozen base or the merge commit itself are acceptable.
            let output = fixture.run().await;
            assert_eq!(output.outcome, Outcome::Blocked);
            let blocked = output.body["observations"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["step"] == "sync")
                .cloned()
                .unwrap();
            assert_eq!(blocked["status"], "blocked");
            assert_eq!(blocked["text"], "approved source identity changed");
            assert!(fixture.github.upload_pack_calls().is_empty());
            assert_eq!(
                git(&fixture.repo, &["rev-parse", "refs/heads/main"]),
                fixture.sha,
                "a moved base ref is left where it was"
            );
            assert!(
                !fixture.repo.join(".git/objects/pack").exists()
                    || std::fs::read_dir(fixture.repo.join(".git/objects/pack"))
                        .unwrap()
                        .all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".idx"))
            );
        }),
    )
    .await
    .unwrap();
}

/// The push step cannot resume in this fixture (its exact-ref observation
/// needs the real remote), so the resumed verdict is exercised directly: a
/// journalled `rejected` process verdict with the remote ref still at its
/// observed old value is the typed refusal, the same as the fresh path,
/// while a verdict-less intent stays uncertain.
#[test]
fn a_journalled_rejected_push_resumes_as_the_typed_refusal() {
    use super::landing_runtime::{EffectPhase, effect_verdict};
    use crate::landing_git::{PushObservation, PushState, RemoteRef};
    use pam_flow::LandingOperation as Op;

    let old = "a".repeat(40);
    let observed = RemoteRef {
        ref_name: "refs/heads/feature/work".into(),
        oid: Some(old.clone()),
    };
    let prepared = |state: PushState| PushObservation {
        ref_name: "refs/heads/feature/work".into(),
        expected_old: Some(old.clone()),
        requested_commit: "b".repeat(40),
        state,
    };
    let cause = |failure: super::CapabilityFailure| match failure {
        super::CapabilityFailure::Refused { cause, .. } => cause,
        other => panic!("expected a refusal, got {other:?}"),
    };
    for phase in [EffectPhase::Resumed, EffectPhase::JustRan] {
        let rejected =
            effect_verdict(&observed, &prepared(PushState::Rejected), Op::Push, phase).unwrap_err();
        assert_eq!(cause(rejected), "landing_push_rejected");
    }
    let unknown = effect_verdict(
        &observed,
        &prepared(PushState::Uncertain),
        Op::Push,
        EffectPhase::Resumed,
    )
    .unwrap_err();
    assert_eq!(cause(unknown), "landing_effect_uncertain");
    let contradiction = effect_verdict(
        &observed,
        &prepared(PushState::ReportedSuccess),
        Op::Push,
        EffectPhase::Resumed,
    )
    .unwrap_err();
    assert_eq!(cause(contradiction), "landing_effect_uncertain");
}
