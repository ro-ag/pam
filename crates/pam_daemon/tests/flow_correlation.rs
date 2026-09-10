//! Revision association through real daemon/IPC/store paths; only HTTP and the
//! credential backend are replaced. No test requests a real service credential.
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

use pam_connectors::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use pam_daemon::admin::{ADMIN_CALLER_AGENT, ADMIN_REPO};
use pam_daemon::flow_service::{
    EVIDENCE_KIND_CONNECTOR_RESULT, EVIDENCE_KIND_FLOW_RESULT, step_capability,
};
use pam_proto::{Envelope, Outcome, Response};
use pam_testkit::{
    FakeSecretBackend, FakeTransport, TestDaemon, envelope_for_repo, open_store, seed_flow,
    seed_relaxed, short_tempdir, with_deadline,
};
use serde_json::{Value, json};

const SHA: &str = "abcdef1234567890abcdef1234567890abcdef12";
const OTHER_SHA: &str = "fedcba1234567890fedcba1234567890fedcba12";
const SOURCE: &str = "https://github.example/team/project.git";
const FLOW: &str = "schema: 1\nid: correlated\nname: Correlated\ninputs:\n  source: {}\n  sha: {}\n  run: { default: '9' }\ncorrelation:\n  repository: '${inputs.source}'\n  commit: '${inputs.sha}'\nsteps:\n  - id: inspect\n    connector: github\n    call: run\n    with: { repo: 'team/project', run_id: '${inputs.run}' }\n";

struct Fixture {
    daemon: TestDaemon,
    repos: Vec<tempfile::TempDir>,
    backend: Arc<FakeSecretBackend>,
}

impl Fixture {
    async fn new(yaml: &str, transport: Arc<dyn HttpTransport>) -> Self {
        pam_flow::parse(yaml).expect("correlated recipe validates");
        let tmp = short_tempdir();
        let repos = vec![short_tempdir(), short_tempdir()];
        seed_relaxed(&tmp).await;
        drop(seed_flow(&tmp, "correlated", yaml));
        let roots: Vec<_> = repos.iter().map(|repo| json!({
            "root":repo.path().canonicalize().unwrap(), "connectors":[
                {"connector":"github","base_url":"https://api.github.test/","access":"connector_wide","targets":[]},
                {"connector":"sonarqube","base_url":"https://sonar.test/","access":"connector_wide","targets":[]},
            ],
        })).collect();
        open_store(&tmp)
            .await
            .set_setting(
                "flows.scope_policy",
                &json!({"version":1,"repositories":roots}).to_string(),
            )
            .await
            .unwrap();
        let backend = Arc::new(FakeSecretBackend::default());
        let backend_for_daemon = backend.clone();
        let daemon = TestDaemon::spawn_at_with(tmp, move |config| {
            config.secret_backend = Some(backend_for_daemon);
            config.http_transport = Some(transport);
        })
        .await;
        for step in ["inspect", "after"] {
            daemon
                .store()
                .insert_grant(&step_capability("correlated", step))
                .await
                .unwrap();
        }
        let mut client = daemon.client().await;
        for (id, base_url) in [
            ("github", "https://api.github.test/"),
            ("sonarqube", "https://sonar.test/"),
        ] {
            let mut request = envelope_for_repo(
                ADMIN_REPO,
                &format!("configure_{id}"),
                "admin.connectors.configure",
                json!({
                    "id":id,"enabled":true,"base_url":base_url,"credential":{"set":"fixture-credential"},
                }),
                true,
            );
            request.caller.agent = ADMIN_CALLER_AGENT.to_owned();
            let response = client.request(&request).await;
            assert!(matches!(response, Response::Result { .. }), "{response:?}");
        }
        Self {
            daemon,
            repos,
            backend,
        }
    }

    async fn restart(self, transport: Arc<dyn HttpTransport>) -> Self {
        let Self {
            daemon,
            repos,
            backend,
        } = self;
        daemon.assert_invariant_clean().await;
        let tmp = daemon.stop().await;
        let backend_for_daemon = backend.clone();
        let daemon = TestDaemon::spawn_at_with(tmp, move |config| {
            config.secret_backend = Some(backend_for_daemon);
            config.http_transport = Some(transport);
        })
        .await;
        Self {
            daemon,
            repos,
            backend,
        }
    }

    fn request(&self, repo: usize, ticket: &str, sha: &str, run: u64) -> Envelope {
        envelope_for_repo(
            &self.repos[repo]
                .path()
                .canonicalize()
                .unwrap()
                .to_string_lossy(),
            ticket,
            "flow.run",
            json!({"id":"correlated","inputs":{"source":SOURCE,"sha":sha,"run":run.to_string()}}),
            true,
        )
    }

    async fn run(&self, ticket: &str) -> Value {
        let mut client = self.daemon.client().await;
        projection(client.request(&self.request(0, ticket, SHA, 9)).await)
    }

    async fn report(&self, ticket: &str) -> Value {
        let rows = self.results(ticket, EVIDENCE_KIND_FLOW_RESULT).await;
        assert_eq!(rows.len(), 1);
        rows.into_iter().next().unwrap()
    }

    async fn results(&self, ticket: &str, kind: &str) -> Vec<Value> {
        let store = self.daemon.store();
        let mut result = Vec::new();
        for row in store.list_evidence(ticket).await.unwrap() {
            if row.kind == kind {
                let row = store.get_evidence(&row.id).await.unwrap().unwrap();
                result.push(serde_json::from_slice(&row.content).unwrap());
            }
        }
        result
    }

    async fn target(&self, ticket: &str) -> Value {
        serde_json::from_str(
            &self
                .daemon
                .store()
                .read_correlation_target(ticket)
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap()
    }

    async fn finish(self) {
        self.daemon.assert_invariant_clean().await;
        self.daemon.stop().await;
    }
}

fn projection(response: Response) -> Value {
    assert!(serde_json::to_vec(&response).unwrap().len() <= 16_384);
    let Response::Result { body, outcome, .. } = response else {
        panic!("{response:?}")
    };
    assert_eq!(
        body["workflow"]["outcome"],
        serde_json::to_value(outcome).unwrap()
    );
    body
}

fn metadata(id: u64, attempt: u64, sha: &str) -> Value {
    json!({"id":id,"run_attempt":attempt,"head_sha":sha,"status":"completed","conclusion":"success",
        "repository":{"full_name":"team/project","clone_url":SOURCE},
        "head_repository":{"full_name":"team/project","clone_url":SOURCE,"html_url":"https://github.example/team/project"}})
}

fn jobs() -> Value {
    json!({"total_count":1,"jobs":[{"id":71,"name":"test","status":"completed","conclusion":"success"}]})
}

fn scripted(metadata: &Value) -> FakeTransport {
    FakeTransport::new()
        .json(200, &metadata.to_string())
        .json(200, &jobs().to_string())
}

fn with_after(yaml: &str) -> String {
    format!(
        "{yaml}  - id: after\n    connector: github\n    call: run\n    needs: [inspect]\n    with: {{ repo: 'team/project', run_id: '${{steps.inspect.result.run_id}}', run_attempt: '${{steps.inspect.result.run_attempt}}' }}\n"
    )
}

#[tokio::test]
async fn matching_target_is_public_and_allows_exact_downstream_reads() {
    with_deadline(async {
        let metadata = metadata(9, 3, SHA);
        let transport = Arc::new(
            scripted(&metadata)
                .json(200, &metadata.to_string())
                .json(200, &jobs().to_string()),
        );
        let fx = Fixture::new(&with_after(FLOW), transport.clone()).await;
        let body = fx.run("matching").await;
        assert_eq!(body["workflow"]["outcome"], "solved");
        assert_eq!(body["correlation"]["status"], "matched");
        assert_eq!(body["correlation"]["commit"], SHA);
        assert_eq!(body["correlation"]["target_id"].as_str().unwrap().len(), 64);
        assert_eq!(transport.requests().len(), 4);
        assert!(transport.url(2).ends_with("/runs/9/attempts/3"));
        let report = fx.report("matching").await;
        assert_eq!(report["steps"][1]["status"], "succeeded");
        assert_eq!(fx.target("matching").await["target"]["repository"], SOURCE);
        fx.finish().await;
    })
    .await;
}

#[tokio::test]
async fn different_sha_host_or_fork_blocks_and_retains_the_actual_product_answer() {
    with_deadline(async {
        for (index, (sha, source)) in [
            (OTHER_SHA, SOURCE),
            (SHA, "https://other.example/team/project.git"),
            (SHA, "https://github.example/attacker/project.git"),
        ]
        .into_iter()
        .enumerate()
        {
            let mut metadata = metadata(9, 3, sha);
            metadata["head_repository"]["clone_url"] = json!(source);
            let transport = Arc::new(scripted(&metadata));
            let fx = Fixture::new(&with_after(FLOW), transport.clone()).await;
            let ticket = format!("mismatch_{index}");
            let body = fx.run(&ticket).await;
            assert_eq!(body["workflow"]["outcome"], "blocked", "{body}");
            assert_eq!(body["correlation"]["status"], "conflicting");
            assert_eq!(
                transport.requests().len(),
                2,
                "dependent request must not reach HTTP"
            );
            let report = fx.report(&ticket).await;
            assert_eq!(
                report["steps"][0]["error"]["cause"],
                "correlation_conflicting"
            );
            assert!(
                report["steps"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|step| step["id"] != "after" || step["status"] != "succeeded")
            );
            let retained = fx.results(&ticket, EVIDENCE_KIND_CONNECTOR_RESULT).await;
            assert_eq!(retained.len(), 1);
            assert_eq!(retained[0]["run"]["head_sha"], sha);
            assert_eq!(retained[0]["run"]["head_repository"]["clone_url"], source);
            assert_eq!(fx.target(&ticket).await["target"]["commit"], SHA);
            fx.finish().await;
        }
    })
    .await;
}

#[tokio::test]
async fn missing_source_identity_and_rebased_pr_head_cannot_match() {
    with_deadline(async {
        let mut missing = metadata(9, 3, SHA);
        missing.as_object_mut().unwrap().remove("head_repository");
        let transport = Arc::new(scripted(&missing));
        let fx = Fixture::new(&with_after(FLOW), transport.clone()).await;
        let body = fx.run("missing").await;
        assert_eq!(body["workflow"]["outcome"], "blocked");
        assert_eq!(body["correlation"]["status"], "missing");
        assert_eq!(transport.requests().len(), 2);
        fx.finish().await;

        let yaml = with_after(&FLOW.replace(
            "steps:\n",
            &format!("  pull_request: 42\n  pull_request_head: {SHA}\nsteps:\n"),
        ));
        let mut rebased = metadata(9, 3, SHA);
        rebased["pull_requests"] = json!([{"number":42,"head":{"sha":OTHER_SHA}}]);
        let transport = Arc::new(scripted(&rebased));
        let fx = Fixture::new(&yaml, transport.clone()).await;
        let body = fx.run("rebased").await;
        assert_eq!(body["workflow"]["outcome"], "blocked");
        assert_eq!(body["correlation"]["status"], "conflicting");
        assert_eq!(transport.requests().len(), 2);
        assert_eq!(
            fx.target("rebased").await["target"]["pull_request_head"],
            SHA
        );
        fx.finish().await;
    })
    .await;
}

#[tokio::test]
async fn retry_cannot_replace_a_previously_bound_run_attempt() {
    with_deadline(async {
        let first = metadata(9, 3, SHA);
        let second = metadata(9, 4, SHA);
        let transport = Arc::new(
            scripted(&first)
                .json(200, &second.to_string())
                .json(200, &jobs().to_string()),
        );
        // An intentionally unsatisfied assertion triggers an ordinary retry;
        // correlation must reject its new attempt before any downstream use.
        let yaml = with_after(&FLOW.replace(
            "    call: run\n",
            "    call: run\n    expect_status: OK\n    retry: { attempts: 2, backoff: 1ms }\n",
        ));
        let fx = Fixture::new(&yaml, transport.clone()).await;
        let body = fx.run("retry").await;
        assert_eq!(body["workflow"]["outcome"], "blocked");
        assert_eq!(body["correlation"]["status"], "conflicting");
        let report = fx.report("retry").await;
        assert_eq!(report["steps"][0]["attempts"], 2);
        let bindings = fx
            .daemon
            .store()
            .read_correlation_steps("retry")
            .await
            .unwrap();
        assert_eq!(bindings.len(), 1);
        let binding: Value = serde_json::from_str(&bindings[0].canonical_json).unwrap();
        assert_eq!(
            binding["identity"]["run_attempt"], 3,
            "first association is immutable"
        );
        let retained = fx.results("retry", EVIDENCE_KIND_CONNECTOR_RESULT).await;
        assert_eq!(retained.len(), 2);
        assert_eq!(retained[0]["run_attempt"], 3);
        assert_eq!(retained[1]["run_attempt"], 4);
        assert_eq!(transport.requests().len(), 4);
        fx.finish().await;
    })
    .await;
}

struct ConcurrentGithub {
    together: tokio::sync::Barrier,
}

impl HttpTransport for ConcurrentGithub {
    fn send<'a>(
        &'a self,
        request: HttpRequest,
        _deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>> {
        Box::pin(async move {
            let body = match request.url.path() {
                "/repos/team/project/actions/runs/9" => {
                    self.together.wait().await;
                    metadata(9, 3, SHA)
                }
                "/repos/team/project/actions/runs/10" => {
                    self.together.wait().await;
                    metadata(10, 1, OTHER_SHA)
                }
                "/repos/team/project/actions/runs/9/attempts/3/jobs"
                | "/repos/team/project/actions/runs/10/attempts/1/jobs" => jobs(),
                path => panic!("unexpected correlation request {path}"),
            };
            Ok(HttpResponse {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&body).unwrap(),
            })
        })
    }
}

#[tokio::test]
async fn overlapping_requests_freeze_separate_repositories_and_revisions() {
    with_deadline(async {
        let transport = Arc::new(ConcurrentGithub {
            together: tokio::sync::Barrier::new(2),
        });
        let fx = Fixture::new(FLOW, transport).await;
        let mut first_client = fx.daemon.client().await;
        let mut second_client = fx.daemon.client().await;
        let first = fx.request(0, "parallel_a", SHA, 9);
        let second = fx.request(1, "parallel_b", OTHER_SHA, 10);
        let (first, second) =
            tokio::join!(first_client.request(&first), second_client.request(&second));
        let first = projection(first);
        let second = projection(second);
        assert_eq!(first["correlation"]["status"], "matched");
        assert_eq!(second["correlation"]["status"], "matched");
        assert_ne!(
            first["correlation"]["target_id"],
            second["correlation"]["target_id"]
        );
        let a = fx.target("parallel_a").await;
        let b = fx.target("parallel_b").await;
        assert_eq!(a["target"]["commit"], SHA);
        assert_eq!(b["target"]["commit"], OTHER_SHA);
        assert_ne!(a["local_repository"], b["local_repository"]);
        fx.finish().await;
    })
    .await;
}

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args([
            "-c",
            "user.name=Correlation fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

#[tokio::test]
async fn durable_result_keeps_the_frozen_target_after_checkout_changes() {
    with_deadline(async {
        let transport = Arc::new(FakeTransport::new());
        let fx = Fixture::new(FLOW, transport).await;
        let repo = fx.repos[0].path();
        git(repo, &["init", "--quiet"]);
        git(repo, &["commit", "--allow-empty", "--quiet", "-m", "first"]);
        let original = git(repo, &["rev-parse", "HEAD"]);
        let transport = Arc::new(scripted(&metadata(9, 3, &original)));
        let fx = fx.restart(transport.clone()).await;
        let mut client = fx.daemon.client().await;
        let body = projection(
            client
                .request(&fx.request(0, "durable", &original, 9))
                .await,
        );
        assert_eq!(body["correlation"]["status"], "matched");
        let frozen = fx.target("durable").await;
        git(
            fx.repos[0].path(),
            &["commit", "--allow-empty", "--quiet", "-m", "second"],
        );
        assert_ne!(git(fx.repos[0].path(), &["rev-parse", "HEAD"]), original);
        drop(client);
        let fx = fx.restart(transport.clone()).await;
        let mut client = fx.daemon.client().await;
        let request = envelope_for_repo(
            &fx.repos[0].path().canonicalize().unwrap().to_string_lossy(),
            "read_durable",
            "flow.result",
            json!({"ticket":"durable"}),
            true,
        );
        let response = client.request(&request).await;
        let Response::Result {
            outcome: Outcome::Solved,
            body: retrieved,
            ..
        } = response
        else {
            panic!("{response:?}")
        };
        assert_eq!(retrieved["agent_result"], body);
        assert_eq!(fx.target("durable").await, frozen);
        assert_eq!(
            transport.requests().len(),
            2,
            "retrieval must not reread products or current HEAD"
        );
        fx.finish().await;
    })
    .await;
}

#[tokio::test]
async fn only_a_job_from_the_matched_attempt_can_supply_a_log() {
    with_deadline(async {
        for (job, expected) in [(71, "matched"), (72, "missing")] {
            let yaml = format!("{FLOW}  - id: after\n    connector: github\n    call: job_log\n    needs: [inspect]\n    with: {{ repo: 'team/project', job_id: {job} }}\n");
            let transport = Arc::new(scripted(&metadata(9, 3, SHA))
                .json(200, &json!({"id":job,"conclusion":"success"}).to_string())
                .bytes(200, b"attached job output\n".to_vec()));
            let fx = Fixture::new(&yaml, transport.clone()).await;
            let body = fx.run("job_log").await;
            assert_eq!(body["correlation"]["status"], expected, "{body}");
            let report = fx.report("job_log").await;
            if job == 71 {
                assert_eq!(body["workflow"]["outcome"], "solved");
                assert_eq!(report["steps"][1]["status"], "succeeded");
                assert!(!report["steps"][1]["evidence"].as_array().unwrap().is_empty());
                assert_eq!(transport.requests().len(), 4, "matched job metadata and log were actually read");
            } else {
                assert_eq!(body["workflow"]["outcome"], "blocked");
                assert_eq!(report["steps"][1]["error"]["cause"], "correlation_missing");
            }
            fx.finish().await;
        }
    }).await;
}

#[tokio::test]
async fn a_live_sonar_green_measure_cannot_verify_a_declared_commit() {
    with_deadline(async {
        let yaml = FLOW.replace("    connector: github\n    call: run\n    with: { repo: 'team/project', run_id: '${inputs.run}' }",
            "    connector: sonarqube\n    call: quality_gate\n    with: { project: project }\n    role: verify\n    expect_status: OK");
        let transport = Arc::new(FakeTransport::new().json(200, r#"{"projectStatus":{"status":"OK","conditions":[]}}"#));
        let fx = Fixture::new(&yaml, transport.clone()).await;
        let body = fx.run("live_sonar").await;
        assert_eq!(body["workflow"]["outcome"], "blocked");
        assert_eq!(body["correlation"]["status"], "missing");
        let report = fx.report("live_sonar").await;
        assert_eq!(report["steps"][0]["error"]["cause"], "correlation_missing");
        let retained = fx.results("live_sonar", EVIDENCE_KIND_CONNECTOR_RESULT).await;
        assert_eq!(retained[0]["status"], "OK", "actual product status is not rewritten");
        assert_eq!(retained[0]["analysis_basis"], "live_measure");
        assert_eq!(transport.requests().len(), 1);
        fx.finish().await;
    }).await;
}

#[tokio::test]
async fn matched_remote_evidence_does_not_authorize_unassociated_local_verification() {
    with_deadline(async {
        let yaml = format!("{FLOW}  - id: after\n    run: [git, --version]\n    role: verify\n    needs: [inspect]\n");
        let transport = Arc::new(scripted(&metadata(9, 3, SHA)));
        let fx = Fixture::new(&yaml, transport.clone()).await;
        let body = fx.run("local_verify").await;
        assert_eq!(body["workflow"]["outcome"], "blocked", "{body}");
        assert_eq!(body["correlation"]["status"], "missing");
        let report = fx.report("local_verify").await;
        assert_eq!(report["steps"][0]["status"], "succeeded");
        let local = &report["steps"][1];
        assert_eq!(local["id"], "after");
        assert_eq!(local["status"], "blocked");
        assert_eq!(local["error"]["cause"], "correlation_missing");
        assert_eq!(local["attempts"], 0, "local verification is refused before command admission");
        assert!(local["exit_status"].is_null());
        assert!(local["evidence"].as_array().unwrap().is_empty());
        assert_eq!(report["budget_usage"]["command_bytes"], 0);
        assert_eq!(transport.requests().len(), 2);
        fx.finish().await;
    }).await;
}
