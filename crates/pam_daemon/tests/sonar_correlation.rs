//! Exact Sonar correlation through the daemon. All service credentials are fake.
use pam_connectors::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use pam_daemon::admin::{ADMIN_CALLER_AGENT, ADMIN_REPO};
use pam_daemon::flow_service::{EVIDENCE_KIND_CONNECTOR_RESULT, step_capability};
use pam_proto::{Outcome, Response};
use pam_testkit::{
    FakeSecretBackend, TestDaemon, envelope_for_repo, open_store, seed_flow, seed_relaxed,
    short_tempdir, with_deadline,
};
use serde_json::{Value, json};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

const SHA: &str = "abcdef1234567890abcdef1234567890abcdef12";
const OTHER: &str = "fedcba1234567890fedcba1234567890fedcba12";
const FLOW: &str = "schema: 1\nid: sonar-correlated\nname: Sonar correlated\ninputs:\n  sha: {}\ncorrelation:\n  repository: 'https://git.example/team/repo'\n  commit: '${inputs.sha}'\nsteps:\n  - id: inspect\n    connector: sonarqube\n    call: analysis\n    with: { project: 'p', ce_task: 'ce1' }\n    role: verify\n    expect_status: OK\n    output: compact\n";

struct Fixture {
    daemon: TestDaemon,
    repo: tempfile::TempDir,
}
impl Fixture {
    async fn new(transport: Arc<dyn HttpTransport>) -> Self {
        Self::with_flow(transport, FLOW).await
    }
    async fn with_flow(transport: Arc<dyn HttpTransport>, yaml: &str) -> Self {
        let tmp = short_tempdir();
        let repo = short_tempdir();
        seed_relaxed(&tmp).await;
        drop(seed_flow(&tmp, "sonar-correlated", yaml));
        open_store(&tmp).await.set_setting("flows.scope_policy",&json!({"version":1,"repositories":[{"root":repo.path().canonicalize().unwrap(),"connectors":[{"connector":"sonarqube","base_url":"https://sonar.test/","access":"targets","targets":["p"]}]}]}).to_string()).await.unwrap();
        let daemon = TestDaemon::spawn_at_with(tmp, move |config| {
            config.secret_backend = Some(Arc::new(FakeSecretBackend::default()));
            config.http_transport = Some(transport);
        })
        .await;
        daemon
            .store()
            .insert_grant(&step_capability("sonar-correlated", "inspect"))
            .await
            .unwrap();
        let fixture = Self { daemon, repo };
        fixture.admin("configure","admin.connectors.configure",json!({"id":"sonarqube","enabled":true,"base_url":"https://sonar.test/","credential":{"set":"fixture-only"}})).await;
        fixture
    }
    async fn admin(&self, id: &str, op: &str, args: Value) -> Value {
        let mut envelope = envelope_for_repo(ADMIN_REPO, id, op, args, true);
        ADMIN_CALLER_AGENT.clone_into(&mut envelope.caller.agent);
        let response = self.daemon.client().await.request(&envelope).await;
        let Response::Result { body, .. } = response else {
            panic!("{response:?}")
        };
        body
    }
    async fn mapping(&self, id: &str, repository: Option<&str>) {
        let prior = self
            .admin(
                &format!("get_{id}"),
                "admin.connectors.sonar_mappings.get",
                json!({}),
            )
            .await;
        let mappings = repository.map_or_else(Vec::new, |repository| {
            vec![json!({"server":"https://sonar.test/","project":"p","repository":repository})]
        });
        self.admin(
            &format!("set_{id}"),
            "admin.connectors.sonar_mappings.set",
            json!({"expected_revision":prior["revision"],"mappings":mappings}),
        )
        .await;
    }
    fn request(&self, id: &str, cap: &str, args: Value) -> pam_proto::Envelope {
        envelope_for_repo(
            &self.repo.path().canonicalize().unwrap().to_string_lossy(),
            id,
            cap,
            args,
            true,
        )
    }
    async fn run(&self, id: &str, sha: &str) -> Response {
        self.daemon
            .client()
            .await
            .request(&self.request(
                id,
                "flow.run",
                json!({"id":"sonar-correlated","inputs":{"sha":sha}}),
            ))
            .await
    }
    async fn retained(&self, ticket: &str) {
        let store = self.daemon.store();
        let rows = store.list_evidence(ticket).await.unwrap();
        let row = rows
            .iter()
            .find(|row| row.kind == EVIDENCE_KIND_CONNECTOR_RESULT)
            .expect("raw product evidence retained");
        let row = store.get_evidence(&row.id).await.unwrap().unwrap();
        let value: Value = serde_json::from_slice(&row.content).unwrap();
        assert_eq!(value["analysis_id"], "a1");
    }
    async fn finish(self) {
        self.daemon.assert_invariant_clean().await;
        self.daemon.stop().await;
    }
}

fn result(response: Response) -> (Outcome, Value) {
    let Response::Result { outcome, body, .. } = response else {
        panic!("{response:?}")
    };
    (outcome, body)
}

struct Sonar {
    entered: Option<Arc<tokio::sync::Notify>>,
    release: Option<Arc<tokio::sync::Notify>>,
}
impl HttpTransport for Sonar {
    fn send<'a>(
        &'a self,
        request: HttpRequest,
        _deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>> {
        Box::pin(async move {
            let body = match request.url.path() {
                "/api/webservices/list" => metadata(),
                "/api/ce/task" => {
                    json!({"task":{"id":"ce1","type":"REPORT","componentKey":"p","status":"SUCCESS","analysisId":"a1"}})
                }
                "/api/project_analyses/search" => {
                    json!({"paging":{"pageIndex":1,"pageSize":100,"total":1},"analyses":[{"key":"a1","revision":SHA}]})
                }
                "/api/qualitygates/project_status" => {
                    if let (Some(entered), Some(release)) = (&self.entered, &self.release) {
                        entered.notify_one();
                        release.notified().await;
                    }
                    json!({"projectStatus":{"status":"OK","conditions":[]}})
                }
                path => panic!("unexpected Sonar fixture request {path}"),
            };
            Ok(HttpResponse {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&body).unwrap(),
            })
        })
    }
}

fn metadata() -> Value {
    json!({"webServices":[{"path":"api/ce","actions":[{"key":"task","params":[{"key":"id"}]}]},{"path":"api/project_analyses","actions":[{"key":"search","params":[{"key":"project"},{"key":"p"},{"key":"ps"},{"key":"branch"}]}]},{"path":"api/qualitygates","actions":[{"key":"project_status","params":[{"key":"analysisId"}]}]}]})
}

#[tokio::test]
async fn exact_mapping_verifies_and_historical_result_keeps_frozen_provenance() {
    with_deadline(async {
        let fx = Fixture::new(Arc::new(Sonar {
            entered: None,
            release: None,
        }))
        .await;
        fx.mapping("initial", Some("https://git.example/team/repo"))
            .await;
        let (outcome, body) = result(fx.run("matched", SHA).await);
        assert_eq!(outcome, Outcome::Verified, "{body}");
        assert_eq!(body["correlation"]["status"], "matched");
        fx.mapping("removed", None).await;
        let (_, historical) = result(
            fx.daemon
                .client()
                .await
                .request(&fx.request("history", "flow.result", json!({"ticket":"matched"})))
                .await,
        );
        assert_eq!(
            historical["agent_result"]["correlation"],
            body["correlation"]
        );
        fx.finish().await;
    })
    .await;
}

#[tokio::test]
async fn wrong_revision_or_missing_mapping_blocks_but_retains_product_evidence() {
    with_deadline(async {
        for mapped in [false, true] {
            let fx = Fixture::new(Arc::new(Sonar {
                entered: None,
                release: None,
            }))
            .await;
            if mapped {
                fx.mapping("initial", Some("https://git.example/team/repo"))
                    .await;
            }
            let (outcome, body) = result(fx.run("blocked", if mapped { OTHER } else { SHA }).await);
            assert_eq!(outcome, Outcome::Blocked, "{body}");
            fx.retained("blocked").await;
            fx.finish().await;
        }
    })
    .await;
}

#[tokio::test]
async fn public_mapping_admin_is_denied_even_with_gui_label() {
    with_deadline(async {
        let fx = Fixture::new(Arc::new(Sonar {
            entered: None,
            release: None,
        }))
        .await;
        let mut forged = envelope_for_repo(
            ADMIN_REPO,
            "forged",
            "admin.connectors.sonar_mappings.set",
            json!({"expected_revision":"forged","mappings":[]}),
            true,
        );
        ADMIN_CALLER_AGENT.clone_into(&mut forged.caller.agent);
        let mut client = fx.daemon.client().await;
        client.send_public(&forged).await;
        assert!(matches!(client.recv().await, Response::Refusal { .. }));
        fx.finish().await;
    })
    .await;
}

#[tokio::test]
async fn mapping_change_during_collection_cannot_publish_verified() {
    with_deadline(async {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let fx = Fixture::new(Arc::new(Sonar {
            entered: Some(entered.clone()),
            release: Some(release.clone()),
        }))
        .await;
        fx.mapping("initial", Some("https://git.example/team/repo"))
            .await;
        let run = fx.run("changed", SHA);
        let change = async {
            entered.notified().await;
            fx.mapping("changed", Some("https://git.example/team/other"))
                .await;
            release.notify_one();
        };
        let (response, ()) = tokio::join!(run, change);
        let (outcome, body) = result(response);
        assert_ne!(outcome, Outcome::Verified, "{body}");
        fx.retained("changed").await;
        fx.finish().await;
    })
    .await;
}

struct LaterGithub {
    sonar: Sonar,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}
impl HttpTransport for LaterGithub {
    fn send<'a>(
        &'a self,
        request: HttpRequest,
        deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>> {
        Box::pin(async move {
            if request.url.host_str() == Some("github.test") {
                assert_eq!(request.url.path(), "/repos/team/repo/actions/runs");
                self.entered.notify_one();
                self.release.notified().await;
                Ok(HttpResponse {
                    status: 200,
                    headers: vec![],
                    body: br#"{"total_count":0,"workflow_runs":[]}"#.to_vec(),
                })
            } else {
                self.sonar.send(request, deadline).await
            }
        })
    }
}

#[tokio::test]
async fn mapping_change_after_sonar_association_invalidates_final_publication() {
    with_deadline(async {
        let entered=Arc::new(tokio::sync::Notify::new());
        let release=Arc::new(tokio::sync::Notify::new());
        let transport=Arc::new(LaterGithub { sonar:Sonar {entered:None,release:None},entered:entered.clone(),release:release.clone() });
        let yaml=format!("{FLOW}  - id: later\n    connector: github\n    call: runs\n    with: {{ repo: 'team/repo' }}\n    needs: [inspect]\n    role: observe\n    output: compact\n");
        let fx=Fixture::with_flow(transport,&yaml).await;
        fx.daemon.store().set_setting("flows.scope_policy",&json!({"version":1,"repositories":[{"root":fx.repo.path().canonicalize().unwrap(),"connectors":[{"connector":"sonarqube","base_url":"https://sonar.test/","access":"targets","targets":["p"]},{"connector":"github","base_url":"https://github.test/","access":"targets","targets":["team/repo"]}]}]}).to_string()).await.unwrap();
        fx.daemon.store().insert_grant(&step_capability("sonar-correlated","later")).await.unwrap();
        fx.admin("github","admin.connectors.configure",json!({"id":"github","enabled":true,"base_url":"https://github.test/","credential":{"set":"fixture-only"}})).await;
        fx.mapping("initial",Some("https://git.example/team/repo")).await;
        let run=fx.run("late_change",SHA);
        let change=async {
            entered.notified().await;
            let bindings=fx.daemon.store().read_correlation_steps("late_change").await.unwrap();
            let prior:Value=serde_json::from_str(&bindings.iter().find(|binding|binding.step_id=="inspect").unwrap().canonical_json).unwrap();
            assert_eq!(prior["decision"]["status"],"matched");
            fx.mapping("late",Some("https://git.example/team/other")).await;
            release.notify_one();
        };
        let (response,())=tokio::join!(run,change);
        let (outcome,body)=result(response);
        assert_ne!(outcome,Outcome::Verified,"{body}");
        assert_eq!(body["correlation"]["status"],"conflicting");
        fx.retained("late_change").await;
        fx.finish().await;
    }).await;
}
