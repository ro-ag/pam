//! Six adapters share one frozen target; only transport and keychain are fakes.
use pam_connectors::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use pam_daemon::{
    admin::{ADMIN_CALLER_AGENT, ADMIN_REPO},
    flow_service::{EVIDENCE_KIND_CONNECTOR_RESULT, step_capability},
};
use pam_proto::{Outcome, Response};
use pam_testkit::{
    FakeSecretBackend, TestDaemon, envelope_for_repo, open_store, seed_flow, seed_relaxed,
    short_tempdir, with_deadline,
};
use serde_json::{Value, json};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Instant,
};
const SHA: &str = "abcdef1234567890abcdef1234567890abcdef12";
const OTHER: &str = "fedcba1234567890fedcba1234567890fedcba12";
const SOURCE: &str = "https://git.example/team/repo.git";
const SITE: &str = "tenant.sharepoint.com,site,web";
const FLOW: &str = r#"schema: 1
id: enterprise
name: Enterprise evidence
correlation:
  repository: https://git.example/team/repo.git
  commit: abcdef1234567890abcdef1234567890abcdef12
steps:
  - id: github
    connector: github
    call: run
    with: {repo: team/repo, run_id: 9, run_attempt: 3}
    role: observe
    output: compact
  - id: jenkins
    connector: jenkins
    call: investigate
    with: {job: team/build, build: 41}
    needs: [github]
    role: verify
    expect_status: SUCCESS
    output: compact
  - id: sonar
    connector: sonarqube
    call: analysis
    with: {project: p, ce_task: ce1}
    needs: [jenkins]
    role: verify
    expect_status: OK
    output: compact
  - id: jira
    connector: jira
    call: issue
    with: {key: TEAM-1}
    needs: [sonar]
    role: observe
    output: compact
  - id: confluence
    connector: confluence
    call: page
    with: {id: '42'}
    needs: [jira]
    role: observe
    output: compact
  - id: sharepoint
    connector: sharepoint
    call: document
    with: {site: 'tenant.sharepoint.com,site,web', drive: drive, item: item}
    needs: [confluence]
    role: observe
    output: compact
"#;
const CONNECTIONS: [(&str, &str, &str); 6] = [
    ("github", "https://github.test/", "team/repo"),
    ("jenkins", "https://jenkins.test/", "team/build"),
    ("sonarqube", "https://sonar.test/", "p"),
    ("jira", "https://jira.test/", "TEAM"),
    ("confluence", "https://confluence.test/wiki/", "42"),
    ("sharepoint", "https://graph.test/v1.0/", SITE),
];
struct Fixture {
    daemon: TestDaemon,
    repo: tempfile::TempDir,
}
impl Fixture {
    async fn new(transport: Arc<dyn HttpTransport>) -> Self {
        let tmp = short_tempdir();
        let repo = short_tempdir();
        seed_relaxed(&tmp).await;
        drop(seed_flow(&tmp, "enterprise", FLOW));
        let scopes:Vec<_>=CONNECTIONS.iter().map(|(id,url,target)|json!({"connector":id,"base_url":url,"access":"targets","targets":[target]})).collect();
        open_store(&tmp).await.set_setting("flows.scope_policy",&json!({"version":1,"repositories":[{"root":repo.path().canonicalize().unwrap(),"connectors":scopes}]}).to_string()).await.unwrap();
        let daemon = TestDaemon::spawn_at_with(tmp, move |config| {
            config.secret_backend = Some(Arc::new(FakeSecretBackend::default()));
            config.http_transport = Some(transport);
        })
        .await;
        let fx = Self { daemon, repo };
        for (id, url, _) in CONNECTIONS {
            fx.daemon
                .store()
                .insert_grant(&step_capability(
                    "enterprise",
                    if id == "sonarqube" { "sonar" } else { id },
                ))
                .await
                .unwrap();
            fx.admin(&format!("configure_{id}"),"admin.connectors.configure",json!({"id":id,"enabled":true,"base_url":url,"username":"fixture@example.invalid","credential":{"set":"fixture-private-token"}})).await;
        }
        let prior = fx
            .admin(
                "mapping_get",
                "admin.connectors.sonar_mappings.get",
                json!({}),
            )
            .await;
        fx.admin("mapping_set","admin.connectors.sonar_mappings.set",json!({"expected_revision":prior["revision"],"mappings":[{"server":"https://sonar.test/","project":"p","repository":SOURCE}]})).await;
        fx
    }
    async fn admin(&self, id: &str, op: &str, args: Value) -> Value {
        let mut req = envelope_for_repo(ADMIN_REPO, id, op, args, true);
        ADMIN_CALLER_AGENT.clone_into(&mut req.caller.agent);
        let response = self.daemon.client().await.request(&req).await;
        let Response::Result { body, .. } = response else {
            panic!("{response:?}")
        };
        body
    }
    async fn run(&self) -> (Outcome, Value) {
        let req = envelope_for_repo(
            &self.repo.path().canonicalize().unwrap().to_string_lossy(),
            "enterprise_run",
            "flow.run",
            json!({"id":"enterprise"}),
            true,
        );
        let response = self.daemon.client().await.request(&req).await;
        let serialized = serde_json::to_string(&response).unwrap();
        assert!(serialized.len() <= 16384);
        assert!(!serialized.contains("fixture-private-token"));
        let Response::Result { outcome, body, .. } = response else {
            panic!("{response:?}")
        };
        (outcome, body)
    }
    async fn captures(&self) -> Vec<Value> {
        let store = self.daemon.store();
        let mut captures = Vec::new();
        for row in store.list_evidence("enterprise_run").await.unwrap() {
            assert_eq!(row.request_id, "enterprise_run");
            if row.kind == EVIDENCE_KIND_CONNECTOR_RESULT {
                let content = store.get_evidence(&row.id).await.unwrap().unwrap().content;
                assert!(!String::from_utf8_lossy(&content).contains("fixture-private-token"));
                captures.push(serde_json::from_slice(&content).unwrap());
            }
        }
        captures
    }
    async fn finish(self) {
        self.daemon.assert_invariant_clean().await;
        self.daemon.stop().await;
    }
}
#[derive(Default)]
struct Enterprise {
    wrong: Option<&'static str>,
    seen: Mutex<Vec<String>>,
}
impl HttpTransport for Enterprise {
    fn send<'a>(
        &'a self,
        request: HttpRequest,
        _deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>> {
        Box::pin(async move {
            let host = request.url.host_str().unwrap();
            let path = request.url.path();
            self.seen.lock().unwrap().push(host.to_owned());
            let body = match (host, path) {
                ("github.test", "/repos/team/repo/actions/runs/9/attempts/3") => {
                    json!({"id":9,"run_attempt":3,"head_sha":SHA,"status":"completed","conclusion":"success","repository":{"full_name":"team/repo","clone_url":SOURCE},"head_repository":{"full_name":"team/repo","clone_url":SOURCE}})
                }
                ("github.test", "/repos/team/repo/actions/runs/9/attempts/3/jobs") => {
                    json!({"total_count":0,"jobs":[]})
                }
                ("jenkins.test", "/job/team/job/build/41/api/json") => {
                    json!({"number":41,"result":"SUCCESS","building":false,"timestamp":1,"duration":1,"actions":[{"remoteUrls":[SOURCE],"lastBuiltRevision":{"SHA1":if self.wrong==Some("jenkins"){OTHER}else{SHA}}}]})
                }
                ("jenkins.test", "/job/team/job/build/41/wfapi/describe") => {
                    json!({"status":"SUCCESS","stages":[]})
                }
                ("sonar.test", "/api/webservices/list") => {
                    json!({"webServices":[{"path":"api/ce","actions":[{"key":"task","params":[{"key":"id"}]}]},{"path":"api/project_analyses","actions":[{"key":"search","params":[{"key":"project"},{"key":"p"},{"key":"ps"},{"key":"branch"}]}]},{"path":"api/qualitygates","actions":[{"key":"project_status","params":[{"key":"analysisId"}]}]}]})
                }
                ("sonar.test", "/api/ce/task") => {
                    json!({"task":{"id":"ce1","type":"REPORT","componentKey":"p","status":"SUCCESS","analysisId":"a1"}})
                }
                ("sonar.test", "/api/project_analyses/search") => {
                    json!({"paging":{"total":1,"pageIndex":1,"pageSize":100},"analyses":[{"key":"a1","revision":if self.wrong==Some("sonar"){OTHER}else{SHA}}]})
                }
                ("sonar.test", "/api/qualitygates/project_status") => {
                    json!({"projectStatus":{"status":"OK","conditions":[]}})
                }
                ("jira.test", "/rest/api/2/issue/TEAM-1") => {
                    json!({"key":"TEAM-1","fields":{"summary":"Change context","description":"Issue context","updated":"2026-09-10T00:00:00Z"}})
                }
                ("confluence.test", "/wiki/api/v2/pages/42") => {
                    json!({"id":"42","title":"Runbook","spaceId":"7","version":{"number":3},"body":{"storage":{"value":"<p>Runbook context</p>","representation":"storage"}}})
                }
                ("graph.test", p) if p == format!("/v1.0/sites/{SITE}") => {
                    json!({"id":SITE,"webUrl":"https://tenant.sharepoint.com/sites/team"})
                }
                ("graph.test", p) if p == format!("/v1.0/sites/{SITE}/drives") => {
                    json!({"value":[{"id":"drive"}]})
                }
                ("graph.test", "/v1.0/drives/drive/items/item") => {
                    json!({"id":"item","parentReference":{"driveId":"drive"},"name":"runbook.docx","webUrl":"https://tenant.sharepoint.com/sites/team/runbook.docx","size":100,"lastModifiedDateTime":"2026-09-10T00:00:00Z","eTag":"e1","cTag":"c1","file":{"mimeType":"application/vnd.openxmlformats-officedocument.wordprocessingml.document"}})
                }
                _ => panic!("unexpected enterprise request {host}{path}"),
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
async fn all_six_products_share_one_target_without_promoting_document_context_to_proof() {
    with_deadline(Box::pin(async {
        let transport = Arc::new(Enterprise::default());
        let fx = Fixture::new(transport.clone()).await;
        let (outcome, body) = fx.run().await;
        assert_eq!(outcome, Outcome::Verified, "{body}");
        assert_eq!(body["correlation"]["status"], "matched");
        let captures = fx.captures().await;
        assert_eq!(captures.len(), 6);
        let docs: Vec<_> = captures
            .iter()
            .filter(|value| value.get("citation").is_some())
            .collect();
        assert_eq!(docs.len(), 3);
        assert!(
            docs.iter()
                .all(|value| value["citation"]["source_url"].is_string())
        );
        let office = docs
            .iter()
            .find(|value| value.get("item").is_some())
            .unwrap();
        assert_eq!(office["content"]["state"], "unsupported_format");
        assert!(office["content"]["text"].is_null());
        assert_eq!(office["partial"], true);
        let bindings = fx
            .daemon
            .store()
            .read_correlation_steps("enterprise_run")
            .await
            .unwrap();
        for row in bindings
            .iter()
            .filter(|row| matches!(row.step_id.as_str(), "jira" | "confluence" | "sharepoint"))
        {
            let value: Value = serde_json::from_str(&row.canonical_json).unwrap();
            assert_eq!(value["decision"]["status"], "unbound");
        }
        let target: Value = serde_json::from_str(
            &fx.daemon
                .store()
                .read_correlation_target("enterprise_run")
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(target["target"]["commit"], SHA);
        assert_eq!(target["target"]["repository"], SOURCE);
        assert_eq!(
            transport
                .seen
                .lock()
                .unwrap()
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            6
        );
        fx.finish().await;
    }))
    .await;
}
#[tokio::test]
async fn unrelated_successful_build_or_analysis_stops_before_documents() {
    with_deadline(Box::pin(async {
        for wrong in ["jenkins", "sonar"] {
            let transport = Arc::new(Enterprise {
                wrong: Some(wrong),
                ..Enterprise::default()
            });
            let fx = Fixture::new(transport.clone()).await;
            let (outcome, body) = fx.run().await;
            assert_eq!(outcome, Outcome::Blocked, "{body}");
            assert_eq!(body["correlation"]["status"], "conflicting");
            assert!(!transport.seen.lock().unwrap().iter().any(|host| matches!(
                host.as_str(),
                "jira.test" | "confluence.test" | "graph.test"
            )));
            assert_eq!(
                fx.captures().await.len(),
                if wrong == "jenkins" { 2 } else { 3 }
            );
            fx.finish().await;
        }
    }))
    .await;
}
