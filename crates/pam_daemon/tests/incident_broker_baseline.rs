//! Synthetic development baseline, not a held-out incident or frontier-agent experiment.
use pam_connectors::{HttpRequest, HttpResponse, HttpTransport, Method, TransportError};
use pam_daemon::{
    admin::{ADMIN_CALLER_AGENT, ADMIN_REPO},
    flow_service::step_capability,
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
const SOURCE: &str = "https://git.example/team/repo.git";
const SITE: &str = "tenant.sharepoint.com,site,web";
const FLOW: &str = r"schema: 1
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
";
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
    async fn request(&self, id: &str, capability: &str, args: Value) -> Response {
        let request = envelope_for_repo(
            &self.repo.path().canonicalize().unwrap().to_string_lossy(),
            id,
            capability,
            args,
            true,
        );
        self.daemon.client().await.request(&request).await
    }
    async fn finish(self) {
        self.daemon.assert_invariant_clean().await;
        self.daemon.stop().await;
    }
}
#[derive(Default)]
struct Enterprise {
    seen: Mutex<Vec<Value>>,
    rejected: Mutex<usize>,
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
            let mut seen = self.seen.lock().unwrap();
            let expected = URLS.get(seen.len()).copied();
            if request.method != Method::Get || expected != Some(request.url.as_str()) {
                *self.rejected.lock().unwrap() += 1;
                return Err(TransportError::Network("unexpected baseline read".into()));
            }
            let body = match (host, path) {
                ("github.test", "/repos/team/repo/actions/runs/9/attempts/3") => {
                    json!({"id":9,"run_attempt":3,"head_sha":SHA,"status":"completed","conclusion":"success","repository":{"full_name":"team/repo","clone_url":SOURCE},"head_repository":{"full_name":"team/repo","clone_url":SOURCE}})
                }
                ("github.test", "/repos/team/repo/actions/runs/9/attempts/3/jobs") => {
                    json!({"total_count":0,"jobs":[]})
                }
                ("jenkins.test", "/job/team/job/build/41/api/json") => {
                    json!({"number":41,"result":"SUCCESS","building":false,"timestamp":1,"duration":1,"actions":[{"remoteUrls":[SOURCE],"lastBuiltRevision":{"SHA1":SHA}}]})
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
                    json!({"paging":{"total":1,"pageIndex":1,"pageSize":100},"analyses":[{"key":"a1","revision":SHA}]})
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
            let body = serde_json::to_vec(&body).unwrap();
            assert!(body.len() <= 16_384);
            seen.push(json!({"method":"GET","url":request.url.as_str(),
                "response_body_bytes":body.len(),"response_body_sha256":pam_compact::sha256_hex(&body)}));
            Ok(HttpResponse {
                status: 200,
                headers: vec![],
                body,
            })
        })
    }
}

const URLS: [&str; 13] = [
    "https://github.test/repos/team/repo/actions/runs/9/attempts/3",
    "https://github.test/repos/team/repo/actions/runs/9/attempts/3/jobs?per_page=100&page=1",
    "https://jenkins.test/job/team/job/build/41/api/json?tree=number%2Cresult%2Cbuilding%2Ctimestamp%2Cduration%2Cactions%5BremoteUrls%2ClastBuiltRevision%5BSHA1%5D%2Crevision%5Bhash%2CpullHash%2CbaseHash%5D%5D",
    "https://jenkins.test/job/team/job/build/41/wfapi/describe",
    "https://sonar.test/api/webservices/list?include_internals=true",
    "https://sonar.test/api/ce/task?id=ce1",
    "https://sonar.test/api/project_analyses/search?project=p&p=1&ps=100",
    "https://sonar.test/api/qualitygates/project_status?analysisId=a1",
    "https://jira.test/rest/api/2/issue/TEAM-1?fields=summary%2Cstatus%2Cissuetype%2Cpriority%2Cassignee%2Cupdated%2Cdescription",
    "https://confluence.test/wiki/api/v2/pages/42?body-format=storage",
    "https://graph.test/v1.0/sites/tenant.sharepoint.com,site,web",
    "https://graph.test/v1.0/sites/tenant.sharepoint.com,site,web/drives?$top=100&$select=id",
    "https://graph.test/v1.0/drives/drive/items/item",
];

fn serialized_bytes(response: &Response) -> usize {
    let bytes = serde_json::to_vec(response).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("fixture-private-token"));
    bytes.len()
}

fn normalize(value: &mut Value, replacements: &[(String, String)]) {
    match value {
        Value::String(text) => {
            for (from, to) in replacements {
                if text == from {
                    text.clone_from(to);
                    break;
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                normalize(item, replacements);
            }
        }
        Value::Object(items) => {
            for item in items.values_mut() {
                normalize(item, replacements);
            }
        }
        _ => {}
    }
}

async fn read_evidence(fixture: &Fixture, id: &str, index: usize) -> (Value, Value) {
    let mut args = json!({"request_id":"enterprise_run","evidence_id":id,"length":16_384});
    let mut bytes = Vec::new();
    let mut pages = Vec::new();
    for page_index in 0..8 {
        let response = fixture
            .request(
                &format!("read_{index}_{page_index}"),
                "evidence.read",
                args.clone(),
            )
            .await;
        let wire_bytes = serialized_bytes(&response);
        let Response::Result { body, .. } = response else {
            panic!("{response:?}")
        };
        assert_eq!(body["encoding"], "hex");
        let data = body["data"].as_str().unwrap();
        assert!(data.len() <= 32_768 && data.len().is_multiple_of(2));
        for offset in (0..data.len()).step_by(2) {
            bytes.push(u8::from_str_radix(&data[offset..offset + 2], 16).unwrap());
        }
        assert!(bytes.len() <= 131_072);
        pages.push(
            json!({"offset":body["offset"],"returned_bytes":body["returned_bytes"],
            "serialized_response_bytes":wire_bytes,"provenance":body["provenance"]}),
        );
        if body["eof"] == true {
            assert_eq!(bytes.len() as u64, body["total_bytes"].as_u64().unwrap());
            assert_eq!(
                pam_compact::sha256_hex(&bytes),
                body["view_sha256"].as_str().unwrap()
            );
            return (
                serde_json::from_slice(&bytes).unwrap(),
                json!({
                "evidence_id":id,"view_id":body["view_id"],"view_sha256":body["view_sha256"],
                "view_bytes":bytes.len(),"offset_basis":body["offset_basis"],
                "identity":body["identity"],"pages":pages}),
            );
        }
        args["offset"] = body["next_offset"].clone();
        args["expected_view_id"] = body["view_id"].clone();
        args["expected_sha256"] = body["view_sha256"].clone();
    }
    panic!("development evidence exceeded its eight-page cap")
}

async fn revoke_and_refuse(fixture: &Fixture, id: &str) -> usize {
    fixture
        .daemon
        .store()
        .set_setting("flows.scope_policy", "{\"version\":1,\"repositories\":[]}")
        .await
        .unwrap();
    let refused = fixture
        .request(
            "read_revoked",
            "evidence.read",
            json!({"request_id":"enterprise_run","evidence_id":id,"length":1}),
        )
        .await;
    assert!(matches!(refused, Response::Refusal { .. }), "{refused:?}");
    serialized_bytes(&refused)
}

fn replay_replacements(fixture: &Fixture, body: &Value, refs: &[String]) -> Vec<(String, String)> {
    let mut replacements: Vec<_> = refs
        .iter()
        .enumerate()
        .map(|(index, id)| (id.clone(), format!("evidence-{index}")))
        .collect();
    replacements.push((
        body["correlation"]["target_id"]
            .as_str()
            .unwrap()
            .to_owned(),
        "fixture-target".into(),
    ));
    replacements.push((
        fixture
            .repo
            .path()
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        "fixture-repository".into(),
    ));
    replacements
}

async fn run_baseline() -> (Value, Value) {
    let setup = Instant::now();
    let transport = Arc::new(Enterprise::default());
    let fixture = Fixture::new(transport.clone()).await;
    let setup_ns = setup.elapsed().as_nanos();
    let started = Instant::now();
    let response = fixture
        .request("enterprise_run", "flow.run", json!({"id":"enterprise"}))
        .await;
    let flow_ns = started.elapsed().as_nanos();
    let response_bytes = serialized_bytes(&response);
    assert!(response_bytes <= 16_384);
    let Response::Result {
        outcome, mut body, ..
    } = response
    else {
        panic!("{response:?}")
    };
    assert_eq!(outcome, Outcome::Verified, "{body}");
    assert_eq!(body["correlation"]["status"], "matched");
    assert_eq!(body["diagnosis"]["status"], "not_attempted");
    let refs: Vec<String> = body["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(refs.len(), 7);
    let replacements = replay_replacements(&fixture, &body, &refs);
    let read_started = Instant::now();
    let mut contents = Vec::new();
    let mut evidence = Vec::new();
    for (index, id) in refs.iter().enumerate() {
        let (mut content, record) = read_evidence(&fixture, id, index).await;
        normalize(&mut content, &replacements);
        if index == 0 {
            assert_eq!(content["flow"]["id"], "enterprise");
            for step in content["steps"].as_array_mut().unwrap() {
                step["duration_ms"] = Value::Null;
            }
        }
        contents.push(content);
        evidence.push(record);
    }
    let retrieval_ns = read_started.elapsed().as_nanos();
    assert_eq!(
        contents
            .iter()
            .filter(|item| item.get("citation").is_some())
            .count(),
        3
    );
    let office = contents
        .iter()
        .find(|item| item.get("item").is_some())
        .unwrap();
    assert_eq!(office["content"]["state"], "unsupported_format");
    assert_eq!(office["partial"], true);
    let denied_response_bytes = revoke_and_refuse(&fixture, &refs[0]).await;
    let calls = transport.seen.lock().unwrap().clone();
    assert_eq!(calls.len(), URLS.len());
    assert_eq!(*transport.rejected.lock().unwrap(), 0);
    let response_body_bytes: u64 = calls
        .iter()
        .map(|call| call["response_body_bytes"].as_u64().unwrap())
        .sum();
    normalize(&mut body, &replacements);
    let stable = json!({"result":body,"connector_evidence":contents,"http":calls});
    let record = json!({"setup_elapsed_ns":setup_ns.to_string(),"flow_elapsed_ns":flow_ns.to_string(),
        "retrieval_elapsed_ns":retrieval_ns.to_string(),"http_calls":calls.len(),"permitted_http_reads":URLS.len(),"unexpected_reads":0,
        "authorized_evidence_reads":evidence.iter().map(|item|item["pages"].as_array().unwrap().len()).sum::<usize>(),
        "evidence_serialized_response_bytes":evidence.iter().flat_map(|item|item["pages"].as_array().unwrap()).map(|page|page["serialized_response_bytes"].as_u64().unwrap()).sum::<u64>(),
        "revoked_evidence_reads":1,
        "http_response_body_bytes":response_body_bytes,"flow_serialized_response_bytes":response_bytes,
        "revoked_read_serialized_response_bytes":denied_response_bytes,"evidence":evidence,
        "normalized_content_sha256":pam_compact::sha256_hex(&serde_json::to_vec(&stable).unwrap())});
    fixture.finish().await;
    (stable, record)
}

#[tokio::test]
async fn synthetic_development_broker_baseline_replays_exact_authorized_evidence() {
    let (first, first_metrics) = with_deadline(Box::pin(run_baseline())).await;
    let (second, second_metrics) = with_deadline(Box::pin(run_baseline())).await;
    assert_eq!(
        first, second,
        "replayed product identity/content must remain stable"
    );
    let report = json!({"schema_version":1,"fixture":"enterprise-six-products-v1",
        "split":"development","authenticity":"synthetic","held_out":false,
        "fixture_source_sha256":pam_compact::sha256_hex(include_bytes!("incident_broker_baseline.rs")),
        "flow_sha256":pam_compact::sha256_hex(FLOW.as_bytes()),
        "arm":"deterministic_broker_public_evidence","runs":[first_metrics,second_metrics],
        "frontier_tokens":null,"corrections":null,"avoided_attempts":null,
        "measurement_status":{"frontier_tokens":"not_measured","corrections":"not_measured","avoided_attempts":"not_measured"},
        "limitations":["No model, frontier agent, live service or real incident was evaluated.",
        "Bytes count HTTP response bodies and serialized PAM responses, not TLS/network wire traffic.",
        "Setup is measured separately; elapsed times describe synthetic local replay, not live-service latency.",
        "Exact local paths, derived local target IDs, evidence IDs and flow step durations are normalized only for replay comparison; provider IDs and revisions are retained.",
        "A paired agent experiment with independently reviewed labels is still required for token savings or qualification."]});
    if let Some(path) = std::env::var_os("PAM_INCIDENT_BROKER_REPORT") {
        let bytes = serde_json::to_vec_pretty(&report).unwrap();
        assert!(bytes.len() <= 1_048_576);
        std::fs::write(path, bytes).unwrap();
    }
}

#[tokio::test]
async fn transcript_mismatch_never_receives_a_scripted_body() {
    let transport = Enterprise::default();
    let request = HttpRequest {
        method: Method::Get,
        body: None,
        url: "https://github.test/repos/team/repo/actions/runs/9/attempts/4"
            .parse()
            .unwrap(),
        headers: Vec::new(),
        max_bytes: 16_384,
        follow_one_https_redirect_without_auth: false,
    };
    let error = transport.send(request, Instant::now()).await.unwrap_err();
    assert!(matches!(error, TransportError::Network(_)));
    assert!(transport.seen.lock().unwrap().is_empty());
    assert_eq!(*transport.rejected.lock().unwrap(), 1);
}
