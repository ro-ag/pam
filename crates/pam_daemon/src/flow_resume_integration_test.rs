//! Real FlowService, journal, lifecycle and evidence paths; only HTTP/keychain fake.
use crate::{
    approval::ApprovalService,
    connector_service::{ConfigurePatch, ConnectorService, CredentialAction},
    daemon::CompletionRouter,
    executor::ExecContext,
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
const FLOW: &str = r#"schema: 1
id: resumable
name: Resumable
correlation:
  repository: https://git.example/team/repo.git
  commit: abcdef1234567890abcdef1234567890abcdef12
steps:
  - id: first
    connector: github
    call: run
    with: {repo: team/repo, run_id: 9, run_attempt: 1}
    output: compact
  - id: second
    connector: github
    call: run
    with: {repo: team/repo, run_id: 10, run_attempt: 1}
    needs: [first]
    output: compact
"#;
#[derive(Default)]
struct Reads {
    first: AtomicUsize,
    second: AtomicUsize,
    entered: tokio::sync::Notify,
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
                json!({"total_count":0,"jobs":[]})
            } else {
                let id = if path == "/repos/team/repo/actions/runs/9/attempts/1" {
                    self.first.fetch_add(1, Ordering::SeqCst);
                    9
                } else {
                    assert_eq!(path, "/repos/team/repo/actions/runs/10/attempts/1");
                    if self.second.fetch_add(1, Ordering::SeqCst) == 0 {
                        self.entered.notify_one();
                        std::future::pending::<()>().await;
                    }
                    10
                };
                json!({"id":id,"run_attempt":1,"head_sha":SHA,"status":"completed","conclusion":"success","repository":{"full_name":"team/repo","clone_url":SOURCE},"head_repository":{"full_name":"team/repo","clone_url":SOURCE}})
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
fn args() -> RunArgs {
    RunArgs {
        id: "resumable".to_owned(),
        inputs: BTreeMap::new(),
    }
}

#[tokio::test]
async fn lifecycle_recovery_skips_checkpointed_read_and_preserves_evidence() {
    tokio::time::timeout(Duration::from_secs(30),Box::pin(async {
        let base=tempfile::tempdir().unwrap();let repo=tempfile::tempdir().unwrap();let root=repo.path().canonicalize().unwrap();
        std::fs::create_dir(base.path().join("flows")).unwrap();std::fs::write(base.path().join("flows/resumable.yaml"),FLOW).unwrap();
        let store=Arc::new(Store::open_in_memory().await.unwrap());
        store.set_setting("policy.profile","\"relaxed\"").await.unwrap();
        store.set_setting("flows.scope_policy",&json!({"version":1,"repositories":[{"root":root,"connectors":[{"connector":"github","base_url":"https://github.test/","access":"targets","targets":["team/repo"]}]}]}).to_string()).await.unwrap();
        let (events,mut receiver)=EventPublisher::for_tests();
        let drain=tokio::spawn(async move{while receiver.recv().await.is_some(){}});
        let approvals=Arc::new(ApprovalService::new(store.clone(),events.clone(),Duration::from_secs(10)));
        let models=ModelService::new(store.clone()).await.unwrap();
        let logs=LogService::new(store.clone(),models.clone());
        let secrets=Arc::new(SecretStore::new(Arc::new(FakeSecretBackend::default())));
        let reads=Arc::new(Reads::default());
        let connectors=Arc::new(ConnectorService::new(store.clone(),secrets.clone(),reads.clone()));
        connectors.configure(pam_flow::ConnectorId::Github,ConfigurePatch{enabled:Some(true),base_url:Some(Some("https://github.test/".to_owned())),credential:Some(CredentialAction::Set("fixture-only".to_owned())),..ConfigurePatch::default()}).await.unwrap();
        let gate=Arc::new(PolicyGate::new(store.clone()).await.unwrap());
        let flows=Arc::new(FlowService::new(base.path(),store.clone(),approvals.clone(),connectors,logs,gate));
        let queue=Arc::new(QueueManager::new(store.clone()));
        let (_cancel,rx)=tokio::sync::watch::channel(false);
        let ctx=ExecContext{budget:crate::request_budget::RequestBudget::new(Instant::now()+Duration::from_secs(25)),request_id:"resume".to_owned(),args:json!({"id":"resumable"}),cancel:rx,events,store:store.clone(),queue:queue.clone(),models,router:CompletionRouter::new(),approvals,flows:flows.clone(),secrets,caller:Caller{agent:"fixture".to_owned(),repo:root.to_string_lossy().into_owned(),pid:std::process::id()},capability:"flow.run".to_owned(),started_at:Instant::now()};
        let expiry=now()+25000;
        store.insert_admitted_request("resume","flow.run",root.to_str().unwrap(),"fixture","{\"id\":\"resumable\"}",None,expiry).await.unwrap();
        assert!(store.authorize_queued_request("resume",root.to_str().unwrap(),now()).await.unwrap());
        assert!(store.start_queued_request("resume",now()).await.unwrap());
        {
            let executing=flows.run(&ctx,args());tokio::pin!(executing);
            tokio::select! {result=&mut executing=>panic!("expected interruption: {result:?}"),()=reads.entered.notified()=>{}}
        } // Simulated process interruption drops execution without running a terminal handler.
        let prepared=store.read_flow_journal("resume").await.unwrap().unwrap();
        assert_eq!(prepared.state,pam_store::FlowJournalState::Prepared);assert!(!prepared.effectful);
        assert_eq!(crate::lifecycle::recover_stuck_rows(&store).await.unwrap(),1);
        assert_eq!(store.get_request("resume").await.unwrap().unwrap().state,RequestState::Queued);
        assert_eq!(store.get_request("resume").await.unwrap().unwrap().expires_at_ms,Some(expiry));
        assert_eq!(queue.rebuild_from_store().await.unwrap(),1);
        assert!(store.start_queued_request("resume",now()).await.unwrap());
        let output=flows.run(&ctx,args()).await.unwrap();
        assert_eq!(reads.first.load(Ordering::SeqCst),1,"completed first read must not repeat");
        assert_eq!(reads.second.load(Ordering::SeqCst),2,"only interrupted read restarts");
        assert_eq!(output.outcome,Outcome::Solved);assert_eq!(output.body["correlation"]["status"],"matched");
        assert_eq!(store.read_correlation_steps("resume").await.unwrap().len(),2);
        let rows=store.list_evidence("resume").await.unwrap();assert_eq!(rows.iter().filter(|row|row.kind=="connector.result").count(),2);
        store.finish_request("resume",RequestState::Done,Some("solved"),AuditEntry{action:"execute",decision:Decision::Allow,actor:Actor::System,detail:None}).await.unwrap();
        let mut read_ctx=ctx;read_ctx.args=json!({"ticket":"resume"});
        let result=crate::flow_result_service::result(&read_ctx).await.unwrap();
        assert_eq!(result.body["agent_result"]["correlation"]["status"],"matched");
        let id=output.evidence.first().unwrap();read_ctx.args=json!({"request_id":"resume","evidence_id":id,"offset":0,"length":1024});
        assert!(crate::evidence_service::read(&read_ctx).await.is_ok());
        drain.abort();
    })).await.unwrap();
}
