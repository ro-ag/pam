//! A failed stateful child may have changed the world; never repeat its effects.
use pam_proto::Response;
use pam_testkit::{
    TestDaemon, envelope_for_repo, seed_allowed_programs, seed_extra_path, seed_flow, seed_relaxed,
    seed_repository_scope, short_tempdir, with_deadline,
};
use serde_json::{Value, json};
use std::io::Write;

#[test]
fn stateful_child() {
    if std::env::var_os("PAM_STATEFUL_RETRY_PROBE").is_none() {
        return;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("effect-count")
        .unwrap();
    file.write_all(b"effect\n").unwrap();
    file.sync_all().unwrap();
    panic!("fixture fails after committing a visible effect");
}

#[tokio::test]
async fn failed_stateful_command_is_never_automatically_retried() {
    with_deadline(Box::pin(async {
        let executable=std::env::current_exe().unwrap();
        let tmp=short_tempdir();let repo=short_tempdir();
        seed_relaxed(&tmp).await;
        seed_repository_scope(&tmp,repo.path(),&[]).await;
        let name=executable.file_name().unwrap().to_str().unwrap();
        seed_allowed_programs(&tmp,&[name]).await;
        seed_extra_path(&tmp,&[executable.parent().unwrap().to_str().unwrap()]).await;
        let yaml=json!({"schema":1,"id":"stateful-once","name":"Stateful once","steps":[{"id":"write-fail","effect":"stateful","run":[name,"--exact","stateful_child","--nocapture"],"env":{"PAM_STATEFUL_RETRY_PROBE":"yes"},"retry":{"attempts":3,"backoff":"1ms"}}]}).to_string();
        drop(seed_flow(&tmp,"stateful-once",&yaml));
        let daemon=TestDaemon::spawn_at(tmp).await;
        daemon.store().insert_grant("flow.run").await.unwrap();
        daemon.store().insert_grant(&pam_daemon::flow_service::step_capability("stateful-once","write-fail")).await.unwrap();
        let request=envelope_for_repo(repo.path().canonicalize().unwrap().to_str().unwrap(),"stateful-run","flow.run",json!({"id":"stateful-once"}),true);
        let response=daemon.client().await.request(&request).await;
        assert!(matches!(&response,Response::Result{..}),"{response:?}");
        let store=daemon.store();
        let evidence=store.list_evidence("stateful-run").await.unwrap();
        let report=evidence.iter().find(|row|row.kind==pam_daemon::flow_service::EVIDENCE_KIND_FLOW_RESULT).unwrap();
        let content=store.get_evidence(&report.id).await.unwrap().unwrap().content;
        let report:Value=serde_json::from_slice(&content).unwrap();
        let step=&report["steps"][0];
        #[cfg(target_os="macos")]
        {
            assert_eq!(std::fs::read(repo.path().join("effect-count")).unwrap(),b"effect\n","a failed effect must run once, even when retry.attempts=3");
            assert_eq!(step["attempts"],1,"{report}");
            assert_ne!(step["status"],"succeeded");
        }
        #[cfg(not(target_os="macos"))]
        {
            assert!(!repo.path().join("effect-count").exists());
            assert_eq!(step["error"]["cause"],"command_containment_unavailable","{report}");
        }
        daemon.assert_single_terminal_audit("stateful-run").await;
        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })).await;
}
