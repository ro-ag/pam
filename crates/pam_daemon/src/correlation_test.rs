use std::collections::BTreeMap;

use pam_flow::{ArgValue, ConnectorId, Flow, Vars};
use pam_store::Store;
use serde_json::{Value, json};

use crate::{
    correlation::{CONFLICT, Frozen, STORAGE},
    evidence_service::ConnectorTarget,
};

fn flow() -> Flow {
    pam_flow::parse(&format!(
        "schema: 1\nid: correlated\nname: Correlated\ncorrelation:\n  repository: 'https://git.example/team/app.git'\n  commit: '{}'\nsteps:\n  - id: run\n    connector: github\n    call: run\n    with: {{repo: 'team/app', run_id: 9}}\n  - id: log\n    connector: github\n    call: job_log\n    with: {{repo: 'team/app', job_id: 2}}\n", "a".repeat(40)
    )).unwrap()
}

fn origin(call: &str) -> ConnectorTarget {
    ConnectorTarget {
        connector: ConnectorId::Github,
        base_url: "https://api.example/".to_owned(),
        call: call.to_owned(),
        args: BTreeMap::from([
            ("repo".to_owned(), ArgValue::Text("team/app".to_owned())),
            (
                if call == "run" { "run_id" } else { "job_id" }.to_owned(),
                ArgValue::Int(if call == "run" { 9 } else { 2 }),
            ),
        ]),
    }
}

fn report(ids: &[u64]) -> Value {
    json!({"run_id":9,"run_attempt":3,"jobs":ids.iter().map(|id| json!({"id":id})).collect::<Vec<_>>(),
        "source_identity":{"status":"unambiguous","repository_urls":["https://git.example/team/app.git"],
        "revisions":["a".repeat(40)],"partial":false,"invalid_metadata":false}})
}

async fn frozen(store: &Store, flow: &Flow) -> Frozen {
    Frozen::prepare(store, "r", "/repo", flow, &Vars::new())
        .await
        .map_err(|e| e.detail)
        .unwrap()
}

async fn seed(store: &Store) {
    store
        .insert_request("r", "flow.run", "/repo", "test", "{}", None)
        .await
        .unwrap();
}

#[tokio::test]
async fn growing_jobs_authorize_exact_logs_after_frozen_state_restore() {
    let store = Store::open_in_memory().await.unwrap();
    seed(&store).await;
    let flow = flow();
    let mut bound = frozen(&store, &flow).await;
    bound
        .associate(
            &store,
            "r",
            &flow.steps[0],
            &origin("run"),
            Some(&report(&[1])),
        )
        .await
        .map_err(|e| e.detail)
        .unwrap();
    let first = store.read_correlation_steps("r").await.unwrap();
    bound
        .associate(
            &store,
            "r",
            &flow.steps[0],
            &origin("run"),
            Some(&report(&[1, 2])),
        )
        .await
        .map_err(|e| e.detail)
        .unwrap();
    assert_eq!(store.read_correlation_steps("r").await.unwrap(), first);
    let mut restored = frozen(&store, &flow).await;
    restored
        .associate(&store, "r", &flow.steps[1], &origin("job_log"), None)
        .await
        .map_err(|e| e.detail)
        .unwrap();
    assert_eq!(restored.report()["steps"]["log"]["status"], "matched");
    let mut wrong = origin("job_log");
    wrong.base_url = "https://other.example/".to_owned();
    assert!(
        restored
            .associate(&store, "r", &flow.steps[1], &wrong, None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn substituted_attempt_and_overflow_do_not_append_job_authority() {
    for substitute in [true, false] {
        let store = Store::open_in_memory().await.unwrap();
        seed(&store).await;
        let flow = flow();
        let mut bound = frozen(&store, &flow).await;
        let initial: Vec<u64> = if substitute {
            vec![1]
        } else {
            (1..=256).collect()
        };
        bound
            .associate(
                &store,
                "r",
                &flow.steps[0],
                &origin("run"),
                Some(&report(&initial)),
            )
            .await
            .map_err(|e| e.detail)
            .unwrap();
        let stored = store.read_correlation_steps("r").await.unwrap();
        let mut incoming = report(&[999]);
        if substitute {
            incoming["run_attempt"] = json!(4);
        }
        let failure = bound
            .associate(&store, "r", &flow.steps[0], &origin("run"), Some(&incoming))
            .await
            .err()
            .unwrap();
        assert_eq!(failure.cause, if substitute { CONFLICT } else { STORAGE });
        assert_eq!(
            store
                .read_correlation_membership("r", "run", &stored[0].canonical_json)
                .await
                .unwrap(),
            Some(initial)
        );
        let mut restored = frozen(&store, &flow).await;
        let mut log = origin("job_log");
        log.args.insert("job_id".to_owned(), ArgValue::Int(999));
        assert!(
            restored
                .associate(&store, "r", &flow.steps[1], &log, None)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn legacy_embedded_membership_requires_a_new_request() {
    let store = Store::open_in_memory().await.unwrap();
    seed(&store).await;
    let flow = flow();
    let mut bound = frozen(&store, &flow).await;
    bound
        .associate(
            &store,
            "r",
            &flow.steps[0],
            &origin("run"),
            Some(&report(&[1])),
        )
        .await
        .map_err(|e| e.detail)
        .unwrap();
    let target = store.read_correlation_target("r").await.unwrap().unwrap();
    let mut legacy: Value =
        serde_json::from_str(&store.read_correlation_steps("r").await.unwrap()[0].canonical_json)
            .unwrap();
    legacy["identity"]["job_ids"] = json!([1]);
    store
        .insert_request("legacy", "flow.run", "/repo", "test", "{}", None)
        .await
        .unwrap();
    store
        .bind_correlation_target("legacy", &target)
        .await
        .unwrap();
    store
        .bind_correlation_step("legacy", "run", &legacy.to_string())
        .await
        .unwrap();
    let error = Frozen::prepare(&store, "legacy", "/repo", &flow, &Vars::new())
        .await
        .err()
        .unwrap();
    assert_eq!(error.cause, STORAGE);
    assert!(error.detail.contains("legacy"));
    assert!(error.detail.contains("new request"));
}
