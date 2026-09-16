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

const SONAR: &str = "https://sonar.example/sonar/";
const REPOSITORY: &str = "https://git.example/team/app.git";

/// A correlated flow whose only step is a Sonar `analysis` read, so
/// [`Frozen::prepare`] snapshots the GUI-owned mapping.
fn sonar_flow() -> Flow {
    pam_flow::parse(&format!(
        "schema: 1\nid: scanned\nname: Scanned\ncorrelation:\n  repository: '{REPOSITORY}'\n  commit: '{}'\nsteps:\n  - id: scan\n    connector: sonarqube\n    call: analysis\n    with: {{project: 'team:app', ce_task: 'task-1'}}\n",
        "a".repeat(40)
    ))
    .unwrap()
}

fn sonar_origin() -> ConnectorTarget {
    ConnectorTarget {
        connector: ConnectorId::Sonarqube,
        base_url: SONAR.to_owned(),
        call: "analysis".to_owned(),
        args: BTreeMap::from([("project".to_owned(), ArgValue::Text("team:app".to_owned()))]),
    }
}

/// What the Sonar analysis call reports for the frozen commit.
fn analysis_result() -> Value {
    json!({"project":"team:app","revision":"a".repeat(40),"revision_basis":"analysis_history"})
}

/// Saves `repository` as the mapping for `team:app` on [`SONAR`] and returns
/// the new revision, replacing whatever the GUI held before.
async fn map_project(store: &Store, repository: &str) -> String {
    let current = crate::sonar_mapping::Snapshot::load(store).await.unwrap();
    crate::sonar_mapping::Snapshot::save(
        store,
        &json!({"expected_revision":current.revision(),"mappings":[{"server":SONAR,"project":"team:app","repository":repository}]}),
    )
    .await
    .map_err(|e| e.to_string())
    .unwrap()
    .revision()
    .to_owned()
}

#[tokio::test]
async fn a_changed_sonar_mapping_revision_conflicts_enrichment_and_the_mapping_check() {
    let store = Store::open_in_memory().await.unwrap();
    seed(&store).await;
    let frozen_revision = map_project(&store, REPOSITORY).await;
    let scanned = sonar_flow();
    let mut bound = frozen(&store, &scanned).await;
    assert_eq!(
        bound.report()["binding"]["sonar_mapping_revision"],
        frozen_revision
    );
    bound
        .check_mapping(&store)
        .await
        .map_err(|e| e.detail)
        .unwrap();

    // Under the frozen mapping the analysis is enriched with the GUI's
    // repository identity and the Sonar-reported revision.
    let mut result = analysis_result();
    bound
        .enrich(&store, &sonar_origin(), Some(&mut result))
        .await
        .map_err(|e| e.detail)
        .unwrap();
    let identity = &result["source_identity"];
    assert_eq!(identity["status"], "unambiguous");
    assert_eq!(identity["repository_urls"], json!([REPOSITORY]));
    assert_eq!(identity["revisions"], json!(["a".repeat(40)]));
    assert_eq!(identity["partial"], false);
    assert_eq!(identity["mapping_revision"], frozen_revision);
    assert_eq!(identity["repository_basis"], "gui_mapping");

    // The GUI remaps the project mid-collection: the revision moves.
    let changed = map_project(&store, "https://git.example/other/app.git").await;
    assert_ne!(changed, frozen_revision);
    let conflict = bound.check_mapping(&store).await.err().unwrap();
    assert_eq!(conflict.cause, CONFLICT);
    assert!(
        conflict.detail.contains("mapping changed"),
        "{}",
        conflict.detail
    );

    // Enrichment refuses the same way and leaves the result untouched.
    let mut later = analysis_result();
    let refused = bound
        .enrich(&store, &sonar_origin(), Some(&mut later))
        .await
        .err()
        .unwrap();
    assert_eq!(refused.cause, CONFLICT);
    assert_eq!(later, analysis_result());
    // Only Sonar analysis reads consult the mapping; a GitHub read is untouched.
    let mut untouched = json!({"id":9});
    bound
        .enrich(&store, &origin("run"), Some(&mut untouched))
        .await
        .map_err(|e| e.detail)
        .unwrap();
    assert_eq!(untouched, json!({"id":9}));

    // Recording the conflict poisons the whole request's correlation.
    bound.invalidate(&conflict);
    let report = bound.report();
    assert_eq!(report["status"], "conflicting");
    assert_eq!(report["steps"]["mapping_check"]["status"], "conflicting");
    assert_eq!(report["steps"]["mapping_check"]["detail"], conflict.detail);
    assert_eq!(
        bound.outcome(pam_proto::Outcome::Solved),
        pam_proto::Outcome::Unresolved
    );
    assert_eq!(bound.summary().status, "conflicting");

    // A flow with no Sonar analysis step froze no mapping: enrichment of an
    // analysis read is refused as missing rather than silently unmapped.
    let github_only = flow();
    store
        .insert_request("g", "flow.run", "/repo", "test", "{}", None)
        .await
        .unwrap();
    let unmapped = Frozen::prepare(&store, "g", "/repo", &github_only, &Vars::new())
        .await
        .map_err(|e| e.detail)
        .unwrap();
    let mut result = analysis_result();
    let missing = unmapped
        .enrich(&store, &sonar_origin(), Some(&mut result))
        .await
        .err()
        .unwrap();
    assert_eq!(missing.cause, crate::correlation::MISSING);
    assert!(result.get("source_identity").is_none());
}

#[tokio::test]
async fn unbound_verification_is_refused_only_for_verify_steps_under_a_target() {
    let store = Store::open_in_memory().await.unwrap();
    seed(&store).await;
    let flow = pam_flow::parse(&format!(
        "schema: 1\nid: proven\nname: Proven\ncorrelation:\n  repository: '{REPOSITORY}'\n  commit: '{}'\nsteps:\n  - id: prove\n    run: [git, status]\n    role: verify\n  - id: look\n    run: [git, status]\n    role: observe\n",
        "a".repeat(40)
    ))
    .unwrap();
    let mut bound = frozen(&store, &flow).await;
    assert!(bound.refuse_unbound_verification(&flow.steps[0]));
    assert!(!bound.refuse_unbound_verification(&flow.steps[1]));
    let report = bound.report();
    assert_eq!(report["steps"]["prove"]["status"], "missing");
    assert!(
        report["steps"]["prove"]["detail"]
            .as_str()
            .unwrap()
            .contains("no authenticated revision binding")
    );
    assert!(report["steps"].get("look").is_none());
    assert_eq!(report["status"], "missing");
    // A missing binding downgrades a proven verdict, never a blocked one.
    assert_eq!(
        bound.outcome(pam_proto::Outcome::Verified),
        pam_proto::Outcome::Unresolved
    );
    assert_eq!(
        bound.outcome(pam_proto::Outcome::Blocked),
        pam_proto::Outcome::Blocked
    );

    // Without a declared target there is nothing to bind to: verification
    // steps run unrefused and the request stays unbound.
    let unbound_flow = pam_flow::parse(
        "schema: 1\nid: unbound\nname: Unbound\nsteps:\n  - id: prove\n    run: [git, status]\n    role: verify\n",
    )
    .unwrap();
    store
        .insert_request("u", "flow.run", "/repo", "test", "{}", None)
        .await
        .unwrap();
    let mut unbound = Frozen::prepare(&store, "u", "/repo", &unbound_flow, &Vars::new())
        .await
        .map_err(|e| e.detail)
        .unwrap();
    assert!(!unbound.refuse_unbound_verification(&unbound_flow.steps[0]));
    assert!(unbound.report()["steps"].as_object().unwrap().is_empty());
    assert_eq!(unbound.report()["status"], "unbound");
    assert_eq!(
        unbound.outcome(pam_proto::Outcome::Solved),
        pam_proto::Outcome::Solved
    );
}

#[tokio::test]
async fn a_landing_receipt_binds_once_and_a_different_receipt_conflicts() {
    let store = Store::open_in_memory().await.unwrap();
    seed(&store).await;
    let flow = pam_flow::parse(&format!(
        "schema: 1\nid: land\nname: Land\ncorrelation:\n  repository: '{REPOSITORY}'\n  commit: '{}'\nsteps:\n  - id: freeze\n    landing: freeze\n",
        "a".repeat(40)
    ))
    .unwrap();
    let step = &flow.steps[0];
    let receipt = json!({"repository":REPOSITORY,"commit":"a".repeat(40),"branch":"feature/work"});
    let mut bound = frozen(&store, &flow).await;
    bound
        .record_landing_receipt(&store, "r", step, &receipt)
        .await
        .map_err(|e| e.detail)
        .unwrap();
    assert_eq!(bound.report()["steps"]["freeze"]["status"], "matched");
    assert_eq!(bound.report()["status"], "matched");
    let stored = store.read_correlation_steps("r").await.unwrap();
    assert_eq!(stored.len(), 1);
    let binding: Value = serde_json::from_str(&stored[0].canonical_json).unwrap();
    assert_eq!(binding["origin"]["kind"], "typed_landing");
    assert_eq!(binding["identity"], receipt);

    // The same receipt again is the same immutable association.
    bound
        .record_landing_receipt(&store, "r", step, &receipt)
        .await
        .map_err(|e| e.detail)
        .unwrap();
    assert_eq!(store.read_correlation_steps("r").await.unwrap(), stored);

    // A receipt naming another commit for the same step conflicts, and the
    // original binding stays pinned.
    let other = json!({"repository":REPOSITORY,"commit":"b".repeat(40),"branch":"feature/work"});
    let conflict = bound
        .record_landing_receipt(&store, "r", step, &other)
        .await
        .err()
        .unwrap();
    assert_eq!(conflict.cause, CONFLICT);
    assert!(conflict.detail.contains("conflicts"), "{}", conflict.detail);
    assert_eq!(store.read_correlation_steps("r").await.unwrap(), stored);
    assert_eq!(bound.report()["steps"]["freeze"]["status"], "matched");

    // A restart restores the matched landing binding from the store.
    let restored = frozen(&store, &flow).await;
    assert_eq!(restored.report()["steps"]["freeze"]["status"], "matched");

    // Only a typed landing step under a frozen target may record a receipt.
    let command = pam_flow::parse(
        "schema: 1\nid: plain\nname: Plain\nsteps:\n  - id: look\n    run: [git, status]\n",
    )
    .unwrap();
    let missing = bound
        .record_landing_receipt(&store, "r", &command.steps[0], &receipt)
        .await
        .err()
        .unwrap();
    assert_eq!(missing.cause, crate::correlation::MISSING);
    store
        .insert_request("u", "flow.run", "/repo", "test", "{}", None)
        .await
        .unwrap();
    let mut unbound = Frozen::prepare(&store, "u", "/repo", &command, &Vars::new())
        .await
        .map_err(|e| e.detail)
        .unwrap();
    assert_eq!(
        unbound
            .record_landing_receipt(&store, "u", step, &receipt)
            .await
            .err()
            .unwrap()
            .cause,
        crate::correlation::MISSING
    );
    assert!(store.read_correlation_steps("u").await.unwrap().is_empty());
}
