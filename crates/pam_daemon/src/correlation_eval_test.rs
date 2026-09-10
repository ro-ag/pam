use crate::correlation_eval::{Status, evaluate, product_identity};
use pam_flow::{ArgValue, ConnectorId, CorrelationTarget};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn target() -> CorrelationTarget {
    CorrelationTarget {
        repository: "https://git.example/team/app.git".into(),
        commit: "a".repeat(40),
        pull_request: None,
        pull_request_head: None,
    }
}
fn reported() -> Value {
    json!({"source_identity":{"status":"unambiguous","repository_urls":["https://git.example/team/app.git"],"revisions":["a".repeat(40)],"partial":false,"invalid_metadata":false}})
}

#[test]
fn exact_source_matches_but_same_basename_host_or_sha_never_substitutes() {
    assert!(
        evaluate(
            &target(),
            ConnectorId::Jenkins,
            "investigate",
            Some(&reported())
        )
        .is_matched()
    );
    for (url, sha) in [
        ("https://other.example/team/app.git", "a".repeat(40)),
        ("https://git.example/other/app.git", "a".repeat(40)),
        ("https://git.example/team/app.git", "b".repeat(40)),
    ] {
        let mut report = reported();
        report["source_identity"]["repository_urls"] = json!([url]);
        report["source_identity"]["revisions"] = json!([sha]);
        let decision = evaluate(&target(), ConnectorId::Github, "run", Some(&report));
        assert_eq!(decision.status, Status::Conflicting);
        assert_eq!(decision.cause(), Some("correlation_conflicting"));
    }
}

#[test]
fn incomplete_ambiguous_or_invalid_evidence_stays_missing() {
    for (key, value) in [
        ("status", json!("ambiguous")),
        ("partial", json!(true)),
        ("invalid_metadata", json!(true)),
        ("revisions", json!(["shortsha"])),
        ("repository_urls", json!(["ssh://git.example/team/app.git"])),
        ("revisions", json!(["a".repeat(40), "b".repeat(40)])),
    ] {
        let mut report = reported();
        report["source_identity"][key] = value;
        assert_eq!(
            evaluate(&target(), ConnectorId::Github, "run", Some(&report)).status,
            Status::Missing
        );
    }
    assert_eq!(
        evaluate(&target(), ConnectorId::Github, "run", None).cause(),
        Some("correlation_missing")
    );
    assert!(evaluate(&target(), ConnectorId::Github, "job_log", Some(&reported())).is_unbound());
    assert_eq!(
        evaluate(
            &target(),
            ConnectorId::Sonarqube,
            "quality_gate",
            Some(&reported())
        )
        .status,
        Status::Missing
    );
}

#[test]
fn fork_source_and_pull_request_head_must_each_match_the_declared_target() {
    let mut target = target();
    target.pull_request = Some(7);
    target.pull_request_head = Some("b".repeat(40));
    let mut report = reported();
    report["run"] = json!({"repository":{"full_name":"base/app"},"head_repository":{"full_name":"fork/app"},"pull_requests_partial":false,"pull_requests":[{"number":7,"head":{"sha":"b".repeat(40)}}]});
    assert!(evaluate(&target, ConnectorId::Github, "run", Some(&report)).is_matched());
    report["run"]["pull_requests"][0]["head"]["sha"] = json!("c".repeat(40));
    assert_eq!(
        evaluate(&target, ConnectorId::Github, "run", Some(&report)).status,
        Status::Conflicting
    );
    report["run"]["pull_requests_partial"] = json!(true);
    assert_eq!(
        evaluate(&target, ConnectorId::Github, "run", Some(&report)).status,
        Status::Missing
    );
    report["source_identity"]["repository_urls"] = json!(["https://git.example/fork/app.git"]);
    assert_eq!(
        evaluate(&target, ConnectorId::Github, "run", Some(&report)).status,
        Status::Conflicting
    );
}

#[test]
fn product_identity_preserves_only_bounded_stable_reported_ids() {
    let mut report = reported();
    report["run_id"] = json!(42);
    report["run_attempt"] = json!(3);
    report["jobs"] = json!(
        (1..=101)
            .map(|id| json!({"id":id,"name":"mutable","status":"running"}))
            .collect::<Vec<_>>()
    );
    report["status"] = json!("success");
    report["timestamp"] = json!(999);
    let args = BTreeMap::from([("repo".into(), ArgValue::Text("team/app".into()))]);
    let before = product_identity(ConnectorId::Github, "run", &args, Some(&report));
    assert_eq!(before["job_ids"].as_array().unwrap().len(), 100);
    assert_eq!(before["run_attempt"], 3);
    assert_eq!(before["repository"], "team/app");
    report["status"] = json!("failure");
    report["timestamp"] = json!(888);
    assert_eq!(
        before,
        product_identity(ConnectorId::Github, "run", &args, Some(&report))
    );
    assert!(serde_json::to_vec(&before).unwrap().len() < 8192);
    let mut bad = reported();
    bad["source_identity"]["repository_urls"] = json!(["x".repeat(3000)]);
    assert_eq!(
        product_identity(
            ConnectorId::Jenkins,
            "investigate",
            &BTreeMap::new(),
            Some(&bad)
        )["source_identity"]["partial"],
        true
    );
}
