use std::collections::BTreeMap;

use pam_proto::{Outcome, Response};
use serde_json::json;

use crate::flow_contract::{
    MAX_OBSERVATION_BYTES, MAX_RESULT_BYTES, ProductObservation, inspect_vars, pagination,
    project_result,
};
use crate::flow_exec::{RunReport, StepReport, StepStatus};

fn report(status: StepStatus, outcome: Outcome, text: &str) -> RunReport {
    let mut step = StepReport::new("investigate", "connector", status);
    step.summary = Some(text.to_owned());
    RunReport {
        outcome,
        summary: "one observation".to_owned(),
        steps: vec![step],
    }
}

#[test]
fn retrieval_success_does_not_change_the_observed_build_failure() {
    let products = BTreeMap::from([(
        "investigate".to_owned(),
        ProductObservation {
            connector: "jenkins".to_owned(),
            status: "FAILURE".to_owned(),
        },
    )]);
    let result = project_result(
        "ticket",
        "flow",
        "digest",
        &report(
            StepStatus::Succeeded,
            Outcome::Unresolved,
            "post completed; attribution unresolved",
        ),
        &["verdict".to_owned()],
        &products,
    )
    .unwrap();
    assert_eq!(result.workflow.outcome, "unresolved");
    assert_eq!(result.observations[0].status, "succeeded");
    assert_eq!(
        result.observations[0].product.as_ref().unwrap().status,
        "FAILURE"
    );
    assert_eq!(result.diagnosis.status, "not_attempted");
}

#[test]
fn skipped_steps_and_recovered_failures_remain_observations() {
    let products = BTreeMap::from([(
        "investigate".to_owned(),
        ProductObservation {
            connector: "jenkins".to_owned(),
            status: "SUCCESS".to_owned(),
        },
    )]);
    let mut report = report(
        StepStatus::Succeeded,
        Outcome::Verified,
        "FAILED child; retry recovered",
    );
    report
        .steps
        .push(StepReport::new("later", "command", StepStatus::Skipped));
    let result = project_result("ticket", "flow", "digest", &report, &[], &products).unwrap();
    assert_eq!(result.workflow.outcome, "verified");
    assert_eq!(
        result.observations[0].product.as_ref().unwrap().status,
        "SUCCESS"
    );
    assert_eq!(result.observations[1].status, "skipped");
}

#[test]
fn escaping_multibyte_and_many_references_fit_complete_json() {
    let mut report = report(
        StepStatus::Failed,
        Outcome::Unresolved,
        &"\"\né漢".repeat(2500),
    );
    report.steps = vec![report.steps[0].clone(); 100];
    let evidence = (0..200)
        .map(|index| format!("ev_{index}"))
        .collect::<Vec<_>>();
    let result = project_result(
        "ticket",
        "flow",
        "digest",
        &report,
        &evidence,
        &BTreeMap::new(),
    )
    .unwrap();
    assert!(serde_json::to_vec(&result).unwrap().len() <= MAX_RESULT_BYTES);
    assert!(
        result
            .observations
            .iter()
            .map(|item| item.text.len())
            .sum::<usize>()
            <= MAX_OBSERVATION_BYTES
    );
    assert!(result.omitted.observations > 0);
    assert!(result.omitted.evidence > 0);
    assert!(result.omitted.observation_bytes > 0);
    let response = Response::Result {
        id: "ticket".to_owned(),
        outcome: Outcome::Unresolved,
        body: serde_json::to_value(result).unwrap(),
        evidence: vec!["verdict".to_owned()],
    };
    assert!(serde_json::to_vec(&response).unwrap().len() <= 16 * 1024);
}

#[test]
fn redaction_precedes_a_secret_crossing_the_summary_boundary() {
    let text = format!(
        "{}\nAuthorization: Bearer should-never-appear",
        "x".repeat(5980)
    );
    let result = project_result(
        "ticket",
        "flow",
        "digest",
        &report(StepStatus::Failed, Outcome::Unresolved, &text),
        &[],
        &BTreeMap::new(),
    )
    .unwrap();
    assert!(
        !serde_json::to_string(&result)
            .unwrap()
            .contains("should-never")
    );
}

#[test]
fn stored_projection_roundtrips_and_rejects_unknown_fields() {
    let result = project_result(
        "ticket",
        "flow",
        "digest",
        &report(StepStatus::Failed, Outcome::Unresolved, "test failed"),
        &[],
        &BTreeMap::new(),
    )
    .unwrap();
    let mut value = serde_json::to_value(result).unwrap();
    let decoded: crate::flow_contract::AgentResult = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), value);
    value["raw_log"] = json!("protected");
    assert!(serde_json::from_value::<crate::flow_contract::AgentResult>(value).is_err());
}

#[test]
fn pagination_refuses_invalid_bounds() {
    assert_eq!(pagination(&json!({})).unwrap(), (0, 20));
    assert_eq!(
        pagination(&json!({"offset": 40,"limit":50})).unwrap(),
        (40, 50)
    );
    for args in [
        json!({"limit":0}),
        json!({"limit":51}),
        json!({"offset":-1}),
        json!({"limit":"20"}),
        json!({"offset":1.5}),
    ] {
        assert!(pagination(&args).is_err());
    }
}

#[test]
fn inspection_does_not_resolve_git_or_prior_step_outputs() {
    let flow = pam_flow::parse("schema: 1\nid: inspect\nname: Inspect\ninputs:\n  origin:\n    default: '${repo.origin}'\n  local:\n    default: '${repo.name}'\nsteps:\n  - id: status\n    run: [git, status]\n").unwrap();
    let (vars, missing) = inspect_vars(
        &flow,
        &BTreeMap::new(),
        std::path::Path::new("/tmp/repository"),
    );
    assert_eq!(missing, ["origin"]);
    assert_eq!(vars.resolve("inputs.local").as_deref(), Some("repository"));
    assert!(vars.resolve("repo.origin").is_none());
    assert!(vars.resolve("steps.status.exit_status").is_none());
}

#[test]
fn inspection_distinguishes_admission_auto_grants_and_manual_approvals() {
    use crate::flow_contract::inspect_gate;
    use crate::policy::{CapabilityClass as Class, Profile};
    for profile in [Profile::Relaxed, Profile::Standard, Profile::Strict] {
        for granted in [false, true] {
            assert_eq!(inspect_gate(profile, granted, Class::ReadOnly), "allowed");
        }
    }
    assert_eq!(
        inspect_gate(Profile::Relaxed, false, Class::NonDestructive),
        "auto_grant_on_execution"
    );
    assert_eq!(
        inspect_gate(Profile::Relaxed, true, Class::External),
        "allowed"
    );
    assert_eq!(
        inspect_gate(Profile::Relaxed, false, Class::External),
        "approval_required"
    );
    assert_eq!(
        inspect_gate(Profile::Standard, false, Class::NonDestructive),
        "not_granted"
    );
    assert_eq!(
        inspect_gate(Profile::Standard, true, Class::NonDestructive),
        "allowed"
    );
    assert_eq!(
        inspect_gate(Profile::Standard, true, Class::External),
        "approval_required"
    );
    assert_eq!(
        inspect_gate(Profile::Strict, false, Class::NonDestructive),
        "not_granted"
    );
    assert_eq!(
        inspect_gate(Profile::Strict, true, Class::NonDestructive),
        "approval_required"
    );
}
