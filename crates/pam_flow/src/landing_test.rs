use serde_json::{Value, json};

use crate::{
    Action, Approval, Effect, LandingOperation, Role, digest, parse, parse_value,
    to_normalized_yaml,
};

fn recipe() -> Value {
    let steps: Vec<_> = LandingOperation::ORDER
        .iter()
        .enumerate()
        .map(|(index, operation)| {
            let name = serde_json::to_value(operation).unwrap();
            let mut step = json!({"id":format!("stage-{index}"), "landing":name});
            if index > 0 {
                step["needs"] = json!([format!("stage-{}", index - 1)]);
            }
            step
        })
        .collect();
    json!({"schema":1,"id":"landing","name":"Landing", "correlation":{
        "repository":"https://git.example/team/repo.git", "commit":"a".repeat(40)
    },"steps":steps})
}

#[test]
fn landing_effects_and_approvals_cannot_be_downgraded() {
    let raw = recipe();
    let flow = parse_value(&raw).unwrap();
    for (index, operation) in LandingOperation::ORDER.into_iter().enumerate() {
        let step = &flow.steps[index];
        assert_eq!(step.action, Action::Landing { operation });
        assert_eq!(step.effect, operation.effect());
        assert!(step.gated(), "every landing stage checks policy");
        assert_eq!(step.kind(), "landing");
        assert_eq!(step.role, Role::default_for(operation.effect()));
        if operation.effect() == Effect::Stateful {
            assert_eq!(step.approval, Approval::Required);
            assert_eq!(step.retry.attempts, 1);
        }
        let mut invalid = raw.clone();
        invalid["steps"][index]["effect"] = json!(if operation.effect() == Effect::Stateful {
            "read_only"
        } else {
            "stateful"
        });
        assert!(parse_value(&invalid).is_err());
        let mut verifying = raw.clone();
        verifying["steps"][index]["role"] = json!("verify");
        assert_eq!(parse_value(&verifying).is_ok(), operation.allows_verify());
    }
}

#[test]
fn landing_rejects_recipe_commands_parameters_and_retry_bypasses() {
    for (field, value) in [
        ("run", json!(["git", "push"])),
        ("connector", json!("github")),
        ("call", json!("merge")),
        ("with", json!({"url":"https://other.example"})),
        ("env", json!({})),
        ("expect_empty_output", json!(false)),
        ("expect_status", json!("success")),
        ("watch", json!({})),
        ("retry", json!({"attempts":2})),
        ("output", json!("summarize")),
        ("output", json!("discard")),
    ] {
        let mut raw = recipe();
        raw["steps"][2][field] = value;
        assert!(
            parse_value(&raw).is_err(),
            "forbidden landing field: {field}"
        );
    }
}

#[test]
fn missing_reordered_repeated_or_failure_gated_stages_are_rejected() {
    let mut no_target = recipe();
    no_target.as_object_mut().unwrap().remove("correlation");
    assert!(parse_value(&no_target).is_err());
    for index in 1..8 {
        for when in [
            json!("always"),
            json!({"failed":format!("stage-{}",index-1)}),
        ] {
            let mut raw = recipe();
            raw["steps"][index]["when"] = when;
            assert!(parse_value(&raw).is_err());
        }
        let mut missing = recipe();
        missing["steps"][index]["needs"] = json!([]);
        assert!(parse_value(&missing).is_err());
        let mut repeated = recipe();
        repeated["steps"][index]["landing"] = repeated["steps"][index - 1]["landing"].clone();
        assert!(parse_value(&repeated).is_err());
    }
    let mut skipped = recipe();
    skipped["steps"][1]["landing"] = json!("push");
    assert!(parse_value(&skipped).is_err());
    let mut extra = recipe();
    extra["steps"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"again","landing":"freeze"}));
    assert!(parse_value(&extra).is_err());
}

#[test]
fn prefixes_and_explicit_predecessor_success_round_trip_without_losing_pins() {
    let mut raw = recipe();
    raw["steps"].as_array_mut().unwrap().truncate(2);
    raw["steps"][0]["when"] = json!("always");
    raw["steps"][1]["when"] = json!({"succeeded":"stage-0"});
    let flow = parse_value(&raw).unwrap();
    let encoded = to_normalized_yaml(&flow);
    let again = parse(&encoded).unwrap();
    assert_eq!(again, flow);
    assert_eq!(digest(&flow), digest(&again));
    assert!(encoded.contains("landing: validate"));
    assert!(!encoded.contains("run:"));
    assert!(!encoded.contains("connector:"));
    let mut explicit = raw.clone();
    explicit["steps"][0]["effect"] = json!("read_only");
    explicit["steps"][0]["output"] = json!("compact");
    assert_eq!(digest(&parse_value(&explicit).unwrap()), digest(&flow));
}

#[test]
fn succeeded_condition_cannot_ignore_additional_failed_dependencies() {
    let mut raw = recipe();
    raw["steps"][2]["needs"] = json!(["stage-0", "stage-1"]);
    raw["steps"][2]["when"] = json!({"succeeded":"stage-1"});
    assert!(parse_value(&raw).is_err());
    raw["steps"][2]["when"] = json!("needs_succeeded");
    assert!(parse_value(&raw).is_ok());
}

#[test]
fn guarded_land_builtin_contains_the_complete_success_gated_chain() {
    let flow = parse(crate::builtin_yaml("guarded-land").unwrap()).unwrap();
    assert_eq!(flow.steps.len(), LandingOperation::ORDER.len());
    for (step, operation) in flow.steps.iter().zip(LandingOperation::ORDER) {
        assert_eq!(step.action, Action::Landing { operation });
        assert_eq!(step.role == Role::Verify, operation.allows_verify());
    }
    assert!(flow.correlation.is_some());
    assert_eq!(parse(&to_normalized_yaml(&flow)).unwrap(), flow);
}
