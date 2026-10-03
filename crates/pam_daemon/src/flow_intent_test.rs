use pam_flow::LandingOperation;
use serde_json::json;

use crate::flow_intent::{EffectIntent, IntentState, StepAttempt};
use crate::flow_recovery::Prepare;

fn step(yaml: &str) -> pam_flow::Step {
    pam_flow::parse(&format!("schema: 1\nid: f\nname: F\nsteps:\n{yaml}"))
        .expect("the fixture flow parses")
        .steps
        .remove(0)
}

/// A landing session written before the shared type (state a free string)
/// reads back unchanged and writes the same bytes: the persisted document and
/// the store's `/intent/state == "prepared"` check are untouched.
#[test]
fn a_landing_intent_keeps_its_persisted_form() {
    let written = json!({
        "step_id": "push",
        "operation": "push",
        "state": "prepared",
        "expected": {"ref_name": "refs/heads/topic"},
    });
    let intent: EffectIntent<LandingOperation> = serde_json::from_value(written.clone()).unwrap();
    assert!(intent.is_prepared("push", &LandingOperation::Push));
    assert!(intent.is_prepared_for("push"));
    assert!(!intent.is_prepared_for("merge"));
    assert!(!intent.is_prepared("push", &LandingOperation::Merge));
    assert_eq!(serde_json::to_value(&intent).unwrap(), written);

    let fresh = EffectIntent::prepared(
        "push",
        LandingOperation::Push,
        json!({"ref_name": "refs/heads/topic"}),
    );
    assert_eq!(serde_json::to_value(&fresh).unwrap(), written);

    // An unknown field is still refused, as the old struct refused it.
    let mut extra = written.clone();
    extra["surprise"] = json!(true);
    assert!(serde_json::from_value::<EffectIntent<LandingOperation>>(extra).is_err());
}

/// A refused mutation settles as `rejected` with its cause, exactly the
/// document the landing runtime wrote before.
#[test]
fn a_rejected_intent_records_its_cause_and_is_no_longer_prepared() {
    let mut intent =
        EffectIntent::prepared("open", LandingOperation::EnsurePr, json!({"target": "t"}));
    intent.reject("landing_pr_rejected");
    assert_eq!(intent.state, IntentState::Rejected);
    assert!(!intent.is_prepared_for("open"));
    assert_eq!(
        serde_json::to_value(&intent).unwrap(),
        json!({
            "step_id": "open",
            "operation": "ensure_pr",
            "state": "rejected",
            "expected": {"target": "t", "rejection": "landing_pr_rejected"},
        })
    );
}

/// The flow journal's attempt: effectful only for a stateful step that runs
/// now or has been armed past its gate; a gated stateful step is journaled
/// as not started and remembered as gating.
#[test]
fn a_step_attempt_is_effectful_exactly_when_the_journal_needs_it() {
    let stateful = step("  - id: s\n    run: [git, push]\n    effect: stateful\n");
    let read_only = step("  - id: r\n    run: [git, status]\n");
    let cases = [
        (&stateful, Prepare::Run, true, false),
        (&stateful, Prepare::Gate, false, true),
        (&stateful, Prepare::Skip, false, false),
        (&read_only, Prepare::Run, false, false),
        (&read_only, Prepare::Gate, false, false),
        (&read_only, Prepare::Skip, false, false),
    ];
    for (step, prepare, effectful, gating) in cases {
        let intent = EffectIntent::attempt(step, prepare);
        assert_eq!(intent.step_id, step.id);
        assert_eq!(intent.state, IntentState::Prepared);
        assert_eq!(
            intent.operation,
            StepAttempt { effectful, gating },
            "{} {prepare:?}",
            step.id
        );
    }
    let armed = EffectIntent::armed(&stateful);
    assert_eq!(
        armed.operation,
        StepAttempt {
            effectful: true,
            gating: false
        }
    );
}
