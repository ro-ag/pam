use std::collections::HashSet;

use serde::Serialize;

use super::*;

const HEADER: &str = r#"
schema_version = 2
id = "engine-test"
name = "Engine test"
description = "Exercise deterministic flow scheduling."
revision = 1

[outcome]
solved = "Report solved work."
changed = "Report changed state."
verified = "Report verified evidence."
unresolved = "Report unresolved work."
blocked = "Report the exact blocker."
"#;

const READ_ONLY_STEP: &str = r#"
[[steps]]
id = "collect"
description = "Collect bounded evidence."
timeout_seconds = 30
effect = "read_only"
semantic = "observe"
action = { type = "command", program = "git", args = ["status"], working_directory = "." }
"#;

const STATEFUL_STEP: &str = r#"
[[steps]]
id = "apply"
description = "Apply one exact approved effect."
approval = "required"
idempotency_key = "engine-test:apply"
timeout_seconds = 30
effect = "stateful"
semantic = "change"
action = { type = "connector", connector = "github.actions", capability = "runs.rerun", resource = { kind = "workflow_run", id = "github:ro-ag/pam/runs/42" } }
"#;

const RETRY_STEP: &str = r#"
[[steps]]
id = "collect"
description = "Collect evidence with a bounded retry budget."
retry = { max_attempts = 3, initial_backoff_ms = 100, max_backoff_ms = 150 }
timeout_seconds = 30
effect = "read_only"
semantic = "verify"
action = { type = "command", program = "cargo", args = ["test"], working_directory = "." }
"#;

const BRANCH_STEPS: &str = r#"
[[steps]]
id = "probe"
description = "Probe the system."
timeout_seconds = 30
effect = "read_only"
semantic = "observe"
action = { type = "command", program = "cargo", args = ["check"], working_directory = "." }

[[steps]]
id = "on-success"
description = "Run only after probe success."
depends_on = ["probe"]
condition = { kind = "succeeded", step = "probe" }
timeout_seconds = 30
effect = "read_only"
semantic = "verify"
action = { type = "command", program = "cargo", args = ["test"], working_directory = "." }

[[steps]]
id = "on-failure"
description = "Run only after probe failure."
depends_on = ["probe"]
condition = { kind = "failed", step = "probe" }
timeout_seconds = 30
effect = "read_only"
semantic = "observe"
action = { type = "command", program = "git", args = ["status"], working_directory = "." }
"#;

fn definition(steps: &str) -> FlowDefinition {
    FlowDefinition::parse_toml(&format!("{HEADER}{steps}"))
        .expect("engine test definition should validate")
}

fn definition_v1(steps: &str) -> FlowDefinition {
    let source = format!("{HEADER}{steps}")
        .replace("schema_version = 2", "schema_version = 1")
        .lines()
        .filter(|line| !line.starts_with("semantic = "))
        .collect::<Vec<_>>()
        .join("\n");
    FlowDefinition::parse_toml(&source).expect("version-one engine fixture should validate")
}

fn run_id(value: &str) -> RunId {
    RunId::parse(value).unwrap()
}

fn start(id: &str, steps: &str) -> FlowRun {
    FlowRun::start(run_id(id), definition(steps)).unwrap()
}

fn evaluated_effect(update: &EngineUpdate) -> EffectAttempt {
    match update.decision() {
        RunDecision::EvaluateEffect { effect, .. } => effect.clone(),
        other => panic!("expected effect evaluation, got {other:?}"),
    }
}

fn approval(update: &EngineUpdate) -> ApprovalToken {
    match update.decision() {
        RunDecision::AwaitApproval { token, .. } => *token,
        other => panic!("expected approval request, got {other:?}"),
    }
}

fn successful_result(label: &str) -> EffectResult {
    EffectResult::succeeded(
        label,
        vec![EvidenceHandle::parse(format!("evidence:{label}")).unwrap()],
    )
    .unwrap()
}

fn failed_result(label: &str, retryable: bool) -> EffectResult {
    EffectResult::failed(
        label,
        retryable,
        vec![EvidenceHandle::parse(format!("evidence:{label}")).unwrap()],
    )
    .unwrap()
}

fn start_effect(run: &mut FlowRun, now_ms: u64) -> EffectAttempt {
    let evaluation = run.next_decision(now_ms).unwrap();
    let effect = evaluated_effect(&evaluation);
    let prepared = run.prepare_effect(&effect, now_ms).unwrap();
    assert!(matches!(
        prepared.decision(),
        RunDecision::Execute { replay: false, .. }
    ));
    assert!(matches!(
        prepared.snapshot().steps()[effect.step_index()].state(),
        StepState::InFlight { .. }
    ));
    effect
}

fn resume(definition: FlowDefinition, snapshot: FlowSnapshot) -> FlowRun {
    let id = snapshot.run_id().clone();
    FlowRun::resume(&id, definition, snapshot).unwrap()
}

fn assert_snapshot_serde_round_trip(snapshot: &FlowSnapshot) {
    let encoded = toml::Value::try_from(snapshot.clone()).unwrap();
    let decoded: FlowSnapshot = encoded.try_into().unwrap();
    assert_eq!(&decoded, snapshot);
}

fn maximum_flow_definition() -> FlowDefinition {
    use std::fmt::Write as _;

    let mut source = HEADER.to_owned();
    for index in 0..MAX_FLOW_STEPS {
        let prefix = format!("step-{index:03}-");
        let step_id = format!("{prefix}{}", "x".repeat(MAX_FLOW_ID_BYTES - prefix.len()));
        write!(
            source,
            r#"
[[steps]]
id = "{step_id}"
description = "Retain the maximum bounded retry evidence."
retry = {{ max_attempts = {MAX_RETRY_ATTEMPTS}, initial_backoff_ms = 1, max_backoff_ms = 1 }}
timeout_seconds = 30
effect = "read_only"
semantic = "observe"
action = {{ type = "command", program = "true", args = [], working_directory = "." }}
"#
        )
        .unwrap();
    }
    FlowDefinition::parse_toml(&source).unwrap()
}

fn maximum_effect_result() -> EffectResult {
    let handle =
        EvidenceHandle::parse(format!("e{}", "x".repeat(MAX_EVIDENCE_HANDLE_BYTES - 1))).unwrap();
    EffectResult::failed(
        "x".repeat(MAX_EFFECT_SUMMARY_BYTES),
        true,
        vec![handle; MAX_EVIDENCE_HANDLES],
    )
    .unwrap()
}

fn validate_update(
    previous: &FlowSnapshot,
    update: &EngineUpdate,
    seen: &mut HashSet<&'static str>,
) {
    validate_snapshot_successor(Some(previous), update.snapshot(), update.transition()).unwrap();
    if let Some(transition) = update.transition() {
        let name = match transition.kind() {
            TransitionKind::StepSkipped { .. } => "step_skipped",
            TransitionKind::ApprovalRequested { .. } => "approval_requested",
            TransitionKind::ApprovalGranted { .. } => "approval_granted",
            TransitionKind::ApprovalDenied { .. } => "approval_denied",
            TransitionKind::EffectEvaluationRequired { .. } => "effect_evaluation_required",
            TransitionKind::EffectAuthorizationDenied { .. } => "effect_authorization_denied",
            TransitionKind::EffectStarted { .. } => "effect_started",
            TransitionKind::EffectSucceeded { .. } => "effect_succeeded",
            TransitionKind::RetryScheduled { .. } => "retry_scheduled",
            TransitionKind::RetryExhausted { .. } => "retry_exhausted",
            TransitionKind::EffectFailed { .. } => "effect_failed",
            TransitionKind::ReconciledNotApplied { .. } => "reconciled_not_applied",
            TransitionKind::ReconciliationUnknown { .. } => "reconciliation_unknown",
            TransitionKind::CancellationRequested => "cancellation_requested",
            TransitionKind::RunCompleted { .. } => "run_completed",
        };
        seen.insert(name);
    }
}

#[test]
fn conditions_take_true_branch_and_skip_false_branch_in_declared_order() {
    let mut run = start("condition-success", BRANCH_STEPS);
    let probe = start_effect(&mut run, 0);
    run.record_effect_result(&probe, successful_result("probe-ok"), 1)
        .unwrap();

    let success = evaluated_effect(&run.next_decision(1).unwrap());
    assert_eq!(success.step_id(), "on-success");
    run.prepare_effect(&success, 1).unwrap();
    run.record_effect_result(&success, successful_result("branch-ok"), 2)
        .unwrap();

    let skipped = run.next_decision(2).unwrap();
    assert!(matches!(
        skipped.transition().unwrap().kind(),
        TransitionKind::StepSkipped { step_id } if step_id == "on-failure"
    ));
    let terminal = run.next_decision(2).unwrap();
    match terminal.decision() {
        RunDecision::Terminal { result } => assert_eq!(result.outcome(), RunOutcome::Solved),
        other => panic!("expected solved result, got {other:?}"),
    }
}

#[test]
fn failed_condition_is_true_only_for_a_recorded_failure() {
    let mut run = start("condition-failure", BRANCH_STEPS);
    let probe = start_effect(&mut run, 0);
    let failed = run
        .record_effect_result(&probe, failed_result("probe-failed", false), 1)
        .unwrap();
    assert!(matches!(
        failed.transition().unwrap().kind(),
        TransitionKind::EffectFailed { step_id, attempt: 1 } if step_id == "probe"
    ));

    let skipped = run.next_decision(1).unwrap();
    assert!(matches!(
        skipped.transition().unwrap().kind(),
        TransitionKind::StepSkipped { step_id } if step_id == "on-success"
    ));
    let failure_branch = evaluated_effect(&run.next_decision(1).unwrap());
    assert_eq!(failure_branch.step_id(), "on-failure");
    run.prepare_effect(&failure_branch, 1).unwrap();
    run.record_effect_result(&failure_branch, successful_result("diagnosed"), 2)
        .unwrap();

    let terminal = run.next_decision(2).unwrap();
    match terminal.decision() {
        RunDecision::Terminal { result } => assert_eq!(result.outcome(), RunOutcome::Unresolved),
        other => panic!("expected unresolved result, got {other:?}"),
    }
}

#[test]
fn retries_use_deterministic_capped_backoff_and_exhaust_truthfully() {
    let flow = definition(RETRY_STEP);
    let mut run = FlowRun::start(run_id("retry-run"), flow.clone()).unwrap();
    let first = start_effect(&mut run, 1_000);
    let retry = run
        .record_effect_result(&first, failed_result("first", true), 1_000)
        .unwrap();
    assert!(matches!(
        retry.decision(),
        RunDecision::WaitRetry {
            not_before_ms: 1_100,
            ..
        }
    ));
    assert_snapshot_serde_round_trip(retry.snapshot());

    let mut run = resume(flow.clone(), retry.snapshot().clone());
    let waiting = run.next_decision(1_099).unwrap();
    assert!(waiting.transition().is_none());
    let second = evaluated_effect(&run.next_decision(1_100).unwrap());
    assert_eq!(second.attempt(), 2);
    assert_eq!(second.idempotency_identity(), first.idempotency_identity());
    run.prepare_effect(&second, 1_100).unwrap();
    let retry = run
        .record_effect_result(&second, failed_result("second", true), 1_100)
        .unwrap();
    assert!(matches!(
        retry.decision(),
        RunDecision::WaitRetry {
            not_before_ms: 1_250,
            ..
        }
    ));

    let third = evaluated_effect(&run.next_decision(1_250).unwrap());
    assert_eq!(third.attempt(), 3);
    run.prepare_effect(&third, 1_250).unwrap();
    run.record_effect_result(&third, failed_result("third", true), 1_250)
        .unwrap();
    let terminal = run.next_decision(1_250).unwrap();
    assert_eq!(terminal.snapshot().status(), RunStatus::Unresolved);
    match terminal.decision() {
        RunDecision::Terminal { result } => assert_eq!(result.outcome(), RunOutcome::Unresolved),
        other => panic!("expected exhausted result, got {other:?}"),
    }
}

#[test]
fn approval_pause_survives_restart_and_requires_the_exact_token() {
    let flow = definition(STATEFUL_STEP);
    let mut run = FlowRun::start(run_id("approval-run"), flow.clone()).unwrap();
    let requested = run.next_decision(10).unwrap();
    let token = approval(&requested);
    assert_eq!(requested.snapshot().status(), RunStatus::WaitingApproval);
    assert_snapshot_serde_round_trip(requested.snapshot());

    let mut wrong_run = start("different-approval-run", STATEFUL_STEP);
    let wrong = approval(&wrong_run.next_decision(10).unwrap());

    let mut run = resume(flow.clone(), requested.snapshot().clone());
    let still_waiting = run.next_decision(20).unwrap();
    assert_eq!(approval(&still_waiting), token);
    assert_eq!(
        run.resolve_approval(wrong, ApprovalDecision::Approve)
            .unwrap_err(),
        FlowEngineError::ApprovalTokenMismatch
    );
    let granted = run
        .resolve_approval(token, ApprovalDecision::Approve)
        .unwrap();
    assert!(matches!(
        granted.transition().unwrap().kind(),
        TransitionKind::ApprovalGranted { .. }
    ));

    let mut denied = start("approval-denied", STATEFUL_STEP);
    let token = approval(&denied.next_decision(0).unwrap());
    let denied = denied
        .resolve_approval(token, ApprovalDecision::Deny)
        .unwrap();
    assert_eq!(denied.snapshot().status(), RunStatus::Blocked);
    match denied.decision() {
        RunDecision::Terminal { result } => assert_eq!(result.outcome(), RunOutcome::Blocked),
        other => panic!("expected blocked result, got {other:?}"),
    }

    let mut cancelled = start("approval-cancelled", STATEFUL_STEP);
    cancelled.next_decision(0).unwrap();
    let cancelled = cancelled.cancel().unwrap();
    assert_eq!(cancelled.snapshot().status(), RunStatus::Cancelled);
    resume(flow, cancelled.snapshot().clone());
}

#[test]
fn stateful_in_flight_resume_reconciles_and_never_blindly_executes() {
    let flow = definition(STATEFUL_STEP);
    let mut run = FlowRun::start(run_id("stateful-restart"), flow.clone()).unwrap();
    let token = approval(&run.next_decision(0).unwrap());
    run.resolve_approval(token, ApprovalDecision::Approve)
        .unwrap();

    let evaluation = run.next_decision(0).unwrap();
    let effect = evaluated_effect(&evaluation);
    assert_snapshot_serde_round_trip(evaluation.snapshot());
    let mut run = resume(flow.clone(), evaluation.snapshot().clone());
    assert!(matches!(
        run.next_decision(0).unwrap().decision(),
        RunDecision::EvaluateEffect { replay: false, .. }
    ));

    let prepared = run.prepare_effect(&effect, 1).unwrap();
    assert!(matches!(prepared.decision(), RunDecision::Execute { .. }));
    assert_snapshot_serde_round_trip(prepared.snapshot());
    let mut run = resume(flow, prepared.snapshot().clone());
    assert!(matches!(
        run.next_decision(2).unwrap().decision(),
        RunDecision::Reconcile { .. }
    ));
    assert_eq!(
        run.prepare_effect(&effect, 2).unwrap_err(),
        FlowEngineError::StatefulReplayRequiresReconcile
    );

    let reconciled = run
        .record_reconciliation(&effect, ReconciliationResult::NotApplied, 2)
        .unwrap();
    assert!(matches!(
        reconciled.decision(),
        RunDecision::EvaluateEffect { replay: false, .. }
    ));
    let prepared = run.prepare_effect(&effect, 3).unwrap();
    assert!(matches!(
        prepared.decision(),
        RunDecision::Execute { replay: false, .. }
    ));
}

#[test]
fn read_only_in_flight_resume_requires_evaluation_before_safe_replay() {
    let flow = definition(READ_ONLY_STEP);
    let mut run = FlowRun::start(run_id("readonly-restart"), flow.clone()).unwrap();
    let effect = start_effect(&mut run, 1);
    let snapshot = run.snapshot().clone();

    assert!(matches!(
        run.next_decision(2).unwrap().decision(),
        RunDecision::AwaitResult { .. }
    ));
    let mut resumed = resume(flow, snapshot);
    let reevaluate = resumed.next_decision(2).unwrap();
    assert!(matches!(
        reevaluate.decision(),
        RunDecision::EvaluateEffect { replay: true, .. }
    ));
    let replay = resumed.prepare_effect(&effect, 2).unwrap();
    assert!(matches!(
        replay.decision(),
        RunDecision::Execute { replay: true, .. }
    ));
}

#[test]
fn cancellation_is_durable_idempotent_and_waits_for_in_flight_truth() {
    let flow = definition(STATEFUL_STEP);
    let mut run = FlowRun::start(run_id("cancel-in-flight"), flow.clone()).unwrap();
    let token = approval(&run.next_decision(0).unwrap());
    run.resolve_approval(token, ApprovalDecision::Approve)
        .unwrap();
    let effect = start_effect(&mut run, 0);
    let cancelling = run.cancel().unwrap();
    assert_eq!(cancelling.snapshot().status(), RunStatus::Cancelling);
    assert!(matches!(
        cancelling.decision(),
        RunDecision::Reconcile { .. }
    ));
    let sequence = cancelling.snapshot().transition_sequence();

    let duplicate = run.cancel().unwrap();
    assert_eq!(duplicate.snapshot().transition_sequence(), sequence);
    assert!(duplicate.transition().is_none());
    let truthful_failure = run
        .record_effect_result(
            &effect,
            failed_result("finished-during-cancel", true),
            u64::MAX,
        )
        .unwrap();
    assert_eq!(truthful_failure.snapshot().status(), RunStatus::Cancelling);
    assert!(matches!(
        truthful_failure.transition().unwrap().kind(),
        TransitionKind::EffectFailed {
            step_id,
            attempt: 1
        } if step_id == "apply"
    ));
    assert!(matches!(
        truthful_failure.snapshot().steps()[0].state(),
        StepState::Failed { attempt: 1 }
    ));

    let cancelled = run.next_decision(u64::MAX).unwrap();
    assert_eq!(cancelled.snapshot().status(), RunStatus::Cancelled);
    assert!(matches!(
        cancelled.snapshot().steps()[0].state(),
        StepState::Failed { attempt: 1 }
    ));
    match cancelled.decision() {
        RunDecision::Terminal { result } => assert_eq!(result.outcome(), RunOutcome::Cancelled),
        other => panic!("expected cancelled result, got {other:?}"),
    }

    let snapshot = cancelled.snapshot().clone();
    let mut resumed = resume(flow, snapshot);
    let duplicate = resumed.cancel().unwrap();
    assert!(duplicate.transition().is_none());
    assert_eq!(duplicate.snapshot().status(), RunStatus::Cancelled);

    let mut before_effect = start("cancel-before-effect", READ_ONLY_STEP);
    let cancelled = before_effect.cancel().unwrap();
    assert_eq!(cancelled.snapshot().status(), RunStatus::Cancelled);

    let mut read_only = start("cancel-read-only", READ_ONLY_STEP);
    start_effect(&mut read_only, 0);
    let cancelled = read_only.cancel().unwrap();
    assert_eq!(cancelled.snapshot().status(), RunStatus::Cancelled);
}

#[test]
fn completed_reconciliation_after_cancellation_records_success_before_cancelling() {
    let flow = definition(STATEFUL_STEP);
    let mut run = FlowRun::start(run_id("cancel-reconciled-success"), flow).unwrap();
    let token = approval(&run.next_decision(0).unwrap());
    run.resolve_approval(token, ApprovalDecision::Approve)
        .unwrap();
    let effect = start_effect(&mut run, 0);
    run.cancel().unwrap();

    let succeeded = run
        .record_reconciliation(
            &effect,
            ReconciliationResult::Completed(successful_result("applied-before-cancel")),
            1,
        )
        .unwrap();
    assert_eq!(succeeded.snapshot().status(), RunStatus::Cancelling);
    assert!(matches!(
        succeeded.transition().unwrap().kind(),
        TransitionKind::EffectSucceeded {
            step_id,
            attempt: 1
        } if step_id == "apply"
    ));
    assert!(matches!(
        succeeded.snapshot().steps()[0].state(),
        StepState::Succeeded { attempt: 1 }
    ));

    let terminal = run.next_decision(1).unwrap();
    assert_eq!(terminal.snapshot().status(), RunStatus::Cancelled);
    assert!(matches!(
        terminal.snapshot().steps()[0].state(),
        StepState::Succeeded { attempt: 1 }
    ));
}

#[test]
fn identical_duplicate_results_are_noops_and_conflicts_fail_closed() {
    let mut run = start("duplicate-result", RETRY_STEP);
    let effect = start_effect(&mut run, 0);
    let first_result = failed_result("temporary", true);
    let first = run
        .record_effect_result(&effect, first_result.clone(), 0)
        .unwrap();
    let sequence = first.snapshot().transition_sequence();

    let duplicate = run.record_effect_result(&effect, first_result, 0).unwrap();
    assert!(duplicate.transition().is_none());
    assert_eq!(duplicate.snapshot().transition_sequence(), sequence);

    assert!(matches!(
        run.record_effect_result(&effect, failed_result("different", true), 0),
        Err(FlowEngineError::ConflictingEffectResult {
            step_id,
            attempt: 1
        }) if step_id == "collect"
    ));
}

#[test]
fn idempotency_identity_is_stable_per_step_and_bound_to_run_and_definition() {
    let flow = definition(RETRY_STEP);
    let first = FlowRun::start(run_id("stable-run"), flow.clone()).unwrap();
    let second = FlowRun::start(run_id("stable-run"), flow.clone()).unwrap();
    assert_eq!(
        first.snapshot().steps()[0].idempotency_identity(),
        second.snapshot().steps()[0].idempotency_identity()
    );

    let different_run = FlowRun::start(run_id("other-run"), flow.clone()).unwrap();
    assert_ne!(
        first.snapshot().steps()[0].idempotency_identity(),
        different_run.snapshot().steps()[0].idempotency_identity()
    );

    let changed_source = format!("{HEADER}{RETRY_STEP}").replace("revision = 1", "revision = 2");
    let changed = FlowDefinition::parse_toml(&changed_source).unwrap();
    let changed = FlowRun::start(run_id("stable-run"), changed).unwrap();
    assert_ne!(
        first.snapshot().steps()[0].idempotency_identity(),
        changed.snapshot().steps()[0].idempotency_identity()
    );
}

#[test]
fn resume_rejects_run_and_definition_mismatches() {
    let flow = definition(READ_ONLY_STEP);
    let run = FlowRun::start(run_id("original-run"), flow.clone()).unwrap();
    let snapshot = run.snapshot().clone();
    assert!(matches!(
        FlowRun::resume(&run_id("wrong-run"), flow.clone(), snapshot.clone()),
        Err(FlowEngineError::RunIdMismatch)
    ));

    let changed_source = format!("{HEADER}{READ_ONLY_STEP}").replace(
        "description = \"Exercise deterministic flow scheduling.\"",
        "description = \"Changed definition.\"",
    );
    let changed = FlowDefinition::parse_toml(&changed_source).unwrap();
    assert!(matches!(
        FlowRun::resume(&run_id("original-run"), changed, snapshot),
        Err(FlowEngineError::DefinitionDigestMismatch)
    ));
}

#[test]
fn resume_rejects_impossible_graph_and_cancellation_states() {
    let flow = definition(BRANCH_STEPS);
    let id = run_id("invalid-restored-state");
    let mut run = FlowRun::start(id.clone(), flow.clone()).unwrap();
    let probe = start_effect(&mut run, 0);
    run.record_effect_result(&probe, successful_result("probe-ok"), 1)
        .unwrap();
    let active = run.next_decision(1).unwrap();
    assert_eq!(evaluated_effect(&active).step_id(), "on-success");

    let mut invalid = toml::Value::try_from(active.snapshot().clone()).unwrap();
    let steps = invalid
        .get_mut("steps")
        .and_then(toml::Value::as_array_mut)
        .unwrap();
    let probe = steps[0].as_table_mut().unwrap();
    probe.insert(
        "state".to_owned(),
        toml::Value::String("pending".to_owned()),
    );
    probe.insert("results".to_owned(), toml::Value::Array(Vec::new()));
    let invalid: FlowSnapshot = invalid.try_into().unwrap();
    assert!(matches!(
        FlowRun::resume(&id, flow, invalid),
        Err(FlowEngineError::SnapshotShapeMismatch)
    ));

    let flow = definition(READ_ONLY_STEP);
    let id = run_id("invalid-cancelled-state");
    let run = FlowRun::start(id.clone(), flow.clone()).unwrap();
    let mut invalid = toml::Value::try_from(run.snapshot().clone()).unwrap();
    let table = invalid.as_table_mut().unwrap();
    table.insert(
        "status".to_owned(),
        toml::Value::String("cancelled".to_owned()),
    );
    table.insert("cancel_requested".to_owned(), toml::Value::Boolean(true));
    let invalid: FlowSnapshot = invalid.try_into().unwrap();
    assert!(matches!(
        FlowRun::resume(&id, flow, invalid),
        Err(FlowEngineError::SnapshotStatusMismatch)
    ));
}

#[test]
fn summaries_and_evidence_handles_are_bounded_and_secret_safe() {
    assert!(EffectResult::succeeded("", Vec::new()).is_err());
    assert!(EffectResult::succeeded("x".repeat(MAX_EFFECT_SUMMARY_BYTES + 1), Vec::new()).is_err());
    assert!(EffectResult::succeeded("Bearer inline-secret", Vec::new()).is_err());
    assert!(toml::from_str::<EffectReport>("summary = \"Bearer inline-secret\"").is_err());
    assert!(EvidenceHandle::parse("github_pat_inline-secret").is_err());
    assert!(RunId::parse("bad run id").is_err());

    let handles = (0..=MAX_EVIDENCE_HANDLES)
        .map(|index| EvidenceHandle::parse(format!("evidence:{index}")).unwrap())
        .collect();
    assert!(EffectResult::succeeded("too many handles", handles).is_err());
}

#[test]
fn maximum_valid_snapshot_and_terminal_result_fit_persistence_and_protocol_budgets() {
    const STORE_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
    const PROTOCOL_FRAME_BYTES: usize = 1024 * 1024;
    const PROTOCOL_OVERHEAD_RESERVE_BYTES: usize = 128 * 1024;

    let mut run = FlowRun::start(
        run_id(&"r".repeat(MAX_RUN_ID_BYTES)),
        maximum_flow_definition(),
    )
    .unwrap();
    let mut now_ms = 0_u64;
    for _ in 0..MAX_FLOW_STEPS {
        for attempt in 1..=MAX_RETRY_ATTEMPTS {
            let effect = evaluated_effect(&run.next_decision(now_ms).unwrap());
            assert_eq!(effect.attempt(), attempt);
            run.prepare_effect(&effect, now_ms).unwrap();
            run.record_effect_result(&effect, maximum_effect_result(), now_ms)
                .unwrap();
            now_ms += 1;
        }
    }
    let terminal = run.next_decision(now_ms).unwrap();
    let RunDecision::Terminal { result } = terminal.decision() else {
        panic!("maximum run should be terminal");
    };
    let snapshot_bytes = rmp_serde::to_vec_named(terminal.snapshot()).unwrap();
    let result_bytes = rmp_serde::to_vec_named(result).unwrap();

    assert!(snapshot_bytes.len() < STORE_SNAPSHOT_BYTES);
    assert!(
        result_bytes.len() < PROTOCOL_FRAME_BYTES - PROTOCOL_OVERHEAD_RESERVE_BYTES,
        "{}-byte result leaves less than 128 KiB for protocol framing",
        result_bytes.len()
    );
    assert_eq!(result.steps().len(), MAX_FLOW_STEPS);
    assert_eq!(
        result.steps()[0]
            .result()
            .unwrap()
            .report()
            .evidence()
            .len(),
        MAX_EVIDENCE_HANDLES
    );
    assert_eq!(
        result.steps()[0].result().unwrap().report().summary().len(),
        MAX_EFFECT_SUMMARY_BYTES
    );
}

#[test]
fn unknown_stateful_reconciliation_blocks_instead_of_reexecuting() {
    let flow = definition(STATEFUL_STEP);
    let mut run = FlowRun::start(run_id("unknown-effect"), flow.clone()).unwrap();
    let token = approval(&run.next_decision(0).unwrap());
    run.resolve_approval(token, ApprovalDecision::Approve)
        .unwrap();
    let effect = evaluated_effect(&run.next_decision(0).unwrap());
    let prepared = run.prepare_effect(&effect, 0).unwrap();
    let mut run = resume(flow, prepared.snapshot().clone());
    let unknown = EffectReport::new(
        "the connector cannot prove whether the effect was applied",
        Vec::new(),
    )
    .unwrap();
    let blocked = run
        .record_reconciliation(&effect, ReconciliationResult::Unknown(unknown), 1)
        .unwrap();
    assert_eq!(blocked.snapshot().status(), RunStatus::Blocked);
    assert!(matches!(
        blocked.decision(),
        RunDecision::Terminal { result } if result.outcome() == RunOutcome::Blocked
    ));
}

#[test]
fn fresh_effect_authorization_denial_blocks_before_execution_and_survives_resume() {
    let flow = definition(READ_ONLY_STEP);
    let mut run = FlowRun::start(run_id("authorization-denied"), flow.clone()).unwrap();
    let evaluation = run.next_decision(0).unwrap();
    let effect = evaluated_effect(&evaluation);
    let previous = run.snapshot().clone();
    let denied = run.deny_effect_authorization(&effect).unwrap();
    validate_snapshot_successor(Some(&previous), denied.snapshot(), denied.transition()).unwrap();
    assert!(matches!(
        denied.transition().unwrap().kind(),
        TransitionKind::EffectAuthorizationDenied {
            step_id,
            attempt: 1,
            replay: false,
        } if step_id == "collect"
    ));
    assert!(matches!(
        denied.decision(),
        RunDecision::Terminal { result } if result.outcome() == RunOutcome::Blocked
    ));
    assert!(denied.snapshot().steps()[0].results().next().is_none());

    let mut resumed = resume(flow.clone(), denied.snapshot().clone());
    let terminal = resumed.next_decision(1).unwrap();
    assert!(terminal.transition().is_none());
    assert!(matches!(
        terminal.decision(),
        RunDecision::Terminal { result } if result.outcome() == RunOutcome::Blocked
    ));

    let mut replayed = FlowRun::start(run_id("authorization-denied-replay"), flow.clone()).unwrap();
    let effect = evaluated_effect(&replayed.next_decision(0).unwrap());
    let started = replayed.prepare_effect(&effect, 0).unwrap();
    let mut replayed = resume(flow, started.snapshot().clone());
    assert!(matches!(
        replayed.next_decision(1).unwrap().decision(),
        RunDecision::EvaluateEffect { replay: true, .. }
    ));
    let denied = replayed.deny_effect_authorization(&effect).unwrap();
    assert!(matches!(
        denied.transition().unwrap().kind(),
        TransitionKind::EffectAuthorizationDenied { replay: true, .. }
    ));
    assert_eq!(denied.snapshot().status(), RunStatus::Blocked);
}

#[test]
#[allow(clippy::too_many_lines)]
fn structural_successor_validation_accepts_every_transition_kind() {
    let mut seen = HashSet::new();

    let mut retry = start("successor-retry", RETRY_STEP);
    validate_snapshot_successor(None, retry.snapshot(), None).unwrap();
    validate_snapshot_successor(Some(retry.snapshot()), retry.snapshot(), None).unwrap();
    for attempt in 1_u8..=3 {
        let previous = retry.snapshot().clone();
        let evaluation = retry.next_decision(u64::from(attempt - 1) * 150).unwrap();
        validate_update(&previous, &evaluation, &mut seen);
        let effect = evaluated_effect(&evaluation);
        let previous = retry.snapshot().clone();
        let started = retry.prepare_effect(&effect, u64::from(attempt)).unwrap();
        validate_update(&previous, &started, &mut seen);
        let previous = retry.snapshot().clone();
        let failed = retry
            .record_effect_result(
                &effect,
                failed_result(&format!("retry-{attempt}"), true),
                u64::from(attempt - 1) * 150,
            )
            .unwrap();
        validate_update(&previous, &failed, &mut seen);
    }
    let previous = retry.snapshot().clone();
    let terminal = retry.next_decision(300).unwrap();
    validate_update(&previous, &terminal, &mut seen);

    let mut failed = start("successor-failed", READ_ONLY_STEP);
    let previous = failed.snapshot().clone();
    let evaluation = failed.next_decision(0).unwrap();
    validate_update(&previous, &evaluation, &mut seen);
    let effect = evaluated_effect(&evaluation);
    let previous = failed.snapshot().clone();
    let started = failed.prepare_effect(&effect, 0).unwrap();
    validate_update(&previous, &started, &mut seen);
    let previous = failed.snapshot().clone();
    let result = failed
        .record_effect_result(&effect, failed_result("permanent", false), 0)
        .unwrap();
    validate_update(&previous, &result, &mut seen);

    let mut authorization_denied = start("successor-authorization-denied", READ_ONLY_STEP);
    let evaluation = authorization_denied.next_decision(0).unwrap();
    let effect = evaluated_effect(&evaluation);
    let previous = authorization_denied.snapshot().clone();
    let denied = authorization_denied
        .deny_effect_authorization(&effect)
        .unwrap();
    validate_update(&previous, &denied, &mut seen);

    let mut branch = start("successor-branch", BRANCH_STEPS);
    let effect = start_effect(&mut branch, 0);
    branch
        .record_effect_result(&effect, successful_result("probe"), 0)
        .unwrap();
    let effect = evaluated_effect(&branch.next_decision(0).unwrap());
    branch.prepare_effect(&effect, 0).unwrap();
    branch
        .record_effect_result(&effect, successful_result("success-branch"), 0)
        .unwrap();
    let previous = branch.snapshot().clone();
    let skipped = branch.next_decision(0).unwrap();
    validate_update(&previous, &skipped, &mut seen);

    let mut approved = start("successor-approved", STATEFUL_STEP);
    let previous = approved.snapshot().clone();
    let requested = approved.next_decision(0).unwrap();
    validate_update(&previous, &requested, &mut seen);
    let token = approval(&requested);
    let previous = approved.snapshot().clone();
    let granted = approved
        .resolve_approval(token, ApprovalDecision::Approve)
        .unwrap();
    validate_update(&previous, &granted, &mut seen);
    let evaluation = approved.next_decision(0).unwrap();
    let effect = evaluated_effect(&evaluation);
    approved.prepare_effect(&effect, 0).unwrap();
    let previous = approved.snapshot().clone();
    let not_applied = approved
        .record_reconciliation(&effect, ReconciliationResult::NotApplied, 0)
        .unwrap();
    validate_update(&previous, &not_applied, &mut seen);

    let mut denied = start("successor-denied", STATEFUL_STEP);
    let token = approval(&denied.next_decision(0).unwrap());
    let previous = denied.snapshot().clone();
    let denied_update = denied
        .resolve_approval(token, ApprovalDecision::Deny)
        .unwrap();
    validate_update(&previous, &denied_update, &mut seen);

    let mut unknown = start("successor-unknown", STATEFUL_STEP);
    let token = approval(&unknown.next_decision(0).unwrap());
    unknown
        .resolve_approval(token, ApprovalDecision::Approve)
        .unwrap();
    let effect = start_effect(&mut unknown, 0);
    let previous = unknown.snapshot().clone();
    let unknown_update = unknown
        .record_reconciliation(
            &effect,
            ReconciliationResult::Unknown(
                EffectReport::new("cannot determine application", Vec::new()).unwrap(),
            ),
            0,
        )
        .unwrap();
    validate_update(&previous, &unknown_update, &mut seen);

    let mut cancelled = start("successor-cancelled", STATEFUL_STEP);
    let token = approval(&cancelled.next_decision(0).unwrap());
    cancelled
        .resolve_approval(token, ApprovalDecision::Approve)
        .unwrap();
    let effect = start_effect(&mut cancelled, 0);
    let previous = cancelled.snapshot().clone();
    let cancellation = cancelled.cancel().unwrap();
    validate_update(&previous, &cancellation, &mut seen);
    let previous = cancelled.snapshot().clone();
    let result = cancelled
        .record_reconciliation(
            &effect,
            ReconciliationResult::Completed(successful_result("applied")),
            0,
        )
        .unwrap();
    validate_update(&previous, &result, &mut seen);
    let previous = cancelled.snapshot().clone();
    let terminal = cancelled.next_decision(0).unwrap();
    validate_update(&previous, &terminal, &mut seen);

    assert_eq!(
        seen,
        HashSet::from([
            "step_skipped",
            "approval_requested",
            "approval_granted",
            "approval_denied",
            "effect_evaluation_required",
            "effect_authorization_denied",
            "effect_started",
            "effect_succeeded",
            "retry_scheduled",
            "retry_exhausted",
            "effect_failed",
            "reconciled_not_applied",
            "reconciliation_unknown",
            "cancellation_requested",
            "run_completed",
        ])
    );
}

#[test]
fn structural_successor_validation_fails_closed_for_tampering() {
    let mut run = start("successor-negative", BRANCH_STEPS);
    let previous = run.snapshot().clone();
    let evaluation = run.next_decision(0).unwrap();

    assert_eq!(
        validate_snapshot_successor(Some(&previous), evaluation.snapshot(), None),
        Err(FlowEngineError::SnapshotTransitionMismatch)
    );

    let other_run = start("successor-other-run", BRANCH_STEPS);
    assert_eq!(
        validate_snapshot_successor(Some(&previous), other_run.snapshot(), None),
        Err(FlowEngineError::SnapshotIdentityMismatch)
    );
    let changed_definition = FlowDefinition::parse_toml(
        &format!("{HEADER}{BRANCH_STEPS}").replace("revision = 1", "revision = 2"),
    )
    .unwrap();
    let changed_digest = FlowRun::start(run_id("successor-negative"), changed_definition).unwrap();
    assert_eq!(
        validate_snapshot_successor(Some(&previous), changed_digest.snapshot(), None),
        Err(FlowEngineError::SnapshotIdentityMismatch)
    );

    let mut approval_run = start("wrong-transition", STATEFUL_STEP);
    let wrong_transition = approval_run.next_decision(0).unwrap();
    assert_eq!(
        validate_snapshot_successor(
            Some(&previous),
            evaluation.snapshot(),
            wrong_transition.transition()
        ),
        Err(FlowEngineError::SnapshotTransitionMismatch)
    );

    let mut wrong_data_value = toml::Value::try_from(evaluation.transition().unwrap()).unwrap();
    let wrong_data_table = wrong_data_value
        .get_mut("kind")
        .and_then(toml::Value::as_table_mut)
        .and_then(|kind| kind.get_mut("effect_evaluation_required"))
        .and_then(toml::Value::as_table_mut)
        .unwrap();
    wrong_data_table.insert("attempt".to_owned(), toml::Value::Integer(2));
    let wrong_data: RunTransition = wrong_data_value.try_into().unwrap();
    assert_eq!(
        validate_snapshot_successor(Some(&previous), evaluation.snapshot(), Some(&wrong_data)),
        Err(FlowEngineError::SnapshotTransitionMismatch)
    );

    let mut extra_mutation_value = toml::Value::try_from(evaluation.snapshot().clone()).unwrap();
    let steps = extra_mutation_value
        .get_mut("steps")
        .and_then(toml::Value::as_array_mut)
        .unwrap();
    steps[1].as_table_mut().unwrap().insert(
        "state".to_owned(),
        toml::Value::String("skipped".to_owned()),
    );
    let extra_mutation: FlowSnapshot = extra_mutation_value.try_into().unwrap();
    assert_eq!(
        validate_snapshot_successor(Some(&previous), &extra_mutation, evaluation.transition()),
        Err(FlowEngineError::SnapshotTransitionMismatch)
    );

    let granted = approval_run
        .resolve_approval(approval(&wrong_transition), ApprovalDecision::Approve)
        .unwrap();
    assert_eq!(
        validate_snapshot_successor(
            Some(wrong_transition.snapshot()),
            granted.snapshot(),
            evaluation.transition()
        ),
        Err(FlowEngineError::SnapshotSequenceMismatch)
    );
    assert_eq!(
        validate_snapshot_successor(None, &previous, evaluation.transition()),
        Err(FlowEngineError::InvalidInitialSnapshot)
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn semantic_events_report_only_durable_meaningful_progress() {
    let mut observed = start("semantic-observe", READ_ONLY_STEP);
    let effect = start_effect(&mut observed, 0);
    let succeeded = observed
        .record_effect_result(&effect, successful_result("observed"), 1)
        .unwrap();
    assert!(matches!(
        succeeded.transition().unwrap().semantic_events(),
        [FlowSemanticEvent::EvidenceFound { step_id, evidence }]
            if step_id == "collect" && evidence[0].as_str() == "evidence:observed"
    ));
    let terminal = observed.next_decision(1).unwrap();
    let RunDecision::Terminal { result } = terminal.decision() else {
        panic!("observe run should finish");
    };
    assert!(result.report().solved().satisfied());
    assert!(!result.report().changed().satisfied());
    assert!(!result.report().verified().satisfied());
    assert_eq!(result.report().solved().step_ids(), ["collect"]);

    let mut verified = start("semantic-verify", RETRY_STEP);
    let effect = start_effect(&mut verified, 0);
    let succeeded = verified
        .record_effect_result(&effect, successful_result("verified"), 1)
        .unwrap();
    assert!(matches!(
        succeeded.transition().unwrap().semantic_events(),
        [
            FlowSemanticEvent::EvidenceFound { step_id, .. },
            FlowSemanticEvent::VerificationPassed { step_id: verified_id, report },
        ] if step_id == "collect"
            && verified_id == "collect"
            && report.summary() == "verified"
    ));
    let RunDecision::Terminal { result } = verified.next_decision(1).unwrap().decision().clone()
    else {
        panic!("verify run should finish");
    };
    assert!(result.report().verified().satisfied());
    assert_eq!(result.report().verified().step_ids(), ["collect"]);

    let mut changed = start("semantic-change", STATEFUL_STEP);
    let approval_update = changed.next_decision(0).unwrap();
    assert!(matches!(
        approval_update.transition().unwrap().semantic_events(),
        [
            FlowSemanticEvent::Waiting {
                step_id,
                reason: FlowWaitReason::Approval,
                not_before_ms: None,
            },
            FlowSemanticEvent::ApprovalRequired { step_id: approval_id },
        ] if step_id == "apply" && approval_id == "apply"
    ));
    changed
        .resolve_approval(approval(&approval_update), ApprovalDecision::Approve)
        .unwrap();
    let evaluation = changed.next_decision(0).unwrap();
    let effect = evaluated_effect(&evaluation);
    let started = changed.prepare_effect(&effect, 0).unwrap();
    assert!(matches!(
        started.transition().unwrap().semantic_events(),
        [FlowSemanticEvent::Waiting {
            reason: FlowWaitReason::EffectResult,
            not_before_ms: None,
            ..
        }]
    ));
    let succeeded = changed
        .record_effect_result(&effect, successful_result("changed"), 1)
        .unwrap();
    assert!(matches!(
        succeeded.transition().unwrap().semantic_events(),
        [
            FlowSemanticEvent::EvidenceFound { .. },
            FlowSemanticEvent::FixApplied { step_id, report },
        ] if step_id == "apply" && report.summary() == "changed"
    ));
    let RunDecision::Terminal { result } = changed.next_decision(1).unwrap().decision().clone()
    else {
        panic!("change run should finish");
    };
    assert!(result.report().changed().satisfied());
    assert!(!result.report().verified().satisfied());
}

#[test]
fn retry_failure_blocking_and_cancellation_emit_truthful_semantics() {
    let mut retry = start("semantic-retry", RETRY_STEP);
    let effect = start_effect(&mut retry, 0);
    let waiting = retry
        .record_effect_result(&effect, failed_result("retry", true), 0)
        .unwrap();
    assert!(matches!(
        waiting.transition().unwrap().semantic_events(),
        [
            FlowSemanticEvent::EvidenceFound { .. },
            FlowSemanticEvent::Waiting {
                reason: FlowWaitReason::Retry,
                not_before_ms: Some(100),
                ..
            },
        ]
    ));

    let mut failed = start("semantic-unresolved", READ_ONLY_STEP);
    let effect = start_effect(&mut failed, 0);
    let update = failed
        .record_effect_result(&effect, failed_result("unresolved", false), 1)
        .unwrap();
    assert!(matches!(
        update.transition().unwrap().semantic_events(),
        [
            FlowSemanticEvent::EvidenceFound { .. },
            FlowSemanticEvent::Unresolved { step_id, report },
        ] if step_id == "collect" && report.summary() == "unresolved"
    ));
    let RunDecision::Terminal { result } = failed.next_decision(1).unwrap().decision().clone()
    else {
        panic!("failed run should finish");
    };
    assert!(result.report().unresolved().satisfied());
    assert!(!result.report().solved().satisfied());

    let mut blocked = start("semantic-blocked", STATEFUL_STEP);
    let requested = blocked.next_decision(0).unwrap();
    let denied = blocked
        .resolve_approval(approval(&requested), ApprovalDecision::Deny)
        .unwrap();
    assert!(matches!(
        denied.transition().unwrap().semantic_events(),
        [FlowSemanticEvent::Blocked { step_id, .. }] if step_id == "apply"
    ));
    let RunDecision::Terminal { result } = denied.decision() else {
        panic!("denied run should block");
    };
    assert!(result.report().blocked().satisfied());

    let mut cancelling = start("semantic-cancelling", STATEFUL_STEP);
    let requested = cancelling.next_decision(0).unwrap();
    cancelling
        .resolve_approval(approval(&requested), ApprovalDecision::Approve)
        .unwrap();
    start_effect(&mut cancelling, 0);
    let update = cancelling.cancel().unwrap();
    assert!(matches!(
        update.transition().unwrap().semantic_events(),
        [FlowSemanticEvent::Waiting {
            step_id,
            reason: FlowWaitReason::Reconciliation,
            not_before_ms: None,
        }] if step_id == "apply"
    ));
}

#[test]
fn semantic_events_are_bounded_legacy_decodable_and_exactly_validated() {
    #[derive(Serialize)]
    struct LegacyTransition<'a> {
        sequence: u64,
        kind: &'a TransitionKind,
    }

    let mut run = start("semantic-codec", STATEFUL_STEP);
    let previous = run.snapshot().clone();
    let update = run.next_decision(0).unwrap();
    let transition = update.transition().unwrap();

    let legacy_bytes = rmp_serde::to_vec_named(&LegacyTransition {
        sequence: transition.sequence(),
        kind: transition.kind(),
    })
    .unwrap();
    let legacy: RunTransition = rmp_serde::from_slice(&legacy_bytes).unwrap();
    assert!(legacy.semantic_events().is_empty());
    assert_eq!(legacy.kind(), transition.kind());
    assert_eq!(
        validate_snapshot_successor(Some(&previous), update.snapshot(), Some(&legacy)),
        Err(FlowEngineError::SnapshotTransitionMismatch)
    );

    let encoded = rmp_serde::to_vec_named(transition).unwrap();
    let decoded: RunTransition = rmp_serde::from_slice(&encoded).unwrap();
    assert_eq!(&decoded, transition);

    let mut oversized = toml::Value::try_from(transition).unwrap();
    let events = oversized
        .get_mut("semantic_events")
        .and_then(toml::Value::as_array_mut)
        .unwrap();
    let event = events[0].clone();
    events.clear();
    events.resize(MAX_FLOW_SEMANTIC_EVENTS_PER_TRANSITION + 1, event);
    assert!(oversized.try_into::<RunTransition>().is_err());
}

#[test]
fn outcome_report_caps_evidence_and_rejects_forged_truth() {
    use std::fmt::Write as _;

    let mut steps = String::new();
    for index in 0..5 {
        write!(
            steps,
            r#"
[[steps]]
id = "verify-{index}"
description = "Verify one fact."
timeout_seconds = 30
effect = "read_only"
semantic = "verify"
action = {{ type = "command", program = "true", args = [], working_directory = "." }}
"#
        )
        .unwrap();
    }
    let mut run = start("bounded-outcome", &steps);
    for index in 0..5 {
        let effect = start_effect(&mut run, index);
        run.record_effect_result(
            &effect,
            successful_result(&format!("verified-{index}")),
            index,
        )
        .unwrap();
    }
    let RunDecision::Terminal { result } = run.next_decision(5).unwrap().decision().clone() else {
        panic!("bounded outcome run should finish");
    };
    assert!(result.report().verified().satisfied());
    assert_eq!(result.report().verified().step_ids().len(), 5);
    assert_eq!(
        result.report().verified().evidence().len(),
        MAX_OUTCOME_EVIDENCE_HANDLES
    );
    assert!(result.report().verified().evidence_truncated());
    assert_eq!(
        result.report().verified().evidence()[0].as_str(),
        "evidence:verified-0"
    );

    let encoded = rmp_serde::to_vec_named(&result).unwrap();
    let decoded: FlowRunResult = rmp_serde::from_slice(&encoded).unwrap();
    assert_eq!(decoded, result);

    let mut forged = toml::Value::try_from(result.clone()).unwrap();
    forged
        .get_mut("report")
        .and_then(toml::Value::as_table_mut)
        .unwrap()
        .get_mut("verified")
        .and_then(toml::Value::as_table_mut)
        .unwrap()
        .insert("satisfied".to_owned(), toml::Value::Boolean(false));
    assert!(forged.try_into::<FlowRunResult>().is_err());

    let mut oversized = toml::Value::try_from(result).unwrap();
    oversized
        .get_mut("report")
        .and_then(toml::Value::as_table_mut)
        .unwrap()
        .get_mut("solved")
        .and_then(toml::Value::as_table_mut)
        .unwrap()
        .insert(
            "summary".to_owned(),
            toml::Value::String("x".repeat(MAX_TEMPLATE_BYTES + 1)),
        );
    assert!(oversized.try_into::<FlowRunResult>().is_err());
}

#[test]
fn legacy_results_and_snapshots_decode_without_claiming_new_semantics() {
    #[derive(Serialize)]
    struct LegacyStepResult<'a> {
        step_id: &'a str,
        kind: StepRunResultKind,
        result: Option<&'a EffectResult>,
        blocked_report: Option<&'a EffectReport>,
    }

    #[derive(Serialize)]
    struct LegacyFlowResult<'a> {
        run_id: &'a RunId,
        definition_digest: FlowDigest,
        outcome: RunOutcome,
        steps: Vec<LegacyStepResult<'a>>,
    }

    let mut run = start("legacy-result", RETRY_STEP);
    let effect = start_effect(&mut run, 0);
    run.record_effect_result(&effect, successful_result("legacy"), 1)
        .unwrap();
    let RunDecision::Terminal { result } = run.next_decision(1).unwrap().decision().clone() else {
        panic!("legacy result run should finish");
    };
    let legacy = LegacyFlowResult {
        run_id: result.run_id(),
        definition_digest: result.definition_digest(),
        outcome: result.outcome(),
        steps: result
            .steps()
            .iter()
            .map(|step| LegacyStepResult {
                step_id: step.step_id(),
                kind: step.kind(),
                result: step.result(),
                blocked_report: step.blocked_report(),
            })
            .collect(),
    };
    let bytes = rmp_serde::to_vec_named(&legacy).unwrap();
    let decoded: FlowRunResult = rmp_serde::from_slice(&bytes).unwrap();
    assert_eq!(
        decoded.steps()[0].semantic_role(),
        StepSemanticRole::Observe
    );
    assert!(!decoded.report().verified().satisfied());
    assert!(!decoded.report().changed().satisfied());
    assert!(decoded.report().solved().satisfied());

    let definition = definition_v1(STATEFUL_STEP);
    let id = run_id("legacy-snapshot");
    let run = FlowRun::start(id.clone(), definition.clone()).unwrap();
    assert_eq!(
        run.snapshot().steps()[0].semantic_role(),
        StepSemanticRole::Change
    );
    let mut value = toml::Value::try_from(run.snapshot().clone()).unwrap();
    value
        .as_table_mut()
        .unwrap()
        .insert("snapshot_version".to_owned(), toml::Value::Integer(1));
    value
        .get_mut("steps")
        .and_then(toml::Value::as_array_mut)
        .unwrap()[0]
        .as_table_mut()
        .unwrap()
        .remove("semantic_role");
    let legacy_snapshot: FlowSnapshot = value.try_into().unwrap();
    assert_eq!(
        legacy_snapshot.steps()[0].semantic_role(),
        StepSemanticRole::Observe
    );
    let resumed = FlowRun::resume(&id, definition, legacy_snapshot.clone()).unwrap();
    assert_eq!(resumed.snapshot().snapshot_version(), FLOW_SNAPSHOT_VERSION);
    assert_eq!(
        resumed.snapshot().steps()[0].semantic_role(),
        StepSemanticRole::Change
    );
    validate_snapshot_upgrade(&legacy_snapshot, resumed.snapshot()).unwrap();

    let mut forged = toml::Value::try_from(resumed.snapshot().clone()).unwrap();
    forged
        .get_mut("steps")
        .and_then(toml::Value::as_array_mut)
        .unwrap()[0]
        .as_table_mut()
        .unwrap()
        .insert(
            "semantic_role".to_owned(),
            toml::Value::String("verify".to_owned()),
        );
    let forged: FlowSnapshot = forged.try_into().unwrap();
    assert_eq!(
        validate_snapshot_upgrade(&legacy_snapshot, &forged),
        Err(FlowEngineError::SnapshotShapeMismatch)
    );
}
