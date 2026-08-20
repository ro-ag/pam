use pam_core::{ContentDigest, EvidenceHandle, ProjectId, RequestId};
use pam_flow::{EffectResult, FlowDefinition, FlowRun, RunDecision, RunId};
use pam_protocol::{
    ApprovalDecisionDisposition, ApprovalDecisionResult, BriefItem, BriefProvenance, BriefResult,
    CancellationDisposition, CancellationResult, ConfigurationPresence, DaemonLifecycleResult,
    Event, EventEnvelope, EvidenceMetadata, EvidenceRedaction, EvidenceRetention, Failure,
    FailureCode, ModelFinishReason, ModelGenerationResult, ModelUsage, NetworkDiagnosticsResult,
    OperationTruth, PROTOCOL_VERSION, PacState, ResultBody, ResultPayload, SourceAvailability,
};

use super::render::{
    EXIT_NOT_FOUND, EXIT_OPERATION_FAILED, EXIT_PENDING, present_result, render_brief,
    render_events, render_evidence_preview,
};

fn handle() -> EvidenceHandle {
    EvidenceHandle::parse("evidence://ci/1842/failure").unwrap()
}

#[test]
fn daemon_stop_acknowledgement_is_rendered_without_process_identity() {
    let presentation = present_result(&ResultBody::Success {
        truth: OperationTruth::Changed,
        payload: ResultPayload::DaemonLifecycle(DaemonLifecycleResult { stopping: true }),
    });

    assert_eq!(presentation.stdout, "stopping=true truth=changed\n");
    assert!(presentation.stderr.is_empty());
}

#[test]
fn approval_decision_renders_only_bounded_identity_and_disposition() {
    let presentation = present_result(&ResultBody::Success {
        truth: OperationTruth::Changed,
        payload: ResultPayload::ApprovalDecision(ApprovalDecisionResult {
            approval_id: pam_core::ApprovalId::new("approval-1"),
            disposition: ApprovalDecisionDisposition::Approved,
        }),
    });

    assert_eq!(
        presentation.stdout,
        "approval_id=approval-1 disposition=approved truth=changed\n"
    );
    assert!(presentation.stderr.is_empty());
}

#[test]
fn network_diagnostics_renders_only_sanitized_configuration_facts() {
    let presentation = present_result(&ResultBody::Success {
        truth: OperationTruth::Observed,
        payload: ResultPayload::NetworkDiagnostics(NetworkDiagnosticsResult {
            platform_roots_enabled: true,
            system_proxy_discovery_enabled: true,
            proxy_environment_presence: ConfigurationPresence::Configured,
            no_proxy_presence: ConfigurationPresence::Invalid,
            pac_state: PacState::DetectedUnsupported,
        }),
    });

    assert_eq!(
        presentation.stdout,
        "platform_roots_enabled=true system_proxy_discovery_enabled=true proxy_environment=configured no_proxy=invalid pac=detected_unsupported truth=observed\n"
    );
    assert!(presentation.stderr.is_empty());
}

#[test]
fn model_output_is_terminal_safe_and_carries_observed_usage() {
    let presentation = present_result(&ResultBody::Success {
        truth: OperationTruth::Observed,
        payload: ResultPayload::ModelGeneration(
            ModelGenerationResult::new(
                "qwen/coder",
                "ok\n\u{1b}[31m",
                ModelFinishReason::Stop,
                ModelUsage {
                    input_tokens: 12,
                    sampled_output_tokens: 3,
                    emitted_output_tokens: 2,
                },
            )
            .unwrap(),
        ),
    });

    assert_eq!(
        presentation.stdout,
        "model=qwen/coder finish_reason=stop input_tokens=12 sampled_output_tokens=3 emitted_output_tokens=2 truth=observed\nOutput:\nok\\n\\u{1b}[31m\n"
    );
    assert!(presentation.stderr.is_empty());
}

#[test]
fn brief_renders_only_the_stable_sections_in_order_with_truth_and_availability() {
    let brief = BriefResult {
        goal: Some(BriefItem {
            text: "Ship\u{1b}[31m continuity".to_owned(),
            truth: OperationTruth::Observed,
            evidence: vec![handle()],
        }),
        decisions: Vec::new(),
        verified: vec![BriefItem {
            text: "tests pass".to_owned(),
            truth: OperationTruth::Verified,
            evidence: Vec::new(),
        }],
        next: Vec::new(),
        provenance: vec![BriefProvenance {
            source: "pam".to_owned(),
            availability: SourceAvailability::Partial,
            truth: OperationTruth::Observed,
            evidence: Some(handle()),
            detail: Some("connector\noffline".to_owned()),
        }],
    };

    assert_eq!(
        render_brief(&brief),
        concat!(
            "Goal\n",
            "- [observed] Ship\\u{1b}[31m continuity\n",
            "  Evidence: evidence://ci/1842/failure\n",
            "Decisions\n",
            "- unresolved [source-availability=partial]\n",
            "Verified\n",
            "- [verified] tests pass\n",
            "Next\n",
            "- unresolved [source-availability=partial]\n",
            "Provenance\n",
            "- pam [availability=partial truth=observed] evidence=evidence://ci/1842/failure detail=connector\\noffline\n",
        )
    );
}

#[test]
fn unavailable_brief_fields_are_explicit() {
    let brief = BriefResult {
        goal: None,
        decisions: Vec::new(),
        verified: Vec::new(),
        next: Vec::new(),
        provenance: vec![BriefProvenance {
            source: "planning-context".to_owned(),
            availability: SourceAvailability::Unavailable,
            truth: OperationTruth::Unresolved,
            evidence: None,
            detail: Some("not configured".to_owned()),
        }],
    };
    let rendered = render_brief(&brief);

    assert!(rendered.starts_with("Goal\n- unavailable [source-availability=unavailable]\n"));
    assert!(rendered.ends_with(
        "Provenance\n- planning-context [availability=unavailable truth=unresolved] detail=not configured\n"
    ));
}

#[test]
fn available_sources_distinguish_empty_sections_from_unavailable_ones() {
    let rendered = render_brief(&BriefResult {
        goal: None,
        decisions: Vec::new(),
        verified: Vec::new(),
        next: Vec::new(),
        provenance: vec![BriefProvenance {
            source: "planning-context".to_owned(),
            availability: SourceAvailability::Available,
            truth: OperationTruth::Observed,
            evidence: None,
            detail: None,
        }],
    });

    assert!(rendered.contains("Decisions\n- empty [source-availability=available]\n"));
    assert!(!rendered.contains("source-availability=unavailable"));
}

#[test]
fn event_rendering_preserves_gap_free_input_order() {
    let event = |sequence, event| EventEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: RequestId::from("target-1"),
        project_id: ProjectId::from("project-1"),
        sequence,
        event,
    };

    assert_eq!(
        render_events(&[event(8, Event::Started), event(9, Event::Completed)]),
        "sequence=8 event=started\nsequence=9 event=completed\n"
    );
}

#[test]
fn flow_transition_rendering_preserves_semantic_progress_without_command_output() {
    let definition =
        FlowDefinition::parse_toml(&super::flow_test::flow_source("render-flow", "Render flow"))
            .unwrap();
    let mut run = FlowRun::start(RunId::parse("render-run").unwrap(), definition).unwrap();
    let update = run.next_decision(42).unwrap();
    let transition = update.transition().unwrap().clone();
    let rendered = render_events(&[EventEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: RequestId::from("render-run"),
        project_id: ProjectId::from("project-1"),
        sequence: 3,
        event: Event::FlowTransition(transition),
    }]);

    assert_eq!(
        rendered,
        "sequence=3 event=flow_transition flow_sequence=1 transition=effect_evaluation_required step=inspect attempt=1\n"
    );
    assert!(!rendered.contains("git"));
}

#[test]
fn semantic_progress_and_terminal_outcome_render_bounded_reports_and_evidence() {
    let definition = FlowDefinition::parse_toml(
        r#"
schema_version = 2
id = "verified-render"
name = "Verified render"
description = "Exercise semantic progress and terminal reports."
revision = 1

[outcome]
solved = "Requested checks completed."
changed = "Requested changes applied."
verified = "Repository state verified."
unresolved = "Checks remain unresolved."
blocked = "Checks are blocked."

[[steps]]
id = "verify"
description = "Verify the worktree."
timeout_seconds = 1
effect = "read_only"
semantic = "verify"
action = { type = "command", program = "git", args = ["diff", "--quiet"], working_directory = "." }
"#,
    )
    .unwrap();
    let mut run = FlowRun::start(RunId::parse("verified-render-run").unwrap(), definition).unwrap();
    let evaluation = run.next_decision(1).unwrap();
    let RunDecision::EvaluateEffect { effect, .. } = evaluation.decision() else {
        panic!("verification should require effect evaluation")
    };
    let effect = effect.clone();
    run.prepare_effect(&effect, 2).unwrap();
    let progress = run
        .record_effect_result(
            &effect,
            EffectResult::succeeded(
                "verification passed",
                vec![pam_flow::EvidenceHandle::parse("evidence:verify").unwrap()],
            )
            .unwrap(),
            3,
        )
        .unwrap();
    let rendered = render_events(&[EventEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: RequestId::from("verified-render-run"),
        project_id: ProjectId::from("project-1"),
        sequence: 8,
        event: Event::FlowTransition(progress.transition().unwrap().clone()),
    }]);
    assert_eq!(
        rendered,
        "sequence=8 event=flow_progress flow_sequence=3 semantic_index=1 progress=evidence_found step=verify evidence=evidence:verify\nsequence=8 event=flow_progress flow_sequence=3 semantic_index=2 progress=verification_passed step=verify summary=verification passed evidence=evidence:verify\n"
    );

    let terminal = run.next_decision(4).unwrap();
    let RunDecision::Terminal { result } = terminal.decision() else {
        panic!("verification should complete the flow")
    };
    let presentation = present_result(&ResultBody::Success {
        truth: OperationTruth::Verified,
        payload: ResultPayload::FlowRun(result.clone()),
    });
    assert_eq!(presentation.exit_code, 0);
    assert!(presentation.stderr.is_empty());
    assert!(presentation.stdout.contains(
        "outcome_section=verified satisfied=true summary=Repository state verified. steps=verify evidence=evidence:verify evidence_truncated=false\n"
    ));
    assert!(presentation.stdout.contains(
        "step=verify semantic=verify status=succeeded result=succeeded summary=verification passed evidence=evidence:verify\n"
    ));
    assert!(!presentation.stdout.contains("git diff"));
}

#[test]
fn unresolved_flow_renders_per_step_failure_and_terminal_safe_evidence() {
    let definition = FlowDefinition::parse_toml(&super::flow_test::flow_source(
        "failure-render",
        "Failure render",
    ))
    .unwrap();
    let mut run = FlowRun::start(RunId::parse("failure-render-run").unwrap(), definition).unwrap();
    let evaluation = run.next_decision(1).unwrap();
    let RunDecision::EvaluateEffect { effect, .. } = evaluation.decision() else {
        panic!("observation should require effect evaluation")
    };
    let effect = effect.clone();
    run.prepare_effect(&effect, 2).unwrap();
    run.record_effect_result(
        &effect,
        EffectResult::failed(
            "diagnostic failed é",
            false,
            vec![pam_flow::EvidenceHandle::parse("evidence:failure").unwrap()],
        )
        .unwrap(),
        3,
    )
    .unwrap();
    let terminal = run.next_decision(4).unwrap();
    let RunDecision::Terminal { result } = terminal.decision() else {
        panic!("failed observation should terminate unresolved")
    };
    let presentation = present_result(&ResultBody::Success {
        truth: OperationTruth::Unresolved,
        payload: ResultPayload::FlowRun(result.clone()),
    });

    assert_eq!(presentation.exit_code, EXIT_OPERATION_FAILED);
    assert!(presentation.stdout.contains(
        "outcome_section=unresolved satisfied=true summary=Unresolved. steps=inspect evidence=evidence:failure evidence_truncated=false\n"
    ));
    assert!(presentation.stdout.contains(
        "step=inspect semantic=observe status=failed result=failed retryable=false summary=diagnostic failed \\u{e9} evidence=evidence:failure\n"
    ));
    assert!(!presentation.stdout.contains('é'));
}

#[test]
fn pending_not_found_and_unresolved_have_deterministic_nonzero_exits() {
    let failure = |code| {
        present_result(&ResultBody::Failure(Failure {
            code,
            message: "not ready".to_owned(),
            recovery: None,
            approval: None,
        }))
    };

    assert_eq!(failure(FailureCode::Pending).exit_code, EXIT_PENDING);
    assert_eq!(failure(FailureCode::NotFound).exit_code, EXIT_NOT_FOUND);
    assert_eq!(
        present_result(&ResultBody::Success {
            truth: OperationTruth::Unresolved,
            payload: ResultPayload::Brief(BriefResult {
                goal: None,
                decisions: Vec::new(),
                verified: Vec::new(),
                next: Vec::new(),
                provenance: Vec::new(),
            }),
        })
        .exit_code,
        EXIT_OPERATION_FAILED
    );
}

#[test]
fn cancelled_flow_result_is_explicit_and_nonzero() {
    let definition = FlowDefinition::parse_toml(
        r#"
schema_version = 1
id = "cancelled-render"
name = "Cancelled render"
description = "Exercise cancelled CLI rendering."
revision = 1

[outcome]
solved = "Solved."
changed = "Changed."
verified = "Verified."
unresolved = "Unresolved."
blocked = "Blocked."

[[steps]]
id = "observe"
description = "Observe Git status."
timeout_seconds = 1
effect = "read_only"
action = { type = "command", program = "git", args = ["status"], working_directory = "." }
"#,
    )
    .unwrap();
    let mut run =
        FlowRun::start(RunId::parse("cancelled-render-run").unwrap(), definition).unwrap();
    let update = run.cancel().unwrap();
    let RunDecision::Terminal { result } = update.decision() else {
        panic!("cancelling before an effect should be terminal")
    };
    let presentation = present_result(&ResultBody::Success {
        truth: OperationTruth::Unresolved,
        payload: ResultPayload::FlowRun(result.clone()),
    });

    assert_eq!(presentation.exit_code, EXIT_OPERATION_FAILED);
    assert!(presentation.stderr.is_empty());
    assert_eq!(
        presentation.stdout,
        format!(
            "run_id=cancelled-render-run definition_digest={} outcome=cancelled steps=1 truth=unresolved\noutcome_section=solved satisfied=false summary=Solved. steps=- evidence=- evidence_truncated=false\noutcome_section=changed satisfied=false summary=Changed. steps=- evidence=- evidence_truncated=false\noutcome_section=verified satisfied=false summary=Verified. steps=- evidence=- evidence_truncated=false\noutcome_section=unresolved satisfied=false summary=Unresolved. steps=- evidence=- evidence_truncated=false\noutcome_section=blocked satisfied=false summary=Blocked. steps=- evidence=- evidence_truncated=false\nstep=observe semantic=observe status=cancelled\n",
            result.definition_digest()
        )
    );
}

#[test]
fn repeated_cancellation_renders_as_observed_without_claiming_another_change() {
    let presentation = present_result(&ResultBody::Success {
        truth: OperationTruth::Observed,
        payload: ResultPayload::Cancellation(CancellationResult {
            target_request_id: RequestId::from("run-1"),
            disposition: CancellationDisposition::AlreadyRequested,
        }),
    });

    assert_eq!(presentation.exit_code, 0);
    assert_eq!(
        presentation.stdout,
        "target_request_id=run-1 disposition=already_requested truth=observed\n"
    );
}

#[test]
fn evidence_preview_escapes_every_control_and_non_ascii_byte() {
    let metadata = EvidenceMetadata {
        handle: handle(),
        digest: ContentDigest::from_sha256([0xab; 32]),
        size_bytes: 8,
        media_type: "text/plain\u{1b}\u{202e}\u{00e9}".to_owned(),
        retention: EvidenceRetention::Project,
        redaction: EvidenceRedaction::Unredacted,
        created_at_unix_ms: 42,
    };
    let rendered =
        render_evidence_preview(&metadata, b"ok\n\x1b[31m\xff", &OperationTruth::Observed);

    assert!(rendered.contains("Media-Type: text/plain\\u{1b}\\u{202e}\\u{e9}\n"));
    assert!(rendered.contains("Truth: observed\n"));
    assert!(rendered.ends_with("Preview:\nok\\n\\x1b[31m\\xff\n"));
    assert!(!rendered.as_bytes().contains(&0x1b));
}
