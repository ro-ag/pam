use pam_core::{ApprovalId, CallerId, IdempotencyKey, ProjectId, RequestId};
use pam_flow::{EffectReport, FlowSemanticEvent, FlowWaitReason, RunOutcome, TransitionKind};
use pam_protocol::{
    ApprovalChallenge, Event, EventEnvelope, Failure, FailureCode, PROTOCOL_VERSION,
    RequestEnvelope,
};

use super::current::{
    CurrentState, TimelineKind, failure_state_for_test, outcome_heading_for_test,
    pending_approval_for_test, timeline_from_events, timeline_semantic_for_test,
    timeline_transition_for_test,
};

#[test]
fn semantic_timeline_preserves_truthful_verification_and_evidence() {
    let flow_evidence = pam_flow::EvidenceHandle::parse("evidence://ci/run/check").unwrap();
    let evidence = pam_core::EvidenceHandle::parse("evidence://ci/run/check").unwrap();
    let fact = timeline_semantic_for_test(&FlowSemanticEvent::VerificationPassed {
        step_id: "verify".to_owned(),
        report: EffectReport::new("All checks passed.", vec![flow_evidence]).unwrap(),
    });

    assert_eq!(fact.label, "Verification passed");
    assert_eq!(fact.summary, "All checks passed.");
    assert_eq!(fact.kind, TimelineKind::Verification);
    assert!(fact.verified);
    assert_eq!(fact.evidence, vec![evidence]);
}

#[test]
fn approval_surface_retains_exact_authenticated_request_without_exposing_credential() {
    let request = RequestEnvelope::project_current(
        RequestId::new("current-1"),
        CallerId::new("gui-1"),
        ProjectId::new("project-1"),
        IdempotencyKey::new("current-1"),
    )
    .authenticated(pam_core::CallerCredential::new("secret"));
    let pending = pending_approval_for_test(
        request,
        ApprovalChallenge {
            approval_id: ApprovalId::new("approval-1"),
            expires_at_unix_ms: 100,
        },
    );

    assert_eq!(pending.approval_id().as_str(), "approval-1");
    assert_eq!(pending.project_id().as_str(), "project-1");
    assert!(!format!("{pending:?}").contains("secret"));
}

#[test]
fn waiting_semantics_do_not_claim_completion() {
    let fact = timeline_semantic_for_test(&FlowSemanticEvent::Waiting {
        step_id: "deploy".to_owned(),
        reason: FlowWaitReason::Approval,
        not_before_ms: None,
    });

    assert_eq!(fact.label, "Waiting");
    assert_eq!(fact.kind, TimelineKind::Request);
    assert!(!fact.verified);
    assert!(fact.summary.contains("approval"));
}

#[test]
fn semantic_timeline_assigns_evidence_at_the_event_boundary() {
    let fact = timeline_semantic_for_test(&FlowSemanticEvent::EvidenceFound {
        step_id: "inspect".to_owned(),
        evidence: vec![pam_flow::EvidenceHandle::parse("evidence://ci/run/inspect").unwrap()],
    });

    assert_eq!(fact.kind, TimelineKind::Evidence);
}

#[test]
fn generic_terminal_completion_is_neutral_and_never_claims_verification() {
    let facts = timeline_from_events(&[EventEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: RequestId::new("completed"),
        project_id: ProjectId::new("project"),
        sequence: 1,
        event: Event::Completed,
    }]);

    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].kind, TimelineKind::Request);
    assert!(!facts[0].verified);
}

#[test]
fn transition_timeline_kind_is_semantic_not_label_derived() {
    let cases = [
        (
            TransitionKind::ApprovalRequested {
                step_id: "deploy".to_owned(),
            },
            TimelineKind::Request,
        ),
        (
            TransitionKind::EffectSucceeded {
                step_id: "deploy".to_owned(),
                attempt: 1,
            },
            TimelineKind::Change,
        ),
        (
            TransitionKind::RunCompleted {
                outcome: RunOutcome::Solved,
            },
            TimelineKind::Request,
        ),
        (
            TransitionKind::EffectFailed {
                step_id: "deploy".to_owned(),
                attempt: 1,
            },
            TimelineKind::Failure,
        ),
    ];

    for (transition, expected) in cases {
        assert_eq!(timeline_transition_for_test(&transition).kind, expected);
    }
}

#[test]
fn solved_terminal_transition_is_neutral_without_a_typed_verification_event() {
    let fact = timeline_transition_for_test(&TransitionKind::RunCompleted {
        outcome: RunOutcome::Solved,
    });

    assert_eq!(fact.kind, TimelineKind::Request);
    assert!(!fact.verified);
}

#[test]
fn non_solved_terminal_transitions_never_claim_verification() {
    for outcome in [
        RunOutcome::Unresolved,
        RunOutcome::Blocked,
        RunOutcome::Cancelled,
    ] {
        let fact = timeline_transition_for_test(&TransitionKind::RunCompleted { outcome });

        assert_eq!(fact.kind, TimelineKind::Failure);
        assert!(!fact.verified);
    }
}

#[test]
fn only_solved_outcomes_claim_ready_for_the_next_agent() {
    assert_eq!(
        outcome_heading_for_test(RunOutcome::Solved),
        ("Ready for the next agent", true)
    );
    for outcome in [
        RunOutcome::Unresolved,
        RunOutcome::Blocked,
        RunOutcome::Cancelled,
    ] {
        let (heading, solved) = outcome_heading_for_test(outcome);
        assert!(!solved);
        assert_ne!(heading, "Ready for the next agent");
    }
}

#[test]
fn forbidden_current_is_blocked_but_internal_current_is_unavailable() {
    let blocked = failure_state_for_test(Failure {
        code: FailureCode::Forbidden,
        message: "forbidden".to_owned(),
        recovery: None,
        approval: None,
    });
    let unavailable = failure_state_for_test(Failure {
        code: FailureCode::Internal,
        message: "internal".to_owned(),
        recovery: None,
        approval: None,
    });

    assert!(matches!(blocked, CurrentState::Blocked { .. }));
    assert!(matches!(unavailable, CurrentState::Degraded { .. }));
}
