use pam_core::{ApprovalId, CallerId, IdempotencyKey, ProjectId, RequestId};
use pam_flow::{EffectReport, FlowSemanticEvent, FlowWaitReason, RunOutcome};
use pam_protocol::{ApprovalChallenge, Failure, FailureCode, RequestEnvelope};

use super::current::{
    CurrentState, failure_state_for_test, outcome_heading_for_test, pending_approval_for_test,
    timeline_semantic_for_test,
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
    assert!(!fact.verified);
    assert!(fact.summary.contains("approval"));
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
