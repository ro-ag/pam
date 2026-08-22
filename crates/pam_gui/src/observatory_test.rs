use pam_protocol::{ActivityResult, Failure, FailureCode};

use super::observatory::{ObservatoryState, failure_state_for_test};

fn failure(code: FailureCode, recovery: Option<String>) -> Failure {
    Failure {
        code,
        message: "observed failure".to_owned(),
        recovery,
        approval: None,
    }
}

#[test]
fn explicit_policy_denials_are_blocked() {
    for code in [FailureCode::Forbidden, FailureCode::ApprovalRequired] {
        let state: ObservatoryState<ActivityResult> =
            failure_state_for_test(failure(code.clone(), None));
        assert!(
            matches!(state, ObservatoryState::Blocked { code: observed, .. } if observed == code)
        );
    }
}

#[test]
fn non_policy_failures_are_unavailable_and_keep_recovery_text() {
    let state: ObservatoryState<ActivityResult> = failure_state_for_test(failure(
        FailureCode::Internal,
        Some("Start the PAM daemon.".to_owned()),
    ));

    assert_eq!(
        state,
        ObservatoryState::Unavailable {
            code: None,
            detail: "observed failure".to_owned(),
            recovery: Some("Start the PAM daemon.".to_owned()),
        }
    );
}
