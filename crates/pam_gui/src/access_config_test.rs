use pam_protocol::{
    ConfigurationPresence, Failure, FailureCode, NetworkDiagnosticsResult, OperationTruth, PacState,
};

use super::access_config::{
    AccessConfigState, access_copy_for_test, access_failure_for_test, map_diagnostics_for_test,
};

#[test]
fn typed_network_facts_map_without_exposing_proxy_values() {
    let view = map_diagnostics_for_test(
        OperationTruth::Observed,
        &NetworkDiagnosticsResult {
            platform_roots_enabled: true,
            system_proxy_discovery_enabled: true,
            proxy_environment_presence: ConfigurationPresence::Configured,
            no_proxy_presence: ConfigurationPresence::Invalid,
            pac_state: PacState::InspectionUnavailable,
        },
    );

    assert_eq!(view.truth, OperationTruth::Observed);
    assert!(view.platform_roots_enabled);
    assert_eq!(view.proxy_environment, "configured");
    assert_eq!(view.no_proxy, "invalid");
    assert_eq!(view.pac, "inspection unavailable");
}

#[test]
fn model_and_access_copy_never_claim_loaded_or_allowed_inventory() {
    let (access, model) = access_copy_for_test();

    assert!(access.contains("Policy gated"));
    assert!(!access.contains("Allowed"));
    assert!(model.contains("not reported"));
    assert!(!model.contains("loaded"));
}

#[test]
fn only_policy_failures_are_classified_as_blocked() {
    for code in [FailureCode::Forbidden, FailureCode::ApprovalRequired] {
        assert!(matches!(
            access_failure_for_test(Failure {
                code,
                message: "blocked".to_owned(),
                recovery: None,
                approval: None,
            }),
            AccessConfigState::Blocked { .. }
        ));
    }

    for code in [
        FailureCode::Unauthenticated,
        FailureCode::ApprovalDenied,
        FailureCode::ApprovalExpired,
        FailureCode::UnsupportedProtocolVersion,
        FailureCode::InvalidRequest,
        FailureCode::FrameTooLarge,
        FailureCode::NotFound,
        FailureCode::Pending,
        FailureCode::IdempotencyConflict,
        FailureCode::Cancelled,
        FailureCode::LeaseConflict,
        FailureCode::Busy,
        FailureCode::Internal,
    ] {
        assert!(matches!(
            access_failure_for_test(Failure {
                code,
                message: "unavailable".to_owned(),
                recovery: None,
                approval: None,
            }),
            AccessConfigState::Unavailable { .. }
        ));
    }
}
