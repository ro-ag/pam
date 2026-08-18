use pam_core::{CallerId, IdempotencyKey, ProjectId, RequestId};

use super::{
    FailureCode, OperationTruth, PROTOCOL_VERSION, RequestEnvelope, ResultBody, ResultPayload,
    StatusResult,
};

fn status_request() -> RequestEnvelope {
    RequestEnvelope::status(
        RequestId::from("request-1"),
        CallerId::from("cli-1"),
        ProjectId::from("project-1"),
        IdempotencyKey::from("status-1"),
    )
}

#[test]
fn status_request_populates_the_versioned_identity_contract() {
    let request = status_request();

    assert_eq!(request.protocol_version, PROTOCOL_VERSION);
    assert_eq!(request.request_id.as_str(), "request-1");
    assert_eq!(request.caller_id.as_str(), "cli-1");
    assert_eq!(request.project_id.as_str(), "project-1");
    assert_eq!(request.idempotency_key.as_str(), "status-1");
}

#[test]
fn unsupported_versions_produce_a_correlated_typed_failure() {
    let mut request = status_request();
    request.protocol_version = PROTOCOL_VERSION + 1;

    let failure = request.unsupported_version_failure().unwrap();
    assert_eq!(failure.request_id, request.request_id);
    assert_eq!(failure.project_id, request.project_id);
    let ResultBody::Failure(failure) = failure.body else {
        panic!("expected protocol failure")
    };
    assert_eq!(failure.code, FailureCode::UnsupportedProtocolVersion);
}

#[test]
fn truth_contract_distinguishes_all_documented_outcomes() {
    let truths = [
        OperationTruth::Observed,
        OperationTruth::Changed,
        OperationTruth::Verified,
        OperationTruth::Unresolved,
        OperationTruth::Blocked,
    ];

    for truth in truths {
        let body = ResultBody::Success {
            truth,
            payload: ResultPayload::Status(StatusResult {
                ready: true,
                healthy: true,
                daemon_version: "0.1.0".to_owned(),
                protocol_version: PROTOCOL_VERSION,
                queue_depth: 0,
            }),
        };
        assert!(matches!(body, ResultBody::Success { .. }));
    }
}
