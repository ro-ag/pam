use pam_core::{CallerId, EvidenceHandle, ProjectId, RequestId};
use pam_protocol::{Capability, RequestPayload};

use super::request::RequestContext;

fn context() -> RequestContext {
    RequestContext::new(CallerId::from("cli-1"), ProjectId::from("project-1"))
}

#[test]
fn observer_and_idempotency_ids_are_unique_per_request() {
    let first = context().brief();
    let second = context().brief();

    assert_ne!(first.request_id, second.request_id);
    assert_ne!(first.idempotency_key, second.idempotency_key);
    assert_ne!(first.request_id.as_str(), first.idempotency_key.as_str());
    assert_eq!(
        first
            .authentication
            .as_ref()
            .expect("test context authenticates requests")
            .expose_secret(),
        "test-caller-credential"
    );
}

#[test]
fn wait_and_result_keep_the_target_separate_from_observer_identity() {
    let target = RequestId::from("target-1");
    let wait = context().wait(target.clone(), 7);
    let result = context().result(target.clone());

    assert_ne!(wait.request_id, target);
    assert_eq!(wait.capability, Capability::WaitForResult);
    assert_eq!(
        wait.payload,
        RequestPayload::WaitForResult {
            target_request_id: target.clone(),
            after_sequence: 7,
        }
    );
    assert_ne!(result.request_id, target);
    assert_eq!(result.capability, Capability::GetResult);
    assert_eq!(
        result.payload,
        RequestPayload::GetResult {
            target_request_id: target,
        }
    );
}

#[test]
fn network_diagnostics_is_authenticated_and_typed() {
    let request = context().network_diagnostics();

    assert_eq!(request.capability, Capability::NetworkDiagnostics);
    assert_eq!(request.payload, RequestPayload::NetworkDiagnostics);
    assert!(request.authentication.is_some());
}

#[test]
fn evidence_requests_are_typed_and_protocol_bounded() {
    let handle = EvidenceHandle::parse("evidence://ci/1842/failure").unwrap();
    let inspect = context().inspect_evidence(handle.clone());
    let read = context().read_evidence(handle.clone(), 256, 1024).unwrap();

    assert_eq!(inspect.capability, Capability::InspectEvidence);
    assert_eq!(
        inspect.payload,
        RequestPayload::InspectEvidence {
            handle: handle.clone(),
        }
    );
    assert_eq!(read.capability, Capability::ReadEvidence);
    assert_eq!(
        read.payload,
        RequestPayload::ReadEvidence {
            handle,
            offset: 256,
            length: 1024,
        }
    );
    assert!(
        context()
            .read_evidence(
                EvidenceHandle::parse("evidence://ci/1842/failure").unwrap(),
                0,
                0,
            )
            .is_err()
    );
}
