use pam_core::{ApprovalId, CallerId, EvidenceHandle, IdempotencyKey, ProjectId, RequestId};
use std::path::Path;

use pam_protocol::{Capability, ExpectedTargetKind, ModelMessage, ModelRole, RequestPayload};

use super::request::RequestContext;

fn context() -> RequestContext {
    context_with_approval(None)
}

fn context_with_approval(approval_id: Option<ApprovalId>) -> RequestContext {
    RequestContext::new(
        CallerId::from("cli-1"),
        ProjectId::from("project-1"),
        approval_id,
    )
}

const PROJECT_ROOT: &str = "/canonical/project";

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
            expected_target_kind: None,
        }
    );
    assert_ne!(result.request_id, target);
    assert_eq!(result.capability, Capability::GetResult);
    assert_eq!(
        result.payload,
        RequestPayload::GetResult {
            target_request_id: target,
            expected_target_kind: None,
        }
    );
}

#[test]
fn flow_requests_bind_exact_run_identity_and_target_kind() {
    let definition = super::flow_test::flow_source("cli-flow", "CLI flow");
    let run = context()
        .flow_run(
            definition.clone(),
            Some(RequestId::from("run-1")),
            Some(IdempotencyKey::from("stable-run-1")),
            Path::new(PROJECT_ROOT),
        )
        .unwrap();
    assert_eq!(run.request_id, RequestId::from("run-1"));
    assert_eq!(run.idempotency_key, IdempotencyKey::from("stable-run-1"));
    assert!(run.authentication.is_some());
    assert!(matches!(
        run.payload,
        RequestPayload::FlowRun {
            definition: ref document,
            project_root: ref root,
        } if document.as_str() == definition && root.as_str() == PROJECT_ROOT
    ));

    let target = RequestId::from("run-1");
    for request in [
        context().flow_cancel(target.clone()),
        context().flow_logs(target.clone(), 2),
        context().flow_wait(target.clone(), 3),
        context().flow_result(target.clone()),
    ] {
        assert_ne!(request.request_id, target);
        let (RequestPayload::Cancel {
            target_request_id: observed_target,
            expected_target_kind: expected,
        }
        | RequestPayload::Replay {
            target_request_id: observed_target,
            expected_target_kind: expected,
            ..
        }
        | RequestPayload::WaitForResult {
            target_request_id: observed_target,
            expected_target_kind: expected,
            ..
        }
        | RequestPayload::GetResult {
            target_request_id: observed_target,
            expected_target_kind: expected,
        }) = request.payload
        else {
            panic!("expected target-scoped flow request")
        };
        assert_eq!(observed_target, target);
        assert_eq!(expected, Some(ExpectedTargetKind::FlowRun));
    }
}

#[test]
fn flow_run_default_idempotency_is_deterministic_from_the_run_id() {
    let definition = super::flow_test::flow_source("cli-flow", "CLI flow");
    let first = context()
        .flow_run(
            definition.clone(),
            Some(RequestId::from("stable-run")),
            None,
            Path::new(PROJECT_ROOT),
        )
        .unwrap();
    let retry = context()
        .flow_run(
            definition,
            Some(RequestId::from("stable-run")),
            None,
            Path::new(PROJECT_ROOT),
        )
        .unwrap();
    assert_eq!(first.request_id, retry.request_id);
    assert_eq!(first.idempotency_key, retry.idempotency_key);
    assert_eq!(first.idempotency_key.as_str(), "flow-run:stable-run");
}

#[test]
fn approved_receipt_is_attached_to_the_exact_retried_request() {
    let target = RequestId::from("target-1");
    let original = context().wait(target.clone(), 7);
    let approval_id = ApprovalId::from("approval-1");
    let retried = context_with_approval(Some(approval_id.clone())).wait(target, 7);

    assert_eq!(original.approval_id, None);
    assert_eq!(retried.approval_id, Some(approval_id));
    assert_eq!(retried.capability, original.capability);
    assert_eq!(retried.payload, original.payload);
    assert_eq!(retried.caller_id, original.caller_id);
    assert_eq!(retried.project_id, original.project_id);
}

#[test]
fn explicit_approval_receipt_is_attached_to_each_supported_single_request() {
    let approval_id = ApprovalId::from("approval-1");
    let context = context_with_approval(Some(approval_id.clone()));
    let requests = [
        context.status(),
        context.brief(),
        context.network_diagnostics(),
        context.wait(RequestId::from("target-1"), 7),
        context.result(RequestId::from("target-1")),
    ];

    for request in requests {
        assert_eq!(request.approval_id.as_ref(), Some(&approval_id));
    }
}

#[test]
fn network_diagnostics_is_authenticated_and_typed() {
    let request = context().network_diagnostics();

    assert_eq!(request.capability, Capability::NetworkDiagnostics);
    assert_eq!(request.payload, RequestPayload::NetworkDiagnostics);
    assert!(request.authentication.is_some());
}

#[test]
fn model_inference_is_authenticated_bounded_and_deadlined() {
    let secret_prompt = "analyze this private table";
    let message = ModelMessage::new(ModelRole::User, secret_prompt).unwrap();
    let request = context()
        .model_infer("qwen/coder".to_owned(), vec![message.clone()], 256, 42)
        .unwrap();

    assert_eq!(request.capability, Capability::ModelInfer);
    assert_eq!(request.deadline_unix_ms, Some(42));
    assert!(request.authentication.is_some());
    assert_eq!(
        request.payload,
        RequestPayload::ModelInfer {
            model: "qwen/coder".to_owned(),
            messages: vec![message],
            max_output_tokens: 256,
        }
    );
    assert!(!format!("{request:?}").contains(secret_prompt));
}

#[test]
fn evidence_requests_are_typed_bounded_and_receipt_free() {
    let handle = EvidenceHandle::parse("evidence://ci/1842/failure").unwrap();
    let evidence_context = context_with_approval(Some(ApprovalId::from("unused-approval")));
    let inspect = evidence_context.inspect_evidence(handle.clone());
    let read = evidence_context
        .read_evidence(handle.clone(), 256, 1024)
        .unwrap();

    assert_eq!(inspect.approval_id, None);
    assert_eq!(read.approval_id, None);

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
