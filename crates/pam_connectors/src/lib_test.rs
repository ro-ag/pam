use std::{
    fs,
    future::Future,
    path::PathBuf,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use pam_core::{ApprovalId, CallerCredential, CallerId, GrantId, ProjectId};
use pam_policy::{ApprovalRequirement, Effect, Grant, ResourceScope};
use pam_store::{
    ApprovalDecision, ApprovalDecisionOutcome, AuthorizationOutcome, AuthorizationRequest,
    PutGrant, Store,
};
use serde::{Deserialize, Serialize};

use super::{
    BoundedSummary, CancellationToken, CapabilityName, ConformanceViolation, Connector,
    ConnectorDescriptor, ConnectorFailure, ConnectorFuture, ConnectorOutput, EffectApproval,
    ExactArtifact, ExactEvidence, FailureKind, FailureMessage, IdempotencyDeclaration,
    IdempotencyKey, InvalidInvocationContext, InvocationContext, MAX_ARTIFACT_NAME_BYTES,
    MAX_ARTIFACT_PAYLOAD_BYTES, MAX_ARTIFACT_PAYLOADS, MAX_EVIDENCE_PAYLOAD_BYTES,
    MAX_EVIDENCE_PAYLOADS, MAX_FAILURE_MESSAGE_BYTES, MAX_IDEMPOTENCY_KEY_BYTES, MAX_SUMMARY_BYTES,
    Operation, OperationCoordinates, OperationEffect, ReconciliationDeclaration, ResourceName,
    RetryGuidance, StatefulContract, Truth, verify_conformance,
};

fn capability(value: &str) -> CapabilityName {
    CapabilityName::parse(value).expect("test capability must be valid")
}

fn resource(value: &str) -> ResourceName {
    ResourceName::parse(value).expect("test resource must be valid")
}

fn evidence_handle() -> super::EvidenceHandle {
    super::EvidenceHandle::parse("evidence://github/run-42").expect("test handle must be valid")
}

fn future_context(idempotency_key: Option<&str>) -> InvocationContext {
    InvocationContext::new(
        Instant::now() + Duration::from_mins(1),
        CancellationToken::new(),
        1,
        idempotency_key.map(IdempotencyKey::from),
    )
    .expect("test context must be valid")
}

#[test]
fn descriptors_and_invocation_contexts_reject_ambiguous_input() {
    let descriptor = ConnectorDescriptor::new("github.actions", "v1").unwrap();
    assert_eq!(descriptor.name(), "github.actions");
    assert_eq!(descriptor.version(), "v1");
    assert!(ConnectorDescriptor::new("GitHub.actions", "v1").is_err());
    assert!(ConnectorDescriptor::new("github..actions", "v1").is_err());
    assert!(ConnectorDescriptor::new("github.actions", "v1\nsecret").is_err());

    let error =
        InvocationContext::new(Instant::now(), CancellationToken::new(), 0, None).unwrap_err();
    assert_eq!(error, InvalidInvocationContext::ZeroAttempt);
    for invalid in ["", "-leading", "has space", "line\nbreak"] {
        let result = InvocationContext::new(
            Instant::now(),
            CancellationToken::new(),
            1,
            Some(IdempotencyKey::from(invalid)),
        );
        assert_eq!(
            result.unwrap_err(),
            InvalidInvocationContext::InvalidIdempotencyKey
        );
    }
    assert!(
        InvocationContext::new(
            Instant::now(),
            CancellationToken::new(),
            1,
            Some(IdempotencyKey::from(
                "x".repeat(MAX_IDEMPOTENCY_KEY_BYTES + 1)
            )),
        )
        .is_err()
    );

    let context = future_context(Some("run-42:rerun-1"));
    assert_eq!(context.attempt().get(), 1);
    assert_eq!(
        context.idempotency_key().map(IdempotencyKey::as_str),
        Some("run-42:rerun-1")
    );
    assert!(context.remaining().is_some());
    assert!(!format!("{context:?}").contains("run-42"));
}

#[test]
fn preflight_honors_shared_cancellation_deadlines_and_stateful_keys() {
    let cancellation = CancellationToken::new();
    let clone = cancellation.clone();
    cancellation.cancel();
    assert!(clone.is_cancelled());
    let context =
        InvocationContext::new(Instant::now() + Duration::from_mins(1), clone, 1, None).unwrap();
    assert_eq!(
        context
            .preflight(OperationEffect::ReadOnly)
            .unwrap_err()
            .kind(),
        FailureKind::Cancelled
    );

    let expired = InvocationContext::new(
        Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
        CancellationToken::new(),
        1,
        None,
    )
    .unwrap();
    assert_eq!(
        expired
            .preflight(OperationEffect::ReadOnly)
            .unwrap_err()
            .kind(),
        FailureKind::Timeout
    );

    let stateful = OperationEffect::Stateful(StatefulContract::new(
        IdempotencyDeclaration::Required,
        ReconciliationDeclaration::Required,
    ));
    assert_eq!(
        future_context(None).preflight(stateful).unwrap_err().kind(),
        FailureKind::InvalidRequest
    );
    future_context(Some("rerun-42"))
        .preflight(stateful)
        .unwrap();
}

#[test]
fn exact_output_and_summary_bounds_are_enforced() {
    assert!(BoundedSummary::new("").is_err());
    assert!(BoundedSummary::new("line\nbreak").is_err());
    assert!(BoundedSummary::new("x".repeat(MAX_SUMMARY_BYTES)).is_ok());
    assert!(BoundedSummary::new("x".repeat(MAX_SUMMARY_BYTES + 1)).is_err());
    assert!(FailureMessage::new("x".repeat(MAX_FAILURE_MESSAGE_BYTES)).is_ok());
    assert!(FailureMessage::new("x".repeat(MAX_FAILURE_MESSAGE_BYTES + 1)).is_err());

    let evidence =
        ExactEvidence::new(evidence_handle(), vec![7; MAX_EVIDENCE_PAYLOAD_BYTES]).unwrap();
    assert_eq!(evidence.bytes().len(), MAX_EVIDENCE_PAYLOAD_BYTES);
    assert!(
        ExactEvidence::new(evidence_handle(), vec![7; MAX_EVIDENCE_PAYLOAD_BYTES + 1]).is_err()
    );
    let artifact = ExactArtifact::new("run.log", vec![9; MAX_ARTIFACT_PAYLOAD_BYTES]).unwrap();
    assert_eq!(artifact.name(), "run.log");
    assert_eq!(artifact.bytes().len(), MAX_ARTIFACT_PAYLOAD_BYTES);
    assert!(ExactArtifact::new("run\0log", Vec::new()).is_err());
    assert!(ExactArtifact::new("x".repeat(MAX_ARTIFACT_NAME_BYTES + 1), Vec::new()).is_err());
    assert!(ExactArtifact::new("large", vec![0; MAX_ARTIFACT_PAYLOAD_BYTES + 1]).is_err());
    assert!(!format!("{evidence:?}").contains("7, 7"));
    assert!(!format!("{artifact:?}").contains("9, 9"));

    let partial_reason = BoundedSummary::new("one page was unavailable").unwrap();
    let output = ConnectorOutput::new(
        42_u64,
        BoundedSummary::new("found one failed run").unwrap(),
        Truth::Partial {
            reason: partial_reason,
        },
        vec![evidence],
        vec![artifact],
    )
    .unwrap();
    assert_eq!(*output.value(), 42);
    assert!(!output.truth().is_complete());
    assert_eq!(output.evidence().len(), 1);
    assert_eq!(output.artifacts().len(), 1);

    let evidence = (0..=MAX_EVIDENCE_PAYLOADS)
        .map(|_| ExactEvidence::new(evidence_handle(), Vec::new()).unwrap())
        .collect();
    assert!(
        ConnectorOutput::new(
            (),
            BoundedSummary::new("too many").unwrap(),
            Truth::Complete,
            evidence,
            Vec::new(),
        )
        .is_err()
    );
    let artifacts = (0..=MAX_ARTIFACT_PAYLOADS)
        .map(|index| ExactArtifact::new(format!("artifact-{index}"), Vec::new()).unwrap())
        .collect();
    assert!(
        ConnectorOutput::new(
            (),
            BoundedSummary::new("too many").unwrap(),
            Truth::Complete,
            Vec::new(),
            artifacts,
        )
        .is_err()
    );
}

#[test]
fn typed_failures_have_safe_debug_and_retry_guidance() {
    let secret = "bearer-super-secret";
    let message = FailureMessage::new(secret).unwrap();
    let authentication = ConnectorFailure::authentication(message.clone());
    assert_eq!(authentication.kind(), FailureKind::Authentication);
    assert_eq!(
        authentication.retry_guidance(),
        RetryGuidance::AfterConfigurationChange
    );
    assert!(!format!("{authentication:?}").contains(secret));
    assert!(!format!("{message:?}").contains(secret));

    let rate_limit = ConnectorFailure::rate_limit(
        FailureMessage::new("quota exhausted").unwrap(),
        Some(Duration::from_secs(30)),
    );
    assert_eq!(
        rate_limit.retry_guidance(),
        RetryGuidance::AfterBackoff {
            delay: Some(Duration::from_secs(30))
        }
    );
    assert_eq!(
        ConnectorFailure::forbidden(message.clone()).retry_guidance(),
        RetryGuidance::Never
    );
    assert_eq!(
        ConnectorFailure::not_found(message.clone()).retry_guidance(),
        RetryGuidance::Never
    );
    assert_eq!(
        ConnectorFailure::network(message.clone()).kind(),
        FailureKind::Network
    );
    assert_eq!(
        ConnectorFailure::certificate(message.clone()).kind(),
        FailureKind::Certificate
    );
    assert_eq!(
        ConnectorFailure::remote(message.clone(), false).retry_guidance(),
        RetryGuidance::Never
    );
    assert_eq!(
        ConnectorFailure::response_too_large(4096).response_limit(),
        Some(4096)
    );
    assert_eq!(
        ConnectorFailure::uncertain_effect(message).retry_guidance(),
        RetryGuidance::ReconcileBeforeRetry
    );
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TestRequest {
    target: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct TestResponse {
    observed: bool,
}

struct ReadOperation;

impl Operation for ReadOperation {
    type Request = TestRequest;
    type Response = TestResponse;

    const EFFECT: OperationEffect = OperationEffect::ReadOnly;

    fn coordinates(request: &Self::Request) -> OperationCoordinates {
        OperationCoordinates::new(capability("runs.read"), resource(&request.target))
    }
}

struct StatefulOperation;

impl Operation for StatefulOperation {
    type Request = TestRequest;
    type Response = TestResponse;

    const EFFECT: OperationEffect = OperationEffect::Stateful(StatefulContract::new(
        IdempotencyDeclaration::Required,
        ReconciliationDeclaration::Required,
    ));

    fn coordinates(request: &Self::Request) -> OperationCoordinates {
        OperationCoordinates::new(capability("runs.rerun"), resource(&request.target))
    }
}

struct ReconciledWithoutRemoteIdempotencyOperation;

impl Operation for ReconciledWithoutRemoteIdempotencyOperation {
    type Request = TestRequest;
    type Response = TestResponse;

    const EFFECT: OperationEffect = OperationEffect::Stateful(StatefulContract::new(
        IdempotencyDeclaration::NotSupported,
        ReconciliationDeclaration::Required,
    ));

    fn coordinates(request: &Self::Request) -> OperationCoordinates {
        OperationCoordinates::new(capability("runs.rerun"), resource(&request.target))
    }
}

struct MissingReconciliationOperation;

impl Operation for MissingReconciliationOperation {
    type Request = TestRequest;
    type Response = TestResponse;

    const EFFECT: OperationEffect = OperationEffect::Stateful(StatefulContract::new(
        IdempotencyDeclaration::NotSupported,
        ReconciliationDeclaration::NotSupported,
    ));

    fn coordinates(request: &Self::Request) -> OperationCoordinates {
        OperationCoordinates::new(capability("runs.rerun"), resource(&request.target))
    }
}

struct FakeConnector {
    descriptor: ConnectorDescriptor,
    transport_calls: AtomicUsize,
}

impl FakeConnector {
    fn new() -> Self {
        Self {
            descriptor: ConnectorDescriptor::new("github.actions", "test-v1").unwrap(),
            transport_calls: AtomicUsize::new(0),
        }
    }

    fn execute<O: Operation<Response = TestResponse>>(
        &self,
        context: InvocationContext,
    ) -> ConnectorFuture<'_, super::ConnectorResult<TestResponse>> {
        Box::pin(async move {
            context.preflight(O::EFFECT)?;
            self.transport_calls.fetch_add(1, Ordering::Relaxed);
            ConnectorOutput::new(
                TestResponse { observed: true },
                BoundedSummary::new("observed").unwrap(),
                Truth::Complete,
                Vec::new(),
                Vec::new(),
            )
            .map_err(|_| ConnectorFailure::response_too_large(0))
        })
    }

    async fn execute_stateful_effect(
        &self,
        request: &TestRequest,
        context: &InvocationContext,
    ) -> Result<ApprovalId, ConnectorFailure> {
        let approval_id = context
            .authorize_effect::<StatefulOperation>(request)
            .await?;
        self.transport_calls.fetch_add(1, Ordering::Relaxed);
        Ok(approval_id)
    }
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .expect("current Unix time must fit u64")
}

fn connector_store_path(name: &str) -> (PathBuf, PathBuf) {
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let directory = std::env::temp_dir().join(format!(
        "pam-connectors-{name}-{}-{}-{}",
        std::process::id(),
        unix_now_ms(),
        NONCE.fetch_add(1, Ordering::Relaxed)
    ));
    (directory.clone(), directory.join("pam.sqlite3"))
}

fn approval_grant(id: &str, caller: &str) -> PutGrant {
    PutGrant {
        grant: Grant {
            id: GrantId::from(id),
            caller: CallerId::from(caller),
            project: ProjectId::from("pam"),
            capability: capability("runs.rerun"),
            resource: ResourceScope::Any,
            effect: Effect::Allow,
            approval: ApprovalRequirement::Once,
            expires_at_ms: None,
            revoked_at_ms: None,
        },
        created_at_ms: unix_now_ms(),
    }
}

fn authorization_request(
    caller: &str,
    target: &str,
    approval_id: Option<ApprovalId>,
) -> AuthorizationRequest {
    AuthorizationRequest {
        caller_id: CallerId::from(caller),
        project_id: ProjectId::from("pam"),
        capability: capability("runs.rerun"),
        resource: resource(target),
        approval_id,
    }
}

fn stateful_context_with(approval: EffectApproval) -> InvocationContext {
    future_context(Some("rerun-42")).with_effect_approval(approval)
}

struct ApprovalFixture {
    directory: PathBuf,
    store: Store,
    developer_credential: CallerCredential,
    attacker_credential: CallerCredential,
}

impl ApprovalFixture {
    async fn open(name: &str) -> Self {
        let (directory, path) = connector_store_path(name);
        let store = Store::open(path).unwrap();
        let developer_credential = CallerCredential::new("developer credential");
        let attacker_credential = CallerCredential::new("attacker credential");
        for (caller, credential) in [
            ("developer", developer_credential.clone()),
            ("attacker", attacker_credential.clone()),
        ] {
            store
                .register_caller(CallerId::from(caller), credential, unix_now_ms())
                .await
                .unwrap();
        }
        store
            .put_grant(approval_grant("developer-rerun", "developer"))
            .await
            .unwrap();
        store
            .put_grant(approval_grant("attacker-rerun", "attacker"))
            .await
            .unwrap();
        Self {
            directory,
            store,
            developer_credential,
            attacker_credential,
        }
    }

    async fn approved(&self, target: &str, now_ms: u64, ttl_ms: u64) -> ApprovalId {
        let AuthorizationOutcome::ApprovalRequired { approval_id, .. } = self
            .store
            .authorize(
                authorization_request("developer", target, None),
                now_ms,
                ttl_ms,
            )
            .await
            .unwrap()
        else {
            panic!("approval-requiring grant must issue a receipt")
        };
        assert_eq!(
            self.store
                .decide_project_approval(
                    approval_id.clone(),
                    ProjectId::from("pam"),
                    CallerId::from("developer"),
                    ApprovalDecision::Approve,
                    now_ms,
                )
                .await
                .unwrap(),
            ApprovalDecisionOutcome::Approved
        );
        approval_id
    }

    async fn audit_count(&self) -> usize {
        let audit = self
            .store
            .export_audit_events(ProjectId::from("pam"), 0, None, 10)
            .await
            .unwrap();
        assert!(
            audit
                .events
                .iter()
                .all(|event| event.action == "connector.effect.authorize")
        );
        audit.events.len()
    }

    async fn close(self) {
        self.store.shutdown().await.unwrap();
        fs::remove_dir_all(self.directory).unwrap();
    }
}

#[tokio::test]
async fn store_issued_effect_approval_requires_authenticated_bound_identity() {
    let fixture = ApprovalFixture::open("approval-identity").await;
    let request = TestRequest {
        target: "github:ro-ag/pam/runs/42/attempts/1".to_owned(),
    };
    let approval_id = fixture
        .approved(&request.target, unix_now_ms(), 300_000)
        .await;
    assert!(
        fixture
            .store
            .bind_effect_approval(
                CallerId::from("developer"),
                CallerCredential::new("wrong credential"),
                ProjectId::from("pam"),
                approval_id.clone(),
            )
            .await
            .unwrap()
            .is_none()
    );
    let attacker_capability = fixture
        .store
        .bind_effect_approval(
            CallerId::from("attacker"),
            fixture.attacker_credential.clone(),
            ProjectId::from("pam"),
            approval_id,
        )
        .await
        .unwrap()
        .expect("registered attacker must authenticate");

    let connector = FakeConnector::new();
    let context = stateful_context_with(EffectApproval::from_store(attacker_capability));
    assert_eq!(
        connector
            .execute_stateful_effect(&request, &context)
            .await
            .unwrap_err()
            .kind(),
        FailureKind::Forbidden
    );
    assert_eq!(connector.transport_calls.load(Ordering::Relaxed), 0);
    assert_eq!(fixture.audit_count().await, 1);
    fixture.close().await;
}

#[tokio::test]
async fn store_issued_effect_approval_is_coordinate_bound_and_one_use() {
    let fixture = ApprovalFixture::open("approval-coordinates").await;
    let request = TestRequest {
        target: "github:ro-ag/pam/runs/42/attempts/1".to_owned(),
    };
    let approval_id = fixture
        .approved(&request.target, unix_now_ms(), 300_000)
        .await;
    let capability = fixture
        .store
        .bind_effect_approval(
            CallerId::from("developer"),
            fixture.developer_credential.clone(),
            ProjectId::from("pam"),
            approval_id.clone(),
        )
        .await
        .unwrap()
        .expect("registered developer must authenticate");
    let approval = EffectApproval::from_store(capability);
    let connector = FakeConnector::new();
    let wrong_request = TestRequest {
        target: "github:ro-ag/pam/runs/43/attempts/1".to_owned(),
    };
    let wrong_context = stateful_context_with(approval.clone());
    assert_eq!(
        connector
            .execute_stateful_effect(&wrong_request, &wrong_context)
            .await
            .unwrap_err()
            .kind(),
        FailureKind::Forbidden
    );
    assert_eq!(connector.transport_calls.load(Ordering::Relaxed), 0);

    let exact_context = stateful_context_with(approval.clone());
    assert_eq!(
        connector
            .execute_stateful_effect(&request, &exact_context)
            .await
            .unwrap(),
        approval_id
    );
    assert_eq!(connector.transport_calls.load(Ordering::Relaxed), 1);
    let replay_context = stateful_context_with(approval);
    assert_eq!(
        connector
            .execute_stateful_effect(&request, &replay_context)
            .await
            .unwrap_err()
            .kind(),
        FailureKind::Forbidden
    );
    assert_eq!(connector.transport_calls.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.audit_count().await, 3);
    fixture.close().await;
}

#[tokio::test]
async fn store_issued_effect_approval_uses_trusted_time_for_expiry() {
    let fixture = ApprovalFixture::open("approval-expiry").await;
    let request = TestRequest {
        target: "github:ro-ag/pam/runs/42/attempts/1".to_owned(),
    };
    let approval_id = fixture.approved(&request.target, 1, 1).await;
    let capability = fixture
        .store
        .bind_effect_approval(
            CallerId::from("developer"),
            fixture.developer_credential.clone(),
            ProjectId::from("pam"),
            approval_id,
        )
        .await
        .unwrap()
        .expect("registered developer must authenticate");
    let connector = FakeConnector::new();
    let context = stateful_context_with(EffectApproval::from_store(capability));
    assert_eq!(
        connector
            .execute_stateful_effect(&request, &context)
            .await
            .unwrap_err()
            .kind(),
        FailureKind::Forbidden
    );
    assert_eq!(connector.transport_calls.load(Ordering::Relaxed), 0);
    assert_eq!(fixture.audit_count().await, 1);
    fixture.close().await;
}

macro_rules! fake_connector {
    ($operation:ty) => {
        impl Connector<$operation> for FakeConnector {
            fn descriptor(&self) -> ConnectorDescriptor {
                self.descriptor.clone()
            }

            fn execute(
                &self,
                _request: TestRequest,
                context: InvocationContext,
            ) -> ConnectorFuture<'_, super::ConnectorResult<TestResponse>> {
                self.execute::<$operation>(context)
            }
        }
    };
}

fake_connector!(ReadOperation);
fake_connector!(StatefulOperation);
fake_connector!(ReconciledWithoutRemoteIdempotencyOperation);
fake_connector!(MissingReconciliationOperation);

#[test]
fn public_harness_accepts_read_only_and_safe_stateful_connectors_without_transport() {
    let connector = FakeConnector::new();
    let request = TestRequest {
        target: "github:ro-ag/pam/runs/42".to_owned(),
    };
    let read_coordinates = ReadOperation::coordinates(&request);
    block_on(verify_conformance::<_, ReadOperation>(
        &connector,
        request.clone(),
        &connector.descriptor,
        &read_coordinates,
    ))
    .unwrap();

    let stateful_coordinates = StatefulOperation::coordinates(&request);
    block_on(verify_conformance::<_, StatefulOperation>(
        &connector,
        request.clone(),
        &connector.descriptor,
        &stateful_coordinates,
    ))
    .unwrap();

    block_on(verify_conformance::<
        _,
        ReconciledWithoutRemoteIdempotencyOperation,
    >(
        &connector,
        request,
        &connector.descriptor,
        &stateful_coordinates,
    ))
    .unwrap();
    assert_eq!(connector.transport_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn public_harness_rejects_missing_stateful_reconciliation() {
    let connector = FakeConnector::new();
    let request = TestRequest {
        target: "github:ro-ag/pam/runs/42".to_owned(),
    };
    let coordinates = MissingReconciliationOperation::coordinates(&request);
    let result = block_on(verify_conformance::<_, MissingReconciliationOperation>(
        &connector,
        request,
        &connector.descriptor,
        &coordinates,
    ));
    assert_eq!(
        result,
        Err(ConformanceViolation::StatefulReconciliationMissing)
    );
    assert_eq!(connector.transport_calls.load(Ordering::Relaxed), 0);
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}
