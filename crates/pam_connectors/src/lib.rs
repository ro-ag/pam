#![forbid(unsafe_code)]

use std::{
    error::Error,
    fmt,
    future::Future,
    num::NonZeroU32,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub use pam_core::{EvidenceHandle, IdempotencyKey};
pub use pam_policy::{CapabilityName, ResourceName};
use serde::{Serialize, de::DeserializeOwned};

#[cfg(test)]
mod github_test;
#[cfg(test)]
mod lib_test;

pub mod github;

pub const MAX_CONNECTOR_NAME_BYTES: usize = 128;
pub const MAX_CONNECTOR_VERSION_BYTES: usize = 64;
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
pub const MAX_SUMMARY_BYTES: usize = 4 * 1024;
pub const MAX_FAILURE_MESSAGE_BYTES: usize = 1024;
pub const MAX_ARTIFACT_NAME_BYTES: usize = 256;
pub const MAX_EVIDENCE_PAYLOAD_BYTES: usize = 1024 * 1024;
pub const MAX_ARTIFACT_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EVIDENCE_PAYLOADS: usize = 16;
pub const MAX_ARTIFACT_PAYLOADS: usize = 16;

/// Stable identity and implementation version of one connector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConnectorDescriptor {
    name: String,
    version: String,
}

impl ConnectorDescriptor {
    /// Creates a descriptor from a lowercase dotted connector name and a printable version.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid dotted name, an empty version, an oversized value, or
    /// a version containing control characters.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, InvalidBoundedValue> {
        let name = name.into();
        let version = version.into();
        validate_connector_name(&name)?;
        validate_text(&version, MAX_CONNECTOR_VERSION_BYTES, "connector version")?;
        Ok(Self { name, version })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// The policy coordinates selected by a typed operation request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperationCoordinates {
    capability: CapabilityName,
    resource: ResourceName,
}

impl OperationCoordinates {
    #[must_use]
    pub const fn new(capability: CapabilityName, resource: ResourceName) -> Self {
        Self {
            capability,
            resource,
        }
    }

    #[must_use]
    pub const fn capability(&self) -> &CapabilityName {
        &self.capability
    }

    #[must_use]
    pub const fn resource(&self) -> &ResourceName {
        &self.resource
    }
}

/// Connector-side idempotency support declared by a stateful operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum IdempotencyDeclaration {
    Required,
    NotSupported,
}

/// Connector-side reconciliation support declared by a stateful operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ReconciliationDeclaration {
    Required,
    NotSupported,
}

/// Safety declarations required for a stateful operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct StatefulContract {
    idempotency: IdempotencyDeclaration,
    reconciliation: ReconciliationDeclaration,
}

impl StatefulContract {
    #[must_use]
    pub const fn new(
        idempotency: IdempotencyDeclaration,
        reconciliation: ReconciliationDeclaration,
    ) -> Self {
        Self {
            idempotency,
            reconciliation,
        }
    }

    #[must_use]
    pub const fn idempotency(self) -> IdempotencyDeclaration {
        self.idempotency
    }

    #[must_use]
    pub const fn reconciliation(self) -> ReconciliationDeclaration {
        self.reconciliation
    }
}

/// Whether an operation observes remote state or can change it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum OperationEffect {
    ReadOnly,
    Stateful(StatefulContract),
}

/// A serializable typed connector operation.
pub trait Operation: Send + Sync + 'static {
    type Request: DeserializeOwned + Serialize + Send + 'static;
    type Response: Serialize + Send + 'static;

    const EFFECT: OperationEffect;

    /// Selects the canonical policy capability and resource for a validated request.
    fn coordinates(request: &Self::Request) -> OperationCoordinates;
}

/// A clonable cooperative cancellation signal.
#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

impl fmt::Debug for CancellationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CancellationToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

/// Per-attempt controls supplied by PAM to a connector.
#[derive(Clone)]
pub struct InvocationContext {
    deadline: Instant,
    cancellation: CancellationToken,
    attempt: NonZeroU32,
    idempotency_key: Option<IdempotencyKey>,
}

impl InvocationContext {
    /// Creates a bounded invocation context. Deadlines may already have elapsed so callers can
    /// pass them through to the normal connector preflight path.
    ///
    /// # Errors
    ///
    /// Returns an error when `attempt` is zero or the optional idempotency key is not a bounded,
    /// shell-safe ASCII value.
    pub fn new(
        deadline: Instant,
        cancellation: CancellationToken,
        attempt: u32,
        idempotency_key: Option<IdempotencyKey>,
    ) -> Result<Self, InvalidInvocationContext> {
        let attempt = NonZeroU32::new(attempt).ok_or(InvalidInvocationContext::ZeroAttempt)?;
        if let Some(key) = &idempotency_key {
            validate_idempotency_key(key.as_str())?;
        }
        Ok(Self {
            deadline,
            cancellation,
            attempt,
            idempotency_key,
        })
    }

    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    #[must_use]
    pub const fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    #[must_use]
    pub const fn attempt(&self) -> NonZeroU32 {
        self.attempt
    }

    #[must_use]
    pub fn idempotency_key(&self) -> Option<&IdempotencyKey> {
        self.idempotency_key.as_ref()
    }

    #[must_use]
    pub fn remaining(&self) -> Option<Duration> {
        self.deadline.checked_duration_since(Instant::now())
    }

    /// Checks cancellation, deadline, and stateful idempotency requirements before transport use.
    ///
    /// # Errors
    ///
    /// Returns a sanitized connector failure when execution must not begin.
    pub fn preflight(&self, effect: OperationEffect) -> Result<(), ConnectorFailure> {
        if self.cancellation.is_cancelled() {
            return Err(ConnectorFailure::cancelled());
        }
        if self.remaining().is_none() {
            return Err(ConnectorFailure::timeout());
        }
        if matches!(effect, OperationEffect::Stateful(_)) && self.idempotency_key.is_none() {
            return Err(ConnectorFailure::invalid_request(FailureMessage::trusted(
                "stateful operation requires an idempotency key",
            )));
        }
        Ok(())
    }
}

impl fmt::Debug for InvocationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvocationContext")
            .field("deadline", &self.deadline)
            .field("cancellation", &self.cancellation)
            .field("attempt", &self.attempt)
            .field("has_idempotency_key", &self.idempotency_key.is_some())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidInvocationContext {
    ZeroAttempt,
    InvalidIdempotencyKey,
}

impl fmt::Display for InvalidInvocationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroAttempt => formatter.write_str("connector attempt must be at least one"),
            Self::InvalidIdempotencyKey => formatter.write_str(
                "idempotency key must contain 1 to 256 shell-safe ASCII bytes and not start with '-'",
            ),
        }
    }
}

impl Error for InvalidInvocationContext {}

/// A bounded, single-line summary intended for users and audit-safe structured output.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BoundedSummary(String);

impl BoundedSummary {
    /// Creates a nonempty summary without Unicode control characters.
    ///
    /// # Errors
    ///
    /// Returns an error when the summary is empty, oversized, or contains a control character.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidBoundedValue> {
        let value = value.into();
        validate_text(&value, MAX_SUMMARY_BYTES, "summary")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BoundedSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BoundedSummary")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for BoundedSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A bounded exact evidence payload associated with the canonical persisted handle.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ExactEvidence {
    handle: EvidenceHandle,
    bytes: Vec<u8>,
}

impl ExactEvidence {
    /// # Errors
    ///
    /// Returns an error when the exact payload exceeds [`MAX_EVIDENCE_PAYLOAD_BYTES`].
    pub fn new(handle: EvidenceHandle, bytes: Vec<u8>) -> Result<Self, InvalidBoundedValue> {
        validate_payload(bytes.len(), MAX_EVIDENCE_PAYLOAD_BYTES, "evidence payload")?;
        Ok(Self { handle, bytes })
    }

    #[must_use]
    pub const fn handle(&self) -> &EvidenceHandle {
        &self.handle
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for ExactEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactEvidence")
            .field("handle", &self.handle)
            .field("byte_len", &self.bytes.len())
            .finish()
    }
}

/// A bounded named artifact returned by a connector.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ExactArtifact {
    name: String,
    bytes: Vec<u8>,
}

impl ExactArtifact {
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, or control-bearing name, or when the exact
    /// payload exceeds [`MAX_ARTIFACT_PAYLOAD_BYTES`].
    pub fn new(name: impl Into<String>, bytes: Vec<u8>) -> Result<Self, InvalidBoundedValue> {
        let name = name.into();
        validate_text(&name, MAX_ARTIFACT_NAME_BYTES, "artifact name")?;
        validate_payload(bytes.len(), MAX_ARTIFACT_PAYLOAD_BYTES, "artifact payload")?;
        Ok(Self { name, bytes })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for ExactArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactArtifact")
            .field("name", &self.name)
            .field("byte_len", &self.bytes.len())
            .finish()
    }
}

/// Whether a connector result covers the complete requested remote truth.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum Truth {
    Complete,
    Partial { reason: BoundedSummary },
}

impl Truth {
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// A typed connector value plus bounded human summary and exact retained payloads.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ConnectorOutput<T> {
    value: T,
    summary: BoundedSummary,
    truth: Truth,
    evidence: Vec<ExactEvidence>,
    artifacts: Vec<ExactArtifact>,
}

impl<T> ConnectorOutput<T> {
    /// # Errors
    ///
    /// Returns an error when the output contains too many evidence or artifact payloads.
    pub fn new(
        value: T,
        summary: BoundedSummary,
        truth: Truth,
        evidence: Vec<ExactEvidence>,
        artifacts: Vec<ExactArtifact>,
    ) -> Result<Self, InvalidBoundedValue> {
        validate_count(
            evidence.len(),
            MAX_EVIDENCE_PAYLOADS,
            "evidence payload count",
        )?;
        validate_count(
            artifacts.len(),
            MAX_ARTIFACT_PAYLOADS,
            "artifact payload count",
        )?;
        Ok(Self {
            value,
            summary,
            truth,
            evidence,
            artifacts,
        })
    }

    #[must_use]
    pub const fn value(&self) -> &T {
        &self.value
    }

    #[must_use]
    pub const fn summary(&self) -> &BoundedSummary {
        &self.summary
    }

    #[must_use]
    pub const fn truth(&self) -> &Truth {
        &self.truth
    }

    #[must_use]
    pub fn evidence(&self) -> &[ExactEvidence] {
        &self.evidence
    }

    #[must_use]
    pub fn artifacts(&self) -> &[ExactArtifact] {
        &self.artifacts
    }

    #[must_use]
    pub fn into_value(self) -> T {
        self.value
    }
}

/// Sanitized diagnostic text. Its `Debug` representation is always redacted.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct FailureMessage(String);

impl FailureMessage {
    /// Creates caller-sanitized diagnostic text.
    ///
    /// The caller must not pass credentials, authorization headers, raw remote bodies, or other
    /// secrets. The value is omitted from `Debug` output as a defense in depth measure.
    ///
    /// # Errors
    ///
    /// Returns an error when the message is empty, oversized, or contains control characters.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidBoundedValue> {
        let value = value.into();
        validate_text(&value, MAX_FAILURE_MESSAGE_BYTES, "failure message")?;
        Ok(Self(value))
    }

    fn trusted(value: &str) -> Self {
        Self(value.to_owned())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for FailureMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl fmt::Display for FailureMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Stable category used for policy-neutral connector failure handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum FailureKind {
    InvalidRequest,
    Authentication,
    Forbidden,
    NotFound,
    RateLimit,
    Timeout,
    Certificate,
    Network,
    Remote,
    ResponseTooLarge,
    Cancelled,
    UncertainEffect,
}

/// Whether and when the engine may try an operation again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryGuidance {
    Never,
    AfterConfigurationChange,
    AfterBackoff { delay: Option<Duration> },
    ReconcileBeforeRetry,
}

/// A sanitized typed connector failure.
#[derive(Clone, Eq, PartialEq)]
pub struct ConnectorFailure {
    kind: FailureKind,
    message: FailureMessage,
    retry: RetryGuidance,
    response_limit: Option<usize>,
}

impl ConnectorFailure {
    #[must_use]
    pub fn invalid_request(message: FailureMessage) -> Self {
        Self::new(FailureKind::InvalidRequest, message, RetryGuidance::Never)
    }

    #[must_use]
    pub fn authentication(message: FailureMessage) -> Self {
        Self::new(
            FailureKind::Authentication,
            message,
            RetryGuidance::AfterConfigurationChange,
        )
    }

    #[must_use]
    pub fn forbidden(message: FailureMessage) -> Self {
        Self::new(FailureKind::Forbidden, message, RetryGuidance::Never)
    }

    #[must_use]
    pub fn not_found(message: FailureMessage) -> Self {
        Self::new(FailureKind::NotFound, message, RetryGuidance::Never)
    }

    #[must_use]
    pub fn rate_limit(message: FailureMessage, retry_after: Option<Duration>) -> Self {
        Self::new(
            FailureKind::RateLimit,
            message,
            RetryGuidance::AfterBackoff { delay: retry_after },
        )
    }

    #[must_use]
    pub fn timeout() -> Self {
        Self::new(
            FailureKind::Timeout,
            FailureMessage::trusted("connector deadline elapsed"),
            RetryGuidance::AfterBackoff { delay: None },
        )
    }

    #[must_use]
    pub fn certificate(message: FailureMessage) -> Self {
        Self::new(
            FailureKind::Certificate,
            message,
            RetryGuidance::AfterConfigurationChange,
        )
    }

    #[must_use]
    pub fn network(message: FailureMessage) -> Self {
        Self::new(
            FailureKind::Network,
            message,
            RetryGuidance::AfterBackoff { delay: None },
        )
    }

    #[must_use]
    pub fn remote(message: FailureMessage, retryable: bool) -> Self {
        let retry = if retryable {
            RetryGuidance::AfterBackoff { delay: None }
        } else {
            RetryGuidance::Never
        };
        Self::new(FailureKind::Remote, message, retry)
    }

    #[must_use]
    pub fn response_too_large(limit: usize) -> Self {
        let mut failure = Self::new(
            FailureKind::ResponseTooLarge,
            FailureMessage::trusted("remote response exceeded the configured byte limit"),
            RetryGuidance::Never,
        );
        failure.response_limit = Some(limit);
        failure
    }

    #[must_use]
    pub fn cancelled() -> Self {
        Self::new(
            FailureKind::Cancelled,
            FailureMessage::trusted("connector invocation was cancelled"),
            RetryGuidance::Never,
        )
    }

    #[must_use]
    pub fn uncertain_effect(message: FailureMessage) -> Self {
        Self::new(
            FailureKind::UncertainEffect,
            message,
            RetryGuidance::ReconcileBeforeRetry,
        )
    }

    fn new(kind: FailureKind, message: FailureMessage, retry: RetryGuidance) -> Self {
        Self {
            kind,
            message,
            retry,
            response_limit: None,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> FailureKind {
        self.kind
    }

    #[must_use]
    pub const fn message(&self) -> &FailureMessage {
        &self.message
    }

    #[must_use]
    pub const fn retry_guidance(&self) -> RetryGuidance {
        self.retry
    }

    #[must_use]
    pub const fn response_limit(&self) -> Option<usize> {
        self.response_limit
    }
}

impl fmt::Debug for ConnectorFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectorFailure")
            .field("kind", &self.kind)
            .field("message", &self.message)
            .field("retry", &self.retry)
            .field("response_limit", &self.response_limit)
            .finish()
    }
}

impl fmt::Display for ConnectorFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.message)
    }
}

impl Error for ConnectorFailure {}

pub type ConnectorResult<T> = Result<ConnectorOutput<T>, ConnectorFailure>;
pub type ConnectorFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A connector implementation for one typed operation.
pub trait Connector<O: Operation>: Send + Sync {
    /// Returns stable connector coordinates. Implementations must not vary this per invocation.
    fn descriptor(&self) -> ConnectorDescriptor;

    /// Executes a typed request. Implementations must call [`InvocationContext::preflight`]
    /// before acquiring credentials or performing transport I/O.
    fn execute(
        &self,
        request: O::Request,
        context: InvocationContext,
    ) -> ConnectorFuture<'_, ConnectorResult<O::Response>>;
}

/// A precise connector contract violation suitable for unit-test output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConformanceViolation {
    DescriptorChanged,
    DescriptorMismatch,
    CoordinatesChanged,
    CoordinatesMismatch,
    StatefulReconciliationMissing,
    CancellationNotHonored,
    DeadlineNotHonored,
    BoundsContractBroken,
    RetryContractBroken,
}

impl fmt::Display for ConformanceViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::DescriptorChanged => "connector descriptor changed between reads",
            Self::DescriptorMismatch => "connector descriptor did not match expected coordinates",
            Self::CoordinatesChanged => "operation coordinates changed for the same request",
            Self::CoordinatesMismatch => "operation coordinates did not match expected values",
            Self::StatefulReconciliationMissing => {
                "stateful operation does not require uncertain-effect reconciliation"
            }
            Self::CancellationNotHonored => {
                "connector did not reject a pre-cancelled invocation as cancelled"
            }
            Self::DeadlineNotHonored => {
                "connector did not reject an expired invocation as timed out"
            }
            Self::BoundsContractBroken => "an SDK bounded constructor accepted invalid input",
            Self::RetryContractBroken => "a connector failure had unsafe retry guidance",
        };
        formatter.write_str(message)
    }
}

impl Error for ConformanceViolation {}

/// Runs the reusable connector contract without making a live request.
///
/// The connector is invoked only with pre-cancelled and already-expired contexts. A conforming
/// implementation returns from preflight before acquiring credentials or performing network I/O.
/// The request is otherwise used only to check stable policy coordinates.
///
/// # Errors
///
/// Returns the first descriptor, coordinate, effect declaration, cancellation, deadline, bounds,
/// or retry-classification violation.
pub async fn verify_conformance<C, O>(
    connector: &C,
    request: O::Request,
    expected_descriptor: &ConnectorDescriptor,
    expected_coordinates: &OperationCoordinates,
) -> Result<(), ConformanceViolation>
where
    C: Connector<O>,
    O: Operation,
    O::Request: Clone,
{
    let first_descriptor = connector.descriptor();
    let second_descriptor = connector.descriptor();
    if first_descriptor != second_descriptor {
        return Err(ConformanceViolation::DescriptorChanged);
    }
    if &first_descriptor != expected_descriptor {
        return Err(ConformanceViolation::DescriptorMismatch);
    }

    let first_coordinates = O::coordinates(&request);
    let second_coordinates = O::coordinates(&request);
    if first_coordinates != second_coordinates {
        return Err(ConformanceViolation::CoordinatesChanged);
    }
    if &first_coordinates != expected_coordinates {
        return Err(ConformanceViolation::CoordinatesMismatch);
    }

    verify_effect_contract(O::EFFECT)?;
    verify_bounds_contract()?;
    verify_retry_contract()?;

    let idempotency_key = matches!(O::EFFECT, OperationEffect::Stateful(_))
        .then(|| IdempotencyKey::from("pam-conformance-attempt"));

    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let cancelled_context = InvocationContext::new(
        Instant::now() + Duration::from_mins(1),
        cancellation,
        1,
        idempotency_key.clone(),
    )
    .map_err(|_| ConformanceViolation::BoundsContractBroken)?;
    let cancelled = connector.execute(request.clone(), cancelled_context).await;
    if !matches!(
        cancelled,
        Err(ref failure) if failure.kind() == FailureKind::Cancelled
    ) {
        return Err(ConformanceViolation::CancellationNotHonored);
    }

    let expired = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);
    let deadline_context =
        InvocationContext::new(expired, CancellationToken::new(), 1, idempotency_key)
            .map_err(|_| ConformanceViolation::BoundsContractBroken)?;
    let timed_out = connector.execute(request, deadline_context).await;
    if !matches!(
        timed_out,
        Err(ref failure) if failure.kind() == FailureKind::Timeout
    ) {
        return Err(ConformanceViolation::DeadlineNotHonored);
    }

    Ok(())
}

fn verify_effect_contract(effect: OperationEffect) -> Result<(), ConformanceViolation> {
    let OperationEffect::Stateful(contract) = effect else {
        return Ok(());
    };
    if contract.reconciliation() != ReconciliationDeclaration::Required {
        return Err(ConformanceViolation::StatefulReconciliationMissing);
    }
    Ok(())
}

fn verify_bounds_contract() -> Result<(), ConformanceViolation> {
    let oversized_summary = "x".repeat(MAX_SUMMARY_BYTES + 1);
    if BoundedSummary::new(oversized_summary).is_ok()
        || BoundedSummary::new("line\nbreak").is_ok()
        || FailureMessage::new("remote\rbody").is_ok()
        || ConnectorDescriptor::new("Invalid.Connector", "1").is_ok()
        || ExactArtifact::new("bad\0name", Vec::new()).is_ok()
        || ExactArtifact::new(
            "large",
            vec![0_u8; MAX_ARTIFACT_PAYLOAD_BYTES.saturating_add(1)],
        )
        .is_ok()
    {
        return Err(ConformanceViolation::BoundsContractBroken);
    }

    let handle = EvidenceHandle::parse("evidence://pam/conformance")
        .map_err(|_| ConformanceViolation::BoundsContractBroken)?;
    if ExactEvidence::new(
        handle.clone(),
        vec![0_u8; MAX_EVIDENCE_PAYLOAD_BYTES.saturating_add(1)],
    )
    .is_ok()
    {
        return Err(ConformanceViolation::BoundsContractBroken);
    }
    let evidence = (0..=MAX_EVIDENCE_PAYLOADS)
        .map(|_| ExactEvidence::new(handle.clone(), Vec::new()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ConformanceViolation::BoundsContractBroken)?;
    let summary = BoundedSummary::new("conformance")
        .map_err(|_| ConformanceViolation::BoundsContractBroken)?;
    if ConnectorOutput::new((), summary, Truth::Complete, evidence, Vec::new()).is_ok() {
        return Err(ConformanceViolation::BoundsContractBroken);
    }

    Ok(())
}

fn verify_retry_contract() -> Result<(), ConformanceViolation> {
    let message =
        FailureMessage::new("sanitized").map_err(|_| ConformanceViolation::BoundsContractBroken)?;
    let never = RetryGuidance::Never;
    let config = RetryGuidance::AfterConfigurationChange;
    let retry = RetryGuidance::AfterBackoff { delay: None };
    let expected = [
        (ConnectorFailure::invalid_request(message.clone()), never),
        (ConnectorFailure::authentication(message.clone()), config),
        (ConnectorFailure::forbidden(message.clone()), never),
        (ConnectorFailure::not_found(message.clone()), never),
        (ConnectorFailure::rate_limit(message.clone(), None), retry),
        (ConnectorFailure::timeout(), retry),
        (ConnectorFailure::certificate(message.clone()), config),
        (ConnectorFailure::network(message.clone()), retry),
        (ConnectorFailure::remote(message.clone(), true), retry),
        (ConnectorFailure::remote(message.clone(), false), never),
        (ConnectorFailure::response_too_large(1), never),
        (ConnectorFailure::cancelled(), never),
        (
            ConnectorFailure::uncertain_effect(message),
            RetryGuidance::ReconcileBeforeRetry,
        ),
    ];
    if expected
        .iter()
        .any(|(failure, guidance)| failure.retry_guidance() != *guidance)
    {
        return Err(ConformanceViolation::RetryContractBroken);
    }
    Ok(())
}

fn validate_connector_name(value: &str) -> Result<(), InvalidBoundedValue> {
    if value.is_empty() || value.len() > MAX_CONNECTOR_NAME_BYTES {
        return Err(InvalidBoundedValue::new(
            "connector name",
            MAX_CONNECTOR_NAME_BYTES,
        ));
    }
    let valid = value.split('.').all(|segment| {
        !segment.is_empty()
            && segment.as_bytes()[0].is_ascii_lowercase()
            && segment.as_bytes()[segment.len() - 1].is_ascii_alphanumeric()
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    });
    if !valid {
        return Err(InvalidBoundedValue::new(
            "connector name",
            MAX_CONNECTOR_NAME_BYTES,
        ));
    }
    Ok(())
}

fn validate_idempotency_key(value: &str) -> Result<(), InvalidInvocationContext> {
    if value.is_empty()
        || value.len() > MAX_IDEMPOTENCY_KEY_BYTES
        || value.starts_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(InvalidInvocationContext::InvalidIdempotencyKey);
    }
    Ok(())
}

fn validate_text(
    value: &str,
    limit: usize,
    field: &'static str,
) -> Result<(), InvalidBoundedValue> {
    if value.is_empty() || value.len() > limit || value.chars().any(char::is_control) {
        return Err(InvalidBoundedValue::new(field, limit));
    }
    Ok(())
}

fn validate_payload(
    length: usize,
    limit: usize,
    field: &'static str,
) -> Result<(), InvalidBoundedValue> {
    if length > limit {
        return Err(InvalidBoundedValue::new(field, limit));
    }
    Ok(())
}

fn validate_count(
    count: usize,
    limit: usize,
    field: &'static str,
) -> Result<(), InvalidBoundedValue> {
    if count > limit {
        return Err(InvalidBoundedValue::new(field, limit));
    }
    Ok(())
}

/// A sanitized constructor error that never includes the rejected value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidBoundedValue {
    field: &'static str,
    limit: usize,
}

impl InvalidBoundedValue {
    const fn new(field: &'static str, limit: usize) -> Self {
        Self { field, limit }
    }

    #[must_use]
    pub const fn field(self) -> &'static str {
        self.field
    }

    #[must_use]
    pub const fn limit(self) -> usize {
        self.limit
    }
}

impl fmt::Display for InvalidBoundedValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} must be nonempty, control-free, and within its {} byte/item limit",
            self.field, self.limit
        )
    }
}

impl Error for InvalidBoundedValue {}
