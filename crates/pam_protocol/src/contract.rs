use std::{error::Error, fmt};

use pam_core::{
    ApprovalId, CallerCredential, CallerId, ContentDigest, EvidenceHandle, IdempotencyKey,
    ProjectId, RequestId,
};
use serde::{Deserialize, Serialize};

use crate::{
    MAX_EVIDENCE_CHUNK_SIZE, MAX_MODEL_MESSAGE_BYTES, MAX_MODEL_MESSAGES, MAX_MODEL_OUTPUT_BYTES,
    MAX_MODEL_OUTPUT_TOKENS, MAX_MODEL_PROMPT_BYTES, PROTOCOL_VERSION,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequestEnvelope {
    pub protocol_version: u16,
    pub request_id: RequestId,
    pub caller_id: CallerId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<CallerCredential>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<ApprovalId>,
    pub project_id: ProjectId,
    pub capability: Capability,
    pub idempotency_key: IdempotencyKey,
    pub deadline_unix_ms: Option<u64>,
    pub payload: RequestPayload,
}

impl RequestEnvelope {
    #[must_use]
    pub fn status(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::DaemonStatus,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::Status,
        }
    }

    /// Creates a cancellation request for `target_request_id`.
    ///
    /// The envelope's `request_id` identifies and correlates this cancellation
    /// operation. The target remains separately identified in the payload so a
    /// response to the observer is never mistaken for the target's result.
    #[must_use]
    pub fn cancel(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
        target_request_id: RequestId,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::CancelRequest,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::Cancel { target_request_id },
        }
    }

    /// Creates an event replay request for `target_request_id`.
    ///
    /// The envelope's `request_id` correlates the replay operation, while
    /// replayed event and terminal result envelopes retain the target request's
    /// identity. Callers may deliberately use the target ID as the observer ID
    /// when reconnecting to the original request. `after_sequence` is exclusive.
    #[must_use]
    pub fn replay(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
        target_request_id: RequestId,
        after_sequence: u64,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::ReplayEvents,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::Replay {
                target_request_id,
                after_sequence,
            },
        }
    }

    /// Creates a read-only request for a compact continuity brief.
    #[must_use]
    pub fn brief(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::Brief,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::Brief,
        }
    }

    /// Creates an authenticated, policy-gated read-only network diagnostics request.
    #[must_use]
    pub fn network_diagnostics(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::NetworkDiagnostics,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::NetworkDiagnostics,
        }
    }

    /// Creates an authenticated, policy-gated request for direct embedded inference.
    ///
    /// # Errors
    ///
    /// Returns a contract error when the model identity, chat messages, prompt byte
    /// budget, output-token bound, or absolute deadline is invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn model_infer(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
        model: impl Into<String>,
        messages: Vec<ModelMessage>,
        max_output_tokens: u32,
        deadline_unix_ms: u64,
    ) -> Result<Self, ProtocolContractError> {
        let model = model.into();
        validate_model_generation(&model, &messages, max_output_tokens)?;
        validate_model_deadline(Some(deadline_unix_ms))?;
        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::ModelInfer,
            idempotency_key,
            deadline_unix_ms: Some(deadline_unix_ms),
            payload: RequestPayload::ModelInfer {
                model,
                messages,
                max_output_tokens,
            },
        })
    }

    /// Revalidates the bounded direct-inference payload after deserialization.
    ///
    /// # Errors
    ///
    /// Returns a contract error for a malformed or over-budget model request.
    pub fn validate_model_request(&self) -> Result<(), ProtocolContractError> {
        match &self.payload {
            RequestPayload::ModelInfer {
                model,
                messages,
                max_output_tokens,
                ..
            } => {
                validate_model_generation(model, messages, *max_output_tokens)?;
                validate_model_deadline(self.deadline_unix_ms)
            }
            _ => Ok(()),
        }
    }

    /// Creates a read-only wait request for `target_request_id`.
    ///
    /// The envelope ID correlates this observer operation. Replayed events retain
    /// the target ID, while the terminal [`ResultEnvelope`] uses the observer ID
    /// with the target's original persisted [`ResultBody`] unchanged.
    #[must_use]
    pub fn wait_for_result(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
        target_request_id: RequestId,
        after_sequence: u64,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::WaitForResult,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::WaitForResult {
                target_request_id,
                after_sequence,
            },
        }
    }

    /// Creates a non-blocking read of a target request's terminal result.
    ///
    /// A completed target's original persisted [`ResultBody`] is returned in an
    /// envelope correlated to this observer request. Pending and missing targets
    /// use [`FailureCode::Pending`] and [`FailureCode::NotFound`], respectively.
    #[must_use]
    pub fn get_result(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
        target_request_id: RequestId,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::GetResult,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::GetResult { target_request_id },
        }
    }

    /// Creates a read-only metadata lookup for an exact evidence handle.
    #[must_use]
    pub fn inspect_evidence(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
        handle: EvidenceHandle,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::InspectEvidence,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::InspectEvidence { handle },
        }
    }

    /// Creates a bounded exact-evidence range request.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolContractError::InvalidEvidenceReadLength`] when `length`
    /// is zero or exceeds [`MAX_EVIDENCE_CHUNK_SIZE`].
    pub fn read_evidence(
        request_id: RequestId,
        caller_id: CallerId,
        project_id: ProjectId,
        idempotency_key: IdempotencyKey,
        handle: EvidenceHandle,
        offset: u64,
        length: u64,
    ) -> Result<Self, ProtocolContractError> {
        validate_evidence_read_length(length)?;
        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_id,
            authentication: None,
            approval_id: None,
            project_id,
            capability: Capability::ReadEvidence,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::ReadEvidence {
                handle,
                offset,
                length,
            },
        })
    }

    /// Attaches the revocable caller credential used to authenticate this request.
    #[must_use]
    pub fn authenticated(mut self, credential: CallerCredential) -> Self {
        self.authentication = Some(credential);
        self
    }

    /// Attaches a previously approved exact-effect receipt for one-time use.
    #[must_use]
    pub fn with_approval(mut self, approval_id: ApprovalId) -> Self {
        self.approval_id = Some(approval_id);
        self
    }

    #[must_use]
    pub fn unsupported_version_failure(&self) -> Option<ResultEnvelope> {
        (self.protocol_version != PROTOCOL_VERSION).then(|| ResultEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: self.request_id.clone(),
            project_id: self.project_id.clone(),
            body: ResultBody::Failure(Failure {
                code: FailureCode::UnsupportedProtocolVersion,
                message: format!(
                    "protocol version {} is unsupported; this daemon supports version {PROTOCOL_VERSION}",
                    self.protocol_version
                ),
                recovery: None,
                approval: None,
            }),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    DaemonStatus,
    CancelRequest,
    ReplayEvents,
    Brief,
    NetworkDiagnostics,
    WaitForResult,
    GetResult,
    InspectEvidence,
    ReadEvidence,
    ModelInfer,
}

impl Capability {
    #[must_use]
    pub const fn policy_name(&self) -> &'static str {
        match self {
            Self::DaemonStatus => "daemon.status",
            Self::CancelRequest => "request.cancel",
            Self::ReplayEvents => "request.replay",
            Self::Brief => "brief.read",
            Self::NetworkDiagnostics => "network.diagnostics",
            Self::WaitForResult => "request.wait",
            Self::GetResult => "request.result.read",
            Self::InspectEvidence => "evidence.inspect",
            Self::ReadEvidence => "evidence.read",
            Self::ModelInfer => "model.infer",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RequestPayload {
    Status,
    Cancel {
        target_request_id: RequestId,
    },
    Replay {
        target_request_id: RequestId,
        after_sequence: u64,
    },
    Brief,
    NetworkDiagnostics,
    WaitForResult {
        target_request_id: RequestId,
        after_sequence: u64,
    },
    GetResult {
        target_request_id: RequestId,
    },
    InspectEvidence {
        handle: EvidenceHandle,
    },
    ReadEvidence {
        handle: EvidenceHandle,
        offset: u64,
        #[serde(deserialize_with = "deserialize_evidence_read_length")]
        length: u64,
    },
    ModelInfer {
        model: String,
        messages: Vec<ModelMessage>,
        max_output_tokens: u32,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResultEnvelope {
    pub protocol_version: u16,
    pub request_id: RequestId,
    pub project_id: ProjectId,
    pub body: ResultBody,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResultBody {
    Success {
        truth: OperationTruth,
        payload: ResultPayload,
    },
    Failure(Failure),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationTruth {
    Observed,
    Changed,
    Verified,
    Unresolved,
    Blocked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResultPayload {
    Status(StatusResult),
    Cancellation(CancellationResult),
    Replay(ReplayResult),
    Brief(BriefResult),
    NetworkDiagnostics(NetworkDiagnosticsResult),
    EvidenceMetadata(EvidenceMetadata),
    EvidenceChunk(EvidenceChunk),
    ModelGeneration(ModelGenerationResult),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRole {
    System,
    User,
    Assistant,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ModelMessage {
    role: ModelRole,
    content: String,
}

impl<'de> Deserialize<'de> for ModelMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Fields {
            role: ModelRole,
            content: String,
        }

        let fields = Fields::deserialize(deserializer)?;
        Self::new(fields.role, fields.content).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for ModelMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelMessage")
            .field("role", &self.role)
            .field("content_bytes", &self.content.len())
            .finish()
    }
}

impl ModelMessage {
    /// Creates one bounded text-only chat message.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolContractError::InvalidModelMessage`] for empty or
    /// over-budget content.
    pub fn new(role: ModelRole, content: impl Into<String>) -> Result<Self, ProtocolContractError> {
        let content = content.into();
        validate_model_message(&content)?;
        Ok(Self { role, content })
    }

    #[must_use]
    pub const fn role(&self) -> ModelRole {
        self.role
    }

    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelFinishReason {
    Stop,
    Length,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelUsage {
    pub input_tokens: u32,
    pub sampled_output_tokens: u32,
    pub emitted_output_tokens: u32,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ModelGenerationResult {
    pub model: String,
    text: String,
    pub finish_reason: ModelFinishReason,
    pub usage: ModelUsage,
}

impl<'de> Deserialize<'de> for ModelGenerationResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Fields {
            model: String,
            text: String,
            finish_reason: ModelFinishReason,
            usage: ModelUsage,
        }

        let fields = Fields::deserialize(deserializer)?;
        Self::new(
            fields.model,
            fields.text,
            fields.finish_reason,
            fields.usage,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for ModelGenerationResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelGenerationResult")
            .field("model", &self.model)
            .field("text_bytes", &self.text.len())
            .field("finish_reason", &self.finish_reason)
            .field("usage", &self.usage)
            .finish()
    }
}

impl ModelGenerationResult {
    /// Creates one bounded direct-runtime result for protocol transport.
    ///
    /// # Errors
    ///
    /// Returns an error when the model identity or output byte bound is invalid.
    pub fn new(
        model: impl Into<String>,
        text: impl Into<String>,
        finish_reason: ModelFinishReason,
        usage: ModelUsage,
    ) -> Result<Self, ProtocolContractError> {
        let model = model.into();
        let text = text.into();
        validate_model_id(&model)?;
        if text.len() > MAX_MODEL_OUTPUT_BYTES {
            return Err(ProtocolContractError::ModelOutputTooLarge {
                actual: text.len(),
                maximum: MAX_MODEL_OUTPUT_BYTES,
            });
        }
        Ok(Self {
            model,
            text,
            finish_reason,
            usage,
        })
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// A compact continuity snapshot in stable presentation order.
///
/// Every entry carries an explicit truth classification. `provenance` records
/// source availability so unavailable context cannot be mistaken for an empty or
/// verified source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BriefResult {
    pub goal: Option<BriefItem>,
    pub decisions: Vec<BriefItem>,
    pub verified: Vec<BriefItem>,
    pub next: Vec<BriefItem>,
    pub provenance: Vec<BriefProvenance>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BriefItem {
    pub text: String,
    pub truth: OperationTruth,
    pub evidence: Vec<EvidenceHandle>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BriefProvenance {
    pub source: String,
    pub availability: SourceAvailability,
    pub truth: OperationTruth,
    pub evidence: Option<EvidenceHandle>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceAvailability {
    Available,
    Partial,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceMetadata {
    pub handle: EvidenceHandle,
    pub digest: ContentDigest,
    pub size_bytes: u64,
    pub media_type: String,
    pub retention: EvidenceRetention,
    pub redaction: EvidenceRedaction,
    pub created_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRetention {
    Session,
    Project,
    Persistent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRedaction {
    Unredacted,
    Redacted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceChunk {
    pub handle: EvidenceHandle,
    pub offset: u64,
    #[serde(deserialize_with = "deserialize_evidence_chunk_bytes")]
    bytes: Vec<u8>,
    pub eof: bool,
}

impl EvidenceChunk {
    /// Creates a bounded exact-evidence response chunk.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolContractError::EvidenceChunkTooLarge`] when `bytes`
    /// exceeds [`MAX_EVIDENCE_CHUNK_SIZE`]. Empty chunks are valid at EOF.
    pub fn new(
        handle: EvidenceHandle,
        offset: u64,
        bytes: Vec<u8>,
        eof: bool,
    ) -> Result<Self, ProtocolContractError> {
        if bytes.len() > MAX_EVIDENCE_CHUNK_SIZE {
            return Err(ProtocolContractError::EvidenceChunkTooLarge {
                actual: bytes.len(),
                maximum: MAX_EVIDENCE_CHUNK_SIZE,
            });
        }
        Ok(Self {
            handle,
            offset,
            bytes,
            eof,
        })
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolContractError {
    InvalidEvidenceReadLength { actual: u64, maximum: u64 },
    EvidenceChunkTooLarge { actual: usize, maximum: usize },
    InvalidModelIdentity,
    InvalidModelMessage,
    InvalidModelConversation,
    InvalidModelDeadline,
    ModelPromptTooLarge { actual: usize, maximum: usize },
    InvalidModelOutputTokens { actual: u32, maximum: u32 },
    ModelOutputTooLarge { actual: usize, maximum: usize },
}

impl fmt::Display for ProtocolContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEvidenceReadLength { actual, maximum } => write!(
                formatter,
                "evidence read length is {actual}; it must be between 1 and {maximum} bytes"
            ),
            Self::EvidenceChunkTooLarge { actual, maximum } => write!(
                formatter,
                "evidence chunk is {actual} bytes; maximum is {maximum}"
            ),
            Self::InvalidModelIdentity => {
                formatter.write_str("model identity must use bounded vendor/name form")
            }
            Self::InvalidModelMessage => write!(
                formatter,
                "model messages must contain 1 to {MAX_MODEL_MESSAGE_BYTES} bytes"
            ),
            Self::InvalidModelConversation => write!(
                formatter,
                "model conversations must contain 1 to {MAX_MODEL_MESSAGES} messages and end with a user message"
            ),
            Self::InvalidModelDeadline => {
                formatter.write_str("model inference requires a positive absolute deadline")
            }
            Self::ModelPromptTooLarge { actual, maximum } => write!(
                formatter,
                "model prompt is {actual} bytes; maximum is {maximum} bytes"
            ),
            Self::InvalidModelOutputTokens { actual, maximum } => write!(
                formatter,
                "model output token bound is {actual}; it must be between 1 and {maximum}"
            ),
            Self::ModelOutputTooLarge { actual, maximum } => write!(
                formatter,
                "model output is {actual} bytes; maximum is {maximum} bytes"
            ),
        }
    }
}

impl Error for ProtocolContractError {}

fn validate_model_generation(
    model: &str,
    messages: &[ModelMessage],
    max_output_tokens: u32,
) -> Result<(), ProtocolContractError> {
    validate_model_id(model)?;
    if messages.is_empty()
        || messages.len() > MAX_MODEL_MESSAGES
        || messages.last().map(ModelMessage::role) != Some(ModelRole::User)
    {
        return Err(ProtocolContractError::InvalidModelConversation);
    }
    let mut total = 0_usize;
    for message in messages {
        validate_model_message(message.content())?;
        total = total.checked_add(message.content().len()).ok_or(
            ProtocolContractError::ModelPromptTooLarge {
                actual: usize::MAX,
                maximum: MAX_MODEL_PROMPT_BYTES,
            },
        )?;
        if total > MAX_MODEL_PROMPT_BYTES {
            return Err(ProtocolContractError::ModelPromptTooLarge {
                actual: total,
                maximum: MAX_MODEL_PROMPT_BYTES,
            });
        }
    }
    if max_output_tokens == 0 || max_output_tokens > MAX_MODEL_OUTPUT_TOKENS {
        return Err(ProtocolContractError::InvalidModelOutputTokens {
            actual: max_output_tokens,
            maximum: MAX_MODEL_OUTPUT_TOKENS,
        });
    }
    Ok(())
}

fn validate_model_deadline(deadline_unix_ms: Option<u64>) -> Result<(), ProtocolContractError> {
    if deadline_unix_ms.is_some_and(|deadline| deadline > 0) {
        Ok(())
    } else {
        Err(ProtocolContractError::InvalidModelDeadline)
    }
}

fn validate_model_message(content: &str) -> Result<(), ProtocolContractError> {
    if content.is_empty() || content.len() > MAX_MODEL_MESSAGE_BYTES || content.contains('\0') {
        Err(ProtocolContractError::InvalidModelMessage)
    } else {
        Ok(())
    }
}

fn validate_model_id(model: &str) -> Result<(), ProtocolContractError> {
    let Some((vendor, name)) = model.split_once('/') else {
        return Err(ProtocolContractError::InvalidModelIdentity);
    };
    if name.contains('/') || !valid_model_segment(vendor) || !valid_model_segment(name) {
        return Err(ProtocolContractError::InvalidModelIdentity);
    }
    Ok(())
}

fn valid_model_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn validate_evidence_read_length(length: u64) -> Result<(), ProtocolContractError> {
    let maximum = MAX_EVIDENCE_CHUNK_SIZE as u64;
    if length == 0 || length > maximum {
        return Err(ProtocolContractError::InvalidEvidenceReadLength {
            actual: length,
            maximum,
        });
    }
    Ok(())
}

fn deserialize_evidence_read_length<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let length = u64::deserialize(deserializer)?;
    validate_evidence_read_length(length).map_err(serde::de::Error::custom)?;
    Ok(length)
}

fn deserialize_evidence_chunk_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    if bytes.len() > MAX_EVIDENCE_CHUNK_SIZE {
        return Err(serde::de::Error::custom(
            ProtocolContractError::EvidenceChunkTooLarge {
                actual: bytes.len(),
                maximum: MAX_EVIDENCE_CHUNK_SIZE,
            },
        ));
    }
    Ok(bytes)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CancellationResult {
    pub target_request_id: RequestId,
    pub disposition: CancellationDisposition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationDisposition {
    Requested,
    AlreadyCancelled,
    AlreadyTerminal,
}

/// Snapshot returned after replaying all available events after the requested sequence.
///
/// `pending` is true when the target has no stored terminal result yet. For a
/// terminal target, the daemon can replay the original stored [`ResultEnvelope`]
/// after its events; that envelope remains correlated to `target_request_id`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayResult {
    pub target_request_id: RequestId,
    pub through_sequence: u64,
    pub pending: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StatusResult {
    pub ready: bool,
    pub healthy: bool,
    pub daemon_version: String,
    pub protocol_version: u16,
    pub queue_depth: u64,
}

/// Sanitized network configuration facts safe to return across the caller boundary.
///
/// The contract deliberately cannot carry proxy URLs, hosts, usernames, or
/// free-form backend diagnostics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkDiagnosticsResult {
    pub platform_roots_enabled: bool,
    pub system_proxy_discovery_enabled: bool,
    pub proxy_environment_presence: ConfigurationPresence,
    pub no_proxy_presence: ConfigurationPresence,
    pub pac_state: PacState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationPresence {
    NotConfigured,
    Configured,
    Invalid,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacState {
    NotDetected,
    DetectedUnsupported,
    InspectionUnavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Failure {
    pub code: FailureCode,
    pub message: String,
    pub recovery: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalChallenge>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApprovalChallenge {
    pub approval_id: ApprovalId,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    Unauthenticated,
    Forbidden,
    ApprovalRequired,
    ApprovalDenied,
    ApprovalExpired,
    UnsupportedProtocolVersion,
    InvalidRequest,
    FrameTooLarge,
    NotFound,
    Pending,
    IdempotencyConflict,
    Cancelled,
    LeaseConflict,
    Busy,
    Internal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventEnvelope {
    pub protocol_version: u16,
    pub request_id: RequestId,
    pub project_id: ProjectId,
    pub sequence: u64,
    pub event: Event,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Accepted,
    Started,
    LeaseExpired,
    CancellationRequested,
    Cancelled,
    Completed,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "message_type", rename_all = "snake_case")]
pub enum ServerMessage {
    Event(EventEnvelope),
    Result(ResultEnvelope),
}

impl ServerMessage {
    #[must_use]
    pub fn protocol_version(&self) -> u16 {
        match self {
            Self::Event(envelope) => envelope.protocol_version,
            Self::Result(envelope) => envelope.protocol_version,
        }
    }
}
