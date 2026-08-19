use std::{error::Error, fmt};

use pam_core::{
    CallerCredential, CallerId, ContentDigest, EvidenceHandle, IdempotencyKey, ProjectId, RequestId,
};
use serde::{Deserialize, Serialize};

use crate::{MAX_EVIDENCE_CHUNK_SIZE, PROTOCOL_VERSION};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequestEnvelope {
    pub protocol_version: u16,
    pub request_id: RequestId,
    pub caller_id: CallerId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<CallerCredential>,
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
            project_id,
            capability: Capability::Brief,
            idempotency_key,
            deadline_unix_ms: None,
            payload: RequestPayload::Brief,
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
    WaitForResult,
    GetResult,
    InspectEvidence,
    ReadEvidence,
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
    EvidenceMetadata(EvidenceMetadata),
    EvidenceChunk(EvidenceChunk),
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
        }
    }
}

impl Error for ProtocolContractError {}

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Failure {
    pub code: FailureCode,
    pub message: String,
    pub recovery: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    Unauthenticated,
    UnsupportedProtocolVersion,
    InvalidRequest,
    FrameTooLarge,
    NotFound,
    Pending,
    IdempotencyConflict,
    Cancelled,
    LeaseConflict,
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
