use std::{error::Error, fmt};

use pam_core::{
    ApprovalId, CallerId, ContentDigest, EvidenceHandle, GrantId, ProjectId, RequestId,
};
use pam_skills::{AgentArtifactId, ScanDiagnostic};

#[derive(Debug)]
pub enum StoreError {
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
    FutureSchema {
        found: u32,
        supported: u32,
    },
    IntegrityCheckFailed(String),
    ForeignKeyCheckFailed(String),
    WorkerStopped,
    InvalidCallerCredential,
    CallerAlreadyRegistered(CallerId),
    AuditEventAlreadyExists,
    InvalidAuditEvent(&'static str),
    InvalidAuditBatchLimit {
        limit: u32,
        maximum: u32,
    },
    AuditCursorOutOfRange(u64),
    AuditHighWaterAhead {
        through: u64,
        maximum: u64,
    },
    InvalidAuditCursorRange {
        after: u64,
        through: u64,
    },
    GrantAlreadyExists(GrantId),
    ApprovalNotFound(ApprovalId),
    InvalidApprovalState,
    ApprovalExpiryOverflow,
    RequestNotFound(RequestId),
    RequestIdConflict(RequestId),
    IdempotencyConflict {
        canonical_request_id: RequestId,
    },
    StaleLease(RequestId),
    InvalidFlowCheckpoint(&'static str),
    FlowCheckpointTooLarge {
        size_bytes: usize,
        maximum_bytes: usize,
    },
    FlowTransitionTooLarge {
        size_bytes: usize,
        maximum_bytes: usize,
    },
    FlowTerminalResultTooLarge {
        size_bytes: usize,
        maximum_bytes: usize,
    },
    FlowCheckpointRevisionConflict {
        request_id: RequestId,
        expected: u64,
        actual: u64,
    },
    FlowCheckpointConflict(RequestId),
    FlowDefinitionDigestMismatch(RequestId),
    FlowCheckpointRequestMismatch(RequestId),
    FlowTerminalOutcomeConflict(RequestId),
    FlowEffectStartConflict(RequestId),
    CorruptFlowAuthorization(RequestId),
    CorruptFlowCheckpoint(RequestId),
    FlowCheckpointRevisionOverflow,
    InvalidState(String),
    TimestampOutOfRange(u64),
    LeaseDurationZero,
    LeaseExpiryOverflow,
    EvidenceTooLarge {
        size_bytes: u64,
        maximum_bytes: u64,
    },
    EvidenceRangeTooLarge {
        length: u64,
        maximum_bytes: u64,
    },
    EvidenceRangeOutOfBounds {
        offset: u64,
        size_bytes: u64,
    },
    InvalidEvidenceMediaType,
    InvalidEvidencePruneRetention,
    InvalidEvidencePruneLimit {
        limit: u32,
        maximum: u32,
    },
    EvidenceNotFound {
        project_id: ProjectId,
        handle: EvidenceHandle,
    },
    EvidenceHandleConflict {
        project_id: ProjectId,
        handle: EvidenceHandle,
    },
    EvidenceBlobMissing(ContentDigest),
    EvidenceBlobCorrupt(ContentDigest),
    UnsafeEvidencePath,
    InvalidModelRecord(&'static str),
    ModelConflict(String),
    ModelNotFound(String),
    IncompleteSkillInventory(Vec<ScanDiagnostic>),
    InvalidSkillInventory(&'static str),
    CorruptSkillArtifact,
    SkillArtifactNotFound {
        project_id: ProjectId,
        artifact_id: AgentArtifactId,
    },
    SkillInventoryTimestampRegression {
        artifact_id: AgentArtifactId,
        observed_at_ms: u64,
        stored_at_ms: u64,
    },
}

impl fmt::Display for StoreError {
    #[allow(clippy::too_many_lines)] // Keep the exhaustive public error mapping auditable.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => formatter.write_str("PAM could not prepare its durable state path."),
            Self::Sqlite(_) => formatter.write_str("PAM durable state is unavailable or corrupt."),
            Self::FutureSchema { found, supported } => write!(
                formatter,
                "PAM durable state schema {found} is newer than supported schema {supported}."
            ),
            Self::IntegrityCheckFailed(_) => {
                formatter.write_str("PAM durable state failed its SQLite integrity check.")
            }
            Self::ForeignKeyCheckFailed(_) => {
                formatter.write_str("PAM durable state contains an orphaned reference.")
            }
            Self::WorkerStopped => formatter.write_str("PAM's durable state worker stopped."),
            Self::InvalidCallerCredential | Self::CallerAlreadyRegistered(_) => {
                format_caller_error(self, formatter)
            }
            Self::AuditEventAlreadyExists => formatter.write_str("audit event ID already exists"),
            Self::InvalidAuditEvent(reason) => write!(formatter, "invalid audit event: {reason}"),
            Self::InvalidAuditBatchLimit { .. } => formatter.write_str("invalid audit batch limit"),
            Self::AuditCursorOutOfRange(_) => {
                formatter.write_str("audit cursor exceeds storage range")
            }
            Self::AuditHighWaterAhead { .. } => {
                formatter.write_str("audit high-water sequence exceeds the current ledger")
            }
            Self::InvalidAuditCursorRange { .. } => invalid_audit_cursor_range(formatter),
            Self::GrantAlreadyExists(grant_id) => {
                write!(formatter, "grant {grant_id} already exists")
            }
            Self::ApprovalNotFound(approval_id) => {
                write!(formatter, "approval {approval_id} does not exist")
            }
            Self::InvalidApprovalState => {
                formatter.write_str("approval is not awaiting this decision")
            }
            Self::ApprovalExpiryOverflow => formatter.write_str("approval expiry overflowed"),
            Self::RequestNotFound(request_id) => {
                write!(formatter, "request {request_id} does not exist")
            }
            Self::RequestIdConflict(request_id) => {
                write!(formatter, "request ID {request_id} is already in use")
            }
            Self::IdempotencyConflict {
                canonical_request_id,
            } => write!(
                formatter,
                "idempotency key belongs to a different operation ({canonical_request_id})"
            ),
            Self::StaleLease(request_id) => {
                write!(formatter, "lease for request {request_id} is stale")
            }
            Self::InvalidFlowCheckpoint(_)
            | Self::FlowCheckpointTooLarge { .. }
            | Self::FlowTransitionTooLarge { .. }
            | Self::FlowTerminalResultTooLarge { .. }
            | Self::FlowCheckpointRevisionConflict { .. }
            | Self::FlowCheckpointConflict(_)
            | Self::FlowDefinitionDigestMismatch(_)
            | Self::FlowCheckpointRequestMismatch(_)
            | Self::FlowTerminalOutcomeConflict(_)
            | Self::FlowEffectStartConflict(_)
            | Self::CorruptFlowAuthorization(_)
            | Self::CorruptFlowCheckpoint(_)
            | Self::FlowCheckpointRevisionOverflow => format_flow_error(self, formatter),
            Self::InvalidState(state) => write!(formatter, "invalid stored request state {state}"),
            Self::TimestampOutOfRange(timestamp) => {
                write!(
                    formatter,
                    "timestamp {timestamp} does not fit SQLite INTEGER"
                )
            }
            Self::LeaseDurationZero => formatter.write_str("lease duration must be non-zero"),
            Self::LeaseExpiryOverflow => formatter.write_str("lease expiry overflowed"),
            Self::EvidenceTooLarge { .. }
            | Self::EvidenceRangeTooLarge { .. }
            | Self::EvidenceRangeOutOfBounds { .. } => format_evidence_bound_error(self, formatter),
            Self::InvalidEvidenceMediaType => formatter.write_str("evidence media type is invalid"),
            Self::InvalidEvidencePruneRetention => invalid_evidence_prune_retention(formatter),
            Self::InvalidEvidencePruneLimit { .. } => invalid_evidence_prune_limit(formatter),
            Self::EvidenceNotFound { project_id, handle } => {
                write!(
                    formatter,
                    "evidence {handle} does not exist in project {project_id}"
                )
            }
            Self::EvidenceHandleConflict { project_id, handle } => write!(
                formatter,
                "evidence {handle} already identifies different content in project {project_id}"
            ),
            Self::EvidenceBlobMissing(_) | Self::EvidenceBlobCorrupt(_) => {
                format_evidence_blob_error(self, formatter)
            }
            Self::UnsafeEvidencePath => formatter.write_str("evidence storage path is unsafe"),
            Self::InvalidModelRecord(_) | Self::ModelConflict(_) | Self::ModelNotFound(_) => {
                format_model_error(self, formatter)
            }
            Self::IncompleteSkillInventory(_)
            | Self::InvalidSkillInventory(_)
            | Self::CorruptSkillArtifact
            | Self::SkillArtifactNotFound { .. }
            | Self::SkillInventoryTimestampRegression { .. } => {
                format_skill_inventory_error(self, formatter)
            }
        }
    }
}

fn format_caller_error(error: &StoreError, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match error {
        StoreError::InvalidCallerCredential => {
            formatter.write_str("caller credential must contain 1 to 256 bytes")
        }
        StoreError::CallerAlreadyRegistered(caller_id) => {
            write!(formatter, "caller {caller_id} is already registered")
        }
        _ => unreachable!("format_caller_error requires a caller error"),
    }
}

fn format_skill_inventory_error(
    error: &StoreError,
    formatter: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    match error {
        StoreError::IncompleteSkillInventory(diagnostics) => write!(
            formatter,
            "skill inventory scan is incomplete ({} diagnostics)",
            diagnostics.len()
        ),
        StoreError::InvalidSkillInventory(reason) => {
            write!(formatter, "skill inventory is invalid: {reason}")
        }
        StoreError::CorruptSkillArtifact => {
            formatter.write_str("stored skill artifact metadata is corrupt")
        }
        StoreError::SkillArtifactNotFound {
            project_id,
            artifact_id,
        } => write!(
            formatter,
            "skill artifact {artifact_id} does not exist in project {project_id}"
        ),
        StoreError::SkillInventoryTimestampRegression {
            artifact_id,
            observed_at_ms,
            stored_at_ms,
        } => write!(
            formatter,
            "skill artifact {artifact_id} was observed at {observed_at_ms}, before stored timestamp {stored_at_ms}"
        ),
        _ => unreachable!("format_skill_inventory_error requires an inventory error"),
    }
}

fn format_flow_error(error: &StoreError, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match error {
        StoreError::InvalidFlowCheckpoint(reason) => {
            write!(formatter, "invalid flow checkpoint: {reason}")
        }
        StoreError::FlowCheckpointTooLarge {
            size_bytes,
            maximum_bytes,
        } => write!(
            formatter,
            "flow checkpoint is {size_bytes} bytes; the maximum is {maximum_bytes} bytes"
        ),
        StoreError::FlowTransitionTooLarge {
            size_bytes,
            maximum_bytes,
        } => write!(
            formatter,
            "flow transition is {size_bytes} bytes; the maximum is {maximum_bytes} bytes"
        ),
        StoreError::FlowTerminalResultTooLarge {
            size_bytes,
            maximum_bytes,
        } => write!(
            formatter,
            "flow terminal result is {size_bytes} bytes; the maximum is {maximum_bytes} bytes"
        ),
        StoreError::FlowCheckpointRevisionConflict {
            request_id,
            expected,
            actual,
        } => write!(
            formatter,
            "flow checkpoint revision conflict for {request_id}: expected {expected}, found {actual}"
        ),
        StoreError::FlowCheckpointConflict(request_id) => write!(
            formatter,
            "flow checkpoint replay for {request_id} conflicts with durable state"
        ),
        StoreError::FlowDefinitionDigestMismatch(request_id) => write!(
            formatter,
            "flow definition digest for {request_id} does not match durable state"
        ),
        StoreError::FlowCheckpointRequestMismatch(request_id) => write!(
            formatter,
            "flow checkpoint run ID does not match request {request_id}"
        ),
        StoreError::FlowTerminalOutcomeConflict(request_id) => write!(
            formatter,
            "flow terminal outcome for {request_id} conflicts with durable request state"
        ),
        StoreError::FlowEffectStartConflict(request_id) => write!(
            formatter,
            "flow effect start for {request_id} conflicts with durable request state"
        ),
        StoreError::CorruptFlowAuthorization(request_id) => {
            write!(formatter, "flow authorization for {request_id} is corrupt")
        }
        StoreError::CorruptFlowCheckpoint(request_id) => {
            write!(formatter, "flow checkpoint for {request_id} is corrupt")
        }
        StoreError::FlowCheckpointRevisionOverflow => {
            formatter.write_str("flow checkpoint revision overflowed")
        }
        _ => unreachable!("format_flow_error requires a flow checkpoint error"),
    }
}

fn format_evidence_blob_error(
    error: &StoreError,
    formatter: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    match error {
        StoreError::EvidenceBlobMissing(digest) => {
            write!(formatter, "evidence blob {digest} is missing")
        }
        StoreError::EvidenceBlobCorrupt(digest) => {
            write!(formatter, "evidence blob {digest} failed verification")
        }
        _ => unreachable!("format_evidence_blob_error requires a blob error"),
    }
}

fn format_evidence_bound_error(
    error: &StoreError,
    formatter: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    match error {
        StoreError::EvidenceTooLarge {
            size_bytes,
            maximum_bytes,
        } => write!(
            formatter,
            "evidence is {size_bytes} bytes; the maximum is {maximum_bytes} bytes"
        ),
        StoreError::EvidenceRangeTooLarge {
            length,
            maximum_bytes,
        } => write!(
            formatter,
            "evidence range is {length} bytes; the maximum is {maximum_bytes} bytes"
        ),
        StoreError::EvidenceRangeOutOfBounds { offset, size_bytes } => write!(
            formatter,
            "evidence offset {offset} exceeds content size {size_bytes}"
        ),
        _ => unreachable!("format_evidence_bound_error requires an evidence bound error"),
    }
}

fn format_model_error(error: &StoreError, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match error {
        StoreError::InvalidModelRecord(reason) => {
            write!(formatter, "model metadata is invalid: {reason}")
        }
        StoreError::ModelConflict(model_id) => write!(
            formatter,
            "model {model_id} is already registered with different metadata"
        ),
        StoreError::ModelNotFound(model_id) => {
            write!(formatter, "model {model_id} is not registered")
        }
        _ => unreachable!("format_model_error requires a model error"),
    }
}

fn invalid_evidence_prune_retention(formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("persistent evidence cannot be pruned by retention policy")
}

fn invalid_audit_cursor_range(formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("audit high-water sequence precedes the after sequence")
}

fn invalid_evidence_prune_limit(formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("invalid evidence prune batch limit")
}

impl Error for StoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            Self::FutureSchema { .. }
            | Self::IntegrityCheckFailed(_)
            | Self::ForeignKeyCheckFailed(_)
            | Self::WorkerStopped
            | Self::InvalidCallerCredential
            | Self::CallerAlreadyRegistered(_)
            | Self::AuditEventAlreadyExists
            | Self::InvalidAuditEvent(_)
            | Self::InvalidAuditBatchLimit { .. }
            | Self::AuditCursorOutOfRange(_)
            | Self::AuditHighWaterAhead { .. }
            | Self::InvalidAuditCursorRange { .. }
            | Self::GrantAlreadyExists(_)
            | Self::ApprovalNotFound(_)
            | Self::InvalidApprovalState
            | Self::ApprovalExpiryOverflow
            | Self::RequestNotFound(_)
            | Self::RequestIdConflict(_)
            | Self::IdempotencyConflict { .. }
            | Self::StaleLease(_)
            | Self::InvalidFlowCheckpoint(_)
            | Self::FlowCheckpointTooLarge { .. }
            | Self::FlowTransitionTooLarge { .. }
            | Self::FlowTerminalResultTooLarge { .. }
            | Self::FlowCheckpointRevisionConflict { .. }
            | Self::FlowCheckpointConflict(_)
            | Self::FlowDefinitionDigestMismatch(_)
            | Self::FlowCheckpointRequestMismatch(_)
            | Self::FlowTerminalOutcomeConflict(_)
            | Self::FlowEffectStartConflict(_)
            | Self::CorruptFlowAuthorization(_)
            | Self::CorruptFlowCheckpoint(_)
            | Self::FlowCheckpointRevisionOverflow
            | Self::InvalidState(_)
            | Self::TimestampOutOfRange(_)
            | Self::LeaseDurationZero
            | Self::LeaseExpiryOverflow
            | Self::EvidenceTooLarge { .. }
            | Self::EvidenceRangeTooLarge { .. }
            | Self::EvidenceRangeOutOfBounds { .. }
            | Self::InvalidEvidenceMediaType
            | Self::InvalidEvidencePruneRetention
            | Self::InvalidEvidencePruneLimit { .. }
            | Self::EvidenceNotFound { .. }
            | Self::EvidenceHandleConflict { .. }
            | Self::EvidenceBlobMissing(_)
            | Self::EvidenceBlobCorrupt(_)
            | Self::UnsafeEvidencePath
            | Self::InvalidModelRecord(_)
            | Self::ModelConflict(_)
            | Self::ModelNotFound(_)
            | Self::IncompleteSkillInventory(_)
            | Self::InvalidSkillInventory(_)
            | Self::CorruptSkillArtifact
            | Self::SkillArtifactNotFound { .. }
            | Self::SkillInventoryTimestampRegression { .. } => None,
        }
    }
}

impl From<std::io::Error> for StoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}
