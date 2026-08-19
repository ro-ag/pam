use std::{error::Error, fmt};

use pam_core::{
    ApprovalId, CallerId, ContentDigest, EvidenceHandle, GrantId, ProjectId, RequestId,
};

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
}

impl fmt::Display for StoreError {
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
            Self::InvalidCallerCredential => {
                formatter.write_str("caller credential must contain 1 to 256 bytes")
            }
            Self::CallerAlreadyRegistered(caller_id) => {
                write!(formatter, "caller {caller_id} is already registered")
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
            Self::InvalidState(state) => write!(formatter, "invalid stored request state {state}"),
            Self::TimestampOutOfRange(timestamp) => {
                write!(
                    formatter,
                    "timestamp {timestamp} does not fit SQLite INTEGER"
                )
            }
            Self::LeaseDurationZero => formatter.write_str("lease duration must be non-zero"),
            Self::LeaseExpiryOverflow => formatter.write_str("lease expiry overflowed"),
            Self::EvidenceTooLarge {
                size_bytes,
                maximum_bytes,
            } => write!(
                formatter,
                "evidence is {size_bytes} bytes; the maximum is {maximum_bytes} bytes"
            ),
            Self::EvidenceRangeTooLarge {
                length,
                maximum_bytes,
            } => write!(
                formatter,
                "evidence range is {length} bytes; the maximum is {maximum_bytes} bytes"
            ),
            Self::EvidenceRangeOutOfBounds { offset, size_bytes } => write!(
                formatter,
                "evidence offset {offset} exceeds content size {size_bytes}"
            ),
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
        }
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
            | Self::UnsafeEvidencePath => None,
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
