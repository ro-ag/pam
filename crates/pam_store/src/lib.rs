#![forbid(unsafe_code)]

mod error;
mod evidence;
mod model;
mod store;

#[cfg(test)]
mod evidence_test;
#[cfg(test)]
mod migration_test;
#[cfg(test)]
mod store_test;

pub use error::StoreError;
pub use model::{
    AUDIT_EXPORT_VERSION, AcceptOutcome, AcceptRequest, AppendAuditEvent, ApprovalDecision,
    ApprovalDecisionOutcome, AuditEventRecord, AuditExport, AuditPruneOutcome, AuthorizationAudit,
    AuthorizationOutcome, AuthorizationRequest, CallerAuthentication, CallerRegistration,
    CallerRevocation, CancelOutcome, EventRecord, EvidenceMetadata, EvidencePruneOutcome,
    EvidenceRedaction, EvidenceRetention, GrantRevocation, Lease, LeasedRequest,
    MAX_AUDIT_ACTION_BYTES, MAX_AUDIT_BATCH_SIZE, MAX_AUDIT_CALLER_ID_BYTES,
    MAX_AUDIT_DECISION_BYTES, MAX_AUDIT_DETAIL_BYTES, MAX_AUDIT_EVENT_ID_BYTES,
    MAX_AUDIT_OUTCOME_BYTES, MAX_AUDIT_PROJECT_ID_BYTES, MAX_EVIDENCE_BYTES,
    MAX_EVIDENCE_MEDIA_TYPE_BYTES, MAX_EVIDENCE_PRUNE_BATCH_SIZE, MAX_EVIDENCE_RANGE_BYTES,
    ProjectPolicy, PutEvidence, PutGrant, Replay, RequestSnapshot, RequestState, StoredResult,
    TerminalState,
};
pub use pam_model::{ModelKey, RegisteredModel};
pub use store::Store;
