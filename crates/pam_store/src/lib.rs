#![forbid(unsafe_code)]

mod error;
mod evidence;
mod inventory;
mod model;
mod store;

#[cfg(test)]
mod evidence_test;
#[cfg(test)]
mod migration_test;
#[cfg(test)]
mod store_test;

pub use error::StoreError;
pub use inventory::{
    MAX_SKILL_INVENTORY_TOMBSTONES_PER_PROJECT, SkillInventoryDrift, StoredAgentArtifact,
};
pub use model::{
    AUDIT_EXPORT_VERSION, AcceptOutcome, AcceptRequest, AppendAuditEvent, ApprovalDecision,
    ApprovalDecisionOutcome, AuditEventRecord, AuditExport, AuditPruneOutcome, AuthorizationAudit,
    AuthorizationOutcome, AuthorizationRequest, AuthorizeFlowRun, CallerAuthentication,
    CallerRegistration, CallerRevocation, CancelOutcome, EventRecord, EvidenceMetadata,
    EvidencePruneOutcome, EvidenceRedaction, EvidenceRetention, ExpectedOperationKind,
    FlowAuthorizationOutcome, FlowAuthorizationRecoveryOutcome, FlowCheckpoint,
    FlowCheckpointDisposition, FlowCheckpointSaveOutcome, FlowEffectAuthorization,
    FlowTerminalResult, GrantRevocation, Lease, LeasedRequest, MAX_AUDIT_ACTION_BYTES,
    MAX_AUDIT_BATCH_SIZE, MAX_AUDIT_CALLER_ID_BYTES, MAX_AUDIT_DECISION_BYTES,
    MAX_AUDIT_DETAIL_BYTES, MAX_AUDIT_EVENT_ID_BYTES, MAX_AUDIT_OUTCOME_BYTES,
    MAX_AUDIT_PROJECT_ID_BYTES, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_MEDIA_TYPE_BYTES,
    MAX_EVIDENCE_PRUNE_BATCH_SIZE, MAX_EVIDENCE_RANGE_BYTES, MAX_FLOW_CHECKPOINT_BYTES,
    MAX_FLOW_TERMINAL_RESULT_BYTES, MAX_FLOW_TRANSITION_BYTES, MAX_PROJECT_CURRENT_QUEUED,
    MAX_SKILLS_AUDIT_REPORT_BYTES, ProjectCurrent, ProjectPolicy, ProjectRequestSummary,
    ProjectWorkload, PutEvidence, PutGrant, RecentAuditEvents, Replay, RequestSnapshot,
    RequestState, SaveFlowCheckpoint, StoredResult, StoredSkillsAuditReport, TerminalState,
};
pub use pam_model::{ModelKey, RegisteredModel};
pub use store::{EffectApprovalCapability, Store};
