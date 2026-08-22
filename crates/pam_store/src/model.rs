use std::fmt;

use pam_core::{
    ApprovalId, CallerId, ContentDigest, EvidenceHandle, GrantId, IdempotencyKey, ProjectId,
    RequestId,
};
use pam_flow::{FlowSnapshot, RunOutcome, RunTransition};
use pam_policy::{CapabilityName, Grant, ResourceName};

pub const MAX_EVIDENCE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_EVIDENCE_PRUNE_BATCH_SIZE: u32 = 1_000;
pub const MAX_EVIDENCE_RANGE_BYTES: u64 = 1024 * 1024;
pub const MAX_EVIDENCE_MEDIA_TYPE_BYTES: usize = 255;
pub const AUDIT_EXPORT_VERSION: u32 = 1;
pub const MAX_AUDIT_ACTION_BYTES: usize = 128;
pub const MAX_AUDIT_BATCH_SIZE: u32 = 1_000;
pub const MAX_AUDIT_CALLER_ID_BYTES: usize = 256;
pub const MAX_AUDIT_DECISION_BYTES: usize = 64;
pub const MAX_AUDIT_DETAIL_BYTES: usize = 16 * 1024;
pub const MAX_AUDIT_EVENT_ID_BYTES: usize = 256;
pub const MAX_AUDIT_OUTCOME_BYTES: usize = 64;
pub const MAX_AUDIT_PROJECT_ID_BYTES: usize = 256;
pub const MAX_FLOW_CHECKPOINT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_FLOW_TRANSITION_BYTES: usize = 64 * 1024;
pub const MAX_FLOW_TERMINAL_RESULT_BYTES: usize = 1024 * 1024;
/// Maximum UTF-8 size of one durable serialized skills audit report.
pub const MAX_SKILLS_AUDIT_REPORT_BYTES: usize = 32 * 1024 * 1024;

/// Latest durable serialized skills audit report for one project.
#[derive(Clone, Eq, PartialEq)]
pub struct StoredSkillsAuditReport {
    pub project_id: ProjectId,
    pub observed_at_ms: u64,
    pub schema_version: u32,
    pub report_json: String,
    pub digest: ContentDigest,
}

impl fmt::Debug for StoredSkillsAuditReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredSkillsAuditReport")
            .field("project_id", &self.project_id)
            .field("observed_at_ms", &self.observed_at_ms)
            .field("schema_version", &self.schema_version)
            .field("report_json", &"<redacted>")
            .field("digest", &self.digest)
            .finish()
    }
}

/// One audit event to append to the durable ledger.
///
/// Callers should redact detail as close to collection as possible. The store
/// applies the bounded audit redactor again at the persistence boundary so a
/// missed caller-side match cannot write a recognized secret to the ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppendAuditEvent {
    pub event_id: String,
    pub project_id: ProjectId,
    pub caller_id: CallerId,
    pub action: String,
    pub decision: String,
    pub outcome: String,
    pub redacted_detail: String,
    pub occurred_at_ms: u64,
    pub retain_until_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEventRecord {
    pub sequence: u64,
    pub event_id: String,
    pub project_id: ProjectId,
    pub caller_id: CallerId,
    pub action: String,
    pub decision: String,
    pub outcome: String,
    pub redacted_detail: String,
    pub occurred_at_ms: u64,
    pub retain_until_ms: u64,
}

/// Versioned typed export seam for deterministic protocol serialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditExport {
    pub version: u32,
    pub project_id: ProjectId,
    pub after_sequence: u64,
    pub through_sequence: u64,
    pub next_after_sequence: u64,
    pub has_more: bool,
    pub events: Vec<AuditEventRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditPruneOutcome {
    pub deleted: u32,
    pub has_more: bool,
}

/// Bounded newest-first slice of the durable audit ledger across all projects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecentAuditEvents {
    pub events: Vec<AuditEventRecord>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallerRegistration {
    pub caller_id: CallerId,
    pub registered_at_ms: u64,
    pub revoked_at_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallerAuthentication {
    Authenticated,
    UnknownCaller,
    Revoked,
    InvalidCredential,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallerRevocation {
    Revoked,
    AlreadyRevoked,
    UnknownCaller,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectPolicy {
    pub project_id: ProjectId,
    pub version: u64,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationRequest {
    pub caller_id: CallerId,
    pub project_id: ProjectId,
    pub capability: CapabilityName,
    pub resource: ResourceName,
    pub approval_id: Option<ApprovalId>,
}

/// Already-redacted metadata appended atomically with one policy evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationAudit {
    pub event_id: String,
    pub action: String,
    pub redacted_detail: String,
    pub retain_until_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationOutcome {
    Allowed,
    Denied,
    ApprovalRequired {
        approval_id: ApprovalId,
        expires_at_ms: u64,
    },
    ApprovalDenied,
    ApprovalExpired,
}

/// One exact flow authorization request coupled to its durable acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizeFlowRun {
    pub accept: AcceptRequest,
    pub resource: ResourceName,
    pub approval_id: Option<ApprovalId>,
    pub audit: AuthorizationAudit,
    /// True when the flow schema contains a stateful step that mandates human approval.
    pub schema_approval_required: bool,
}

/// Result of atomically authorizing and, on success, accepting one flow run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowAuthorizationOutcome {
    Accepted(AcceptOutcome),
    Denied,
    ApprovalRequired {
        approval_id: ApprovalId,
        expires_at_ms: u64,
    },
    ApprovalDenied,
    ApprovalExpired,
}

/// Fresh authorization result at one flow effect boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowEffectAuthorization {
    Allowed,
    Denied,
}

/// Outcome of atomically recovering one corrupt queued flow authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowAuthorizationRecoveryOutcome {
    Failed(StoredResult),
    AlreadyTerminal(StoredResult),
    /// Another transaction changed the request or repaired its proof.
    NoLongerEligible,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDecision {
    Approve,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDecisionOutcome {
    Approved,
    Denied,
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantRevocation {
    Revoked,
    AlreadyRevoked,
    UnknownGrant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PutGrant {
    pub grant: Grant,
    pub created_at_ms: u64,
}

impl PutGrant {
    #[must_use]
    pub fn grant_id(&self) -> &GrantId {
        &self.grant.id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceRetention {
    Session,
    Project,
    Persistent,
}

impl EvidenceRetention {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Project => "project",
            Self::Persistent => "persistent",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceRedaction {
    Unredacted,
    Redacted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidencePruneOutcome {
    pub handles_deleted: u32,
    pub blobs_deleted: u32,
    pub blobs_pending: u32,
    /// A cleanup operation failed after logical handle deletion, so numeric
    /// counts remain exact but do not describe every unresolved cleanup item.
    pub cleanup_unresolved: bool,
    pub has_more: bool,
}

impl EvidenceRedaction {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Unredacted => "unredacted",
            Self::Redacted => "redacted",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PutEvidence {
    pub handle: EvidenceHandle,
    pub project_id: ProjectId,
    pub media_type: String,
    pub retention: EvidenceRetention,
    pub redaction: EvidenceRedaction,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceMetadata {
    pub handle: EvidenceHandle,
    pub digest: ContentDigest,
    pub size_bytes: u64,
    pub media_type: String,
    pub project_id: ProjectId,
    pub retention: EvidenceRetention,
    pub redaction: EvidenceRedaction,
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptRequest {
    pub request_id: RequestId,
    pub caller_id: CallerId,
    pub project_id: ProjectId,
    pub idempotency_key: IdempotencyKey,
    pub operation_kind: String,
    pub operation: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcceptOutcome {
    Created {
        request_id: RequestId,
        queue_sequence: u64,
    },
    Existing {
        request_id: RequestId,
        state: RequestState,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestState {
    Queued,
    Leased,
    CancellationRequested,
    Succeeded,
    Failed,
    Cancelled,
}

impl RequestState {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Leased => "leased",
            Self::CancellationRequested => "cancellation_requested",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Optional immutable operation classification for target-scoped store operations.
///
/// This store-owned type keeps durable storage independent of the wire protocol while allowing
/// callers to request an atomic kind check before observing or mutating a target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedOperationKind {
    FlowRun,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalState {
    Succeeded,
    Failed,
    Cancelled,
}

impl TerminalState {
    pub(super) const fn request_state(self) -> RequestState {
        match self {
            Self::Succeeded => RequestState::Succeeded,
            Self::Failed => RequestState::Failed,
            Self::Cancelled => RequestState::Cancelled,
        }
    }

    pub(super) const fn event_kind(self) -> &'static str {
        match self {
            Self::Succeeded => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lease {
    pub request_id: RequestId,
    pub project_id: ProjectId,
    pub owner: String,
    pub token: String,
    pub attempt: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeasedRequest {
    pub lease: Lease,
    pub queue_sequence: u64,
    pub operation_kind: String,
    pub operation: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelOutcome {
    Cancelled,
    CancellationRequested,
    AlreadyRequested,
    AlreadyTerminal(RequestState),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventRecord {
    pub sequence: u64,
    pub kind: String,
    pub payload: Vec<u8>,
    pub recorded_at_ms: u64,
}

/// One durable flow checkpoint owned by a scheduler request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowCheckpoint {
    pub request_id: RequestId,
    pub snapshot: FlowSnapshot,
    pub checkpoint_revision: u64,
    pub updated_at_ms: u64,
    /// Exact encoded terminal result, present only when the snapshot is terminal.
    pub terminal_result: Option<FlowTerminalResult>,
}

/// Encoded protocol result durably bound to a terminal flow checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowTerminalResult {
    pub outcome: RunOutcome,
    pub encoded_result: Vec<u8>,
}

/// A compare-and-swap checkpoint write performed under a live scheduler lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SaveFlowCheckpoint {
    pub lease: Lease,
    /// Zero creates the first checkpoint; otherwise this must match the stored revision.
    pub expected_revision: u64,
    pub snapshot: FlowSnapshot,
    /// The single semantic transition represented by this snapshot update.
    pub transition: Option<RunTransition>,
    /// Required for terminal snapshots and forbidden for non-terminal snapshots.
    pub terminal_result: Option<FlowTerminalResult>,
    pub updated_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowCheckpointDisposition {
    Created,
    Updated,
    Unchanged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowCheckpointSaveOutcome {
    pub checkpoint: FlowCheckpoint,
    pub disposition: FlowCheckpointDisposition,
    /// The event appended atomically for a newly persisted transition.
    pub event: Option<EventRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredResult {
    pub state: RequestState,
    pub payload: Vec<u8>,
    pub completed_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Replay {
    pub events: Vec<EventRecord>,
    pub result: Option<StoredResult>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestSnapshot {
    pub request_id: RequestId,
    pub project_id: ProjectId,
    pub queue_sequence: u64,
    pub state: RequestState,
    pub attempt: u64,
    pub lease_expires_at_ms: Option<u64>,
}

/// Current non-status scheduler workload for one project.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectWorkload {
    pub queued: u64,
    pub active: bool,
}

/// Maximum number of queued requests returned by [`crate::Store::project_current`].
pub const MAX_PROJECT_CURRENT_QUEUED: usize = 64;

/// Bounded scheduler metadata safe to expose in a project-current read model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectRequestSummary {
    pub request_id: RequestId,
    pub operation_kind: String,
    pub state: RequestState,
    pub queue_sequence: u64,
    pub accepted_at_ms: u64,
    pub completed_at_ms: Option<u64>,
}

/// Transactionally consistent current scheduler state for one project.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectCurrent {
    pub queued: Vec<ProjectRequestSummary>,
    pub queued_truncated: bool,
    pub active: Option<ProjectRequestSummary>,
    pub latest_terminal: Option<ProjectRequestSummary>,
}
