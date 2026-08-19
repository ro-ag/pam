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
    AcceptOutcome, AcceptRequest, ApprovalDecision, ApprovalDecisionOutcome, AuthorizationOutcome,
    AuthorizationRequest, CallerAuthentication, CallerRegistration, CallerRevocation,
    CancelOutcome, EventRecord, EvidenceMetadata, EvidenceRedaction, EvidenceRetention,
    GrantRevocation, Lease, LeasedRequest, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_MEDIA_TYPE_BYTES,
    MAX_EVIDENCE_RANGE_BYTES, ProjectPolicy, PutEvidence, PutGrant, Replay, RequestSnapshot,
    RequestState, StoredResult, TerminalState,
};
pub use store::Store;
