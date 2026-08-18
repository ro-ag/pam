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
    AcceptOutcome, AcceptRequest, CancelOutcome, EventRecord, EvidenceMetadata, EvidenceRedaction,
    EvidenceRetention, Lease, LeasedRequest, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_MEDIA_TYPE_BYTES,
    MAX_EVIDENCE_RANGE_BYTES, PutEvidence, Replay, RequestSnapshot, RequestState, StoredResult,
    TerminalState,
};
pub use store::Store;
