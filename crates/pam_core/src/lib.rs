#![forbid(unsafe_code)]

mod evidence;
mod identity;
mod queue;

#[cfg(test)]
mod evidence_test;
#[cfg(test)]
mod identity_test;
#[cfg(test)]
mod queue_test;

pub use evidence::{
    ContentDigest, EvidenceHandle, EvidenceReference, InvalidContentDigest, InvalidEvidenceHandle,
};
pub use identity::{
    ApprovalId, CallerCredential, CallerId, GrantId, IdempotencyKey, MAX_CALLER_CREDENTIAL_LENGTH,
    ProjectId, RequestId,
};
pub use queue::{ProjectPermit, ProjectQueue};

pub const APPLICATION_VERSION: &str = env!("CARGO_PKG_VERSION");
