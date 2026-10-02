//! Durable state: requests, audit, evidence, grants, approvals, callers, settings, model
//! jobs — one database file in WAL mode with embedded migrations. Secrets never live here;
//! they belong to the OS credential store. The store stays thin (open, migrate, a handful
//! of typed helpers); richer queries belong to the services that own them.
//!
//! Engine: `SQLite` itself, through the `rusqlite` client with the engine's
//! source bundled and linked statically (never the system library, so every
//! target runs the same engine). Write-ahead logging, a full sync per commit,
//! foreign keys and the hardening settings are applied to the connection at
//! open and read back (see `open`). The engine's client is synchronous; the
//! public API is async. There is one connection: every call waits for it on an
//! async gate and then runs its statements as one closure on a blocking thread
//! of the caller's runtime, to completion, so a call whose future is dropped
//! never leaves a transaction open, and a write it had started either
//! committed whole or not at all (see `conn_gate`). Integrity is enforced
//! twice — CHECK and foreign-key constraints in the database, typed enums in
//! Rust.

mod conn_gate;
mod db;
mod error;
mod migrations;
mod open;
mod store;

pub use error::{EngineError, StoreError};
pub use store::{
    Actor, ApprovalResolution, ApprovalRow, AuditEntry, AuditRow, CallerRow, CompressionStats,
    ConnectorPatch, ConnectorRow, CorrelationBind, CorrelationStep, DEFAULT_REQUEST_LIST_LIMIT,
    Decision, EVIDENCE_KIND_FLOW_CHECKPOINT, EVIDENCE_KIND_LOG_COMPACT, EvidenceMeta,
    EvidenceOrigins, EvidencePrune, EvidenceRange, EvidenceRangeOutcome, EvidenceRangeRequest,
    EvidenceRow, EvidenceViewInsert, EvidenceViewMeta, FlowJournal, FlowJournalBegin,
    FlowJournalIdentity, FlowJournalState, FlowResultMeta, GrantChange, GrantChangeOutcome,
    GrantRow, LandingSession, MAX_EVIDENCE_MAP_BYTES, MAX_EVIDENCE_MAP_SEGMENTS, MAX_EXPIRY_BATCH,
    MAX_FLOW_CHECKPOINT_BYTES, MAX_FLOW_JOURNAL_EVIDENCE, MAX_LIST_LIMIT, ModelJobRow,
    OUTCOME_ADMIN_DENIED, PendingApproval, RequestBudgetCharge, RequestBudgetUsage, RequestIngress,
    RequestOrigin, RequestPrune, RequestRow, RequestState, RequestStatusMeta, RetentionCensus,
    Store,
};

#[cfg(test)]
mod conn_gate_test;
#[cfg(test)]
mod error_test;
#[cfg(test)]
mod evidence_views_test;
#[cfg(test)]
mod migrations_test;
#[cfg(test)]
mod open_test;
#[cfg(test)]
mod store_integrity_test;
#[cfg(test)]
mod store_test;

#[cfg(test)]
mod flow_results_test;

#[cfg(test)]
mod correlation_test;

#[cfg(test)]
mod flow_journal_test;
#[cfg(test)]
mod request_budget_test;

#[cfg(test)]
mod terminal_uncertainty_test;

#[cfg(test)]
mod watch_schedule_test;

#[cfg(test)]
mod watch_progress_test;

#[cfg(test)]
mod correlation_membership_test;

#[cfg(test)]
mod landing_session_test;
