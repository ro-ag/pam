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
//! public API is async. One connection writes: every call waits for it on an
//! async gate and then runs its statements as one closure on a blocking thread
//! of the caller's runtime, to completion, so a call whose future is dropped
//! never leaves a transaction open, and a write it had started either
//! committed whole or not at all (see `conn_gate`). A file-backed store has a
//! second, read-only connection behind a gate of its own, which the list
//! queries and the large reads use: they neither wait for a write nor hold
//! one up. Integrity is enforced twice — CHECK and foreign-key constraints in
//! the database, typed enums in Rust.
//!
//! Upgrades never start without the way back. Before a database is migrated
//! its files are copied into `backup/` beside it, and a database last written
//! by the previous engine is also checked in full, once; an open that cannot
//! make the copy, or finds the database damaged, is refused and leaves every
//! file as it found it (see `open` for the whole path, `backup` for the
//! copies and how to restore one).
//!
//! [`Store::close`] ends a store in good order and leaves the main file as
//! the whole database. A store that is dropped instead, or whose process is
//! killed, leaves a write-ahead log the next open replays; nothing a call had
//! returned from is lost either way. Dropping never checkpoints, and nothing
//! may rely on it doing so: the rows of a dropped store are read by opening
//! the file through the store again, not by reading or copying the main
//! file, which is complete on its own only after `close`.

mod backup;
mod conn_gate;
mod db;
mod error;
mod header;
mod migrations;
mod open;
mod store;
mod view_chunks;

pub use error::{EngineError, StoreError};
pub use store::{ACTION_FLOW_CHECKPOINT_ORPHANED, FlowCheckpoint};
pub use store::{
    Actor, ApprovalResolution, ApprovalRow, AuditEntry, AuditRow, CallerRow, CompressionStats,
    ConnectorPatch, ConnectorRow, CorrelationBind, CorrelationStep, DEFAULT_REQUEST_LIST_LIMIT,
    Decision, EVIDENCE_KIND_FLOW_CHECKPOINT, EVIDENCE_KIND_LOG_COMPACT, EvidenceMeta,
    EvidenceOrigins, EvidencePrune, EvidenceRange, EvidenceRangeOutcome, EvidenceRangeRequest,
    EvidenceRow, EvidenceViewInsert, EvidenceViewMeta, FlowJournal, FlowJournalBegin,
    FlowJournalIdentity, FlowJournalState, FlowResultMeta, GrantChange, GrantChangeOutcome,
    GrantRow, LandingSession, MAX_EVIDENCE_MAP_BYTES, MAX_EVIDENCE_MAP_SEGMENTS, MAX_EXPIRY_BATCH,
    MAX_FLOW_CHECKPOINT_BYTES, MAX_FLOW_JOURNAL_EVIDENCE, MAX_LIST_LIMIT,
    MAX_POLICY_LAST_GOOD_BYTES, ModelJobRow, OUTCOME_ADMIN_DENIED, PendingApproval,
    RequestBudgetCharge, RequestBudgetUsage, RequestIngress, RequestOrigin, RequestPrune,
    RequestRow, RequestState, RequestStatusMeta, RetentionCensus, SETTING_POLICY_LAST_GOOD, Store,
};
pub use store::{
    BoundaryCensus, BoundaryObservationInsert, BoundaryObservationRow, BoundaryPeer,
    BoundaryReportInsert, BoundaryReportRow, MAX_BOUNDARY_OBSERVATIONS, MAX_BOUNDARY_REPORT_BYTES,
    MAX_BOUNDARY_REPORTS, MAX_EXPECTED_OBSERVATIONS, OBSERVATION_ADMIN_CONTACT,
    OBSERVATION_ADMIN_HANDSHAKE_FAILED, OBSERVATION_PUBLIC_UNKNOWN_HARNESS,
    SETTING_ADMIN_CONTACTS_EXPECTED_TOTAL, SETTING_ADMIN_CONTACTS_TOTAL,
    SETTING_PUBLIC_UNKNOWN_TOTAL,
};
pub use store::{FLOW_STEP_PREFIX, GrantBinding, SCOPE_REPOSITORY};
pub use store::{
    MAX_AGENT_BYTES, MAX_CAPABILITY_BYTES, MAX_CAUSE_BYTES, MAX_DETAIL_BYTES, MAX_PEER_EXE_BYTES,
    MAX_REFUSAL_LIST_LIMIT, MAX_REFUSALS, MAX_REPO_BYTES, MAX_REQUEST_ID_BYTES, RefusalRecord,
    RefusalRow, RefusalWrite, bounded,
};

#[cfg(test)]
mod backup_test;
#[cfg(test)]
mod close_test;
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
mod read_test;
#[cfg(test)]
mod store_integrity_test;
#[cfg(test)]
mod store_test;
#[cfg(test)]
mod sync_cost_test;
#[cfg(test)]
mod upgrade_test;
#[cfg(test)]
mod view_chunks_test;

#[cfg(test)]
mod flow_results_test;

#[cfg(test)]
mod grant_binding_test;

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

#[cfg(test)]
mod boundary_test;

#[cfg(test)]
mod refusal_test;
