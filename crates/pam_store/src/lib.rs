//! Durable state: requests, audit, evidence, grants, approvals, callers, settings, model
//! jobs — one database file in WAL mode with embedded migrations. Secrets never live here;
//! they belong to the OS credential store. The store stays thin (open, migrate, a handful
//! of typed helpers); richer queries belong to the services that own them.
//!
//! Engine: [Turso](https://docs.rs/turso) (formerly Limbo), a pure-Rust `SQLite` rewrite,
//! file-format compatible; `mimalloc` (bundled C allocator) is disabled, `pure-rust-crypto`
//! is enabled, and the workspace patches in a vendored `turso_core` whose vector distances
//! are plain Rust, so `simsimd`'s C kernel is not linked (see `vendor/turso_core/PATCH.md`).
//! WAL is native (nothing switches it on); `PRAGMA user_version`, CHECK constraints,
//! triggers, and `PRAGMA foreign_keys = ON` all work. The API is async; Turso drives its
//! own I/O, and this crate's only `tokio` dependency is the `sync` mutex that owns the one
//! connection: every statement runs through its guard, and a `BEGIN`..`COMMIT` window that a
//! dropped caller abandons is rolled back before the next statement (see `conn_gate`).
//! Integrity is enforced twice — CHECK and foreign-key constraints in the database, typed enums in
//! Rust — and the daemon still owns threading and task placement.

mod conn_gate;
mod error;
mod migrations;
mod store;

pub use error::StoreError;
pub use store::{
    Actor, ApprovalResolution, ApprovalRow, AuditEntry, AuditRow, CallerRow, CompressionStats,
    ConnectorPatch, ConnectorRow, CorrelationBind, CorrelationStep, DEFAULT_REQUEST_LIST_LIMIT,
    Decision, EVIDENCE_KIND_FLOW_CHECKPOINT, EVIDENCE_KIND_LOG_COMPACT, EvidenceMeta,
    EvidenceOrigins, EvidencePrune, EvidenceRange, EvidenceRangeOutcome, EvidenceRangeRequest,
    EvidenceRow, EvidenceViewInsert, EvidenceViewMeta, FlowJournal, FlowJournalBegin,
    FlowJournalIdentity, FlowJournalState, FlowResultMeta, GrantChange, GrantChangeOutcome,
    GrantRow, LandingSession, MAX_EVIDENCE_MAP_BYTES, MAX_EVIDENCE_MAP_SEGMENTS, MAX_EXPIRY_BATCH,
    MAX_FLOW_CHECKPOINT_BYTES, MAX_FLOW_JOURNAL_EVIDENCE, MAX_LIST_LIMIT, ModelJobRow,
    OUTCOME_ADMIN_DENIED, PendingApproval, RequestBudgetCharge, RequestBudgetUsage, RequestPrune,
    RequestRow, RequestState, RequestStatusMeta, Store,
};

#[cfg(test)]
mod conn_gate_test;
#[cfg(test)]
mod evidence_views_test;
#[cfg(test)]
mod migrations_test;
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
