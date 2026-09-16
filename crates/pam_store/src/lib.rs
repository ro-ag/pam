//! Durable state: requests, audit, evidence, grants, approvals, callers, settings, model
//! jobs — one database file in WAL mode with embedded migrations. Secrets never live here;
//! they belong to the OS credential store. The store stays thin (open, migrate, a handful
//! of typed helpers); richer queries belong to the services that own them.
//!
//! Engine: [Turso](https://docs.rs/turso) (formerly Limbo), a pure-Rust `SQLite` rewrite,
//! file-format compatible; `mimalloc` (bundled C allocator) is disabled and
//! `pure-rust-crypto` is enabled, but `turso_core` still unconditionally links `simsimd`, a
//! small C SIMD kernel for vector distance — the one residue in an otherwise pure-Rust
//! stack. WAL is native (nothing switches it on); `PRAGMA user_version`, CHECK constraints,
//! and `PRAGMA foreign_keys = ON` all work. The API is async; Turso drives its own I/O, and
//! this crate's only `tokio` dependency is the `sync` mutex serializing every statement on
//! the one connection (held across each `BEGIN`..`COMMIT` window).
//! Integrity is enforced twice — CHECK and foreign-key constraints in the database, typed enums in
//! Rust — and the daemon still owns threading and task placement.

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
    FlowJournalIdentity, FlowJournalState, FlowResultMeta, GrantRow, LandingSession,
    MAX_FLOW_CHECKPOINT_BYTES, MAX_FLOW_JOURNAL_EVIDENCE, MAX_LIST_LIMIT, ModelJobRow,
    PendingApproval, RequestBudgetCharge, RequestBudgetUsage, RequestPrune, RequestRow,
    RequestState, RequestStatusMeta, Store,
};

#[cfg(test)]
mod evidence_views_test;
#[cfg(test)]
mod migrations_test;
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
