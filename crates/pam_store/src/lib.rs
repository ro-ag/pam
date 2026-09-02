//! Durable state: requests, audit, evidence, grants, approvals, callers,
//! settings, model jobs. One database file in WAL mode with embedded migrations.
//! Secrets never live here; they belong to the OS credential store.
//!
//! The store is deliberately thin: it opens the database, applies
//! migrations, and offers a handful of typed helpers that the tests and
//! early services need. Richer queries (queue lanes, policy lookups,
//! audit views) belong to the services that own them and arrive with
//! those tasks.
//!
//! # Engine notes
//!
//! The engine is [Turso](https://docs.rs/turso) (formerly Limbo), a
//! pure-Rust rewrite of `SQLite`; the file format is
//! `SQLite`-compatible. The `mimalloc` default feature is disabled
//! (bundled C allocator) and `pure-rust-crypto` is enabled, so the SQL
//! engine, storage, and crypto are all Rust. One residue remains as of
//! turso 0.7: `turso_core` unconditionally links `simsimd`, a small C
//! SIMD kernel used for vector distance functions.
//!
//! - WAL is the engine's native journal mode; nothing needs to switch
//!   it on, and `PRAGMA journal_mode` reports `wal`.
//! - `PRAGMA user_version`, CHECK constraints, and enforced foreign
//!   keys (`PRAGMA foreign_keys = ON`) all work, so the schema keeps
//!   its integrity constraints in the database as well as in the typed
//!   Rust enums.
//! - The API is async ([`Store::open`] and every helper await). Turso
//!   drives its own I/O and does not require a specific runtime; this
//!   crate depends on `tokio` only for the `sync` mutex serializing
//!   [`Store::finish_request`] transactions (and fully in tests). The
//!   daemon still owns threading and task placement.

mod error;
mod migrations;
mod store;

pub use error::StoreError;
pub use store::{
    Actor, ApprovalResolution, ApprovalRow, AuditEntry, AuditRow, CallerRow,
    DEFAULT_REQUEST_LIST_LIMIT, Decision, GrantRow, MAX_REQUEST_LIST_LIMIT, ModelJobRow,
    PendingApproval, RequestRow, RequestState, Store,
};

#[cfg(test)]
mod migrations_test;
#[cfg(test)]
mod store_test;
