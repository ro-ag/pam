//! Durable state: requests, audit, evidence, grants, approvals, callers,
//! settings. One `SQLite` file in WAL mode with embedded migrations.
//! Secrets never live here; they belong to the OS credential store.
