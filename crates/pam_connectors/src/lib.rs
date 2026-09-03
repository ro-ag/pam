//! Read-only connectors over an injected HTTP transport (system `curl`
//! in production). One module per connector; secrets never reach argv,
//! logs, or evidence. See
//! `docs/specs/2026-09-02-flows-connectors-design.md`.

#![forbid(unsafe_code)]
