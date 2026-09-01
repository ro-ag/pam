//! Library side of the `pam` binary: testable modules behind the thin CLI.
//!
//! The binary in `main.rs` stays a thin shell; everything worth unit-testing
//! lives here.
//!
//! # CLI surface (v0)
//!
//! One binary, mode by subcommand — client by default, `pam daemon` for
//! the background service, `pam gui` for the desktop control center.
//! Agents see **only static subcommands**: there is no
//! raw-protocol escape hatch, and no security commands — grants,
//! approvals, revocations, and profile changes are GUI-only by design
//! (the spine spec).
//!
//! - `pam status [--json]` — daemon health snapshot.
//! - `pam echo [ARGS_JSON] [--wait/--no-wait] [--deadline-ms N] [--json]`
//!   — diagnostic capability: mirrors its JSON-object args back.
//!   `delay_ms` / `fail` args drive the long-running and failure paths;
//!   for testing pam itself, not for production use.
//! - `pam cancel <ticket>` — cancel a queued or running request.
//! - `pam wait <ticket> [--timeout-ms N]` — block until the ticket's
//!   terminal event (quiet).
//! - `pam subscribe <ticket> [--timeout-ms N]` — same wait, printing
//!   every event as it arrives.
//! - `pam daemon` — run the daemon in the foreground;
//!   `pam daemon stop` — signal the running daemon to drain and exit.
//! - `pam gui` — open the desktop control center window.
//!
//! # Exit codes
//!
//! | code | meaning |
//! |------|---------|
//! | 0 | success (result `solved` / `changed` / `verified`, or a ticket) |
//! | 1 | transport or other client-side failure |
//! | 2 | usage error |
//! | 3 | the daemon refused the request |
//! | 4 | result `unresolved` |
//! | 5 | result `blocked` |

pub mod caller;
pub mod client;
pub mod render;
pub mod request;

#[cfg(test)]
mod caller_test;
#[cfg(test)]
mod client_test;
#[cfg(test)]
mod render_test;
#[cfg(test)]
mod request_test;
