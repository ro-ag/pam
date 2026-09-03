//! Library side of the `pam` binary: testable modules behind the thin CLI.
//!
//! The binary in `main.rs` stays a thin shell; everything worth unit-testing
//! lives in library crates. The client-side modules (`client`, `request`,
//! `caller`, and the base-dir resolution) live in `pam_client` — shared
//! with the GUI bridge, which cannot depend on this crate (this crate
//! depends on `pam_gui` for `pam gui`) — and are re-exported here so
//! callers keep using `pam::client` and friends.
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
//! - `pam flow list [--json]` — the flows this machine has, as
//!   `id  source  steps  name` (an unparsable file says why instead).
//! - `pam flow show <id>` — that flow's canonical YAML.
//! - `pam flow run <id> [KEY=VALUE]... [--no-wait] [--deadline-ms N]
//!   [--json]` — run a flow and print its verdict: one line per step,
//!   the summary sentence, and any step summary text. The deadline
//!   defaults to 30 minutes, because a flow that runs `cargo test` is
//!   not a 60 s request. The whole run travels in **one** request, so
//!   nothing prints until it ends; to watch it step by step, start it
//!   with `--no-wait` and follow the ticket with `pam subscribe`.
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

use std::path::Path;

pub use pam_client::{base_dir_from, caller, client, default_base_dir, request};

pub mod render;

/// True when `exe` sits inside a macOS application bundle
/// (`…/Something.app/Contents/MacOS/pam`): a bare double-click launch,
/// which should open the GUI. A bare terminal launch prints help.
///
/// The check is on a component's *extension*, not a suffix, so
/// `pam.app.backup` and `pam.application` are not bundles; the macOS
/// filesystem is case-insensitive, so the extension match is too.
#[must_use]
pub fn launched_from_app_bundle(exe: &Path) -> bool {
    exe.components().any(|part| {
        Path::new(part.as_os_str())
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("app"))
    })
}

#[cfg(test)]
mod config_test;
#[cfg(test)]
mod lib_test;
#[cfg(test)]
mod render_test;
