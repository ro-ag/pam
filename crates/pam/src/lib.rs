//! Library side of the `pam` binary: testable modules behind the thin CLI. Client-side modules
//! (`client`, `request`, `caller`, base-dir resolution) live in `pam_client` — shared with the GUI
//! bridge, which cannot depend on this crate — and are re-exported here.
//!
//! CLI surface (v0): client by default, `pam daemon` for the background service, `pam gui` for the
//! desktop control center. Agents see **only static subcommands** — no raw-protocol escape hatch
//! and no security commands (grants, approvals, revocations, profile changes are GUI-only). `echo`
//! is diagnostic-only, not for production. `flow run` defaults to a 30-minute deadline and streams
//! as one request (`--no-wait` + `subscribe` to watch step by step). `service install` stops a
//! loose daemon first; `uninstall` stops the managed daemon on macOS/Linux (the next command starts
//! one lazily). Exit codes: `0` success, `1` transport/client failure, `2` usage error, `3`
//! refused, `4` unresolved, `5` blocked.

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
