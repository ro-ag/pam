//! Client-side library for pam, shared by the CLI (`crates/pam`) and the
//! GUI bridge (`crates/pam_gui`).
//!
//! `crates/pam` depends on `pam_gui` (single-binary law: `pam gui` hands
//! the process to the Tauri event loop), so the GUI cannot depend on the
//! `pam` crate without a cycle. Everything both sides need — daemon
//! lifecycle ([`client`]), envelope building ([`request`]), advisory
//! caller identity ([`caller`]), and the base-dir resolution below —
//! lives here instead; `pam` re-exports these modules so its public
//! surface (`pam::client`, …) is unchanged.

use std::ffi::OsString;
use std::path::PathBuf;

pub mod caller;
pub mod client;
pub mod request;
pub mod service;

#[cfg(test)]
mod caller_test;
#[cfg(test)]
mod client_test;
#[cfg(test)]
mod lib_test;
#[cfg(test)]
mod request_test;
#[cfg(test)]
mod service_test;

/// The base directory every pam mode works under: `$PAM_BASE_DIR` when
/// set and non-empty, otherwise `~/.pam`. `None` only when neither the
/// override nor the home directory resolves.
///
/// The environment override is a testing/dev knob (deliberately not a
/// CLI flag): it lets a test or a scratch session point a real spawned
/// `pam daemon` process *and* the clients (CLI and GUI alike) at an
/// isolated base dir. The auto-spawned daemon inherits the client's
/// environment, so both sides always resolve the same base.
#[must_use]
pub fn default_base_dir() -> Option<PathBuf> {
    base_dir_from(std::env::var_os("PAM_BASE_DIR"), std::env::home_dir())
}

/// [`default_base_dir`] with the environment injected — the resolution
/// rule itself, unit-testable without mutating process environment
/// (which the workspace's `unsafe` denial forbids in edition 2024).
#[must_use]
pub fn base_dir_from(env_override: Option<OsString>, home: Option<PathBuf>) -> Option<PathBuf> {
    match env_override {
        Some(base) if !base.is_empty() => Some(PathBuf::from(base)),
        _ => Some(home?.join(".pam")),
    }
}
