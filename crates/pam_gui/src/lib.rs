//! The Tauri shell behind `pam gui`: window setup, webview context, and the
//! IPC commands the frontend may invoke.
//!
//! # Architecture
//!
//! pam ships **one binary**; the GUI is not a separate app. This crate is a
//! plain library — `crates/pam` depends on it and `pam gui` calls [`run`],
//! which hands the process to the Tauri event loop. Everything Tauri owns
//! lives here: `tauri.conf.json`, the capability files under
//! `capabilities/`, the bundle icons, and the build script that generates
//! the ACL manifest for the commands below.
//!
//! # Dev context vs embedded frontend
//!
//! Which frontend the window loads is decided at **compile time** by the
//! `embed` cargo feature (see `build.rs` for the full story):
//!
//! - default (`embed` off): the window loads the Vite dev server at
//!   `http://127.0.0.1:1420`. Dev flow: start the server
//!   (`npm --prefix frontend run dev`, or the `gui-dev` entry in
//!   `.claude/launch.json`), then `cargo run -p pam -- gui`. A plain
//!   `cargo build` never reads `frontend/dist`, so the workspace compiles
//!   from a clean checkout without npm — but such a binary (release
//!   included) shows a white window when no dev server is running.
//! - `embed` on (production): `frontend/dist` is compiled into the binary.
//!   Build with `npm --prefix frontend run build` followed by
//!   `cargo build --release -p pam --features gui-embed` (or
//!   `npm --prefix frontend run gui:build`, which does both).
//!
//! The tauri CLI (`tauri dev` / `tauri build`) is deliberately not part of
//! the flow: it expects the tauri crate to own the app binary, which
//! conflicts with the single-binary layout; the explicit cargo feature
//! replaces its `--features tauri/custom-protocol` switch.
//!
//! # Build weight
//!
//! There is no feature gate around the GUI: the owner ships one binary, so
//! CLI-only builds pay the Tauri/wry compile cost too. Accepted trade-off —
//! revisit only if workspace build times become a real problem.

#[cfg(test)]
mod lib_test;

/// IPC liveness probe: proves the frontend can reach Rust over Tauri's
/// invoke bridge. The placeholder UI calls it on mount and displays the
/// reply; real daemon IPC arrives with a later task.
#[tauri::command]
fn ping() -> &'static str {
    "pong"
}

/// Opens the pam desktop window and runs the Tauri event loop until the
/// window closes.
///
/// Must be called on the main thread (macOS requires the event loop
/// there), before any async runtime takes over the process.
///
/// # Errors
///
/// Returns an error when the platform webview runtime cannot start.
pub fn run() -> tauri::Result<()> {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![ping])
        .run(tauri::generate_context!())
}
