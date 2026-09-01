//! Build script for the pam GUI shell.
//!
//! `tauri_build` reads `tauri.conf.json` (next to this file), validates the
//! capability files under `capabilities/`, and generates the ACL manifest
//! that the `allow-*` permissions in `capabilities/main-window.json`
//! refer to — `AppManifest::commands` below is the list of `#[tauri::command]`
//! functions that get an auto-generated `allow-<command>` permission.
//!
//! # Which frontend the binary carries (the "white window" law)
//!
//! `tauri::generate_context!` in `lib.rs` picks its webview source at
//! compile time, driven by the `custom-protocol` feature of the `tauri`
//! crate (surfaced here as the `embed` feature of this crate):
//!
//! - feature off (any plain `cargo build`, debug *or* release): the dev
//!   context is compiled in — the window loads `devUrl`
//!   (`http://127.0.0.1:1420`, the Vite dev server) and `frontend/dist` is
//!   never read, so a clean checkout builds without ever running npm.
//!   Offline, such a binary shows an empty white window; that is expected.
//! - feature on (`cargo build --release -p pam --features gui-embed`):
//!   `frontend/dist` is embedded into the binary at compile time. The dist
//!   directory must exist — run `npm --prefix frontend run build` first, or
//!   codegen aborts with a clear panic naming the missing path.

fn main() {
    let manifest = tauri_build::AppManifest::new().commands(&[
        "daemon_status",
        "admin_call",
        "request_capability",
        "daemon_stop",
        "events_subscribe",
    ]);
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest))
        .expect("failed to run the tauri build script for pam_gui");
}
