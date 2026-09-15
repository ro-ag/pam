//! Build script for the pam app crate: produces the `pam` binary the Tauri CLI expects.
//! `tauri_build` reads `tauri.conf.json`, validates `capabilities/`, and generates the ACL
//! manifest that `allow-*` permissions in `capabilities/main-window.json` refer to —
//! `AppManifest::commands` below lists the `#[tauri::command]` functions granted an
//! auto-generated `allow-<command>` permission.
//!
//! Which frontend ships is fixed at compile time by the `tauri` crate's `custom-protocol` feature
//! (via `tauri::generate_context!`): off (any plain `cargo build`) loads `devUrl`
//! (`http://127.0.0.1:1420`) and never reads `frontend/dist`, so a clean checkout builds without
//! npm; offline this shows an expected empty white window. On (this crate's `gui-embed` feature)
//! embeds `frontend/dist` at compile time — run `npm --prefix frontend run build` first, or
//! codegen panics naming the missing path.

fn main() {
    let manifest = tauri_build::AppManifest::new().commands(&[
        "daemon_status",
        "admin_call",
        "request_capability",
        "daemon_stop",
        "events_subscribe",
        "read_daemon_log",
        "service_status",
        "service_install",
        "service_uninstall",
    ]);
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest))
        .expect("failed to run the tauri build script for pam");
}
