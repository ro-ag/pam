const COMMANDS: &[&str] = &[
    "bootstrap",
    "catalog",
    "activate_project",
    "refresh_project",
    "start_daemon",
    "stop_daemon",
    "decide_approval",
    "load_evidence",
    "load_flow_workspace",
    "open_flow",
    "validate_flow",
    "save_flow",
];

fn main() {
    let manifest = tauri_build::AppManifest::new().commands(COMMANDS);
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest))
        .expect("failed to build the PAM desktop shell");
}
