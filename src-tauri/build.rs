const COMMANDS: &[&str] = &[
    "bootstrap",
    "catalog",
    "activate_project",
    "refresh_project",
    "start_daemon",
    "stop_daemon",
    "register_gui_caller",
    "decide_approval",
    "load_evidence",
    "load_flow_workspace",
    "load_skill_inventory",
    "load_skill_audit",
    "run_skill_audit",
    "open_flow",
    "validate_flow",
    "save_flow",
];

fn main() {
    let manifest = tauri_build::AppManifest::new().commands(COMMANDS);
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest))
        .expect("failed to build the PAM desktop shell");
}
