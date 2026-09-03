//! Config sanity for the Tauri app: the pieces that must stay in lockstep
//! (dev-server port, window basics, capability grants, bundle metadata,
//! per-platform overlays) are asserted here so a drive-by edit to one side
//! fails fast.

const TAURI_CONF: &str = include_str!("../tauri.conf.json");
const MAIN_WINDOW_CAPABILITY: &str = include_str!("../capabilities/main-window.json");
const BUILD_SCRIPT: &str = include_str!("../build.rs");
const MACOS_CONF: &str = include_str!("../tauri.macos.conf.json");
const LINUX_CONF: &str = include_str!("../tauri.linux.conf.json");
const WINDOWS_CONF: &str = include_str!("../tauri.windows.conf.json");
const DESKTOP_TEMPLATE: &str = include_str!("../linux/pam.desktop");
const NSIS_HOOKS: &str = include_str!("../nsis/hooks.nsh");

fn tauri_conf() -> serde_json::Value {
    serde_json::from_str(TAURI_CONF).expect("tauri.conf.json parses")
}

/// Every bridge command the frontend may invoke: `build.rs` mints its
/// `allow-<command>` permission and the main-window capability grants it.
const BRIDGE_COMMANDS: [&str; 6] = [
    "daemon_status",
    "admin_call",
    "request_capability",
    "daemon_stop",
    "events_subscribe",
    "read_daemon_log",
];

#[test]
fn dev_url_matches_the_vite_port() {
    // vite.config.ts pins 1420 (strictPort); .claude/launch.json advertises
    // the same port. The three must agree or the dev window loads nothing.
    let conf = tauri_conf();
    assert_eq!(conf["build"]["devUrl"], "http://127.0.0.1:1420");
}

#[test]
fn frontend_dist_points_at_the_repo_root_frontend() {
    let conf = tauri_conf();
    assert_eq!(conf["build"]["frontendDist"], "../../frontend/dist");
}

#[test]
fn main_window_has_the_scaffold_geometry() {
    let conf = tauri_conf();
    let window = &conf["app"]["windows"][0];
    assert_eq!(window["label"], "main");
    assert_eq!(window["title"], "PAM");
    assert_eq!(window["width"], 1280);
    assert_eq!(window["height"], 800);
    assert_eq!(window["minWidth"], 900);
    assert_eq!(window["minHeight"], 600);
}

#[test]
fn binary_name_stays_pam() {
    // The single-binary law: the GUI is `pam gui`, never its own executable.
    let conf = tauri_conf();
    assert_eq!(conf["mainBinaryName"], "pam");
}

#[test]
fn main_window_capability_grants_the_bridge_and_dragging() {
    let capability: serde_json::Value =
        serde_json::from_str(MAIN_WINDOW_CAPABILITY).expect("main-window.json parses");
    assert_eq!(capability["windows"], serde_json::json!(["main"]));
    let permissions = capability["permissions"]
        .as_array()
        .expect("permissions is an array");
    let mut needed = vec![
        // core:default includes core:event:default — the frontend's
        // pam://event listener rides on it.
        "core:default".to_owned(),
        "core:window:allow-start-dragging".to_owned(),
    ];
    for command in BRIDGE_COMMANDS {
        needed.push(format!("allow-{}", command.replace('_', "-")));
    }
    for permission in needed {
        assert!(
            permissions.iter().any(|granted| *granted == permission),
            "capability must grant {permission}"
        );
    }
}

#[test]
fn build_script_mints_a_permission_for_every_bridge_command() {
    for command in BRIDGE_COMMANDS {
        assert!(
            BUILD_SCRIPT.contains(&format!("\"{command}\"")),
            "build.rs AppManifest must list {command}"
        );
    }
    assert!(
        !BUILD_SCRIPT.contains("\"ping\""),
        "the ping scaffold command is gone"
    );
}

#[test]
fn bundling_is_on_with_pam_olds_metadata() {
    let conf = tauri_conf();
    assert_eq!(conf["bundle"]["active"], true);
    assert_eq!(conf["bundle"]["category"], "DeveloperTool");
    assert_eq!(conf["mainBinaryName"], "pam");
    assert_eq!(conf["build"]["beforeBuildCommand"]["cwd"], "../../frontend");
}

#[test]
fn platform_overlays_name_pam_olds_targets() {
    let parse = |s: &str| serde_json::from_str::<serde_json::Value>(s).expect("overlay parses");
    assert_eq!(
        parse(MACOS_CONF)["bundle"]["targets"],
        serde_json::json!(["app"])
    );
    assert_eq!(
        parse(MACOS_CONF)["bundle"]["macOS"]["minimumSystemVersion"],
        "12.0"
    );
    assert_eq!(
        parse(LINUX_CONF)["bundle"]["targets"],
        serde_json::json!(["appimage", "deb"])
    );
    assert_eq!(
        parse(WINDOWS_CONF)["bundle"]["targets"],
        serde_json::json!(["nsis"])
    );
    assert_eq!(
        parse(WINDOWS_CONF)["bundle"]["windows"]["nsis"]["installMode"],
        "currentUser"
    );
}

#[test]
fn desktop_entry_and_shortcuts_open_the_gui() {
    assert!(DESKTOP_TEMPLATE.lines().any(|l| l == "Exec={{exec}} gui"));
    assert!(NSIS_HOOKS.contains("NSIS_HOOK_POSTINSTALL"));
    assert_eq!(NSIS_HOOKS.matches("\"gui\"").count(), 2);
}

#[test]
fn every_bridge_command_is_built_and_granted() {
    let capability: serde_json::Value =
        serde_json::from_str(MAIN_WINDOW_CAPABILITY).expect("capability parses");
    let granted = capability["permissions"]
        .as_array()
        .expect("permissions array");
    for command in BRIDGE_COMMANDS {
        assert!(
            BUILD_SCRIPT.contains(&format!("\"{command}\"")),
            "{command} missing from build.rs"
        );
        let permission = format!("allow-{}", command.replace('_', "-"));
        assert!(
            granted.iter().any(|p| p == permission.as_str()),
            "{permission} not granted"
        );
    }
}
