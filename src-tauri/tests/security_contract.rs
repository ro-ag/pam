use std::{env, fs, path::Path};

use serde_json::{Value, json};

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
    "daemon_activity",
    "caller_registry",
    "load_skill_inventory",
    "manage_skill_library",
    "load_skill_audit",
    "run_skill_audit",
    "open_flow",
    "validate_flow",
    "save_flow",
];

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: impl AsRef<Path>) -> String {
    let path = path.as_ref();
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
        .replace("\r\n", "\n")
}

fn read_json(path: impl AsRef<Path>) -> Value {
    let path = path.as_ref();
    serde_json::from_str(&read(path))
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

#[test]
fn main_window_is_local_and_has_only_bounded_permissions() {
    let capability = read_json(manifest_dir().join("capabilities/main-window.json"));
    let mut expected = COMMANDS
        .iter()
        .map(|command| Value::String(format!("allow-{}", command.replace('_', "-"))))
        .collect::<Vec<_>>();
    expected.push(Value::String("core:app:allow-set-app-theme".to_owned()));

    assert_eq!(capability["local"], true);
    assert_eq!(capability["windows"], json!(["main"]));
    assert_eq!(capability["permissions"], Value::Array(expected));
    assert!(capability.get("remote").is_none());
}

#[test]
fn build_manifest_and_handler_expose_the_same_bounded_commands() {
    let build = read(manifest_dir().join("build.rs"));
    let shell = read(manifest_dir().join("src/lib.rs"));
    let commands = read(manifest_dir().join("src/commands.rs"));
    let manifest = read(manifest_dir().join("Cargo.toml"));
    let workspace_manifest = read(manifest_dir().join("../Cargo.toml"));
    let runtime_dependencies = manifest
        .split_once("[dependencies]")
        .and_then(|(_, rest)| rest.split_once("[dev-dependencies]"))
        .map(|(dependencies, _)| dependencies)
        .expect("runtime dependency section must be bounded");

    assert_eq!(
        commands.matches("#[tauri::command]").count(),
        COMMANDS.len()
    );
    for command in COMMANDS {
        assert!(build.contains(&format!("\"{command}\"")));
        assert!(shell.contains(&format!("commands::{command}")));
        assert!(commands.contains(&format!("fn {command}(")));
    }
    assert!(build.contains("AppManifest::new().commands(COMMANDS)"));
    assert!(workspace_manifest.contains("tauri = { version = \"=2.11.5\""));
    assert!(workspace_manifest.contains("tauri-build = { version = \"=2.6.3\""));
    assert!(!commands.contains("serde_json"));
    for forbidden in [
        "tauri-plugin-shell",
        "tauri-plugin-fs",
        "tauri-plugin-http",
        "serde_json",
    ] {
        assert!(!runtime_dependencies.contains(forbidden));
    }
}

#[test]
fn production_window_and_csp_are_exact_and_remote_free() {
    let config = read_json(manifest_dir().join("tauri.conf.json"));
    let vite_config = read(manifest_dir().join("../frontend/vite.config.ts"));
    let windows = config["app"]["windows"]
        .as_array()
        .expect("windows must be an array");
    let csp = config["app"]["security"]["csp"]
        .as_str()
        .expect("production CSP must be text");

    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0]["label"], "main");
    assert_eq!(windows[0]["width"], 1_440);
    assert_eq!(windows[0]["height"], 900);
    assert_eq!(windows[0]["minWidth"], 320);
    assert_eq!(windows[0]["minHeight"], 600);
    assert_eq!(windows[0]["backgroundColor"], "#f6f3ec");
    assert_eq!(windows[0]["theme"], "Light");
    assert_eq!(windows[0]["decorations"], true);
    assert_eq!(windows[0]["hiddenTitle"], true);
    assert_eq!(windows[0]["titleBarStyle"], "Overlay");
    assert_eq!(
        config["app"]["security"]["capabilities"],
        json!(["main-window"])
    );
    assert_eq!(
        csp,
        "default-src 'self'; connect-src ipc: http://ipc.localhost; font-src 'self'; img-src 'self'; object-src 'none'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-src 'none'; frame-ancestors 'none'; form-action 'none'"
    );
    for forbidden in ["'unsafe-inline'", "ws://", "wss://", "https://"] {
        assert!(!csp.contains(forbidden));
    }
    assert!(
        vite_config.contains("assetsInlineLimit: 0"),
        "production assets must be emitted as files because font-src permits only 'self'"
    );
}

#[test]
fn bundle_contract_covers_only_the_requested_desktop_targets() {
    let config = read_json(manifest_dir().join("tauri.conf.json"));
    let macos = read_json(manifest_dir().join("tauri.macos.conf.json"));
    let linux = read_json(manifest_dir().join("tauri.linux.conf.json"));
    let windows = read_json(manifest_dir().join("tauri.windows.conf.json"));

    // Single-binary product: the bundle ships no sidecar executables.
    assert_eq!(config["bundle"]["externalBin"], json!(null));
    assert_eq!(config["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(config["bundle"]["category"], "DeveloperTool");
    assert_eq!(
        config["bundle"]["icon"],
        json!(["icons/icon.png", "icons/icon.ico", "icons/icon.icns"])
    );
    assert_eq!(
        fs::read(manifest_dir().join("icons/icon.ico"))
            .expect("Windows builds require an ICO application icon")
            .get(..4),
        Some([0, 0, 1, 0].as_slice())
    );
    assert_eq!(
        fs::read(manifest_dir().join("icons/icon.icns"))
            .expect("macOS builds require an ICNS application icon")
            .get(..4),
        Some(b"icns".as_slice())
    );
    assert_eq!(macos["bundle"]["macOS"]["minimumSystemVersion"], "12.0");
    assert_eq!(macos["bundle"]["targets"], json!(["app"]));
    assert!(
        manifest_dir()
            .join("../tools/package-macos-dmg.sh")
            .is_file(),
        "the headless DMG packager must be present"
    );
    assert_eq!(linux["bundle"]["targets"], json!(["appimage", "deb"]));
    assert_eq!(windows["bundle"]["targets"], json!(["nsis"]));
    assert_eq!(
        windows["bundle"]["windows"]["nsis"]["installMode"],
        "currentUser"
    );
}
