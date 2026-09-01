//! Config sanity for the GUI shell: the pieces that must stay in lockstep
//! (dev-server port, window basics, capability grants) are asserted here so
//! a drive-by edit to one side fails fast.

use super::ping;

const TAURI_CONF: &str = include_str!("../tauri.conf.json");
const MAIN_WINDOW_CAPABILITY: &str = include_str!("../capabilities/main-window.json");

fn tauri_conf() -> serde_json::Value {
    serde_json::from_str(TAURI_CONF).expect("tauri.conf.json parses")
}

#[test]
fn ping_returns_pong() {
    assert_eq!(ping(), "pong");
}

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
fn main_window_capability_grants_ping_and_dragging() {
    let capability: serde_json::Value =
        serde_json::from_str(MAIN_WINDOW_CAPABILITY).expect("main-window.json parses");
    assert_eq!(capability["windows"], serde_json::json!(["main"]));
    let permissions = capability["permissions"]
        .as_array()
        .expect("permissions is an array");
    for needed in [
        "core:default",
        "allow-ping",
        "core:window:allow-start-dragging",
    ] {
        assert!(
            permissions.iter().any(|permission| permission == needed),
            "capability must grant {needed}"
        );
    }
}
