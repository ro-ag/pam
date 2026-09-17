//! The bare-launch rule: a double-clicked `.app` opens the GUI, a bare
//! terminal launch stays a CLI.

use std::path::Path;

use crate::launched_from_app_bundle;

#[test]
fn a_binary_inside_an_app_bundle_wants_the_gui() {
    assert!(launched_from_app_bundle(Path::new(
        "/Applications/pam.app/Contents/MacOS/pam"
    )));
}

#[test]
fn a_plain_binary_stays_a_cli() {
    assert!(!launched_from_app_bundle(Path::new("/usr/local/bin/pam")));
    assert!(!launched_from_app_bundle(Path::new(
        "/tmp/pam.app.backup/pam"
    )));
    assert!(!launched_from_app_bundle(Path::new(
        "/tmp/pam.application/pam"
    )));
}

#[test]
fn the_playbook_carries_the_whole_agent_loop() {
    for marker in [
        "pam status --json",
        "pam flow list --json",
        "pam flow inspect <id> key=value --json",
        "pam flow run <id> key=value --no-wait --json",
        "pam wait <ticket> --json",
        "pam flow result <ticket> --json",
        "pam evidence read",
        "PAM_SOCKET_DIR",
        "input_unknown",
        "AGENTS.md",
    ] {
        assert!(
            crate::PLAYBOOK.contains(marker),
            "the playbook must teach `{marker}`"
        );
    }
    assert!(
        !crate::PLAYBOOK.contains("admin."),
        "the playbook never points an agent at the admin surface"
    );
}
