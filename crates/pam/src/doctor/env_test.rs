//! The env facts and the harness-to-profile mapping.

use std::path::PathBuf;
use std::sync::Arc;

use pam_proto::doctor::{Frontend, MAX_PATH_BYTES, Platform};

use super::Options;
use super::env::{facts, frontend, profile_for_chain};
use super::inventory::Context;
use super::os_test::FakeOs;

fn names(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn the_profile_follows_the_nearest_known_harness() {
    let name =
        |chain: &[&str]| profile_for_chain(&names(chain)).map(super::profiles::Harness::name);
    assert_eq!(name(&["zsh", "claude"]), Some("claude-code"));
    assert_eq!(name(&["node", "Claude Code"]), Some("claude-code"));
    assert_eq!(name(&["codex"]), Some("codex"));
    assert_eq!(name(&["bash", "gemini"]), Some("gemini-cli"));
    assert_eq!(name(&["copilot"]), Some("copilot-cli"));
    assert_eq!(name(&["github-copilot"]), Some("copilot-cli"));
    // A known agent without a profile of its own gets the generic fragment.
    assert_eq!(name(&["cursor"]), Some("sandbox-exec"));
    assert_eq!(name(&["zsh", "login"]), None);
    assert_eq!(name(&[]), None);
}

#[test]
fn the_frontend_is_the_build_feature() {
    let expected = if cfg!(feature = "gui-embed") {
        Frontend::Embedded
    } else {
        Frontend::DevelopmentServer
    };
    assert_eq!(frontend(), expected);
}

#[test]
fn the_facts_are_the_clients_view_fitted_to_the_bounds() {
    let base = PathBuf::from("/tmp/pamdoc-base");
    let os = FakeOs::unsandboxed()
        .with_env("PAM_SOCKET_DIR", "/tmp/pamdoc-session")
        .with_env("PAM_BASE_DIR", &"b".repeat(2000));
    let context = Context::new(Platform::Macos, &Options::new(base), Arc::new(os)).unwrap();
    let env = facts(&context, vec!["zsh\n".to_owned(), "x".repeat(500)]);
    assert_eq!(env.socket_dir.as_deref(), Some("/tmp/pamdoc-session"));
    assert_eq!(
        env.base_dir_override.as_deref().map(str::len),
        Some(MAX_PATH_BYTES)
    );
    assert_eq!(env.resolved_base, "/tmp/pamdoc-base");
    assert_eq!(env.resolved_endpoint, "/tmp/pamdoc-session/pam.sock");
    assert_eq!(env.client_version, pam_daemon::daemon::DAEMON_VERSION);
    assert_eq!(env.exe.as_deref(), Some("/usr/local/bin/pam"));
    assert_eq!(env.cwd_repo, None, "no working directory, no repository");
    assert_eq!(env.harness_chain[0], "zsh ");
    assert_eq!(env.harness_chain[1].len(), 256);
}

#[test]
fn the_repository_comes_from_the_working_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::create_dir_all(repo.join("src")).unwrap();
    let mut os = FakeOs::unsandboxed();
    os.cwd = Some(repo.join("src"));
    let context = Context::new(
        Platform::Macos,
        &Options::new(PathBuf::from("/tmp/pamdoc-base")),
        Arc::new(os),
    )
    .unwrap();
    let env = facts(&context, Vec::new());
    assert_eq!(
        env.cwd_repo.map(PathBuf::from),
        Some(repo.canonicalize().unwrap())
    );
    assert!(env.harness_chain.is_empty());
}
