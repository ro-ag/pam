use std::fs;

use crate::caller::{classify_chain, detect_caller, find_repo_root};

fn chain(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn classify_matches_exact_agent_name() {
    assert_eq!(
        classify_chain(&chain(&["claude", "zsh", "login"])),
        "claude"
    );
}

#[test]
fn classify_nearest_ancestor_wins() {
    assert_eq!(classify_chain(&chain(&["cursor", "claude"])), "cursor");
}

#[test]
fn classify_is_case_insensitive() {
    assert_eq!(classify_chain(&chain(&["Claude"])), "claude");
}

#[test]
fn classify_matches_prefixed_variants() {
    assert_eq!(classify_chain(&chain(&["claude-code"])), "claude");
    assert_eq!(classify_chain(&chain(&["github-copilot"])), "copilot");
}

#[test]
fn classify_falls_back_to_immediate_parent() {
    assert_eq!(classify_chain(&chain(&["zsh", "login"])), "zsh");
}

#[test]
fn classify_skips_empty_names_in_fallback() {
    assert_eq!(classify_chain(&chain(&["", "bash"])), "bash");
}

#[test]
fn classify_empty_chain_is_unknown() {
    assert_eq!(classify_chain(&[]), "unknown");
}

#[test]
fn repo_root_found_from_nested_child() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("repo");
    let deep = root.join("a").join("b").join("c");
    fs::create_dir_all(&deep).expect("nested dirs");
    fs::create_dir(root.join(".git")).expect(".git dir");
    assert_eq!(find_repo_root(&deep), Some(root));
}

#[test]
fn repo_root_accepts_git_file_worktree() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("worktree");
    let deep = root.join("src");
    fs::create_dir_all(&deep).expect("nested dirs");
    fs::write(root.join(".git"), "gitdir: /elsewhere/.git/worktrees/wt").expect(".git file");
    assert_eq!(find_repo_root(&deep), Some(root));
}

#[test]
fn repo_root_none_without_git_entry() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let deep = tmp.path().join("plain").join("dir");
    fs::create_dir_all(&deep).expect("nested dirs");
    let found = find_repo_root(&deep);
    // The tempdir's own ancestors (e.g. the system temp root) carry no
    // `.git`, so nothing at or below the tempdir may be reported either.
    assert!(found.is_none_or(|root| !root.starts_with(tmp.path())));
}

#[test]
fn detect_caller_reports_self() {
    let caller = detect_caller();
    assert_eq!(caller.pid, std::process::id());
    assert!(!caller.agent.is_empty());
    assert!(!caller.repo.is_empty());
}
