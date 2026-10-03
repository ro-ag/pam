//! Advisory caller identity stamped into every request [`pam_proto::Envelope`]. **Not authentication**: the
//! client inspects its own parent-process chain and cwd to guess the invoking agent and repo; the
//! daemon uses these only for attribution, filtering, and audit. A malicious local process can
//! trivially forge them — the security wall is the filesystem: only processes that can reach the
//! runtime directory (and the public socket in it) can talk to the daemon at all.
//!
//! `agent`: parent-process chain walked upward (bounded, cycle-safe), each name matched lowercased
//! by **prefix** against known agents (`claude`, `claude-code` → `claude`); nearest match wins,
//! else the immediate parent's name, else `unknown`. The table and the rule live in
//! [`pam_proto::caller`] because the daemon classifies the kernel peer's ancestry with the same
//! ones; they are re-exported here. `repo`: canonicalized cwd replaced by the repo top level on a
//! `.git` entry (directory, or file for worktrees) found walking upward — pure filesystem walk, no
//! `git`/`libgit2`; a stable project-identity marker is deliberately deferred. `pid`: the client's
//! own process id.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use pam_proto::Caller;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

pub use pam_proto::caller::{KNOWN_AGENTS, MAX_CHAIN_DEPTH, classify_chain};

/// Detects the advisory identity of the current process.
///
/// Infallible by design: every field degrades gracefully (`unknown` agent,
/// raw working-directory text) rather than failing, because identity here is
/// audit context, not a precondition.
#[must_use]
pub fn detect_caller() -> Caller {
    let pid = std::process::id();
    let agent = classify_chain(&parent_chain(pid));
    let repo = detect_repo();
    Caller { agent, repo, pid }
}

/// Finds the repository top level containing `start`, if any.
///
/// Walks `start` and its ancestors looking for a `.git` entry — a directory
/// for a normal work tree, or a file for a linked git worktree. Pure
/// filesystem walk; never shells out to `git`.
#[must_use]
pub fn find_repo_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|dir| dir.join(".git").symlink_metadata().is_ok())
        .map(Path::to_path_buf)
}

/// Names of the current process's ancestors, nearest first, bounded by
/// [`MAX_CHAIN_DEPTH`] and cycle-safe. The process itself is excluded.
fn parent_chain(own_pid: u32) -> Vec<String> {
    let mut system = System::new();
    let mut names = Vec::new();
    let mut seen = HashSet::new();
    let mut pid = Pid::from_u32(own_pid);
    // Inclusive bound: the first visit is the process itself, which
    // contributes no name.
    for _ in 0..=MAX_CHAIN_DEPTH {
        if !seen.insert(pid) {
            break;
        }
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            false,
            ProcessRefreshKind::nothing(),
        );
        let Some(process) = system.process(pid) else {
            break;
        };
        if pid.as_u32() != own_pid {
            names.push(process.name().to_string_lossy().into_owned());
        }
        let Some(parent) = process.parent() else {
            break;
        };
        pid = parent;
    }
    names
}

/// Normalized repository path for the current working directory.
///
/// Canonicalizes the working directory (falling back to the raw path when
/// canonicalization fails), then substitutes the repository top level when
/// one is found; `unknown` only when the working directory itself is
/// unreadable.
fn detect_repo() -> String {
    let Ok(cwd) = std::env::current_dir() else {
        return "unknown".to_owned();
    };
    let cwd = cwd.canonicalize().unwrap_or(cwd);
    let root = find_repo_root(&cwd).unwrap_or(cwd);
    root.to_string_lossy().into_owned()
}
