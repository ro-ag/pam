//! Advisory caller identity stamped into every request [`Envelope`].
//!
//! # This is not authentication
//!
//! Everything in this module is **advisory, self-reported context**: the
//! client inspects its own parent-process chain to guess which agent invoked
//! it and normalizes its working directory to name the repository it acts on.
//! The daemon uses these values for attribution, filtering, and audit — and
//! for nothing else. A malicious local process can trivially forge them.
//! The security wall is the filesystem: only processes that can reach the
//! runtime directory (and its `pam.sock` socket) can talk to the daemon at
//! all.
//!
//! # Detection rules
//!
//! - `agent`: the parent-process chain is walked upward (bounded depth,
//!   cycle-safe) and each process name is matched, lowercased, by **prefix**
//!   against a table of known agents — so `Claude`, `claude`, and
//!   `claude-code` all classify as `claude`. The nearest matching ancestor
//!   wins. With no match, the immediate parent's name (typically a shell such
//!   as `zsh`) is reported so the audit trail still says something; an empty
//!   chain reports `unknown`.
//! - `repo`: the canonicalized current working directory, replaced by the
//!   repository top level when a `.git` entry (directory, or file for git
//!   worktrees) is found walking upward. Detected by a pure filesystem walk —
//!   no `git` subprocess, no `libgit2`. The value stays normalized path text;
//!   a stable project-identity marker is deliberately deferred.
//! - `pid`: the client's own process id.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use pam_proto::Caller;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

/// Upper bound on how many ancestors the parent-process walk visits.
const MAX_CHAIN_DEPTH: usize = 10;

/// Known agent process-name prefixes and the canonical agent name each one
/// reports as. Matched lowercased, nearest ancestor first.
const KNOWN_AGENTS: &[(&str, &str)] = &[
    ("claude", "claude"),
    ("github-copilot", "copilot"),
    ("copilot", "copilot"),
    ("codex", "codex"),
    ("cursor", "cursor"),
    ("gemini", "gemini"),
    ("aider", "aider"),
];

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

/// Classifies a parent-process chain (nearest ancestor first) into an agent
/// name.
///
/// Each name is lowercased and matched by prefix against the known-agent
/// table; the first (nearest) match wins. Without a match, the first
/// non-empty name in the chain — the immediate parent, typically a shell —
/// is returned verbatim, and an effectively empty chain yields `unknown`.
#[must_use]
pub fn classify_chain(names: &[String]) -> String {
    for name in names {
        let lowered = name.to_lowercase();
        for (prefix, canonical) in KNOWN_AGENTS {
            if lowered.starts_with(prefix) {
                return (*canonical).to_owned();
            }
        }
    }
    names
        .iter()
        .find(|name| !name.is_empty())
        .cloned()
        .unwrap_or_else(|| "unknown".to_owned())
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
