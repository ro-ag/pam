//! Startup sweep of orphaned private landing workspaces.
//!
//! `freeze` creates `<workspace_root>/landing-<ulid>` and
//! [`crate::flow_service`] releases it when the ticket ends inside a run. A
//! ticket that died with the daemon and is later failed by queue recovery
//! never reaches that release, so its workspace would stay behind. The
//! sweep runs once at boot, after recovery has settled every ticket and
//! before any request can run: every workspace of the exact freeze shape
//! under an approved workspace root that no live ticket's landing session
//! names is removed. A workspace of any other shape is not ours and stays.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use pam_store::Store;

use crate::flow_service::{landing_workspace, release_workspace};
use crate::landing_policy::Snapshot as Policy;

/// Removes every orphaned landing workspace and returns how many went. A
/// policy or store that cannot be read sweeps nothing: an unreadable
/// answer is never a reason to delete.
pub(crate) async fn sweep_orphaned_workspaces(store: &Store) -> usize {
    let policy = match Policy::load(store).await {
        Ok(policy) => policy,
        Err(error) => {
            tracing::warn!(
                cause = error.cause,
                "landing policy is unreadable; leaving landing workspaces untouched"
            );
            return 0;
        }
    };
    let roots: Vec<PathBuf> = policy.workspace_roots().map(Path::to_path_buf).collect();
    if roots.is_empty() {
        return 0;
    }
    let live = match store.live_landing_session_documents().await {
        Ok(documents) => live_checktrees(&documents),
        Err(error) => {
            tracing::warn!(
                %error,
                "live landing sessions are unreadable; leaving landing workspaces untouched"
            );
            return 0;
        }
    };
    let removed =
        crate::blocking_jobs::run(crate::blocking_jobs::Kind::RepositoryIdentity, move || {
            sweep_roots(&roots, &live)
        })
        .await;
    match removed {
        Ok(removed) => removed.len(),
        Err(error) => {
            tracing::warn!(%error, "the landing workspace sweep did not run");
            0
        }
    }
}

/// The checktrees the live sessions name; a document without one names
/// nothing and protects nothing.
fn live_checktrees(documents: &[String]) -> BTreeSet<PathBuf> {
    documents
        .iter()
        .filter_map(|document| serde_json::from_str::<serde_json::Value>(document).ok())
        .filter_map(|session| {
            session
                .get("checktree")
                .and_then(serde_json::Value::as_str)
                .map(PathBuf::from)
        })
        .collect()
}

/// Walks each root once and removes every exact-shape workspace whose
/// checktree no live session names, logging each removal. Returns the
/// workspaces that are gone.
pub(crate) fn sweep_roots(roots: &[PathBuf], live: &BTreeSet<PathBuf>) -> Vec<PathBuf> {
    let mut removed = Vec::new();
    for root in roots {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let checktree = entry.path().join("tree");
            let Some(workspace) = landing_workspace(&checktree, root) else {
                continue;
            };
            if live.contains(&checktree) || !entry.path().is_dir() {
                continue;
            }
            if release_workspace(&checktree, root) {
                tracing::info!(
                    workspace = %workspace.display(),
                    "removed a landing workspace no live ticket names"
                );
                removed.push(workspace);
            } else {
                tracing::warn!(
                    workspace = %workspace.display(),
                    "an orphaned landing workspace could not be removed"
                );
            }
        }
    }
    removed
}
