use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pam_store::{Actor, AuditEntry, Decision, RequestState, Store};

use super::landing_sweep::{sweep_orphaned_workspaces, sweep_roots};

const SOURCE: &str = "https://github.test/team/repo.git";
const SERVER: &str = "https://api.github.test/";

/// A canonical temp root with an approved repository and a private
/// workspace root, and the landing policy that names them.
struct Fixture {
    _dirs: tempfile::TempDir,
    repo: PathBuf,
    workspace: PathBuf,
    store: Arc<Store>,
}

impl Fixture {
    async fn new() -> Self {
        let dirs = tempfile::tempdir().unwrap();
        let root = dirs.path().canonicalize().unwrap();
        let repo = root.join("repo");
        let workspace = root.join("workspaces");
        std::fs::create_dir(&repo).unwrap();
        std::fs::create_dir(&workspace).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let store = Arc::new(Store::open_in_memory().await.unwrap());
        let policy = serde_json::json!({"version":1,"repositories":[{"root":repo,"repository":SOURCE,"github_server":SERVER,"github_repository":"team/repo","base":"main","branches":["feature/work"],"workspace_root":workspace,"checks":[{"name":"local","argv":["true"],"timeout_seconds":10}],"required_checks":["ci"],"main_checks":["ci"],"permissions":{"push":true,"create_pr":true,"merge":true,"sync":true}}]});
        store
            .set_setting("flows.landing_policy", &policy.to_string())
            .await
            .unwrap();
        Self {
            _dirs: dirs,
            repo,
            workspace,
            store,
        }
    }

    /// A freeze-shaped workspace under the approved root; returns its
    /// checktree, which is what a landing session records.
    fn workspace(&self) -> PathBuf {
        let checktree = self
            .workspace
            .join(format!("landing-{}", ulid::Ulid::new()))
            .join("tree");
        std::fs::create_dir_all(&checktree).unwrap();
        std::fs::write(checktree.join("file"), "frozen\n").unwrap();
        checktree
    }

    /// A running `flow.run` ticket whose landing session names `checktree`.
    async fn ticket(&self, id: &str, checktree: &Path) {
        let repo = self.repo.to_string_lossy().into_owned();
        self.store
            .insert_admitted_request(id, "flow.run", &repo, "claude", "{}", None, 10_000)
            .await
            .unwrap();
        assert!(
            self.store
                .authorize_queued_request(id, &repo, 0)
                .await
                .unwrap()
        );
        assert!(self.store.start_queued_request(id, 0).await.unwrap());
        let document = serde_json::json!({"version":1,"checktree":checktree}).to_string();
        assert!(
            self.store
                .save_landing_session(id, None, &document, 0)
                .await
                .unwrap()
        );
    }

    /// What queue recovery does to a ticket that died with the daemon.
    async fn fail(&self, id: &str) {
        assert!(
            self.store
                .finish_request(
                    id,
                    RequestState::Failed,
                    Some("lease_expired"),
                    AuditEntry {
                        action: "recovery_refusal",
                        decision: Decision::Refuse,
                        actor: Actor::System,
                        detail: Some("lease_expired"),
                    },
                )
                .await
                .unwrap()
        );
    }
}

#[tokio::test]
async fn the_sweep_removes_workspaces_of_terminal_and_unknown_tickets_only() {
    let fixture = Fixture::new().await;
    let live = fixture.workspace();
    let died = fixture.workspace();
    let unknown = fixture.workspace();
    fixture.ticket("live", &live).await;
    fixture.ticket("died", &died).await;
    fixture.fail("died").await;
    // Not ours: a foreign directory and a landing-named one without a
    // valid ulid keep their contents.
    let foreign = fixture.workspace.join("scratch");
    std::fs::create_dir(&foreign).unwrap();
    let odd = fixture.workspace.join("landing-not-a-ulid").join("tree");
    std::fs::create_dir_all(&odd).unwrap();

    assert_eq!(sweep_orphaned_workspaces(&fixture.store).await, 2);

    assert!(live.is_dir(), "a live ticket keeps its workspace");
    assert!(
        !died.parent().unwrap().exists(),
        "a ticket recovery failed releases its workspace"
    );
    assert!(
        !unknown.parent().unwrap().exists(),
        "a workspace no session names is an orphan"
    );
    assert!(foreign.is_dir());
    assert!(odd.is_dir());

    // A second boot finds nothing to do.
    assert_eq!(sweep_orphaned_workspaces(&fixture.store).await, 0);
    assert!(live.is_dir());
}

#[tokio::test]
async fn the_sweep_touches_nothing_without_a_policy_or_with_a_broken_one() {
    let fixture = Fixture::new().await;
    let orphan = fixture.workspace();

    fixture
        .store
        .set_setting("flows.landing_policy", "{\"version\":7}")
        .await
        .unwrap();
    assert_eq!(sweep_orphaned_workspaces(&fixture.store).await, 0);
    assert!(orphan.is_dir(), "an unreadable policy never deletes");

    let bare = Store::open_in_memory().await.unwrap();
    assert_eq!(sweep_orphaned_workspaces(&bare).await, 0);
    assert!(orphan.is_dir(), "no approved roots means nothing to sweep");
}

#[test]
fn the_walk_applies_the_exact_freeze_shape_guard_per_root() {
    let dirs = tempfile::tempdir().unwrap();
    let root = dirs.path().canonicalize().unwrap();
    let ulid = ulid::Ulid::new().to_string();
    let orphan = root.join(format!("landing-{ulid}"));
    std::fs::create_dir_all(orphan.join("tree")).unwrap();
    let kept = root.join(format!("landing-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(kept.join("tree")).unwrap();
    let file = root.join(format!("landing-{}", ulid::Ulid::new()));
    std::fs::write(&file, "not a directory").unwrap();
    let other = root.join("landing-");
    std::fs::create_dir(&other).unwrap();
    let live = BTreeSet::from([kept.join("tree")]);

    let removed = sweep_roots(std::slice::from_ref(&root), &live);

    assert_eq!(removed, vec![orphan.clone()]);
    assert!(!orphan.exists());
    assert!(kept.join("tree").is_dir());
    assert!(
        file.is_file(),
        "a file is not a workspace, whatever its name"
    );
    assert!(other.is_dir());
    // A root that does not exist is skipped, not an error.
    assert!(sweep_roots(&[root.join("missing")], &live).is_empty());
}
