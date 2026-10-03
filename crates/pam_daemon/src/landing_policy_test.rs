use crate::landing_policy::{Snapshot, valid_ref};
use crate::managed_policy::PolicyView;
use pam_store::Store;
use serde_json::json;

#[test]
fn ref_targets_cannot_be_options_revisions_or_wildcards() {
    for value in [
        "--all",
        "main..other",
        "HEAD~1",
        "branch@{1}",
        "refs/*",
        "a//b",
        "a.lock",
        "a/.b",
        "a b",
    ] {
        assert!(!valid_ref(value), "{value}");
    }
    assert!(valid_ref("feat/approved-work"));
}

#[tokio::test]
async fn missing_policy_denies_and_stale_editor_cannot_overwrite() {
    let store = Store::open_in_memory().await.unwrap();
    let base = tempfile::tempdir().unwrap();
    let current = Snapshot::load(&store).await.unwrap();
    assert!(current.repository(base.path()).is_err());
    let stale = json!({"expected_revision":"stale", "repositories":[]});
    assert_eq!(
        Snapshot::save(&store, &PolicyView::unmanaged(), &stale, base.path())
            .await
            .err()
            .unwrap()
            .cause(),
        "landing_policy_changed"
    );
    let valid = json!({"expected_revision":current.revision,"repositories":[]});
    assert!(
        Snapshot::save(&store, &PolicyView::unmanaged(), &valid, base.path())
            .await
            .is_ok()
    );
    let unknown = json!({"expected_revision":current.revision,"repositories":[],"grant_all":true});
    assert_eq!(
        Snapshot::save(&store, &PolicyView::unmanaged(), &unknown, base.path())
            .await
            .err()
            .unwrap()
            .cause(),
        "landing_policy_invalid"
    );
}

// --- The managed policy ------------------------------------------------------

/// A landing recipe for `repo` on `server`, with `permissions`.
fn recipe(
    repo: &std::path::Path,
    workspace: &std::path::Path,
    server: &str,
    permissions: &serde_json::Value,
) -> serde_json::Value {
    json!({"root":repo,"repository":"https://github.com/org/repo","github_server":server,
        "github_repository":"org/repo","base":"main","branches":["feature/work"],
        "workspace_root":workspace,
        "checks":[{"name":"test","argv":["cargo","test"],"timeout_seconds":300}],
        "required_checks":["ci"],"main_checks":["ci"],"permissions":permissions})
}

/// Canonical repository, workspace and protected-base directories; the
/// workspace is private, as a save requires.
fn landing_dirs() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let (repo, workspace, protected) = (root.join("repo"), root.join("work"), root.join("pam"));
    for directory in [&repo, &workspace, &protected] {
        std::fs::create_dir(directory).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    (temp, repo, workspace, protected)
}

fn landing_view() -> PolicyView {
    crate::scope_policy_test::view(&json!({
        "version": 1,
        "revision": "land-1",
        "landing": {
            "max_permissions": { "merge": false },
            "allowed_github_servers": ["api.github.com"]
        }
    }))
}

#[tokio::test]
async fn the_effective_landing_document_caps_permissions_and_drops_foreign_servers() {
    let (_temp, repo, workspace, _protected) = landing_dirs();
    let other = repo.parent().unwrap().join("other");
    let other_work = repo.parent().unwrap().join("other-work");
    std::fs::create_dir(&other).unwrap();
    std::fs::create_dir(&other_work).unwrap();
    let all = json!({"push":true,"create_pr":true,"merge":true,"sync":true});
    let store = Store::open_in_memory().await.unwrap();
    let stored = json!({"version":1,"repositories":[
        recipe(&repo, &workspace, "https://api.github.com/", &all),
        recipe(&other, &other_work, "https://github.example.com/", &all),
    ]})
    .to_string();
    store
        .set_setting("flows.landing_policy", &stored)
        .await
        .unwrap();
    let view = landing_view();

    let user = Snapshot::load(&store).await.unwrap();
    let effective = Snapshot::load_effective(&store, &view).await.unwrap();
    assert_eq!(
        effective.revision, user.revision,
        "the revision is the stored document's"
    );
    let kept = effective.repository(&repo).unwrap();
    assert!(kept.permissions.push && kept.permissions.create_pr && kept.permissions.sync);
    assert!(!kept.permissions.merge, "the ceiling caps merge off");
    assert!(effective.ceiling_forbids("merge") && !effective.ceiling_forbids("push"));
    let error = effective.repository(&other).err().unwrap();
    assert_eq!(error.cause, crate::managed_policy::CAUSE_POLICY_DENIED);
    assert!(user.repository(&other).unwrap().permissions.merge);
    assert_eq!(
        store
            .get_setting("flows.landing_policy")
            .await
            .unwrap()
            .as_deref(),
        Some(stored.as_str()),
        "the stored document is never rewritten"
    );

    let body = user.managed_response(&view, &effective);
    assert_eq!(body["repositories"].as_array().unwrap().len(), 2);
    assert_eq!(
        body["effective"]["repositories"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        body["effective"]["max_permissions"]["value"]["merge"],
        false
    );
    assert_eq!(body["effective"]["max_permissions"]["source"], "policy");
    assert_eq!(body["effective"]["max_permissions"]["clamped"], true);
    assert_eq!(
        body["effective"]["allowed_github_servers"]["constraint"]["landing.allowed_github_servers"],
        json!(["api.github.com"])
    );
    assert_eq!(body["landing_policy_dropped"][0]["root"], json!(other));
    assert_eq!(
        body["landing_policy_dropped"][0]["key"],
        "landing.allowed_github_servers"
    );

    // No policy: nothing is capped or dropped.
    let plain = Snapshot::load_effective(&store, &PolicyView::unmanaged())
        .await
        .unwrap();
    assert!(plain.repository(&other).unwrap().permissions.merge);
}

#[tokio::test]
async fn a_landing_save_above_the_ceiling_or_to_a_foreign_server_is_refused() {
    use crate::landing_policy::SaveRefusal;
    use crate::managed_policy::{CAUSE_POLICY_FROZEN, CAUSE_POLICY_NOT_ALLOWED, Key};
    let (_temp, repo, workspace, protected) = landing_dirs();
    let store = Store::open_in_memory().await.unwrap();
    let view = landing_view();
    let current = Snapshot::load(&store).await.unwrap();
    let merge = json!({"push":true,"create_pr":true,"merge":true,"sync":false});
    let update = json!({"expected_revision": current.revision, "repositories": [
        recipe(&repo, &workspace, "https://api.github.com/", &merge)
    ]});
    let Err(SaveRefusal::Managed(refusal)) =
        Snapshot::save(&store, &view, &update, &protected).await
    else {
        panic!("the ceiling refuses");
    };
    assert_eq!(refusal.cause, CAUSE_POLICY_NOT_ALLOWED);
    assert_eq!(refusal.key, Key::LandingMaxPermissions);
    assert!(
        refusal.detail.contains("merge for")
            && refusal.detail.contains("(landing.max_permissions)")
            && refusal.detail.contains("rev land-1"),
        "{}",
        refusal.detail
    );
    let foreign = json!({"expected_revision": current.revision, "repositories": [
        recipe(&repo, &workspace, "https://github.example.com/",
            &json!({"push":true,"create_pr":false,"merge":false,"sync":false}))
    ]});
    let Err(SaveRefusal::Managed(refusal)) =
        Snapshot::save(&store, &view, &foreign, &protected).await
    else {
        panic!("the server allowlist refuses");
    };
    assert_eq!(refusal.key, Key::LandingAllowedGithubServers);
    assert!(
        store
            .get_setting("flows.landing_policy")
            .await
            .unwrap()
            .is_none(),
        "nothing was written"
    );

    // A held ceiling freezes a save that adds anything.
    let held = crate::scope_policy_test::view(&json!({
        "version": 1, "landing": { "max_permissions": { "merge": "no" } }
    }));
    assert!(held.is_held(Key::LandingMaxPermissions));
    let Err(SaveRefusal::Managed(refusal)) =
        Snapshot::save(&store, &held, &foreign, &protected).await
    else {
        panic!("the held key refuses");
    };
    assert_eq!(refusal.cause, CAUSE_POLICY_FROZEN);

    // Within the ceiling the save goes through (the workspace check is
    // qualified on unix only).
    #[cfg(unix)]
    {
        let fine = json!({"expected_revision": current.revision, "repositories": [
            recipe(&repo, &workspace, "https://api.github.com/",
                &json!({"push":true,"create_pr":true,"merge":false,"sync":true}))
        ]});
        let saved = Snapshot::save(&store, &view, &fine, &protected).await;
        assert!(saved.is_ok(), "{:?}", saved.err());
        // Removing the recipe only narrows: it passes the held key.
        let removal = json!({"expected_revision": saved.unwrap().revision, "repositories": []});
        assert!(
            Snapshot::save(&store, &held, &removal, &protected)
                .await
                .is_ok()
        );
    }
}
