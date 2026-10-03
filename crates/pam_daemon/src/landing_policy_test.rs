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

/// A document saved before `git_path`, `merge_method` and pinned checks
/// existed keeps its exact revision: unset fields are omitted and a
/// name-only check stays a plain string, so the canonical bytes are what the
/// earlier shape (mirrored here) produced.
#[tokio::test]
async fn a_legacy_document_keeps_its_revision() {
    #[derive(serde::Serialize)]
    struct LegacyCheck {
        name: String,
        argv: Vec<String>,
        timeout_seconds: u16,
    }
    #[derive(serde::Serialize)]
    #[allow(clippy::struct_excessive_bools)] // The stored shape: four independent grants.
    struct LegacyPermissions {
        push: bool,
        create_pr: bool,
        merge: bool,
        sync: bool,
    }
    #[derive(serde::Serialize)]
    struct LegacyRepository {
        root: std::path::PathBuf,
        repository: String,
        github_server: String,
        github_repository: String,
        base: String,
        branches: Vec<String>,
        workspace_root: std::path::PathBuf,
        read_cache_roots: Vec<std::path::PathBuf>,
        checks: Vec<LegacyCheck>,
        required_checks: Vec<String>,
        main_checks: Vec<String>,
        permissions: LegacyPermissions,
    }
    #[derive(serde::Serialize)]
    struct LegacyDocument {
        version: u8,
        repositories: Vec<LegacyRepository>,
    }
    let (_temp, repo, workspace, _protected) = landing_dirs();
    let store = Store::open_in_memory().await.unwrap();
    let legacy = LegacyDocument {
        version: 1,
        repositories: vec![LegacyRepository {
            root: repo.clone(),
            repository: "https://github.com/org/repo".into(),
            github_server: "https://api.github.com/".into(),
            github_repository: "org/repo".into(),
            base: "main".into(),
            branches: vec!["feature/work".into()],
            workspace_root: workspace,
            read_cache_roots: Vec::new(),
            checks: vec![LegacyCheck {
                name: "test".into(),
                argv: vec!["cargo".into(), "test".into()],
                timeout_seconds: 300,
            }],
            required_checks: vec!["ci".into()],
            main_checks: vec!["ci".into(), "deploy".into()],
            permissions: LegacyPermissions {
                push: true,
                create_pr: true,
                merge: true,
                sync: true,
            },
        }],
    };
    let canonical = serde_json::to_string(&legacy).unwrap();
    store
        .set_setting("flows.landing_policy", &canonical)
        .await
        .unwrap();
    let snapshot = Snapshot::load(&store).await.unwrap();
    assert_eq!(
        snapshot.revision,
        pam_compact::sha256_hex(canonical.as_bytes()),
        "the revision an in-flight landing froze still matches"
    );
    let body = snapshot.response();
    assert!(body["git_path"].is_null());
    let recipe = &body["repositories"][0];
    assert!(recipe.get("merge_method").is_none(), "{recipe}");
    assert_eq!(recipe["main_checks"], json!(["ci", "deploy"]));
    let repository = snapshot.repository(&repo).unwrap();
    assert_eq!(
        repository.merge_method(),
        pam_connectors::github_landing::MergeMethod::Squash,
        "squash is the default"
    );
    assert!(repository.configured_git().is_none());
}

/// Pinned checks and the merge method round-trip; a duplicate check name,
/// an app id of zero and an unknown merge method are refused.
#[tokio::test]
async fn pinned_checks_and_merge_methods_are_validated() {
    use pam_connectors::github_landing::{MergeMethod, RequiredCheck};
    let (_temp, repo, workspace, _protected) = landing_dirs();
    let store = Store::open_in_memory().await.unwrap();
    let all = json!({"push":true,"create_pr":true,"merge":true,"sync":true});
    let mut pinned = recipe(&repo, &workspace, "https://api.github.com/", &all);
    pinned["required_checks"] = json!(["lint", {"name":"ci","app_id":15368}]);
    pinned["merge_method"] = json!("rebase");
    store
        .set_setting(
            "flows.landing_policy",
            &json!({"version":1,"repositories":[pinned.clone()]}).to_string(),
        )
        .await
        .unwrap();
    let snapshot = Snapshot::load(&store).await.unwrap();
    let repository = snapshot.repository(&repo).unwrap();
    assert_eq!(
        repository.required_checks,
        vec![
            RequiredCheck::named("lint"),
            RequiredCheck::pinned("ci", 15368)
        ]
    );
    assert_eq!(repository.merge_method(), MergeMethod::Rebase);
    for (field, value) in [
        ("required_checks", json!(["ci", {"name":"ci","app_id":1}])),
        ("required_checks", json!([{"name":"ci","app_id":0}])),
        ("merge_method", json!("fast_forward")),
    ] {
        let mut bad = pinned.clone();
        bad[field] = value.clone();
        store
            .set_setting(
                "flows.landing_policy",
                &json!({"version":1,"repositories":[bad]}).to_string(),
            )
            .await
            .unwrap();
        assert_eq!(
            Snapshot::load(&store).await.err().unwrap().cause,
            "landing_policy_invalid",
            "{field}: {value}"
        );
    }
}

/// The Git path in Settings is saved only when it passes the broker's trust
/// check; a group-writable one is refused before anything is written.
#[cfg(unix)]
#[tokio::test]
async fn a_git_path_is_saved_only_when_trusted() {
    use std::os::unix::fs::PermissionsExt;
    let (_temp, repo, workspace, protected) = landing_dirs();
    let root = repo.parent().unwrap();
    let bin = root.join("bin");
    std::fs::create_dir(&bin).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let git = bin.join("git");
    std::fs::write(&git, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o775)).unwrap();
    let store = Store::open_in_memory().await.unwrap();
    let current = Snapshot::load(&store).await.unwrap();
    let permissions = json!({"push":true,"create_pr":true,"merge":true,"sync":true});
    let update = |revision: &str| {
        json!({"expected_revision": revision, "git_path": git,
            "repositories": [recipe(&repo, &workspace, "https://api.github.com/", &permissions)]})
    };
    let refused = Snapshot::save(
        &store,
        &PolicyView::unmanaged(),
        &update(&current.revision),
        &protected,
    )
    .await
    .err()
    .unwrap();
    assert_eq!(refused.cause(), "landing_git_untrusted");
    assert!(
        store
            .get_setting("flows.landing_policy")
            .await
            .unwrap()
            .is_none()
    );
    std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755)).unwrap();
    // The fixture tree's ancestors must be trusted too; skip where the
    // temporary directory itself is not (a shared, group-writable TMPDIR).
    if crate::landing_git::resolve_broker_git(
        Some((&git, crate::landing_git::GitSource::Settings)),
        &protected,
    )
    .is_err()
    {
        return;
    }
    let saved = Snapshot::save(
        &store,
        &PolicyView::unmanaged(),
        &update(&current.revision),
        &protected,
    )
    .await
    .unwrap();
    assert_eq!(saved.response()["git_path"], json!(git));
    let repository = saved.repository(&repo).unwrap();
    assert_eq!(
        repository.configured_git(),
        Some((git.as_path(), crate::landing_git::GitSource::Settings))
    );
}

/// `landing.git_path` and `landing.merge_method` locked by the managed
/// policy replace the human's values in the effective document, are shown as
/// managed entries, and refuse a save that changes them.
#[tokio::test]
async fn the_managed_policy_locks_the_git_path_and_merge_method() {
    use crate::landing_policy::SaveRefusal;
    use crate::managed_policy::{CAUSE_SETTING_LOCKED, Key};
    use pam_connectors::github_landing::MergeMethod;
    let (human_git, locked_git) = if cfg!(windows) {
        (
            r"C:\Tools\git.exe",
            r"C:\Program Files\Git\mingw64\bin\git.exe",
        )
    } else {
        (
            "/opt/homebrew/bin/git",
            "/Library/Developer/CommandLineTools/usr/bin/git",
        )
    };
    let (_temp, repo, workspace, protected) = landing_dirs();
    let store = Store::open_in_memory().await.unwrap();
    let all = json!({"push":true,"create_pr":true,"merge":true,"sync":true});
    let mut stored = recipe(&repo, &workspace, "https://api.github.com/", &all);
    stored["merge_method"] = json!("rebase");
    store
        .set_setting(
            "flows.landing_policy",
            &json!({"version":1,"git_path":human_git,"repositories":[stored.clone()]}).to_string(),
        )
        .await
        .unwrap();
    let view = crate::scope_policy_test::view(&json!({
        "version": 1,
        "revision": "git-1",
        "landing": {
            "git_path": { "locked": locked_git },
            "merge_method": { "locked": "merge", "reason": "SEC-7" }
        }
    }));
    let user = Snapshot::load(&store).await.unwrap();
    let effective = Snapshot::load_effective(&store, &view).await.unwrap();
    let repository = effective.repository(&repo).unwrap();
    assert_eq!(repository.merge_method(), MergeMethod::Merge);
    assert!(repository.merge_method_locked);
    assert_eq!(
        repository.configured_git(),
        Some((
            std::path::Path::new(locked_git),
            crate::landing_git::GitSource::Policy
        ))
    );
    assert_eq!(
        user.repository(&repo).unwrap().merge_method(),
        MergeMethod::Rebase,
        "the stored document keeps the human's value"
    );
    let body = user.managed_response(&view, &effective);
    assert_eq!(body["git_path"], human_git);
    assert_eq!(body["effective"]["git_path"]["value"], locked_git);
    assert_eq!(body["effective"]["git_path"]["locked"], true);
    assert_eq!(body["effective"]["merge_method"]["value"], "merge");
    assert_eq!(body["effective"]["merge_method"]["source"], "policy");
    assert_eq!(
        body["effective"]["repositories"][0]["merge_method"],
        "merge"
    );

    // Changing either locked value is refused; an unrelated edit passes the
    // lock checks (it then reaches the workspace check).
    let mut changed = stored.clone();
    changed["merge_method"] = json!("squash");
    let update = json!({"expected_revision": user.revision, "git_path": human_git,
        "repositories": [changed]});
    let Err(SaveRefusal::Managed(refusal)) =
        Snapshot::save(&store, &view, &update, &protected).await
    else {
        panic!("the locked merge method refuses");
    };
    assert_eq!(refusal.cause, CAUSE_SETTING_LOCKED);
    assert_eq!(refusal.key, Key::LandingMergeMethod);
    assert!(refusal.detail.contains("SEC-7"), "{}", refusal.detail);
    let update = json!({"expected_revision": user.revision, "repositories": [stored.clone()]});
    let Err(SaveRefusal::Managed(refusal)) =
        Snapshot::save(&store, &view, &update, &protected).await
    else {
        panic!("the locked Git path refuses");
    };
    assert_eq!(refusal.key, Key::LandingGitPath);
    let same = json!({"expected_revision": user.revision, "git_path": human_git,
        "repositories": [stored]});
    assert!(
        !matches!(
            Snapshot::save(&store, &view, &same, &protected).await,
            Err(SaveRefusal::Managed(_))
        ),
        "an edit that keeps the locked values is not refused by the policy"
    );
}
