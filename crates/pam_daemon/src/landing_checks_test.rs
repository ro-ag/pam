#![cfg(unix)]
use super::prepare_sync;
use crate::{flow_service::FlowSettings, landing_policy::Repository};
use serde_json::json;
use std::{os::unix::fs::PermissionsExt, path::PathBuf};

struct Fixture {
    _temp: tempfile::TempDir,
    policy: Repository,
    protected: PathBuf,
    tree: PathBuf,
    settings: FlowSettings,
}
fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    for name in ["repo", "workspaces", "private"] {
        std::fs::create_dir(base.join(name)).unwrap();
        std::fs::set_permissions(base.join(name), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let tree = base.join("workspaces/landing-fixture/tree");
    std::fs::create_dir_all(&tree).unwrap();
    let policy = serde_json::from_value(json!({
        "root":base.join("repo"),"repository":"https://github.com/org/repo",
        "github_server":"https://api.github.com/","github_repository":"org/repo",
        "base":"main","branches":["feature/work"],"workspace_root":base.join("workspaces"),
        "checks":[{"name":"build","argv":["git","${source}","${artifacts}/output","$HOME"],"timeout_seconds":30}],
        "required_checks":["ci"],"main_checks":["ci"],"permissions":{"push":false,"create_pr":false,"merge":false,"sync":false}
    })).unwrap();
    Fixture {
        _temp: temp,
        policy,
        protected: base.join("private"),
        tree,
        settings: FlowSettings::platform_default(),
    }
}

#[test]
fn checks_use_only_private_outputs_and_literal_documented_placeholders() {
    let fixture = fixture();
    let spec = prepare_sync(
        &fixture.policy,
        0,
        &fixture.tree,
        &fixture.settings,
        &fixture.protected,
    )
    .unwrap();
    let artifacts = fixture.tree.parent().unwrap().join("artifacts");
    assert_eq!(
        spec.argv,
        vec![
            fixture.tree.to_string_lossy(),
            artifacts.join("output").to_string_lossy(),
            "$HOME".into()
        ]
    );
    assert_eq!(spec.containment.artifact_roots, vec![artifacts.clone()]);
    assert!(!spec.containment.allow_repository_writes);
    assert!(spec.env.iter().any(|(key, value)| key == "CARGO_TARGET_DIR"
        && value == &artifacts.join("target").to_string_lossy()));
    assert_eq!(
        std::fs::metadata(artifacts).unwrap().permissions().mode() & 0o077,
        0
    );
}

#[test]
fn cache_mount_cannot_replace_source_and_unapproved_program_refuses() {
    let mut fixture = fixture();
    let cache = fixture.policy.root.join("node_modules");
    std::fs::create_dir(&cache).unwrap();
    fixture.policy.read_cache_roots.push(cache.clone());
    std::fs::write(fixture.tree.join("node_modules"), "tracked source").unwrap();
    assert!(
        prepare_sync(
            &fixture.policy,
            0,
            &fixture.tree,
            &fixture.settings,
            &fixture.protected
        )
        .is_err()
    );
    std::fs::remove_file(fixture.tree.join("node_modules")).unwrap();
    let spec = prepare_sync(
        &fixture.policy,
        0,
        &fixture.tree,
        &fixture.settings,
        &fixture.protected,
    )
    .unwrap();
    assert!(spec.containment.read_only_roots.contains(&cache));
    assert_eq!(
        std::fs::read_link(fixture.tree.join("node_modules")).unwrap(),
        cache
    );
    fixture.settings.allowed_programs.clear();
    assert!(
        prepare_sync(
            &fixture.policy,
            0,
            &fixture.tree,
            &fixture.settings,
            &fixture.protected
        )
        .is_err()
    );
}
