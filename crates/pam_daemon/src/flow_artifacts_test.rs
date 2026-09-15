#![cfg(unix)]
use super::{CAUSE_ARTIFACTS_ROOT_INVALID, build_env, needs_artifacts, prepare};
use crate::flow_service::FlowSettings;
use std::{os::unix::fs::PermissionsExt, path::PathBuf};

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    repo: PathBuf,
    protected: PathBuf,
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    for name in ["repo", "root", "private"] {
        std::fs::create_dir(base.join(name)).unwrap();
        std::fs::set_permissions(base.join(name), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    Fixture {
        _temp: temp,
        root: base.join("root"),
        repo: base.join("repo"),
        protected: base.join("private"),
    }
}

#[test]
fn prepare_creates_a_private_per_repository_tree_with_read_only_cache_links() {
    let fixture = fixture();
    let cache = fixture.root.parent().unwrap().join("registry");
    std::fs::create_dir(&cache).unwrap();

    let artifacts = prepare(
        &fixture.root,
        &fixture.repo,
        &fixture.protected,
        std::slice::from_ref(&cache),
    )
    .unwrap();

    assert_eq!(artifacts.parent(), Some(fixture.root.as_path()));
    let name = artifacts.file_name().unwrap().to_str().unwrap();
    assert!(name.starts_with("repo-"), "{name}");
    for sub in ["home", "cargo", "target", "tmp", "npm"] {
        let dir = artifacts.join(sub);
        assert!(dir.is_dir(), "{sub} is missing");
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o077,
            0
        );
    }
    assert_eq!(
        std::fs::read_link(artifacts.join("cargo/registry")).unwrap(),
        cache
    );
    // A second preparation lands in the very same tree: the target dir
    // is reused across runs, which is the whole point of a configured root.
    assert_eq!(
        prepare(&fixture.root, &fixture.repo, &fixture.protected, &[cache]).unwrap(),
        artifacts
    );
}

#[test]
fn two_repositories_with_the_same_name_get_separate_trees() {
    let fixture = fixture();
    let other = fixture.root.parent().unwrap().join("elsewhere/repo");
    std::fs::create_dir_all(&other).unwrap();
    let first = prepare(&fixture.root, &fixture.repo, &fixture.protected, &[]).unwrap();
    let second = prepare(&fixture.root, &other, &fixture.protected, &[]).unwrap();
    assert_ne!(first, second);
    assert_eq!(first.parent(), second.parent());
}

#[test]
fn a_cache_that_is_not_a_known_toolchain_cache_is_not_linked() {
    let fixture = fixture();
    let cache = fixture.root.parent().unwrap().join("something");
    std::fs::create_dir(&cache).unwrap();
    let artifacts = prepare(&fixture.root, &fixture.repo, &fixture.protected, &[cache]).unwrap();
    assert!(
        std::fs::read_dir(artifacts.join("cargo"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn a_root_inside_the_repository_or_the_private_base_is_refused() {
    let fixture = fixture();
    for root in [
        fixture.repo.join("builds"),
        fixture.protected.join("builds"),
        fixture.root.parent().unwrap().to_path_buf(),
    ] {
        let refusal = prepare(&root, &fixture.repo, &fixture.protected, &[]).unwrap_err();
        assert_eq!(
            refusal.cause,
            CAUSE_ARTIFACTS_ROOT_INVALID,
            "{}",
            root.display()
        );
        assert!(
            refusal.recovery.contains("Settings"),
            "{}",
            refusal.recovery
        );
    }
}

#[test]
fn a_missing_root_is_created_private_and_a_shared_one_is_refused() {
    let fixture = fixture();
    let fresh = fixture.root.join("nested");
    let artifacts = prepare(&fresh, &fixture.repo, &fixture.protected, &[]).unwrap();
    assert!(artifacts.starts_with(&fresh));
    assert_eq!(
        std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o077,
        0
    );

    std::fs::set_permissions(&fixture.root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let refusal = prepare(&fixture.root, &fixture.repo, &fixture.protected, &[]).unwrap_err();
    assert_eq!(refusal.cause, CAUSE_ARTIFACTS_ROOT_INVALID);
    assert!(refusal.detail.contains("private"), "{}", refusal.detail);
}

#[test]
fn build_env_redirects_home_cargo_target_and_temp_into_the_tree() {
    let fixture = fixture();
    let artifacts = fixture.root.join("repo-x");
    let env = build_env(&FlowSettings::platform_default(), &artifacts);
    let get = |name: &str| {
        env.iter()
            .find(|(key, _)| key == name)
            .map_or_else(|| panic!("{name} is unset"), |(_, value)| value.clone())
    };
    assert_eq!(get("HOME"), artifacts.join("home").to_string_lossy());
    assert_eq!(get("CARGO_HOME"), artifacts.join("cargo").to_string_lossy());
    assert_eq!(
        get("CARGO_TARGET_DIR"),
        artifacts.join("target").to_string_lossy()
    );
    for name in ["TMPDIR", "TMP", "TEMP"] {
        assert_eq!(get(name), artifacts.join("tmp").to_string_lossy());
    }
    assert_eq!(
        get("npm_config_cache"),
        artifacts.join("npm").to_string_lossy()
    );
    assert_eq!(get("PAM_ARTIFACTS"), artifacts.to_string_lossy());
    assert_eq!(env.iter().filter(|(key, _)| key == "HOME").count(), 1);
}

#[test]
fn needs_artifacts_names_the_toolchains_whose_caches_are_redirected() {
    for program in ["cargo", "rustc", "rustup", "npm", "npx", "pnpm", "yarn"] {
        assert!(needs_artifacts(program), "{program}");
    }
    for program in ["git", "gh", "make", "pam-flow-helper"] {
        assert!(!needs_artifacts(program), "{program}");
    }
}

#[test]
fn a_root_named_through_a_symlinked_prefix_is_resolved_to_its_real_directory() {
    // macOS spells /tmp as a symlink to /private/tmp; a human typing the
    // short form must not be refused as a retargeting attempt.
    let fixture = fixture();
    let link = fixture.root.parent().unwrap().join("link");
    std::os::unix::fs::symlink(&fixture.root, &link).unwrap();
    let artifacts = prepare(&link, &fixture.repo, &fixture.protected, &[]).unwrap();
    assert!(
        artifacts.starts_with(&fixture.root),
        "{}",
        artifacts.display()
    );
    assert!(artifacts.join("target").is_dir());
}

#[test]
fn a_root_that_does_not_exist_yet_under_a_symlinked_prefix_is_created_on_first_use() {
    let fixture = fixture();
    let link = fixture.root.parent().unwrap().join("link");
    std::os::unix::fs::symlink(&fixture.root, &link).unwrap();
    let fresh = link.join("builds");
    assert!(!fresh.exists());
    let artifacts = prepare(&fresh, &fixture.repo, &fixture.protected, &[]).unwrap();
    assert!(
        artifacts.starts_with(fixture.root.join("builds")),
        "{}",
        artifacts.display()
    );
    assert_eq!(
        std::fs::metadata(fixture.root.join("builds"))
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );
}
