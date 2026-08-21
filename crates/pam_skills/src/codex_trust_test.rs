use std::fs;

#[cfg(unix)]
use std::os::unix::fs::symlink;

use super::{
    CodexProjectTrust, CodexProjectTrustError, ScanDiagnosticKind, ScanLimits,
    resolve_codex_project_trust, scan_test::TestDirectory,
};

fn write_decision(home: &TestDirectory, project_path: &std::path::Path, decision: &str) {
    home.write(
        "config.toml",
        format!(
            "[projects.\"{}\"]\ntrust_level = \"{decision}\"\n",
            toml_key(project_path)
        ),
    );
}

fn toml_key(path: &std::path::Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn resolve(home: Option<&TestDirectory>, project: &TestDirectory) -> CodexProjectTrust {
    resolve_codex_project_trust(
        home.map(TestDirectory::path),
        project.path(),
        ScanLimits::default(),
    )
    .unwrap()
}

#[test]
fn resolves_exact_trusted_untrusted_and_missing_decisions() {
    let project = TestDirectory::new("codex-trust-exact-project");
    let home = TestDirectory::new("codex-trust-exact-home");

    assert_eq!(resolve(None, &project), CodexProjectTrust::Unspecified);
    assert_eq!(
        resolve(Some(&home), &project),
        CodexProjectTrust::Unspecified
    );

    write_decision(&home, project.path(), "trusted");
    assert_eq!(resolve(Some(&home), &project), CodexProjectTrust::Trusted);

    write_decision(&home, project.path(), "untrusted");
    assert_eq!(resolve(Some(&home), &project), CodexProjectTrust::Untrusted);
}

#[test]
fn unrelated_parent_child_and_prefix_entries_do_not_grant_trust() {
    let parent = TestDirectory::new("codex-trust-parent");
    let project_path = parent.path().join("project");
    let child_path = project_path.join("child");
    fs::create_dir_all(&child_path).unwrap();
    let prefix_path = parent.path().join("project-evil");
    fs::create_dir(&prefix_path).unwrap();
    let unrelated = TestDirectory::new("codex-trust-unrelated");
    let home = TestDirectory::new("codex-trust-relations-home");

    for candidate in [parent.path(), child_path.as_path(), prefix_path.as_path()] {
        write_decision(&home, candidate, "trusted");
        assert_eq!(
            resolve_codex_project_trust(Some(home.path()), &project_path, ScanLimits::default())
                .unwrap(),
            CodexProjectTrust::Unspecified
        );
    }

    write_decision(&home, unrelated.path(), "trusted");
    assert_eq!(
        resolve_codex_project_trust(Some(home.path()), &project_path, ScanLimits::default())
            .unwrap(),
        CodexProjectTrust::Unspecified
    );
}

#[test]
fn canonical_dot_dot_alias_grants_only_the_same_project() {
    let parent = TestDirectory::new("codex-trust-dot-dot-parent");
    let project = parent.path().join("project");
    let sibling = parent.path().join("sibling");
    fs::create_dir(&project).unwrap();
    fs::create_dir(&sibling).unwrap();
    let home = TestDirectory::new("codex-trust-dot-dot-home");
    let alias = sibling.join("..").join("project");
    write_decision(&home, &alias, "trusted");

    assert_eq!(
        resolve_codex_project_trust(Some(home.path()), &project, ScanLimits::default()).unwrap(),
        CodexProjectTrust::Trusted
    );
}

#[cfg(unix)]
#[test]
fn canonical_symlink_alias_grants_only_the_same_project() {
    let project = TestDirectory::new("codex-trust-symlink-project");
    let aliases = TestDirectory::new("codex-trust-symlink-aliases");
    let alias = aliases.path().join("project-alias");
    symlink(project.path(), &alias).unwrap();
    let home = TestDirectory::new("codex-trust-symlink-home");
    write_decision(&home, &alias, "trusted");

    assert_eq!(
        resolve_codex_project_trust(Some(home.path()), project.path(), ScanLimits::default())
            .unwrap(),
        CodexProjectTrust::Trusted
    );
}

#[test]
fn conflicting_canonical_aliases_fail_closed() {
    let parent = TestDirectory::new("codex-trust-conflict-parent");
    let project = parent.path().join("project");
    let sibling = parent.path().join("sibling");
    fs::create_dir(&project).unwrap();
    fs::create_dir(&sibling).unwrap();
    let alias = sibling.join("..").join("project");
    let home = TestDirectory::new("codex-trust-conflict-home");
    home.write(
        "config.toml",
        format!(
            "[projects.\"{}\"]\ntrust_level = \"trusted\"\n\n[projects.\"{}\"]\ntrust_level = \"untrusted\"\n",
            toml_key(&project),
            toml_key(&alias)
        ),
    );

    assert_eq!(
        resolve_codex_project_trust(Some(home.path()), &project, ScanLimits::default())
            .unwrap_err(),
        CodexProjectTrustError::ConflictingAliases
    );
}

#[test]
fn stale_unrelated_absolute_entry_is_ignored() {
    let project = TestDirectory::new("codex-trust-stale-project");
    let home = TestDirectory::new("codex-trust-stale-home");
    let stale = home.path().join("does-not-exist");
    write_decision(&home, &stale, "trusted");

    assert_eq!(
        resolve(Some(&home), &project),
        CodexProjectTrust::Unspecified
    );
}

#[test]
fn unrelated_or_stale_invalid_trust_values_are_ignored() {
    let project = TestDirectory::new("codex-trust-unrelated-invalid-project");
    let unrelated = TestDirectory::new("codex-trust-unrelated-invalid-other");
    let home = TestDirectory::new("codex-trust-unrelated-invalid-home");
    let stale = home.path().join("does-not-exist");
    home.write(
        "config.toml",
        format!(
            "[projects.\"{}\"]\ntrust_level = 1\n\n[projects.\"{}\"]\ntrust_level = \"invalid\"\n",
            toml_key(unrelated.path()),
            toml_key(&stale)
        ),
    );

    assert_eq!(
        resolve(Some(&home), &project),
        CodexProjectTrust::Unspecified
    );
}

#[test]
fn invalid_paths_shapes_and_levels_fail_closed() {
    let project = TestDirectory::new("codex-trust-invalid-project");
    for (label, source, expected) in [
        (
            "relative",
            "[projects.relative]\ntrust_level = \"trusted\"\n".to_owned(),
            CodexProjectTrustError::InvalidProjectPath,
        ),
        (
            "nul",
            "[projects.\"\\u0000\"]\ntrust_level = \"trusted\"\n".to_owned(),
            CodexProjectTrustError::InvalidProjectPath,
        ),
        (
            "projects-type",
            "projects = \"invalid\"\n".to_owned(),
            CodexProjectTrustError::InvalidProjectsType,
        ),
        (
            "entry-type",
            format!("projects.\"{}\" = \"trusted\"\n", toml_key(project.path())),
            CodexProjectTrustError::InvalidProjectEntryType,
        ),
        (
            "level-type",
            format!(
                "[projects.\"{}\"]\ntrust_level = 1\n",
                toml_key(project.path())
            ),
            CodexProjectTrustError::InvalidTrustLevelType,
        ),
        (
            "level-value",
            format!(
                "[projects.\"{}\"]\ntrust_level = \"maybe\"\n",
                toml_key(project.path())
            ),
            CodexProjectTrustError::InvalidTrustLevelValue,
        ),
    ] {
        let home = TestDirectory::new(label);
        home.write("config.toml", source);
        assert_eq!(
            resolve_codex_project_trust(Some(home.path()), project.path(), ScanLimits::default())
                .unwrap_err(),
            expected
        );
    }
}

#[test]
fn malformed_non_utf8_and_oversized_configs_fail_closed() {
    let project = TestDirectory::new("codex-trust-content-project");

    let malformed = TestDirectory::new("codex-trust-malformed-home");
    malformed.write("config.toml", b"[");
    assert_eq!(
        resolve_codex_project_trust(
            Some(malformed.path()),
            project.path(),
            ScanLimits::default()
        )
        .unwrap_err(),
        CodexProjectTrustError::MalformedConfig
    );

    let non_utf8 = TestDirectory::new("codex-trust-non-utf8-home");
    non_utf8.write("config.toml", [0xff]);
    assert_eq!(
        resolve_codex_project_trust(Some(non_utf8.path()), project.path(), ScanLimits::default())
            .unwrap_err(),
        CodexProjectTrustError::NonUtf8Config
    );

    let oversized = TestDirectory::new("codex-trust-oversized-home");
    oversized.write("config.toml", b"projects = {}\n");
    let error = resolve_codex_project_trust(
        Some(oversized.path()),
        project.path(),
        ScanLimits {
            max_file_bytes: 4,
            ..ScanLimits::default()
        },
    )
    .unwrap_err();
    let CodexProjectTrustError::ConfigScan(diagnostics) = error else {
        panic!("expected bounded scan error");
    };
    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.kind() == ScanDiagnosticKind::FileTooLarge
            && diagnostic.logical_path() == "config.toml"
    }));
}

#[cfg(unix)]
#[test]
fn symlinked_user_config_fails_closed() {
    let project = TestDirectory::new("codex-trust-config-symlink-project");
    let home = TestDirectory::new("codex-trust-config-symlink-home");
    let outside = TestDirectory::new("codex-trust-config-symlink-outside");
    write_decision(&outside, project.path(), "trusted");
    symlink(
        outside.path().join("config.toml"),
        home.path().join("config.toml"),
    )
    .unwrap();

    let error =
        resolve_codex_project_trust(Some(home.path()), project.path(), ScanLimits::default())
            .unwrap_err();
    let CodexProjectTrustError::ConfigScan(diagnostics) = error else {
        panic!("expected unsafe config scan error");
    };
    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.kind() == ScanDiagnosticKind::UnsafeSymlink
            && diagnostic.logical_path() == "config.toml"
    }));
}
