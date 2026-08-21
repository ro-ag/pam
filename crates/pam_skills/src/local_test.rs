use serde_json::json;

use super::{
    ArtifactKind, ArtifactScope, LocalInventoryError, LocalInventoryRoots, OriginAgent,
    ScanDiagnosticKind, ScanLimits, scan_local_inventory, scan_test::TestDirectory,
};

fn roots<'a>(
    project: &'a TestDirectory,
    user_home: Option<&'a TestDirectory>,
    registry: Option<&'a TestDirectory>,
) -> LocalInventoryRoots<'a> {
    LocalInventoryRoots {
        user_home: user_home.map(TestDirectory::path),
        claude_plugin_registry_root: registry.map(TestDirectory::path),
        codex_system_config_root: None,
        codex_home: None,
        project_root: project.path(),
        current_working_directory: project.path(),
        codex_project_trusted: false,
        cursor_global_rule: None,
    }
}

fn plugin(label: &str, skill_body: &[u8]) -> TestDirectory {
    let plugin = TestDirectory::new(label);
    plugin.write(".claude-plugin/plugin.json", br#"{"name":"quality"}"#);
    plugin.write("skills/audit/SKILL.md", skill_body);
    plugin
}

fn write_registry(registry: &TestDirectory, plugins: &serde_json::Value) {
    registry.write(
        "installed_plugins.json",
        serde_json::to_vec(&json!({"version": 2, "plugins": plugins})).unwrap(),
    );
}

fn write_enabled(directory: &TestDirectory, relative: &str, id: &str, enabled: bool) {
    directory.write(
        relative,
        serde_json::to_vec(&json!({"enabledPlugins": {id: enabled}})).unwrap(),
    );
}

#[test]
fn merges_all_adapters_into_one_deterministic_report() {
    let project = TestDirectory::new("local-merged");
    project.write("CLAUDE.md", b"claude\n");
    project.write("AGENTS.md", b"agents\n");
    project.write(
        ".cursor/rules/manual.mdc",
        b"---\nalwaysApply: false\n---\nmanual\n",
    );

    let report = scan_local_inventory(roots(&project, None, None), ScanLimits::default()).unwrap();
    assert!(report.complete(), "{:?}", report.diagnostics());
    assert!(report.artifacts().iter().any(|artifact| {
        artifact.origin() == OriginAgent::ClaudeCode && artifact.kind() == ArtifactKind::Instruction
    }));
    assert!(report.artifacts().iter().any(|artifact| {
        artifact.origin() == OriginAgent::Codex && artifact.kind() == ArtifactKind::Instruction
    }));
    assert!(report.artifacts().iter().any(|artifact| {
        artifact.origin() == OriginAgent::Cursor && artifact.kind() == ArtifactKind::Rule
    }));
    assert_eq!(
        report,
        scan_local_inventory(roots(&project, None, None), ScanLimits::default()).unwrap()
    );
}

#[test]
fn codex_project_trust_is_explicit_in_integrated_scans() {
    let project = TestDirectory::new("local-codex-trust");
    project.write(".codex/config.toml", b"model = \"trusted\"\n");

    let untrusted =
        scan_local_inventory(roots(&project, None, None), ScanLimits::default()).unwrap();
    assert!(untrusted.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == ScanDiagnosticKind::UntrustedProjectConfig
            && diagnostic.logical_path() == ".codex/config.toml"
    }));
    assert!(!untrusted.artifacts().iter().any(|artifact| {
        artifact.origin() == OriginAgent::Codex && artifact.logical_path() == ".codex/config.toml"
    }));

    let mut trusted_roots = roots(&project, None, None);
    trusted_roots.codex_project_trusted = true;
    let trusted = scan_local_inventory(trusted_roots, ScanLimits::default()).unwrap();
    assert!(trusted.complete(), "{:?}", trusted.diagnostics());
    assert!(trusted.artifacts().iter().any(|artifact| {
        artifact.origin() == OriginAgent::Codex && artifact.logical_path() == ".codex/config.toml"
    }));
}

#[test]
fn registry_selects_only_the_exact_projects_version() {
    let project_a = TestDirectory::new("local-plugin-project-a");
    let project_b = TestDirectory::new("local-plugin-project-b");
    let registry = TestDirectory::new("local-plugin-registry-projects");
    let plugin_a = plugin("local-plugin-version-a", b"version a\n");
    let plugin_b = plugin("local-plugin-version-b", b"version b\n");
    write_enabled(
        &project_a,
        ".claude/settings.json",
        "quality@official",
        true,
    );
    write_enabled(
        &project_b,
        ".claude/settings.json",
        "quality@official",
        true,
    );
    write_registry(
        &registry,
        &json!({
            "quality@official": [
                {
                    "installPath": plugin_a.path(),
                    "scope": "project",
                    "projectPath": project_a.path(),
                    "version": "1"
                },
                {
                    "installPath": plugin_b.path(),
                    "scope": "project",
                    "projectPath": project_b.path(),
                    "version": "2"
                }
            ]
        }),
    );

    let a = scan_local_inventory(
        roots(&project_a, None, Some(&registry)),
        ScanLimits::default(),
    )
    .unwrap();
    let b = scan_local_inventory(
        roots(&project_b, None, Some(&registry)),
        ScanLimits::default(),
    )
    .unwrap();
    assert!(a.complete(), "{:?}", a.diagnostics());
    assert!(b.complete(), "{:?}", b.diagnostics());
    let a_hash = a
        .artifacts()
        .iter()
        .find(|artifact| {
            artifact.logical_path() == "plugins/quality@official/skills/audit/SKILL.md"
        })
        .unwrap()
        .content_hash();
    let b_hash = b
        .artifacts()
        .iter()
        .find(|artifact| {
            artifact.logical_path() == "plugins/quality@official/skills/audit/SKILL.md"
        })
        .unwrap()
        .content_hash();
    assert_ne!(a_hash, b_hash);
}

#[test]
fn unrelated_or_managed_only_unset_installations_are_ignored() {
    let project = TestDirectory::new("local-plugin-current-project");
    let unrelated = TestDirectory::new("local-plugin-unrelated-project");
    let registry = TestDirectory::new("local-plugin-unrelated-registry");
    let unrelated_plugin = plugin("local-plugin-unrelated-root", b"unrelated\n");
    write_registry(
        &registry,
        &json!({
            "quality@official": [
                {
                    "installPath": unrelated_plugin.path(),
                    "scope": "project",
                    "projectPath": unrelated.path()
                },
                {"installPath": unrelated_plugin.path(), "scope": "managed"}
            ]
        }),
    );

    let report = scan_local_inventory(
        roots(&project, None, Some(&registry)),
        ScanLimits::default(),
    )
    .unwrap();
    assert!(report.complete(), "{:?}", report.diagnostics());
    assert!(
        report
            .artifacts()
            .iter()
            .all(|artifact| artifact.scope() != ArtifactScope::Plugin)
    );
}

#[test]
fn enabled_plugins_overlay_project_then_local_over_user() {
    let project = TestDirectory::new("local-plugin-overlay-project");
    let home = TestDirectory::new("local-plugin-overlay-home");
    let registry = TestDirectory::new("local-plugin-overlay-registry");
    let installed = plugin("local-plugin-overlay-root", b"active\n");
    write_registry(
        &registry,
        &json!({
            "quality@official": [
                {"installPath": installed.path(), "scope": "user"}
            ]
        }),
    );
    write_enabled(&home, ".claude/settings.json", "quality@official", false);
    write_enabled(&project, ".claude/settings.json", "quality@official", true);

    let project_enabled = scan_local_inventory(
        roots(&project, Some(&home), Some(&registry)),
        ScanLimits::default(),
    )
    .unwrap();
    assert!(project_enabled.artifacts().iter().any(|artifact| {
        artifact.logical_path() == "plugins/quality@official/skills/audit/SKILL.md"
    }));

    write_enabled(
        &project,
        ".claude/settings.local.json",
        "quality@official",
        false,
    );
    let local_disabled = scan_local_inventory(
        roots(&project, Some(&home), Some(&registry)),
        ScanLimits::default(),
    )
    .unwrap();
    assert!(
        local_disabled
            .artifacts()
            .iter()
            .all(|artifact| artifact.scope() != ArtifactScope::Plugin)
    );
}

#[test]
fn indeterminate_missing_and_ambiguous_plugins_fail_closed() {
    let project = TestDirectory::new("local-plugin-fail-closed-project");
    let home = TestDirectory::new("local-plugin-fail-closed-home");
    let registry = TestDirectory::new("local-plugin-fail-closed-registry");
    let first = plugin("local-plugin-ambiguous-one", b"one\n");
    let second = plugin("local-plugin-ambiguous-two", b"two\n");
    write_registry(
        &registry,
        &json!({
            "quality@official": [
                {"installPath": first.path(), "scope": "user"}
            ]
        }),
    );
    assert_eq!(
        scan_local_inventory(
            roots(&project, Some(&home), Some(&registry)),
            ScanLimits::default()
        )
        .unwrap_err(),
        LocalInventoryError::IndeterminatePluginEnablement("quality@official".to_owned())
    );

    write_enabled(&home, ".claude/settings.json", "missing@official", true);
    write_registry(&registry, &json!({}));
    assert_eq!(
        scan_local_inventory(
            roots(&project, Some(&home), Some(&registry)),
            ScanLimits::default()
        )
        .unwrap_err(),
        LocalInventoryError::EnabledPluginNotInstalled("missing@official".to_owned())
    );

    write_enabled(&home, ".claude/settings.json", "quality@official", true);
    write_registry(
        &registry,
        &json!({
            "quality@official": [
                {"installPath": first.path(), "scope": "user"},
                {"installPath": second.path(), "scope": "user"}
            ]
        }),
    );
    assert_eq!(
        scan_local_inventory(
            roots(&project, Some(&home), Some(&registry)),
            ScanLimits::default()
        )
        .unwrap_err(),
        LocalInventoryError::AmbiguousPluginInstallations("quality@official".to_owned())
    );
}

#[test]
fn malformed_unsupported_and_unsafe_plugin_configuration_fails_closed() {
    let project = TestDirectory::new("local-plugin-invalid-project");
    for (label, value, expected) in [
        (
            "unsupported",
            json!({"version": 3, "plugins": {}}),
            LocalInventoryError::UnsupportedPluginRegistryVersion(3),
        ),
        (
            "relative",
            json!({
                "version": 2,
                "plugins": {
                    "plugin@official": [{"installPath": "relative", "scope": "user"}]
                }
            }),
            LocalInventoryError::UnsafePluginInstallPath,
        ),
        (
            "missing-project-path",
            json!({
                "version": 2,
                "plugins": {
                    "plugin@official": [{"installPath": project.path(), "scope": "project"}]
                }
            }),
            LocalInventoryError::UnsafePluginProjectPath("plugin@official".to_owned()),
        ),
    ] {
        let registry = TestDirectory::new(label);
        registry.write(
            "installed_plugins.json",
            serde_json::to_vec(&value).unwrap(),
        );
        assert_eq!(
            scan_local_inventory(
                roots(&project, None, Some(&registry)),
                ScanLimits::default()
            )
            .unwrap_err(),
            expected
        );
    }

    let registry = TestDirectory::new("malformed-registry");
    registry.write("installed_plugins.json", b"{");
    assert_eq!(
        scan_local_inventory(
            roots(&project, None, Some(&registry)),
            ScanLimits::default()
        )
        .unwrap_err(),
        LocalInventoryError::MalformedPluginRegistry
    );

    let home = TestDirectory::new("malformed-settings");
    home.write(".claude/settings.json", br#"{"enabledPlugins":[]}"#);
    assert_eq!(
        scan_local_inventory(roots(&project, Some(&home), None), ScanLimits::default())
            .unwrap_err(),
        LocalInventoryError::MalformedClaudeSettings(ArtifactScope::User)
    );
}
