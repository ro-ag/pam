use serde_json::json;

use super::{
    ArtifactKind, LocalInventoryError, LocalInventoryRoots, OriginAgent, ScanLimits,
    scan_local_inventory, scan_test::TestDirectory,
};

fn roots<'a>(
    project: &'a TestDirectory,
    registry: Option<&'a TestDirectory>,
) -> LocalInventoryRoots<'a> {
    LocalInventoryRoots {
        user_home: None,
        claude_plugin_registry_root: registry.map(TestDirectory::path),
        codex_system_config_root: None,
        codex_home: None,
        project_root: project.path(),
        current_working_directory: project.path(),
        cursor_global_rule: None,
    }
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

    let report = scan_local_inventory(roots(&project, None), ScanLimits::default()).unwrap();
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
        scan_local_inventory(roots(&project, None), ScanLimits::default()).unwrap()
    );
}

#[test]
fn version_two_plugin_registry_supplies_only_explicit_install_roots() {
    let project = TestDirectory::new("local-plugin-project");
    let registry = TestDirectory::new("local-plugin-registry");
    let plugin = TestDirectory::new("local-plugin-root");
    plugin.write(".claude-plugin/plugin.json", br#"{"name":"quality"}"#);
    plugin.write("skills/audit/SKILL.md", b"audit\n");
    registry.write(
        "installed_plugins.json",
        serde_json::to_vec(&json!({
            "version": 2,
            "plugins": {
                "quality@official": [
                    {"installPath": plugin.path(), "scope": "user", "version": "1"},
                    {"installPath": plugin.path(), "scope": "user", "version": "1"}
                ]
            }
        }))
        .unwrap(),
    );

    let report =
        scan_local_inventory(roots(&project, Some(&registry)), ScanLimits::default()).unwrap();
    assert!(report.complete(), "{:?}", report.diagnostics());
    assert_eq!(
        report
            .artifacts()
            .iter()
            .filter(|artifact| artifact.scope() == super::ArtifactScope::Plugin)
            .count(),
        2
    );
}

#[test]
fn malformed_unsupported_and_relative_plugin_registries_fail_closed() {
    let project = TestDirectory::new("local-plugin-invalid-project");
    for (label, value, expected) in [
        (
            "unsupported",
            json!({"version": 3, "plugins": {}}),
            LocalInventoryError::UnsupportedPluginRegistryVersion(3),
        ),
        (
            "relative",
            json!({"version": 2, "plugins": {"plugin": [{"installPath": "relative"}]}}),
            LocalInventoryError::UnsafePluginInstallPath,
        ),
    ] {
        let registry = TestDirectory::new(label);
        registry.write(
            "installed_plugins.json",
            serde_json::to_vec(&value).unwrap(),
        );
        assert_eq!(
            scan_local_inventory(roots(&project, Some(&registry)), ScanLimits::default())
                .unwrap_err(),
            expected
        );
    }

    let registry = TestDirectory::new("malformed");
    registry.write("installed_plugins.json", b"{");
    assert_eq!(
        scan_local_inventory(roots(&project, Some(&registry)), ScanLimits::default()).unwrap_err(),
        LocalInventoryError::MalformedPluginRegistry
    );
}
