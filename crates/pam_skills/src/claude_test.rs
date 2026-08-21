use std::{fs, path::Path};

use super::{
    AgentArtifact, ArtifactKind, ArtifactScope, CanonicalEntryId, CanonicalLibrary,
    ClaudePluginRoot, ClaudeScanRoots, LibraryInsertDisposition, LoadSemantics, ScanDiagnosticKind,
    ScanLimits, scan_claude_code, scan_test::TestDirectory,
};

fn artifact<'a>(
    artifacts: &'a [AgentArtifact],
    path: &str,
    kind: ArtifactKind,
    scope: ArtifactScope,
) -> &'a AgentArtifact {
    artifacts
        .iter()
        .find(|artifact| {
            artifact.logical_path() == path && artifact.kind() == kind && artifact.scope() == scope
        })
        .unwrap_or_else(|| panic!("missing {scope:?} {kind:?} artifact {path}"))
}

#[test]
fn discovers_user_and_project_artifacts_with_safe_semantics() {
    let user = TestDirectory::new("claude-user");
    user.write(".claude/CLAUDE.md", b"user instructions\n");
    user.write(".claude/skills/review/SKILL.md", b"# Review\n");
    user.write(".claude/agents/triage.md", b"# Triage\n");
    user.write(".claude/rules/always.md", b"Always check tests.\n");
    user.write(
        ".claude/settings.json",
        br#"{"hooks":{"PreToolUse":[{"command":"do-not-run"}]}}"#,
    );
    user.write(
        ".claude/plugins/cache/ignored/.claude-plugin/plugin.json",
        br#"{"name":"ignored"}"#,
    );

    let project = TestDirectory::new("claude-project");
    project.write("CLAUDE.md", b"root\n");
    project.write(".claude/CLAUDE.md", b"project\n");
    project.write("CLAUDE.local.md", b"local\n");
    project.write(".claude/skills/deploy/SKILL.md", b"# Deploy\n");
    project.write(".claude/agents/release.md", b"# Release\n");
    project.write(
        ".claude/rules/rust/path.md",
        b"---\r\npaths:\r\n  - crates/**/*.rs\r\n---\r\nUse clippy.\r\n",
    );
    project.write(".claude/settings.json", br#"{"permissions":{}}"#);
    project.write(".claude/settings.local.json", br#"{"hooks":{}}"#);

    let roots = ClaudeScanRoots::new(Some(user.path()), Some(project.path()), &[]);
    let report = scan_claude_code(roots, ScanLimits::default());
    assert!(report.complete(), "{:?}", report.diagnostics());

    assert_eq!(
        artifact(
            report.artifacts(),
            ".claude/skills/review/SKILL.md",
            ArtifactKind::Skill,
            ArtifactScope::User,
        )
        .load_semantics(),
        LoadSemantics::ModelSelected
    );
    assert_eq!(
        artifact(
            report.artifacts(),
            ".claude/rules/always.md",
            ArtifactKind::Rule,
            ArtifactScope::User,
        )
        .load_semantics(),
        LoadSemantics::Always
    );
    assert_eq!(
        artifact(
            report.artifacts(),
            ".claude/rules/rust/path.md",
            ArtifactKind::Rule,
            ArtifactScope::Project,
        )
        .load_semantics(),
        LoadSemantics::PathConditional
    );
    assert_eq!(
        artifact(
            report.artifacts(),
            ".claude/settings.json",
            ArtifactKind::Hook,
            ArtifactScope::User,
        )
        .load_semantics(),
        LoadSemantics::EventTriggered
    );
    for path in ["CLAUDE.md", ".claude/CLAUDE.md"] {
        assert_eq!(
            artifact(
                report.artifacts(),
                path,
                ArtifactKind::Instruction,
                ArtifactScope::Project,
            )
            .load_semantics(),
            LoadSemantics::Always
        );
    }
    assert_eq!(
        artifact(
            report.artifacts(),
            "CLAUDE.local.md",
            ArtifactKind::Instruction,
            ArtifactScope::Local,
        )
        .load_semantics(),
        LoadSemantics::Always
    );
    assert!(!report.artifacts().iter().any(|artifact| {
        artifact.logical_path().contains("plugins/cache") || artifact.name() == "do-not-run"
    }));

    let repeated = scan_claude_code(roots, ScanLimits::default());
    assert_eq!(report, repeated);
}

#[test]
fn settings_hook_and_config_adopt_the_same_exact_private_source() {
    let project = TestDirectory::new("claude-settings-adoption-project");
    let home = TestDirectory::new("claude-settings-adoption-home");
    let relative = ".claude/settings.json";
    let settings = br#"{
  "hooks": {"PreToolUse": [{"command": "private-settings-source"}]},
  "permissions": {"allow": ["Read"]}
}
"#;
    project.write(relative, settings);
    let source_path = project.path().join(relative);
    let canonical_source_path = fs::canonicalize(&source_path).unwrap();

    let report = scan_claude_code(
        ClaudeScanRoots::new(None, Some(project.path()), &[]),
        ScanLimits {
            max_aggregate_bytes: settings.len(),
            ..ScanLimits::default()
        },
    );
    assert!(report.complete(), "{:?}", report.diagnostics());
    let hook = artifact(
        report.artifacts(),
        relative,
        ArtifactKind::Hook,
        ArtifactScope::Project,
    );
    let config = artifact(
        report.artifacts(),
        relative,
        ArtifactKind::Config,
        ArtifactScope::Project,
    );
    let library = CanonicalLibrary::open(home.path()).unwrap();
    let hook_entry = CanonicalEntryId::parse("claude-settings-hook").unwrap();
    let config_entry = CanonicalEntryId::parse("claude-settings-config").unwrap();

    let hook_outcome = library
        .adopt(hook_entry.clone(), hook.id(), &report)
        .unwrap();
    let config_outcome = library
        .adopt(config_entry.clone(), config.id(), &report)
        .unwrap();

    assert_eq!(
        hook_outcome.disposition(),
        LibraryInsertDisposition::Inserted
    );
    assert_eq!(
        config_outcome.disposition(),
        LibraryInsertDisposition::Inserted
    );
    assert_eq!(
        library.read(&hook_entry, hook_outcome.version()).unwrap(),
        settings
    );
    assert_eq!(
        library
            .read(&config_entry, config_outcome.version())
            .unwrap(),
        settings
    );
    assert_eq!(fs::read(&source_path).unwrap(), settings);
    assert_eq!(
        fs::canonicalize(&source_path).unwrap(),
        canonical_source_path
    );
    for rendered in [
        serde_json::to_string(&report).unwrap(),
        format!("{report:?}"),
        format!("{hook_outcome:?}"),
        format!("{config_outcome:?}"),
    ] {
        assert!(!rendered.contains("private-settings-source"));
    }
}

#[test]
fn scans_only_explicit_plugin_roots_and_their_contributions() {
    let plugin = TestDirectory::new("claude-plugin");
    plugin.write(".claude-plugin/plugin.json", br#"{"name":"quality"}"#);
    plugin.write("skills/audit/SKILL.md", b"# Audit\n");
    plugin.write("agents/reviewer.md", b"# Reviewer\n");
    plugin.write(
        "hooks/hooks.json",
        br#"{"hooks":{"PostToolUse":[{"command":"never-executed"}]}}"#,
    );
    plugin.write("unrelated/private.txt", b"not inventory\n");
    let plugins = [ClaudePluginRoot::new("quality", plugin.path())];

    let report = scan_claude_code(
        ClaudeScanRoots::new(None, None, &plugins),
        ScanLimits::default(),
    );
    assert!(report.complete(), "{:?}", report.diagnostics());
    assert_eq!(report.artifacts().len(), 4);
    assert_eq!(
        artifact(
            report.artifacts(),
            "plugins/quality/.claude-plugin/plugin.json",
            ArtifactKind::Plugin,
            ArtifactScope::Plugin,
        )
        .load_semantics(),
        LoadSemantics::PluginEnabled
    );
    artifact(
        report.artifacts(),
        "plugins/quality/skills/audit/SKILL.md",
        ArtifactKind::Skill,
        ArtifactScope::Plugin,
    );
    artifact(
        report.artifacts(),
        "plugins/quality/agents/reviewer.md",
        ArtifactKind::Agent,
        ArtifactScope::Plugin,
    );
    artifact(
        report.artifacts(),
        "plugins/quality/hooks/hooks.json",
        ArtifactKind::Hook,
        ArtifactScope::Plugin,
    );
    assert!(
        !report
            .artifacts()
            .iter()
            .any(|artifact| artifact.logical_path().contains("unrelated"))
    );
}

#[test]
fn invalid_metadata_is_diagnostic_but_never_executed() {
    let project = TestDirectory::new("claude-invalid-json");
    let sentinel = project.path().join("hook-ran");
    project.write(
        ".claude/settings.json",
        format!(
            "{{\"hooks\":{{\"PreToolUse\":[{{\"command\":\"touch {}\"}}]}}",
            sentinel.display()
        ),
    );

    let report = scan_claude_code(
        ClaudeScanRoots::new(None, Some(project.path()), &[]),
        ScanLimits::default(),
    );
    assert!(!report.complete());
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == ScanDiagnosticKind::InvalidJson
            && diagnostic.logical_path() == ".claude/settings.json"
    }));
    artifact(
        report.artifacts(),
        ".claude/settings.json",
        ArtifactKind::Config,
        ArtifactScope::Project,
    );
    assert!(!sentinel.exists());
}

#[cfg(unix)]
#[test]
fn symlink_escape_is_rejected_and_marks_scan_incomplete() {
    use std::os::unix::fs::symlink;

    let project = TestDirectory::new("claude-symlink-project");
    let outside = TestDirectory::new("claude-symlink-outside");
    outside.write("outside.md", b"secret\n");
    fs::create_dir_all(project.path().join(".claude/rules")).unwrap();
    symlink(
        outside.path().join("outside.md"),
        project.path().join(".claude/rules/escape.md"),
    )
    .unwrap();

    let report = scan_claude_code(
        ClaudeScanRoots::new(None, Some(project.path()), &[]),
        ScanLimits::default(),
    );
    assert!(!report.complete());
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == ScanDiagnosticKind::UnsafeSymlink
            && diagnostic.logical_path() == ".claude/rules/escape.md"
    }));
    assert!(report.artifacts().is_empty());
}

#[test]
fn artifact_and_file_limits_produce_partial_sorted_output() {
    let project = TestDirectory::new("claude-limits");
    project.write("CLAUDE.md", b"root\n");
    project.write("CLAUDE.local.md", b"local\n");
    project.write(".claude/CLAUDE.md", b"project that is too large\n");

    let report = scan_claude_code(
        ClaudeScanRoots::new(None, Some(project.path()), &[]),
        ScanLimits {
            max_file_bytes: 10,
            max_artifacts: 1,
            ..ScanLimits::default()
        },
    );
    assert!(!report.complete());
    assert_eq!(report.artifacts().len(), 1);
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| { diagnostic.kind() == ScanDiagnosticKind::FileTooLarge })
    );
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| { diagnostic.kind() == ScanDiagnosticKind::ArtifactLimitExceeded })
    );
    assert!(
        report
            .artifacts()
            .windows(2)
            .all(|window| window[0] <= window[1])
    );
}

#[test]
fn invalid_plugin_id_is_a_typed_diagnostic() {
    let plugin = TestDirectory::new("claude-plugin-invalid");
    let plugins = [ClaudePluginRoot::new("../escape", plugin.path())];
    let report = scan_claude_code(
        ClaudeScanRoots::new(None, None, &plugins),
        ScanLimits::default(),
    );

    assert!(!report.complete());
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| { diagnostic.kind() == ScanDiagnosticKind::InvalidPluginId })
    );
}

#[test]
fn manifestless_enabled_plugin_scans_component_directories() {
    let plugin = TestDirectory::new("claude-plugin-manifestless");
    plugin.write("skills/audit/SKILL.md", b"# Audit\n");
    plugin.write("agents/reviewer.md", b"# Reviewer\n");
    plugin.write("hooks/hooks.json", br#"{"hooks":{}}"#);
    plugin.write(
        "rules/rust/path.md",
        b"---\npaths:\n  - crates/**/*.rs\n---\nUse clippy.\n",
    );
    plugin.write("instructions/release.md", b"Release carefully.\n");
    let plugins = [ClaudePluginRoot::new("quality", plugin.path())];

    let report = scan_claude_code(
        ClaudeScanRoots::new(None, None, &plugins),
        ScanLimits::default(),
    );
    assert!(report.complete(), "{:?}", report.diagnostics());
    assert_eq!(report.artifacts().len(), 5);
    assert!(!report.artifacts().iter().any(|artifact| {
        artifact.kind() == ArtifactKind::Plugin
            || artifact
                .logical_path()
                .contains(".claude-plugin/plugin.json")
    }));
    artifact(
        report.artifacts(),
        "plugins/quality/skills/audit/SKILL.md",
        ArtifactKind::Skill,
        ArtifactScope::Plugin,
    );
    artifact(
        report.artifacts(),
        "plugins/quality/agents/reviewer.md",
        ArtifactKind::Agent,
        ArtifactScope::Plugin,
    );
    artifact(
        report.artifacts(),
        "plugins/quality/hooks/hooks.json",
        ArtifactKind::Hook,
        ArtifactScope::Plugin,
    );
    assert_eq!(
        artifact(
            report.artifacts(),
            "plugins/quality/rules/rust/path.md",
            ArtifactKind::Rule,
            ArtifactScope::Plugin,
        )
        .load_semantics(),
        LoadSemantics::PathConditional
    );
    assert_eq!(
        artifact(
            report.artifacts(),
            "plugins/quality/instructions/release.md",
            ArtifactKind::Instruction,
            ArtifactScope::Plugin,
        )
        .load_semantics(),
        LoadSemantics::Always
    );
}

#[test]
fn empty_manifestless_enabled_plugin_is_complete_without_a_plugin_artifact() {
    let plugin = TestDirectory::new("claude-plugin-empty-manifestless");
    let plugins = [ClaudePluginRoot::new("empty", plugin.path())];

    let report = scan_claude_code(
        ClaudeScanRoots::new(None, None, &plugins),
        ScanLimits::default(),
    );
    assert!(report.complete(), "{:?}", report.diagnostics());
    assert!(report.artifacts().is_empty());
}

#[test]
fn malformed_existing_plugin_manifest_remains_a_typed_diagnostic() {
    let plugin = TestDirectory::new("claude-plugin-malformed-manifest");
    plugin.write(".claude-plugin/plugin.json", br#"{"name":"broken""#);
    let plugins = [ClaudePluginRoot::new("broken", plugin.path())];

    let report = scan_claude_code(
        ClaudeScanRoots::new(None, None, &plugins),
        ScanLimits::default(),
    );
    assert!(!report.complete());
    assert_eq!(report.artifacts().len(), 1);
    artifact(
        report.artifacts(),
        "plugins/broken/.claude-plugin/plugin.json",
        ArtifactKind::Plugin,
        ArtifactScope::Plugin,
    );
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == ScanDiagnosticKind::InvalidJson
            && diagnostic.logical_path() == "plugins/broken/.claude-plugin/plugin.json"
    }));
}

#[test]
fn non_utf8_rule_content_is_hashed_but_load_semantics_are_unavailable() {
    let project = TestDirectory::new("claude-non-utf8");
    project.write(".claude/rules/binary.md", [0xff, 0xfe, 0xfd]);

    let report = scan_claude_code(
        ClaudeScanRoots::new(None, Some(project.path()), &[]),
        ScanLimits::default(),
    );
    assert!(!report.complete());
    assert_eq!(
        artifact(
            report.artifacts(),
            ".claude/rules/binary.md",
            ArtifactKind::Rule,
            ArtifactScope::Project,
        )
        .load_semantics(),
        LoadSemantics::Unavailable
    );
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| { diagnostic.kind() == ScanDiagnosticKind::NonUtf8Content })
    );
}

#[test]
fn absent_optional_roots_are_not_errors() {
    let report = scan_claude_code(ClaudeScanRoots::new(None, None, &[]), ScanLimits::default());
    assert!(report.complete());
    assert!(report.artifacts().is_empty());
    assert!(report.diagnostics().is_empty());
}

#[test]
fn configured_missing_root_is_incomplete() {
    let directory = TestDirectory::new("claude-missing-root");
    let missing = directory.path().join("missing");
    let report = scan_claude_code(
        ClaudeScanRoots::new(None, Some(Path::new(&missing)), &[]),
        ScanLimits::default(),
    );
    assert!(!report.complete());
    assert_eq!(
        report.diagnostics()[0].kind(),
        ScanDiagnosticKind::RootUnavailable
    );
}
