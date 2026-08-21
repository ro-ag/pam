use std::fs;

use pam_core::ContentDigest;
use sha2::{Digest, Sha256};

use super::{
    AgentArtifact, ArtifactKind, ArtifactScope, CursorGlobalRuleSource, CursorGlobalRulesStatus,
    CursorScanRoots, LoadSemantics, OriginAgent, ScanDiagnosticKind, ScanLimits, scan_cursor,
    scan_test::TestDirectory,
};

fn digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_sha256(Sha256::digest(bytes).into())
}

fn artifact<'a>(
    artifacts: &'a [AgentArtifact],
    path: &str,
    kind: ArtifactKind,
    scope: ArtifactScope,
) -> &'a AgentArtifact {
    artifacts
        .iter()
        .find(|artifact| {
            artifact.logical_path() == path
                && artifact.kind() == kind
                && artifact.scope() == scope
                && artifact.origin() == OriginAgent::Cursor
        })
        .unwrap_or_else(|| panic!("missing {scope:?} {kind:?} artifact at {path}"))
}

#[test]
fn classifies_all_mdc_semantics_and_nested_project_sources() {
    let project = TestDirectory::new("cursor-semantics");
    let always = b"---\nalwaysApply: true\n---\nalways\n";
    let always_crlf = b"---\r\nalwaysApply: true\r\n---\r\nalways\r\n";
    let path = b"---\r\nalwaysApply: false\r\nglobs:\r\n  - \"**/*.rs\"\r\n---\r\npath\r\n";
    project.write(".cursor/rules/always.mdc", always);
    project.write(".cursor/rules/always-crlf.mdc", always_crlf);
    project.write(".cursor/rules/rust/path.mdc", path);
    project.write(
        ".cursor/rules/model.mdc",
        b"---\ndescription: Use for API design\nalwaysApply: false\n---\nmodel\n",
    );
    project.write(
        ".cursor/rules/manual.mdc",
        b"---\ndescription:\nglobs: []\nalwaysApply: false\n---\nmanual\n",
    );
    project.write(".cursor/rules/ignored.md", b"ignored\n");
    project.write(
        "crates/.cursor/rules/nested.mdc",
        b"---\ndescription: Nested rule\n---\nnested\n",
    );
    project.write("AGENTS.md", b"root agents\n");
    project.write("crates/AGENTS.md", b"crate agents\n");
    project.write("crates/app/AGENTS.md", b"app agents\n");
    project.write("crates/app/deeper/AGENTS.md", b"below cwd\n");
    let cwd = project.path().join("crates/app");

    let roots = CursorScanRoots::new(project.path(), &cwd, None);
    let report = scan_cursor(roots, ScanLimits::default());
    assert!(report.complete(), "{:?}", report.diagnostics());
    assert_eq!(
        report.global_rules_status(),
        CursorGlobalRulesStatus::NotLocallyDiscoverable
    );
    for (file, semantics) in [
        ("always.mdc", LoadSemantics::Always),
        ("always-crlf.mdc", LoadSemantics::Always),
        ("rust/path.mdc", LoadSemantics::PathConditional),
        ("model.mdc", LoadSemantics::ModelSelected),
        ("manual.mdc", LoadSemantics::Explicit),
    ] {
        let path = format!(".cursor/rules/{file}");
        assert_eq!(
            artifact(
                report.artifacts(),
                &path,
                ArtifactKind::Rule,
                ArtifactScope::Project,
            )
            .load_semantics(),
            semantics
        );
    }
    assert_eq!(
        artifact(
            report.artifacts(),
            "crates/.cursor/rules/nested.mdc",
            ArtifactKind::Rule,
            ArtifactScope::Project,
        )
        .load_semantics(),
        LoadSemantics::ModelSelected
    );
    for path in ["AGENTS.md", "crates/AGENTS.md", "crates/app/AGENTS.md"] {
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
    assert!(!report.artifacts().iter().any(|artifact| {
        matches!(
            artifact.logical_path(),
            ".cursor/rules/ignored.md" | "crates/app/deeper/AGENTS.md"
        )
    }));
    assert_eq!(
        artifact(
            report.artifacts(),
            ".cursor/rules/always.mdc",
            ArtifactKind::Rule,
            ArtifactScope::Project,
        )
        .content_hash(),
        &digest(always)
    );
    assert_eq!(
        artifact(
            report.artifacts(),
            ".cursor/rules/rust/path.mdc",
            ArtifactKind::Rule,
            ArtifactScope::Project,
        )
        .content_hash(),
        &digest(path)
    );
    assert_eq!(
        artifact(
            report.artifacts(),
            ".cursor/rules/always-crlf.mdc",
            ArtifactKind::Rule,
            ArtifactScope::Project,
        )
        .content_hash(),
        &digest(always_crlf)
    );
    assert_ne!(digest(always), digest(always_crlf));
    assert_eq!(report, scan_cursor(roots, ScanLimits::default()));
}

#[test]
fn global_rule_is_only_read_from_an_explicit_source_and_legacy_is_root_only() {
    let project = TestDirectory::new("cursor-global-project");
    project.write(".cursorrules", b"legacy root\n");
    project.write("nested/.cursorrules", b"ignored legacy\n");
    let global = TestDirectory::new("cursor-global-source");
    global.write("rules/global.md", b"private global body\n");
    let source = CursorGlobalRuleSource::new(global.path(), "rules/global.md".as_ref());

    let report = scan_cursor(
        CursorScanRoots::new(project.path(), project.path(), Some(source)),
        ScanLimits::default(),
    );
    assert!(report.complete(), "{:?}", report.diagnostics());
    assert_eq!(
        report.global_rules_status(),
        CursorGlobalRulesStatus::ExplicitlyConfigured
    );
    assert_eq!(
        artifact(
            report.artifacts(),
            "rules/global.md",
            ArtifactKind::Rule,
            ArtifactScope::User,
        )
        .load_semantics(),
        LoadSemantics::Always
    );
    assert_eq!(
        artifact(
            report.artifacts(),
            ".cursorrules",
            ArtifactKind::Rule,
            ArtifactScope::Project,
        )
        .load_semantics(),
        LoadSemantics::Always
    );
    assert!(
        !report
            .artifacts()
            .iter()
            .any(|artifact| artifact.logical_path() == "nested/.cursorrules")
    );
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("private global body")
    );

    let absent = scan_cursor(
        CursorScanRoots::new(project.path(), project.path(), None),
        ScanLimits::default(),
    );
    assert!(absent.complete(), "{:?}", absent.diagnostics());
    assert_eq!(
        serde_json::to_value(absent.global_rules_status()).unwrap(),
        "not_locally_discoverable"
    );
}

#[test]
fn invalid_and_non_utf8_frontmatter_are_typed_without_losing_hashes() {
    let project = TestDirectory::new("cursor-invalid-frontmatter");
    let invalid = b"---\ndescription: never closed\n";
    let binary = [0xff, 0xfe, 0xfd];
    project.write(".cursor/rules/invalid.mdc", invalid);
    project.write(".cursor/rules/binary.mdc", binary);

    let report = scan_cursor(
        CursorScanRoots::new(project.path(), project.path(), None),
        ScanLimits::default(),
    );
    assert!(!report.complete());
    for (path, kind) in [
        (
            ".cursor/rules/invalid.mdc",
            ScanDiagnosticKind::InvalidFrontmatter,
        ),
        (
            ".cursor/rules/binary.mdc",
            ScanDiagnosticKind::NonUtf8Content,
        ),
    ] {
        assert!(
            report.diagnostics().iter().any(|diagnostic| {
                diagnostic.logical_path() == path && diagnostic.kind() == kind
            })
        );
        assert_eq!(
            artifact(
                report.artifacts(),
                path,
                ArtifactKind::Rule,
                ArtifactScope::Project,
            )
            .load_semantics(),
            LoadSemantics::Unavailable
        );
    }
    assert_eq!(
        artifact(
            report.artifacts(),
            ".cursor/rules/invalid.mdc",
            ArtifactKind::Rule,
            ArtifactScope::Project,
        )
        .content_hash(),
        &digest(invalid)
    );
}

#[test]
fn invalid_project_root_to_cwd_relation_is_typed() {
    let project = TestDirectory::new("cursor-project-root");
    project.write("AGENTS.md", b"project\n");
    let outside = TestDirectory::new("cursor-outside-cwd");

    let report = scan_cursor(
        CursorScanRoots::new(project.path(), outside.path(), None),
        ScanLimits::default(),
    );
    assert!(
        report.diagnostics().iter().any(|diagnostic| {
            diagnostic.kind() == ScanDiagnosticKind::InvalidProjectRootRelation
        })
    );
    assert!(report.artifacts().is_empty());
}

#[test]
fn inherited_file_bounds_produce_partial_output() {
    let project = TestDirectory::new("cursor-bounds");
    project.write(".cursor/rules/large.mdc", b"12345");
    project.write("AGENTS.md", b"1234");

    let report = scan_cursor(
        CursorScanRoots::new(project.path(), project.path(), None),
        ScanLimits {
            max_file_bytes: 4,
            ..ScanLimits::default()
        },
    );
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == ScanDiagnosticKind::FileTooLarge
            && diagnostic.logical_path() == ".cursor/rules/large.mdc"
    }));
    assert_eq!(report.artifacts().len(), 1);
    artifact(
        report.artifacts(),
        "AGENTS.md",
        ArtifactKind::Instruction,
        ArtifactScope::Project,
    );
}

#[cfg(unix)]
#[test]
fn inherited_symlink_policy_rejects_rule_escape() {
    use std::os::unix::fs::symlink;

    let project = TestDirectory::new("cursor-symlink-project");
    let outside = TestDirectory::new("cursor-symlink-outside");
    outside.write("outside.mdc", b"secret\n");
    fs::create_dir_all(project.path().join(".cursor/rules")).unwrap();
    symlink(
        outside.path().join("outside.mdc"),
        project.path().join(".cursor/rules/escape.mdc"),
    )
    .unwrap();

    let report = scan_cursor(
        CursorScanRoots::new(project.path(), project.path(), None),
        ScanLimits::default(),
    );
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == ScanDiagnosticKind::UnsafeSymlink
            && diagnostic.logical_path() == ".cursor/rules/escape.mdc"
    }));
    assert!(report.artifacts().is_empty());
}
