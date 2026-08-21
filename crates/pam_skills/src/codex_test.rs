use std::fs;

use pam_core::ContentDigest;
use sha2::{Digest, Sha256};

use super::{
    AgentArtifact, ArtifactKind, ArtifactScope, CodexScanRoots, LoadSemantics, OriginAgent,
    ScanDiagnosticKind, ScanLimits, scan_codex, scan_test::TestDirectory,
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
                && artifact.origin() == OriginAgent::Codex
        })
        .unwrap_or_else(|| panic!("missing {scope:?} {kind:?} artifact at {path}"))
}

#[test]
fn inventories_layers_nested_agents_and_top_level_prompts_deterministically() {
    let system = TestDirectory::new("codex-system");
    system.write(
        "config.toml",
        b"project_doc_fallback_filenames = [\"SYSTEM.md\"]\n",
    );
    let home = TestDirectory::new("codex-home");
    home.write(
        "config.toml",
        b"project_doc_fallback_filenames = [\"USER.md\"]\r\n",
    );
    home.write("AGENTS.override.md", b"");
    home.write("AGENTS.md", b"global\n");
    home.write("prompts/review.md", b"review\n");
    home.write("prompts/nested/ignored.md", b"ignored\n");
    home.write("prompts/ignored.txt", b"ignored\n");

    let project = TestDirectory::new("codex-project");
    project.write(
        ".codex/config.toml",
        b"project_doc_fallback_filenames = [\"ROOT.md\"]\n",
    );
    project.write(
        "crates/app/.codex/config.toml",
        b"project_doc_fallback_filenames = [\"TEAM.md\"]\r\n",
    );
    project.write("ROOT.md", b"superseded fallback\n");
    project.write("TEAM.md", b"root fallback\n");
    project.write("crates/AGENTS.override.md", b"crate override\n");
    project.write("crates/AGENTS.md", b"shadowed\n");
    project.write("crates/app/AGENTS.override.md", b"");
    project.write("crates/app/AGENTS.md", b"app agents\n");
    project.write("crates/app/deeper/AGENTS.md", b"below cwd\n");
    let cwd = project.path().join("crates/app");

    let roots = CodexScanRoots::new(
        Some(system.path()),
        Some(home.path()),
        Some(project.path()),
        Some(&cwd),
        true,
    );
    let report = scan_codex(roots, ScanLimits::default());
    assert!(report.complete(), "{:?}", report.diagnostics());

    for (path, scope) in [
        ("config.toml", ArtifactScope::System),
        ("config.toml", ArtifactScope::User),
        (".codex/config.toml", ArtifactScope::Project),
        ("crates/app/.codex/config.toml", ArtifactScope::Project),
    ] {
        assert_eq!(
            artifact(report.artifacts(), path, ArtifactKind::Config, scope).load_semantics(),
            LoadSemantics::ConfigurationLayer
        );
    }
    for (path, scope) in [
        ("AGENTS.md", ArtifactScope::User),
        ("TEAM.md", ArtifactScope::Project),
        ("crates/AGENTS.override.md", ArtifactScope::Project),
        ("crates/app/AGENTS.md", ArtifactScope::Project),
    ] {
        assert_eq!(
            artifact(report.artifacts(), path, ArtifactKind::Instruction, scope,).load_semantics(),
            LoadSemantics::Always
        );
    }
    assert_eq!(
        artifact(
            report.artifacts(),
            "prompts/review.md",
            ArtifactKind::Prompt,
            ArtifactScope::User,
        )
        .load_semantics(),
        LoadSemantics::Explicit
    );
    assert!(!report.artifacts().iter().any(|artifact| {
        matches!(
            artifact.logical_path(),
            "ROOT.md" | "crates/AGENTS.md" | "prompts/nested/ignored.md"
        )
    }));
    assert_eq!(report, scan_codex(roots, ScanLimits::default()));
}

#[test]
fn exact_hashes_distinguish_lf_and_crlf_content() {
    let home = TestDirectory::new("codex-line-endings-home");
    let lf = b"global\n";
    home.write("AGENTS.md", lf);
    let project = TestDirectory::new("codex-line-endings-project");
    let crlf = b"project\r\n";
    project.write("AGENTS.md", crlf);

    let report = scan_codex(
        CodexScanRoots::new(
            None,
            Some(home.path()),
            Some(project.path()),
            Some(project.path()),
            true,
        ),
        ScanLimits::default(),
    );
    assert!(report.complete(), "{:?}", report.diagnostics());
    assert_eq!(
        artifact(
            report.artifacts(),
            "AGENTS.md",
            ArtifactKind::Instruction,
            ArtifactScope::User,
        )
        .content_hash(),
        &digest(lf)
    );
    assert_eq!(
        artifact(
            report.artifacts(),
            "AGENTS.md",
            ArtifactKind::Instruction,
            ArtifactScope::Project,
        )
        .content_hash(),
        &digest(crlf)
    );
}

#[test]
fn project_config_is_gated_by_trust_while_agents_use_the_trusted_layers() {
    let home = TestDirectory::new("codex-trust-home");
    home.write(
        "config.toml",
        b"project_doc_fallback_filenames = [\"USER.md\"]\n",
    );
    let project = TestDirectory::new("codex-trust-project");
    project.write(
        ".codex/config.toml",
        format!(
            "project_doc_fallback_filenames = [\"TEAM.md\"]\n# {}\n",
            "padding".repeat(32)
        ),
    );
    project.write("USER.md", b"user fallback\n");
    project.write("TEAM.md", b"project fallback\n");

    let untrusted = scan_codex(
        CodexScanRoots::new(
            None,
            Some(home.path()),
            Some(project.path()),
            Some(project.path()),
            false,
        ),
        ScanLimits {
            max_file_bytes: 64,
            ..ScanLimits::default()
        },
    );
    assert!(untrusted.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == ScanDiagnosticKind::UntrustedProjectConfig
            && diagnostic.logical_path() == ".codex/config.toml"
    }));
    assert!(!untrusted.artifacts().iter().any(|artifact| {
        artifact.logical_path() == ".codex/config.toml" && artifact.kind() == ArtifactKind::Config
    }));
    assert!(!untrusted.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == ScanDiagnosticKind::FileTooLarge
            && diagnostic.logical_path() == ".codex/config.toml"
    }));
    artifact(
        untrusted.artifacts(),
        "USER.md",
        ArtifactKind::Instruction,
        ArtifactScope::Project,
    );

    let trusted = scan_codex(
        CodexScanRoots::new(
            None,
            Some(home.path()),
            Some(project.path()),
            Some(project.path()),
            true,
        ),
        ScanLimits::default(),
    );
    assert!(trusted.complete(), "{:?}", trusted.diagnostics());
    artifact(
        trusted.artifacts(),
        ".codex/config.toml",
        ArtifactKind::Config,
        ArtifactScope::Project,
    );
    artifact(
        trusted.artifacts(),
        "TEAM.md",
        ArtifactKind::Instruction,
        ArtifactScope::Project,
    );
}

#[test]
fn invalid_toml_and_unsafe_fallbacks_are_typed_and_not_followed() {
    let system = TestDirectory::new("codex-invalid-system");
    system.write("config.toml", b"invalid = [\n");
    let home = TestDirectory::new("codex-unsafe-home");
    home.write(
        "config.toml",
        b"project_doc_fallback_filenames = [\"../escape.md\"]\n",
    );
    let project = TestDirectory::new("codex-unsafe-project");
    project.write("escape.md", b"must not load\n");

    let report = scan_codex(
        CodexScanRoots::new(
            Some(system.path()),
            Some(home.path()),
            Some(project.path()),
            Some(project.path()),
            true,
        ),
        ScanLimits::default(),
    );
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == ScanDiagnosticKind::InvalidToml
            && diagnostic.logical_path() == "config.toml"
    }));
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == ScanDiagnosticKind::UnsafeFallbackFilename
            && diagnostic.logical_path() == "config.toml"
    }));
    assert!(!report.artifacts().iter().any(|artifact| {
        artifact.logical_path() == "escape.md" && artifact.kind() == ArtifactKind::Instruction
    }));
}

#[test]
fn invalid_project_root_to_cwd_relation_skips_project_inventory() {
    let project = TestDirectory::new("codex-project-root");
    project.write("AGENTS.md", b"project\n");
    let outside = TestDirectory::new("codex-outside-cwd");

    let report = scan_codex(
        CodexScanRoots::new(None, None, Some(project.path()), Some(outside.path()), true),
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
    let home = TestDirectory::new("codex-bounds-home");
    home.write("AGENTS.md", b"12345");
    home.write("prompts/small.md", b"1234");

    let report = scan_codex(
        CodexScanRoots::new(None, Some(home.path()), None, None, false),
        ScanLimits {
            max_file_bytes: 4,
            ..ScanLimits::default()
        },
    );
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == ScanDiagnosticKind::FileTooLarge
            && diagnostic.logical_path() == "AGENTS.md"
    }));
    assert_eq!(report.artifacts().len(), 1);
    artifact(
        report.artifacts(),
        "prompts/small.md",
        ArtifactKind::Prompt,
        ArtifactScope::User,
    );
}

#[cfg(unix)]
#[test]
fn inherited_symlink_policy_rejects_prompt_escape() {
    use std::os::unix::fs::symlink;

    let home = TestDirectory::new("codex-symlink-home");
    let outside = TestDirectory::new("codex-symlink-outside");
    outside.write("secret.md", b"secret\n");
    fs::create_dir_all(home.path().join("prompts")).unwrap();
    symlink(
        outside.path().join("secret.md"),
        home.path().join("prompts/escape.md"),
    )
    .unwrap();

    let report = scan_codex(
        CodexScanRoots::new(None, Some(home.path()), None, None, false),
        ScanLimits::default(),
    );
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == ScanDiagnosticKind::UnsafeSymlink
            && diagnostic.logical_path() == "prompts/escape.md"
    }));
    assert!(report.artifacts().is_empty());
}
