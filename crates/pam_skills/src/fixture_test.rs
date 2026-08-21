use std::{fs, path::Path};

#[cfg(windows)]
use std::path::Component;

use super::{
    AgentArtifact, ArtifactKind, ArtifactScope, ClaudeScanRoots, CodexScanRoots, CursorScanRoots,
    LoadSemantics, OriginAgent, ScanLimits, scan_claude_code, scan_codex, scan_cursor,
};

const CLAUDE_LF: &[u8] = include_bytes!("../tests/fixtures/native-project/.claude/rules/native.md");
const CODEX_CRLF: &[u8] =
    include_bytes!("../tests/fixtures/native-project/workspace child/.codex/config.toml");
const CURSOR_CRLF: &[u8] =
    include_bytes!("../tests/fixtures/native-project/workspace child/.cursor/rules/native.mdc");

fn fixture_root() -> std::path::PathBuf {
    fs::canonicalize(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("native-project"),
    )
    .unwrap()
}

fn artifact<'a>(
    artifacts: &'a [AgentArtifact],
    origin: OriginAgent,
    path: &str,
) -> &'a AgentArtifact {
    artifacts
        .iter()
        .find(|artifact| artifact.origin() == origin && artifact.logical_path() == path)
        .unwrap_or_else(|| panic!("missing {origin:?} fixture artifact at {path}"))
}

fn assert_lf(bytes: &[u8]) {
    assert!(bytes.contains(&b'\n'));
    assert!(!bytes.contains(&b'\r'));
}

fn assert_crlf(bytes: &[u8]) {
    assert!(bytes.windows(2).any(|pair| pair == b"\r\n"));
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            assert!(index > 0 && bytes[index - 1] == b'\r');
        } else if *byte == b'\r' {
            assert_eq!(bytes.get(index + 1), Some(&b'\n'));
        }
    }
}

#[test]
fn static_fixture_tree_scans_through_native_paths() {
    assert_lf(CLAUDE_LF);
    assert_crlf(CODEX_CRLF);
    assert_crlf(CURSOR_CRLF);

    let project = fixture_root();
    let cwd = project.join("workspace child");
    #[cfg(windows)]
    assert!(matches!(
        project.components().next(),
        Some(Component::Prefix(_))
    ));

    let claude = scan_claude_code(
        ClaudeScanRoots::new(None, Some(&project), &[]),
        ScanLimits::default(),
    );
    assert!(claude.complete(), "{:?}", claude.diagnostics());
    let claude_rule = artifact(
        claude.artifacts(),
        OriginAgent::ClaudeCode,
        ".claude/rules/native.md",
    );
    assert_eq!(claude_rule.kind(), ArtifactKind::Rule);
    assert_eq!(claude_rule.scope(), ArtifactScope::Project);
    assert_eq!(claude_rule.load_semantics(), LoadSemantics::PathConditional);

    let codex = scan_codex(
        CodexScanRoots::new(None, None, Some(&project), Some(&cwd), true),
        ScanLimits::default(),
    );
    assert!(codex.complete(), "{:?}", codex.diagnostics());
    let codex_config = artifact(
        codex.artifacts(),
        OriginAgent::Codex,
        "workspace child/.codex/config.toml",
    );
    assert_eq!(codex_config.kind(), ArtifactKind::Config);
    assert_eq!(codex_config.scope(), ArtifactScope::Project);
    assert_eq!(
        codex_config.load_semantics(),
        LoadSemantics::ConfigurationLayer
    );

    let cursor = scan_cursor(
        CursorScanRoots::new(&project, &cwd, None),
        ScanLimits::default(),
    );
    assert!(cursor.complete(), "{:?}", cursor.diagnostics());
    let cursor_rule = artifact(
        cursor.artifacts(),
        OriginAgent::Cursor,
        "workspace child/.cursor/rules/native.mdc",
    );
    assert_eq!(cursor_rule.kind(), ArtifactKind::Rule);
    assert_eq!(cursor_rule.scope(), ArtifactScope::Project);
    assert_eq!(cursor_rule.load_semantics(), LoadSemantics::PathConditional);

    for logical_path in [
        claude_rule.logical_path(),
        codex_config.logical_path(),
        cursor_rule.logical_path(),
    ] {
        assert!(!logical_path.contains('\\'));
    }
}
