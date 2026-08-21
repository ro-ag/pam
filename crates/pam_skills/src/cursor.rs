use std::{fs, path::Path, path::PathBuf};

use serde::Serialize;

use crate::{
    AgentArtifact, ArtifactKind, ArtifactScope, LoadSemantics, OriginAgent, ScanDiagnostic,
    scan::{RootedPath, ScanDiagnosticKind, ScanLimits, ScanReport, ScanSession, ScannedFile},
};

const PROJECT_RELATION_DIAGNOSTIC_PATH: &str = "<project-root-to-cwd>";

#[derive(Clone, Copy, Debug)]
pub struct CursorGlobalRuleSource<'a> {
    pub root: &'a Path,
    pub relative_path: &'a Path,
}

impl<'a> CursorGlobalRuleSource<'a> {
    #[must_use]
    pub const fn new(root: &'a Path, relative_path: &'a Path) -> Self {
        Self {
            root,
            relative_path,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CursorScanRoots<'a> {
    pub project_root: &'a Path,
    pub current_working_directory: &'a Path,
    pub global_rule: Option<CursorGlobalRuleSource<'a>>,
}

impl<'a> CursorScanRoots<'a> {
    #[must_use]
    pub const fn new(
        project_root: &'a Path,
        current_working_directory: &'a Path,
        global_rule: Option<CursorGlobalRuleSource<'a>>,
    ) -> Self {
        Self {
            project_root,
            current_working_directory,
            global_rule,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CursorGlobalRulesStatus {
    NotLocallyDiscoverable,
    ExplicitlyConfigured,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CursorScanReport {
    scan: ScanReport,
    global_rules_status: CursorGlobalRulesStatus,
}

impl CursorScanReport {
    #[must_use]
    pub const fn scan_report(&self) -> &ScanReport {
        &self.scan
    }

    #[must_use]
    pub const fn global_rules_status(&self) -> CursorGlobalRulesStatus {
        self.global_rules_status
    }

    #[must_use]
    pub fn artifacts(&self) -> &[AgentArtifact] {
        self.scan.artifacts()
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[ScanDiagnostic] {
        self.scan.diagnostics()
    }

    #[must_use]
    pub const fn complete(&self) -> bool {
        self.scan.complete()
    }

    #[must_use]
    pub fn into_scan_report(self) -> ScanReport {
        self.scan
    }
}

/// Inventories Cursor rules and instructions without inspecting application databases.
#[must_use]
pub fn scan_cursor(roots: CursorScanRoots<'_>, limits: ScanLimits) -> CursorScanReport {
    let mut session = ScanSession::new(limits);
    let global_rules_status = match roots.global_rule {
        Some(source) => {
            scan_global_rule(&mut session, source);
            CursorGlobalRulesStatus::ExplicitlyConfigured
        }
        None => CursorGlobalRulesStatus::NotLocallyDiscoverable,
    };

    if let Some(root) = session.open_root(roots.project_root, "", "project")
        && let Some(directories) =
            project_directories(&mut session, &root, roots.current_working_directory)
    {
        scan_legacy_rule(&mut session, &root);
        for directory in directories {
            scan_rules(&mut session, &root, &directory);
            scan_agents(&mut session, &root, &directory);
        }
    }

    CursorScanReport {
        scan: session.finish(),
        global_rules_status,
    }
}

fn scan_global_rule(session: &mut ScanSession, source: CursorGlobalRuleSource<'_>) {
    let Some(root) = session.open_root(source.root, "", "cursor_global_rules") else {
        return;
    };
    let Some(file) = session.read_optional_file(&root, source.relative_path) else {
        return;
    };
    let Some(name) = source
        .relative_path
        .file_stem()
        .and_then(|name| name.to_str())
    else {
        session.diagnostic(&file.logical_path, ScanDiagnosticKind::NonUtf8Path);
        return;
    };
    add_file_artifact(
        session,
        file,
        name,
        ArtifactKind::Rule,
        ArtifactScope::User,
        LoadSemantics::Always,
    );
}

fn project_directories(
    session: &mut ScanSession,
    root: &RootedPath,
    cwd: &Path,
) -> Option<Vec<PathBuf>> {
    let Ok(canonical_cwd) = fs::canonicalize(cwd) else {
        session.diagnostic(
            PROJECT_RELATION_DIAGNOSTIC_PATH,
            ScanDiagnosticKind::InvalidProjectRootRelation,
        );
        return None;
    };
    let is_directory = fs::metadata(&canonical_cwd).is_ok_and(|metadata| metadata.is_dir());
    let Ok(relative_cwd) = canonical_cwd.strip_prefix(root.canonical_path()) else {
        session.diagnostic(
            PROJECT_RELATION_DIAGNOSTIC_PATH,
            ScanDiagnosticKind::InvalidProjectRootRelation,
        );
        return None;
    };
    if !is_directory {
        session.diagnostic(
            PROJECT_RELATION_DIAGNOSTIC_PATH,
            ScanDiagnosticKind::InvalidProjectRootRelation,
        );
        return None;
    }

    let mut directories = vec![PathBuf::new()];
    let mut current = PathBuf::new();
    for component in relative_cwd.components() {
        current.push(component);
        directories.push(current.clone());
    }
    Some(directories)
}

fn scan_legacy_rule(session: &mut ScanSession, root: &RootedPath) {
    let path = Path::new(".cursorrules");
    let Some(file) = session.read_optional_file(root, path) else {
        return;
    };
    add_file_artifact(
        session,
        file,
        ".cursorrules",
        ArtifactKind::Rule,
        ArtifactScope::Project,
        LoadSemantics::Always,
    );
}

fn scan_rules(session: &mut ScanSession, root: &RootedPath, directory: &Path) {
    let rules_directory = directory.join(".cursor/rules");
    let rules = session.walk_files(root, &rules_directory, is_mdc);
    for path in rules {
        let Some(file) = session.read_optional_file(root, &path) else {
            continue;
        };
        let Some(name) = path.file_stem().and_then(|name| name.to_str()) else {
            session.diagnostic(&file.logical_path, ScanDiagnosticKind::NonUtf8Path);
            continue;
        };
        let semantics = mdc_semantics(session, &file);
        add_file_artifact(
            session,
            file,
            name,
            ArtifactKind::Rule,
            ArtifactScope::Project,
            semantics,
        );
    }
}

fn scan_agents(session: &mut ScanSession, root: &RootedPath, directory: &Path) {
    let path = directory.join("AGENTS.md");
    let Some(file) = session.read_optional_file(root, &path) else {
        return;
    };
    add_file_artifact(
        session,
        file,
        "AGENTS.md",
        ArtifactKind::Instruction,
        ArtifactScope::Project,
        LoadSemantics::Always,
    );
}

fn is_mdc(path: &Path) -> bool {
    path.extension().and_then(|extension| extension.to_str()) == Some("mdc")
}

fn mdc_semantics(session: &mut ScanSession, file: &ScannedFile) -> LoadSemantics {
    let Ok(source) = std::str::from_utf8(&file.bytes) else {
        session.diagnostic(&file.logical_path, ScanDiagnosticKind::NonUtf8Content);
        return LoadSemantics::Unavailable;
    };
    if let Ok(semantics) = parse_frontmatter(source) {
        semantics
    } else {
        session.diagnostic(&file.logical_path, ScanDiagnosticKind::InvalidFrontmatter);
        LoadSemantics::Unavailable
    }
}

fn parse_frontmatter(source: &str) -> Result<LoadSemantics, ()> {
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    let mut lines = source.lines();
    if lines.next().map(str::trim) != Some("---") {
        return Ok(LoadSemantics::Explicit);
    }

    let mut always_apply = false;
    let mut has_globs = false;
    let mut has_description = false;
    let mut reading_globs = false;
    let mut closed = false;
    for line in lines {
        let trimmed = line.trim();
        if trimmed == "---" {
            closed = true;
            break;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            if reading_globs && trimmed.starts_with('-') {
                has_globs |= meaningful_value(trimmed.trim_start_matches('-'));
            }
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            return Err(());
        };
        let key = key.trim();
        let value = value.trim();
        reading_globs = key == "globs";
        match key {
            "alwaysApply" => {
                always_apply = match value {
                    "true" => true,
                    "false" => false,
                    _ => return Err(()),
                };
            }
            "globs" => has_globs |= meaningful_value(value),
            "description" => has_description |= meaningful_value(value),
            _ => {}
        }
    }
    if !closed {
        return Err(());
    }
    if always_apply {
        Ok(LoadSemantics::Always)
    } else if has_globs {
        Ok(LoadSemantics::PathConditional)
    } else if has_description {
        Ok(LoadSemantics::ModelSelected)
    } else {
        Ok(LoadSemantics::Explicit)
    }
}

fn meaningful_value(value: &str) -> bool {
    !matches!(
        value.trim(),
        "" | "[]" | "[ ]" | "\"\"" | "''" | "null" | "~"
    )
}

fn add_file_artifact(
    session: &mut ScanSession,
    file: ScannedFile,
    name: &str,
    kind: ArtifactKind,
    scope: ArtifactScope,
    load_semantics: LoadSemantics,
) {
    match AgentArtifact::new(
        name,
        &file.logical_path,
        kind,
        scope,
        OriginAgent::Cursor,
        load_semantics,
        file.content_hash,
    ) {
        Ok(artifact) => session.push_artifact(artifact),
        Err(_) => session.diagnostic(&file.logical_path, ScanDiagnosticKind::InvalidArtifact),
    }
}
