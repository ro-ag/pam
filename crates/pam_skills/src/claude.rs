use std::path::Path;

use serde_json::Value;

use crate::{
    AgentArtifact, ArtifactKind, ArtifactScope, LoadSemantics, MAX_ARTIFACT_NAME_BYTES,
    OriginAgent,
    scan::{
        RootedPath, ScanDiagnosticKind, ScanLimits, ScanReport, ScanSession, ScannedFile,
        is_markdown,
    },
};

#[derive(Clone, Copy, Debug)]
pub struct ClaudePluginRoot<'a> {
    pub id: &'a str,
    pub root: &'a Path,
}

impl<'a> ClaudePluginRoot<'a> {
    #[must_use]
    pub const fn new(id: &'a str, root: &'a Path) -> Self {
        Self { id, root }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ClaudeScanRoots<'a> {
    pub user_home: Option<&'a Path>,
    pub project_root: Option<&'a Path>,
    pub enabled_plugins: &'a [ClaudePluginRoot<'a>],
}

impl<'a> ClaudeScanRoots<'a> {
    #[must_use]
    pub const fn new(
        user_home: Option<&'a Path>,
        project_root: Option<&'a Path>,
        enabled_plugins: &'a [ClaudePluginRoot<'a>],
    ) -> Self {
        Self {
            user_home,
            project_root,
            enabled_plugins,
        }
    }
}

/// Inventories Claude Code artifacts without evaluating their contents.
///
/// Plugin roots must be supplied explicitly by the caller. This adapter never
/// searches Claude's plugin download or marketplace caches.
#[must_use]
pub fn scan_claude_code(roots: ClaudeScanRoots<'_>, limits: ScanLimits) -> ScanReport {
    let mut session = ScanSession::new(limits);
    if let Some(user_home) = roots.user_home
        && let Some(root) = session.open_root(user_home, "", "user")
    {
        scan_user(&mut session, &root);
    }
    if let Some(project_root) = roots.project_root
        && let Some(root) = session.open_root(project_root, "", "project")
    {
        scan_project(&mut session, &root);
    }

    let mut plugins = roots.enabled_plugins.iter().collect::<Vec<_>>();
    plugins.sort_unstable_by(|left, right| left.id.cmp(right.id));
    for plugin in plugins {
        scan_plugin(&mut session, plugin);
    }
    session.finish()
}

fn scan_user(session: &mut ScanSession, root: &RootedPath) {
    scan_instruction(
        session,
        root,
        Path::new(".claude/CLAUDE.md"),
        ArtifactScope::User,
    );
    scan_standard_directories(session, root, ArtifactScope::User);
    scan_settings(
        session,
        root,
        Path::new(".claude/settings.json"),
        ArtifactScope::User,
    );
    scan_settings(
        session,
        root,
        Path::new(".claude/settings.local.json"),
        ArtifactScope::User,
    );
}

fn scan_project(session: &mut ScanSession, root: &RootedPath) {
    for path in [
        Path::new("CLAUDE.md"),
        Path::new(".claude/CLAUDE.md"),
        Path::new("CLAUDE.local.md"),
    ] {
        scan_instruction(session, root, path, ArtifactScope::Project);
    }
    scan_standard_directories(session, root, ArtifactScope::Project);
    scan_settings(
        session,
        root,
        Path::new(".claude/settings.json"),
        ArtifactScope::Project,
    );
    scan_settings(
        session,
        root,
        Path::new(".claude/settings.local.json"),
        ArtifactScope::Local,
    );
}

fn scan_standard_directories(session: &mut ScanSession, root: &RootedPath, scope: ArtifactScope) {
    let skills = session.walk_files(root, Path::new(".claude/skills"), |path| {
        path.file_name().and_then(|name| name.to_str()) == Some("SKILL.md")
    });
    for path in skills {
        if let Some(file) = session.read_optional_file(root, &path) {
            let name = path
                .parent()
                .and_then(Path::file_name)
                .and_then(|name| name.to_str());
            add_file_artifact(
                session,
                file,
                name,
                ArtifactKind::Skill,
                scope,
                LoadSemantics::ModelSelected,
            );
        }
    }

    let agents = session.walk_files(root, Path::new(".claude/agents"), is_markdown);
    for path in agents {
        if let Some(file) = session.read_optional_file(root, &path) {
            let name = path.file_stem().and_then(|name| name.to_str());
            add_file_artifact(
                session,
                file,
                name,
                ArtifactKind::Agent,
                scope,
                LoadSemantics::ModelSelected,
            );
        }
    }

    let rules = session.walk_files(root, Path::new(".claude/rules"), is_markdown);
    for path in rules {
        if let Some(file) = session.read_optional_file(root, &path) {
            let name = path.file_stem().and_then(|name| name.to_str());
            let semantics = rule_semantics(session, &file);
            add_file_artifact(session, file, name, ArtifactKind::Rule, scope, semantics);
        }
    }
}

fn scan_instruction(
    session: &mut ScanSession,
    root: &RootedPath,
    path: &Path,
    scope: ArtifactScope,
) {
    let Some(file) = session.read_optional_file(root, path) else {
        return;
    };
    let name = path.file_name().and_then(|name| name.to_str());
    add_file_artifact(
        session,
        file,
        name,
        ArtifactKind::Instruction,
        scope,
        LoadSemantics::Always,
    );
}

fn scan_settings(session: &mut ScanSession, root: &RootedPath, path: &Path, scope: ArtifactScope) {
    let Some(file) = session.read_optional_file(root, path) else {
        return;
    };
    let name = path.file_name().and_then(|name| name.to_str());
    let parsed = serde_json::from_slice::<Value>(&file.bytes);
    let has_hooks = if let Ok(ref settings) = parsed {
        settings.get("hooks").is_some_and(nonempty_json)
    } else {
        session.diagnostic(&file.logical_path, ScanDiagnosticKind::InvalidJson);
        false
    };
    if has_hooks {
        add_file_artifact(
            session,
            ScannedFile {
                logical_path: file.logical_path.clone(),
                bytes: Vec::new(),
                content_hash: file.content_hash.clone(),
            },
            Some("hooks"),
            ArtifactKind::Hook,
            scope,
            LoadSemantics::EventTriggered,
        );
    }
    add_file_artifact(
        session,
        file,
        name,
        ArtifactKind::Config,
        scope,
        LoadSemantics::ConfigurationLayer,
    );
}

fn scan_plugin(session: &mut ScanSession, plugin: &ClaudePluginRoot<'_>) {
    if !valid_plugin_id(plugin.id) {
        session.diagnostic(plugin.id, ScanDiagnosticKind::InvalidPluginId);
        return;
    }
    let logical_prefix = format!("plugins/{}", plugin.id);
    let Some(root) = session.open_root(plugin.root, logical_prefix, plugin.id) else {
        return;
    };

    let manifest_path = Path::new(".claude-plugin/plugin.json");
    if let Some(file) = session.read_optional_file(&root, manifest_path) {
        validate_json(session, &file);
        add_file_artifact(
            session,
            file,
            Some(plugin.id),
            ArtifactKind::Plugin,
            ArtifactScope::Plugin,
            LoadSemantics::PluginEnabled,
        );
    } else {
        session.diagnostic(
            &format!("plugins/{}/.claude-plugin/plugin.json", plugin.id),
            ScanDiagnosticKind::MissingPluginManifest,
        );
    }

    let skills = session.walk_files(&root, Path::new("skills"), |path| {
        path.file_name().and_then(|name| name.to_str()) == Some("SKILL.md")
    });
    for path in skills {
        if let Some(file) = session.read_optional_file(&root, &path) {
            let name = path
                .parent()
                .and_then(Path::file_name)
                .and_then(|name| name.to_str());
            add_file_artifact(
                session,
                file,
                name,
                ArtifactKind::Skill,
                ArtifactScope::Plugin,
                LoadSemantics::ModelSelected,
            );
        }
    }

    let agents = session.walk_files(&root, Path::new("agents"), is_markdown);
    for path in agents {
        if let Some(file) = session.read_optional_file(&root, &path) {
            let name = path.file_stem().and_then(|name| name.to_str());
            add_file_artifact(
                session,
                file,
                name,
                ArtifactKind::Agent,
                ArtifactScope::Plugin,
                LoadSemantics::ModelSelected,
            );
        }
    }

    if let Some(file) = session.read_optional_file(&root, Path::new("hooks/hooks.json")) {
        validate_json(session, &file);
        add_file_artifact(
            session,
            file,
            Some("hooks"),
            ArtifactKind::Hook,
            ArtifactScope::Plugin,
            LoadSemantics::EventTriggered,
        );
    }
}

fn validate_json(session: &mut ScanSession, file: &ScannedFile) {
    if serde_json::from_slice::<Value>(&file.bytes).is_err() {
        session.diagnostic(&file.logical_path, ScanDiagnosticKind::InvalidJson);
    }
}

fn add_file_artifact(
    session: &mut ScanSession,
    file: ScannedFile,
    name: Option<&str>,
    kind: ArtifactKind,
    scope: ArtifactScope,
    load_semantics: LoadSemantics,
) {
    let Some(name) = name else {
        session.diagnostic(&file.logical_path, ScanDiagnosticKind::NonUtf8Path);
        return;
    };
    match AgentArtifact::new(
        name,
        &file.logical_path,
        kind,
        scope,
        OriginAgent::ClaudeCode,
        load_semantics,
        file.content_hash,
    ) {
        Ok(artifact) => session.push_artifact(artifact),
        Err(_) => session.diagnostic(&file.logical_path, ScanDiagnosticKind::InvalidArtifact),
    }
}

fn rule_semantics(session: &mut ScanSession, file: &ScannedFile) -> LoadSemantics {
    let Ok(source) = std::str::from_utf8(&file.bytes) else {
        session.diagnostic(&file.logical_path, ScanDiagnosticKind::NonUtf8Content);
        return LoadSemantics::Unavailable;
    };
    if frontmatter_has_paths(source) {
        LoadSemantics::PathConditional
    } else {
        LoadSemantics::Always
    }
}

fn frontmatter_has_paths(source: &str) -> bool {
    let mut lines = source.strip_prefix('\u{feff}').unwrap_or(source).lines();
    if lines.next().map(str::trim) != Some("---") {
        return false;
    }
    let mut paths_block = false;
    for line in lines {
        let trimmed = line.trim();
        if trimmed == "---" {
            break;
        }
        if let Some(value) = trimmed.strip_prefix("paths:") {
            paths_block = true;
            let value = value.trim();
            if !value.is_empty() && value != "[]" {
                return true;
            }
            continue;
        }
        if paths_block {
            if trimmed.starts_with('-') && trimmed.len() > 1 {
                return true;
            }
            if (!line.starts_with(' ') && !line.starts_with('\t'))
                || (!trimmed.is_empty() && !trimmed.starts_with('#'))
            {
                paths_block = false;
            }
        }
    }
    false
}

fn nonempty_json(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Array(values) => !values.is_empty(),
        Value::Object(values) => !values.is_empty(),
        Value::String(value) => !value.is_empty(),
        Value::Bool(value) => *value,
        Value::Number(_) => true,
    }
}

pub(crate) fn valid_plugin_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ARTIFACT_NAME_BYTES
        && !id.contains('/')
        && !id.contains('\\')
        && !id.contains('\0')
        && !matches!(id, "." | "..")
}
