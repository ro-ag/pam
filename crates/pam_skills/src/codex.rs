use std::{fs, path::Path, path::PathBuf};

use serde::Deserialize;

use crate::{
    AgentArtifact, ArtifactKind, ArtifactScope, LoadSemantics, MAX_ARTIFACT_NAME_BYTES,
    OriginAgent,
    scan::{
        RootedPath, ScanDiagnosticKind, ScanLimits, ScanReport, ScanSession, ScannedFile,
        is_markdown,
    },
};

const CONFIG_FILE: &str = "config.toml";
const PROJECT_CONFIG_FILE: &str = ".codex/config.toml";
const AGENTS_OVERRIDE_FILE: &str = "AGENTS.override.md";
const AGENTS_FILE: &str = "AGENTS.md";
const PROJECT_RELATION_DIAGNOSTIC_PATH: &str = "<project-root-to-cwd>";

#[derive(Clone, Copy, Debug)]
pub struct CodexScanRoots<'a> {
    pub system_config_root: Option<&'a Path>,
    pub codex_home: Option<&'a Path>,
    pub project_root: Option<&'a Path>,
    pub current_working_directory: Option<&'a Path>,
    pub trusted_project: bool,
}

impl<'a> CodexScanRoots<'a> {
    #[must_use]
    pub const fn new(
        system_config_root: Option<&'a Path>,
        codex_home: Option<&'a Path>,
        project_root: Option<&'a Path>,
        current_working_directory: Option<&'a Path>,
        trusted_project: bool,
    ) -> Self {
        Self {
            system_config_root,
            codex_home,
            project_root,
            current_working_directory,
            trusted_project,
        }
    }
}

/// Inventories Codex configuration and instruction artifacts without retaining content.
#[must_use]
pub fn scan_codex(roots: CodexScanRoots<'_>, limits: ScanLimits) -> ScanReport {
    let mut session = ScanSession::new(limits);
    let mut fallback_filenames = Vec::new();

    if let Some(system_config_root) = roots.system_config_root
        && let Some(root) = session.open_root(system_config_root, "", "system")
        && let Some(configured) = scan_config(
            &mut session,
            &root,
            Path::new(CONFIG_FILE),
            ArtifactScope::System,
        )
    {
        fallback_filenames = configured;
    }

    let user_root = roots
        .codex_home
        .and_then(|home| session.open_root(home, "", "codex_home"));
    if let Some(ref root) = user_root
        && let Some(configured) = scan_config(
            &mut session,
            root,
            Path::new(CONFIG_FILE),
            ArtifactScope::User,
        )
    {
        fallback_filenames = configured;
    }

    let project = open_project(&mut session, roots);
    if let Some((ref root, ref directories)) = project {
        if roots.trusted_project {
            for directory in directories {
                let path = directory.join(PROJECT_CONFIG_FILE);
                if let Some(configured) =
                    scan_config(&mut session, root, &path, ArtifactScope::Project)
                {
                    fallback_filenames = configured;
                }
            }
        } else {
            for directory in directories {
                diagnose_untrusted_config(&mut session, root, &directory.join(PROJECT_CONFIG_FILE));
            }
        }
    }

    if let Some(ref root) = user_root {
        scan_global_agents(&mut session, root);
        scan_prompts(&mut session, root);
    }
    if let Some((ref root, ref directories)) = project {
        for directory in directories {
            scan_project_agents(&mut session, root, directory, &fallback_filenames);
        }
    }

    session.finish()
}

fn open_project(
    session: &mut ScanSession,
    roots: CodexScanRoots<'_>,
) -> Option<(RootedPath, Vec<PathBuf>)> {
    let project_root = roots.project_root?;
    let root = session.open_root(project_root, "", "project")?;
    let Some(cwd) = roots.current_working_directory else {
        session.diagnostic(
            PROJECT_RELATION_DIAGNOSTIC_PATH,
            ScanDiagnosticKind::InvalidProjectRootRelation,
        );
        return None;
    };
    let directories = project_directories(session, &root, cwd)?;
    Some((root, directories))
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

fn scan_config(
    session: &mut ScanSession,
    root: &RootedPath,
    path: &Path,
    scope: ArtifactScope,
) -> Option<Vec<String>> {
    let file = session.read_optional_file(root, path)?;
    let configured = parse_fallback_filenames(session, &file);
    add_file_artifact(
        session,
        file,
        CONFIG_FILE,
        ArtifactKind::Config,
        scope,
        LoadSemantics::ConfigurationLayer,
    );
    configured
}

fn diagnose_untrusted_config(session: &mut ScanSession, root: &RootedPath, path: &Path) {
    if let Some(logical_path) = session.inspect_optional_file(root, path) {
        session.diagnostic(&logical_path, ScanDiagnosticKind::UntrustedProjectConfig);
    }
}

#[derive(Deserialize)]
struct SafeConfigFields {
    project_doc_fallback_filenames: Option<Vec<String>>,
}

fn parse_fallback_filenames(session: &mut ScanSession, file: &ScannedFile) -> Option<Vec<String>> {
    let Ok(source) = std::str::from_utf8(&file.bytes) else {
        session.diagnostic(&file.logical_path, ScanDiagnosticKind::InvalidToml);
        return None;
    };
    let Ok(config) = toml::from_str::<SafeConfigFields>(source) else {
        session.diagnostic(&file.logical_path, ScanDiagnosticKind::InvalidToml);
        return None;
    };
    let filenames = config.project_doc_fallback_filenames?;
    if filenames.iter().any(|filename| !safe_filename(filename)) {
        session.diagnostic(
            &file.logical_path,
            ScanDiagnosticKind::UnsafeFallbackFilename,
        );
        return None;
    }
    let mut unique = Vec::with_capacity(filenames.len());
    for filename in filenames {
        if !unique.contains(&filename) {
            unique.push(filename);
        }
    }
    Some(unique)
}

fn safe_filename(filename: &str) -> bool {
    let bytes = filename.as_bytes();
    let windows_drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    !(filename.is_empty()
        || filename.len() > MAX_ARTIFACT_NAME_BYTES
        || filename.contains(['\0', '/', '\\'])
        || matches!(filename, "." | "..")
        || windows_drive)
}

fn scan_global_agents(session: &mut ScanSession, root: &RootedPath) {
    scan_first_nonempty_agents(
        session,
        root,
        Path::new(""),
        &[AGENTS_OVERRIDE_FILE, AGENTS_FILE],
        ArtifactScope::User,
    );
}

fn scan_project_agents(
    session: &mut ScanSession,
    root: &RootedPath,
    directory: &Path,
    fallback_filenames: &[String],
) {
    let mut candidates = vec![AGENTS_OVERRIDE_FILE, AGENTS_FILE];
    candidates.extend(fallback_filenames.iter().map(String::as_str));
    candidates.dedup();
    scan_first_nonempty_agents(
        session,
        root,
        directory,
        &candidates,
        ArtifactScope::Project,
    );
}

fn scan_first_nonempty_agents(
    session: &mut ScanSession,
    root: &RootedPath,
    directory: &Path,
    candidates: &[&str],
    scope: ArtifactScope,
) {
    for candidate in candidates {
        let path = directory.join(candidate);
        let Some(file) = session.read_optional_file(root, &path) else {
            continue;
        };
        if file.bytes.is_empty() {
            continue;
        }
        add_file_artifact(
            session,
            file,
            candidate,
            ArtifactKind::Instruction,
            scope,
            LoadSemantics::Always,
        );
        return;
    }
}

fn scan_prompts(session: &mut ScanSession, root: &RootedPath) {
    let prompts = session.list_files(root, Path::new("prompts"), is_markdown);
    for path in prompts {
        let Some(file) = session.read_optional_file(root, &path) else {
            continue;
        };
        let Some(name) = path.file_stem().and_then(|name| name.to_str()) else {
            session.diagnostic(&file.logical_path, ScanDiagnosticKind::NonUtf8Path);
            continue;
        };
        add_file_artifact(
            session,
            file,
            name,
            ArtifactKind::Prompt,
            ArtifactScope::User,
            LoadSemantics::Explicit,
        );
    }
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
        OriginAgent::Codex,
        load_semantics,
        file.content_hash,
    ) {
        Ok(artifact) => session.push_artifact(artifact),
        Err(_) => session.diagnostic(&file.logical_path, ScanDiagnosticKind::InvalidArtifact),
    }
}
