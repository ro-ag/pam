use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    AgentArtifact, ArtifactScope, ClaudePluginRoot, ClaudeScanRoots, CodexProjectTrust,
    CodexProjectTrustError, CursorGlobalRuleSource, CursorGlobalRulesStatus, CursorScanRoots,
    ScanDiagnostic, ScanLimits, ScanReport,
    claude::valid_plugin_id,
    resolve_codex_project_trust,
    scan::{ScanSession, merge_scan_reports},
    scan_claude_code, scan_codex, scan_cursor,
};

const PLUGIN_REGISTRY_FILE: &str = "installed_plugins.json";
const USER_SETTINGS_FILE: &str = ".claude/settings.json";
const PROJECT_SETTINGS_FILE: &str = ".claude/settings.json";
const LOCAL_SETTINGS_FILE: &str = ".claude/settings.local.json";
const SUPPORTED_PLUGIN_REGISTRY_VERSION: u32 = 2;

#[derive(Clone, Copy, Debug)]
pub struct LocalInventoryRoots<'a> {
    pub user_home: Option<&'a Path>,
    pub claude_plugin_registry_root: Option<&'a Path>,
    pub codex_system_config_root: Option<&'a Path>,
    pub codex_home: Option<&'a Path>,
    pub project_root: &'a Path,
    pub current_working_directory: &'a Path,
    pub cursor_global_rule: Option<CursorGlobalRuleSource<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LocalInventoryReport {
    scan: ScanReport,
    cursor_global_rules_status: CursorGlobalRulesStatus,
}

impl LocalInventoryReport {
    #[must_use]
    pub const fn scan_report(&self) -> &ScanReport {
        &self.scan
    }

    #[must_use]
    pub const fn cursor_global_rules_status(&self) -> CursorGlobalRulesStatus {
        self.cursor_global_rules_status
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

/// Scans all supported local agent ecosystems through their bounded adapters.
///
/// # Errors
///
/// Returns an error before producing a report when an explicitly configured
/// Claude plugin registry is unsafe, malformed, or uses another schema version.
pub fn scan_local_inventory(
    roots: LocalInventoryRoots<'_>,
    limits: ScanLimits,
) -> Result<LocalInventoryReport, LocalInventoryError> {
    let plugins = plugin_roots(roots, limits)?;
    let codex_project_trust =
        resolve_codex_project_trust(roots.codex_home, roots.project_root, limits)?;
    let plugin_views = plugins
        .iter()
        .map(|plugin| ClaudePluginRoot::new(&plugin.id, &plugin.path))
        .collect::<Vec<_>>();
    let claude = scan_claude_code(
        ClaudeScanRoots::new(roots.user_home, Some(roots.project_root), &plugin_views),
        limits,
    );
    let codex = scan_codex(
        crate::CodexScanRoots::new(
            roots.codex_system_config_root,
            roots.codex_home,
            Some(roots.project_root),
            Some(roots.current_working_directory),
            codex_project_trust == CodexProjectTrust::Trusted,
        ),
        limits,
    );
    let cursor = scan_cursor(
        CursorScanRoots::new(
            roots.project_root,
            roots.current_working_directory,
            roots.cursor_global_rule,
        ),
        limits,
    );
    let cursor_global_rules_status = cursor.global_rules_status();
    let scan = merge_scan_reports([claude, codex, cursor.into_scan_report()], limits);
    Ok(LocalInventoryReport {
        scan,
        cursor_global_rules_status,
    })
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct OwnedPluginRoot {
    id: String,
    path: PathBuf,
}

#[derive(Deserialize)]
struct PluginRegistry {
    version: u32,
    plugins: BTreeMap<String, Vec<PluginInstallation>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PluginInstallation {
    install_path: PathBuf,
    scope: PluginScope,
    project_path: Option<PathBuf>,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum PluginScope {
    Managed,
    User,
    Project,
    Local,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClaudeSettings {
    #[serde(default)]
    enabled_plugins: BTreeMap<String, bool>,
}

fn plugin_roots(
    roots: LocalInventoryRoots<'_>,
    limits: ScanLimits,
) -> Result<Vec<OwnedPluginRoot>, LocalInventoryError> {
    let mut session = ScanSession::new(limits);
    let registry_root = roots
        .claude_plugin_registry_root
        .and_then(|root| session.open_root(root, "", "claude_plugin_registry"));
    let registry_file = registry_root
        .as_ref()
        .and_then(|root| session.read_optional_file(root, Path::new(PLUGIN_REGISTRY_FILE)));

    let user_root = roots
        .user_home
        .and_then(|root| session.open_root(root, "", "claude_user_home"));
    let user_settings = user_root
        .as_ref()
        .and_then(|root| session.read_optional_file(root, Path::new(USER_SETTINGS_FILE)));

    let project_root = session.open_root(roots.project_root, "", "claude_project");
    let project_settings = project_root
        .as_ref()
        .and_then(|root| session.read_optional_file(root, Path::new(PROJECT_SETTINGS_FILE)));
    let local_settings = project_root
        .as_ref()
        .and_then(|root| session.read_optional_file(root, Path::new(LOCAL_SETTINGS_FILE)));

    let diagnostics = session.finish().diagnostics().to_vec();
    if !diagnostics.is_empty() {
        return Err(LocalInventoryError::PluginRegistryScan(diagnostics));
    }

    let registry = parse_registry(registry_file.as_ref().map(|file| file.bytes.as_slice()))?;
    let mut enabled_plugins = parse_settings(user_settings, ArtifactScope::User)?;
    enabled_plugins.extend(parse_settings(project_settings, ArtifactScope::Project)?);
    enabled_plugins.extend(parse_settings(local_settings, ArtifactScope::Local)?);
    select_plugin_roots(registry, enabled_plugins, roots.project_root)
}

fn parse_registry(bytes: Option<&[u8]>) -> Result<PluginRegistry, LocalInventoryError> {
    let Some(bytes) = bytes else {
        return Ok(PluginRegistry {
            version: SUPPORTED_PLUGIN_REGISTRY_VERSION,
            plugins: BTreeMap::new(),
        });
    };
    let registry = serde_json::from_slice::<PluginRegistry>(bytes)
        .map_err(|_| LocalInventoryError::MalformedPluginRegistry)?;
    if registry.version != SUPPORTED_PLUGIN_REGISTRY_VERSION {
        return Err(LocalInventoryError::UnsupportedPluginRegistryVersion(
            registry.version,
        ));
    }
    for (id, installations) in &registry.plugins {
        if !valid_registry_plugin_id(id) {
            return Err(LocalInventoryError::MalformedPluginRegistry);
        }
        for installation in installations {
            validate_installation(id, installation)?;
        }
    }
    Ok(registry)
}

fn parse_settings(
    file: Option<crate::scan::ScannedFile>,
    scope: ArtifactScope,
) -> Result<BTreeMap<String, bool>, LocalInventoryError> {
    let Some(file) = file else {
        return Ok(BTreeMap::new());
    };
    let settings = serde_json::from_slice::<ClaudeSettings>(&file.bytes)
        .map_err(|_| LocalInventoryError::MalformedClaudeSettings(scope))?;
    if settings
        .enabled_plugins
        .keys()
        .any(|id| !valid_registry_plugin_id(id))
    {
        return Err(LocalInventoryError::MalformedClaudeSettings(scope));
    }
    Ok(settings.enabled_plugins)
}

fn select_plugin_roots(
    registry: PluginRegistry,
    mut enabled_plugins: BTreeMap<String, bool>,
    project_root: &Path,
) -> Result<Vec<OwnedPluginRoot>, LocalInventoryError> {
    let canonical_project_root = fs::canonicalize(project_root)
        .map_err(|_| LocalInventoryError::UnsafePluginProjectPath("<project>".to_owned()))?;
    let mut selected = Vec::new();

    for (id, installations) in registry.plugins {
        let applicable = installations
            .into_iter()
            .filter(|installation| installation_applies(installation, &canonical_project_root))
            .collect::<Vec<_>>();
        let enabled = enabled_plugins.remove(&id);
        if applicable.is_empty() {
            if enabled == Some(true) {
                return Err(LocalInventoryError::EnabledPluginNotInstalled(id));
            }
            continue;
        }
        let Some(enabled) = enabled else {
            return Err(LocalInventoryError::IndeterminatePluginEnablement(id));
        };
        if !enabled {
            continue;
        }

        let mut eligible = BTreeSet::new();
        for installation in applicable {
            let canonical = fs::canonicalize(&installation.install_path)
                .map_err(|_| LocalInventoryError::UnsafePluginInstallPath)?;
            if !canonical.is_dir() {
                return Err(LocalInventoryError::UnsafePluginInstallPath);
            }
            eligible.insert(canonical);
        }

        let path = match eligible.len() {
            0 => return Err(LocalInventoryError::EnabledPluginNotInstalled(id)),
            1 => eligible.pop_first().expect("one eligible plugin root"),
            _ => return Err(LocalInventoryError::AmbiguousPluginInstallations(id)),
        };
        selected.push(OwnedPluginRoot { id, path });
    }

    if let Some((id, _)) = enabled_plugins.into_iter().find(|(_, enabled)| *enabled) {
        return Err(LocalInventoryError::EnabledPluginNotInstalled(id));
    }

    selected.sort_unstable();
    Ok(selected)
}

fn installation_applies(installation: &PluginInstallation, project_root: &Path) -> bool {
    match installation.scope {
        PluginScope::Managed => false,
        PluginScope::User => true,
        PluginScope::Project | PluginScope::Local => installation
            .project_path
            .as_deref()
            .and_then(|path| fs::canonicalize(path).ok())
            .is_some_and(|path| path == project_root),
    }
}

fn validate_installation(
    id: &str,
    installation: &PluginInstallation,
) -> Result<(), LocalInventoryError> {
    if !safe_absolute_path(&installation.install_path) {
        return Err(LocalInventoryError::UnsafePluginInstallPath);
    }
    if matches!(
        installation.scope,
        PluginScope::Project | PluginScope::Local
    ) && !installation
        .project_path
        .as_deref()
        .is_some_and(safe_absolute_path)
    {
        return Err(LocalInventoryError::UnsafePluginProjectPath(id.to_owned()));
    }
    Ok(())
}

fn safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && !path.as_os_str().as_encoded_bytes().contains(&0)
        && !path
            .components()
            .any(|component| component == Component::ParentDir)
}

fn valid_registry_plugin_id(id: &str) -> bool {
    let Some((plugin, marketplace)) = id.split_once('@') else {
        return false;
    };
    valid_plugin_id(id)
        && !marketplace.contains('@')
        && valid_plugin_id_part(plugin)
        && valid_plugin_id_part(marketplace)
}

fn valid_plugin_id_part(part: &str) -> bool {
    let mut characters = part.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_alphanumeric())
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '_')
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalInventoryError {
    CodexProjectTrust(CodexProjectTrustError),
    PluginRegistryScan(Vec<ScanDiagnostic>),
    MalformedPluginRegistry,
    MalformedClaudeSettings(ArtifactScope),
    UnsupportedPluginRegistryVersion(u32),
    UnsafePluginInstallPath,
    UnsafePluginProjectPath(String),
    IndeterminatePluginEnablement(String),
    EnabledPluginNotInstalled(String),
    AmbiguousPluginInstallations(String),
}

impl fmt::Display for LocalInventoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CodexProjectTrust(error) => error.fmt(formatter),
            Self::PluginRegistryScan(diagnostics) => write!(
                formatter,
                "Claude plugin registry scan failed with {} diagnostics",
                diagnostics.len()
            ),
            Self::MalformedPluginRegistry => {
                formatter.write_str("Claude plugin registry is malformed")
            }
            Self::MalformedClaudeSettings(scope) => {
                write!(
                    formatter,
                    "Claude {} settings are malformed",
                    scope.as_str()
                )
            }
            Self::UnsupportedPluginRegistryVersion(version) => write!(
                formatter,
                "Claude plugin registry version {version} is unsupported"
            ),
            Self::UnsafePluginInstallPath => {
                formatter.write_str("Claude plugin registry contains a non-absolute install path")
            }
            Self::UnsafePluginProjectPath(id) => write!(
                formatter,
                "Claude plugin {id} has an unsafe or missing project path"
            ),
            Self::IndeterminatePluginEnablement(id) => write!(
                formatter,
                "Claude plugin {id} has no explicit enabledPlugins state"
            ),
            Self::EnabledPluginNotInstalled(id) => {
                write!(
                    formatter,
                    "enabled Claude plugin {id} is not installed here"
                )
            }
            Self::AmbiguousPluginInstallations(id) => write!(
                formatter,
                "enabled Claude plugin {id} has multiple applicable install roots"
            ),
        }
    }
}

impl Error for LocalInventoryError {}

impl From<CodexProjectTrustError> for LocalInventoryError {
    fn from(error: CodexProjectTrustError) -> Self {
        Self::CodexProjectTrust(error)
    }
}
