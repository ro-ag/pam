use std::{collections::BTreeMap, error::Error, fmt, path::Path, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    AgentArtifact, ClaudePluginRoot, ClaudeScanRoots, CursorGlobalRuleSource,
    CursorGlobalRulesStatus, CursorScanRoots, ScanDiagnostic, ScanLimits, ScanReport,
    claude::valid_plugin_id,
    scan::{ScanSession, merge_scan_reports},
    scan_claude_code, scan_codex, scan_cursor,
};

const PLUGIN_REGISTRY_FILE: &str = "installed_plugins.json";
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
    let plugins = match roots.claude_plugin_registry_root {
        Some(root) => plugin_roots(root, limits)?,
        None => Vec::new(),
    };
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
            true,
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
}

fn plugin_roots(
    registry_root: &Path,
    limits: ScanLimits,
) -> Result<Vec<OwnedPluginRoot>, LocalInventoryError> {
    let mut session = ScanSession::new(limits);
    let root = session.open_root(registry_root, "", "claude_plugin_registry");
    let file = root
        .as_ref()
        .and_then(|root| session.read_optional_file(root, Path::new(PLUGIN_REGISTRY_FILE)));
    let diagnostics = session.finish().diagnostics().to_vec();
    if !diagnostics.is_empty() {
        return Err(LocalInventoryError::PluginRegistryScan(diagnostics));
    }
    let Some(file) = file else {
        return Ok(Vec::new());
    };
    let registry = serde_json::from_slice::<PluginRegistry>(&file.bytes)
        .map_err(|_| LocalInventoryError::MalformedPluginRegistry)?;
    if registry.version != SUPPORTED_PLUGIN_REGISTRY_VERSION {
        return Err(LocalInventoryError::UnsupportedPluginRegistryVersion(
            registry.version,
        ));
    }
    let mut plugins = Vec::new();
    for (id, installations) in registry.plugins {
        if !valid_plugin_id(&id) {
            return Err(LocalInventoryError::MalformedPluginRegistry);
        }
        for installation in installations {
            if !installation.install_path.is_absolute() {
                return Err(LocalInventoryError::UnsafePluginInstallPath);
            }
            plugins.push(OwnedPluginRoot {
                id: id.clone(),
                path: installation.install_path,
            });
        }
    }
    plugins.sort_unstable();
    plugins.dedup();
    Ok(plugins)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalInventoryError {
    PluginRegistryScan(Vec<ScanDiagnostic>),
    MalformedPluginRegistry,
    UnsupportedPluginRegistryVersion(u32),
    UnsafePluginInstallPath,
}

impl fmt::Display for LocalInventoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PluginRegistryScan(diagnostics) => write!(
                formatter,
                "Claude plugin registry scan failed with {} diagnostics",
                diagnostics.len()
            ),
            Self::MalformedPluginRegistry => {
                formatter.write_str("Claude plugin registry is malformed")
            }
            Self::UnsupportedPluginRegistryVersion(version) => write!(
                formatter,
                "Claude plugin registry version {version} is unsupported"
            ),
            Self::UnsafePluginInstallPath => {
                formatter.write_str("Claude plugin registry contains a non-absolute install path")
            }
        }
    }
}

impl Error for LocalInventoryError {}
