use std::{
    env, fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use directories::BaseDirs;
use pam_core::ProjectId;
use pam_platform::{IdentityError, ProjectIdentity, discover_project, user_data_dir};
use pam_skills::{
    AgentArtifactId, CursorGlobalRulesStatus, LocalInventoryError, LocalInventoryRoots,
    ScanDiagnostic, ScanLimits, scan_local_inventory,
};
use pam_store::{SkillInventoryDrift, Store, StoreError, StoredAgentArtifact};
use serde::Serialize;

use crate::render::{EXIT_OPERATION_FAILED, escape_text};

const JSON_SCHEMA_VERSION: u32 = 1;

pub(crate) async fn list(json: bool) -> i32 {
    execute(InventorySelection::List, json).await
}

pub(crate) async fn show(artifact_id: AgentArtifactId, json: bool) -> i32 {
    execute(InventorySelection::Show(artifact_id), json).await
}

async fn execute(selection: InventorySelection, json: bool) -> i32 {
    let environment = match SkillsEnvironment::discover() {
        Ok(environment) => environment,
        Err(error) => return report_error(&error),
    };
    let observed_at_ms = match now_ms() {
        Ok(now) => now,
        Err(error) => return report_error(&error),
    };
    let request = InventoryRequest {
        roots: environment.roots(),
        project_id: environment.project.id(),
        state_path: &environment.state_path,
        observed_at_ms,
    };
    let output = match run_inventory(request, selection).await {
        Ok(output) => output,
        Err(error) => return report_error(&error),
    };
    let rendered = match render_inventory(&output, json) {
        Ok(rendered) => rendered,
        Err(error) => return report_error(&error),
    };
    println!("{rendered}");
    0
}

pub(crate) struct SkillsEnvironment {
    project: ProjectIdentity,
    user_home: PathBuf,
    claude_plugin_registry_root: Option<PathBuf>,
    codex_system_config_root: Option<PathBuf>,
    codex_home: Option<PathBuf>,
    state_path: PathBuf,
}

impl SkillsEnvironment {
    fn discover() -> Result<Self, SkillsError> {
        let current_working_directory =
            env::current_dir().map_err(SkillsError::CurrentDirectory)?;
        let project =
            discover_project(&current_working_directory).map_err(SkillsError::Identity)?;
        let base_dirs = BaseDirs::new().ok_or(SkillsError::HomeUnavailable)?;
        let user_home = base_dirs.home_dir().to_path_buf();
        let plugin_registry_root = user_home.join(".claude/plugins");
        let plugin_registry = plugin_registry_root.join("installed_plugins.json");
        let claude_plugin_registry_root = fs::symlink_metadata(plugin_registry)
            .is_ok()
            .then_some(plugin_registry_root);
        let system = PathBuf::from("/etc/codex");
        let codex_system_config_root = system.is_dir().then_some(system);
        let codex_home = match env::var_os("CODEX_HOME") {
            Some(path) if !path.is_empty() => Some(PathBuf::from(path)),
            _ => {
                let default = user_home.join(".codex");
                default.is_dir().then_some(default)
            }
        };
        let state_path = user_data_dir()
            .map_err(SkillsError::Identity)?
            .join("state.sqlite3");
        Ok(Self {
            project,
            user_home,
            claude_plugin_registry_root,
            codex_system_config_root,
            codex_home,
            state_path,
        })
    }

    pub(crate) fn roots(&self) -> LocalInventoryRoots<'_> {
        LocalInventoryRoots {
            user_home: Some(&self.user_home),
            claude_plugin_registry_root: self.claude_plugin_registry_root.as_deref(),
            codex_system_config_root: self.codex_system_config_root.as_deref(),
            codex_home: self.codex_home.as_deref(),
            project_root: self.project.root(),
            current_working_directory: self.project.root(),
            cursor_global_rule: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        current_working_directory: &Path,
        user_home: PathBuf,
        state_path: PathBuf,
    ) -> Result<Self, SkillsError> {
        let default_codex_home = user_home.join(".codex");
        let codex_home = default_codex_home.is_dir().then_some(default_codex_home);
        Ok(Self {
            project: discover_project(current_working_directory).map_err(SkillsError::Identity)?,
            user_home,
            claude_plugin_registry_root: None,
            codex_system_config_root: None,
            codex_home,
            state_path,
        })
    }
}

pub(crate) struct InventoryRequest<'a> {
    pub(crate) roots: LocalInventoryRoots<'a>,
    pub(crate) project_id: &'a ProjectId,
    pub(crate) state_path: &'a Path,
    pub(crate) observed_at_ms: u64,
}

pub(crate) enum InventorySelection {
    List,
    Show(AgentArtifactId),
}

#[derive(Debug)]
pub(crate) enum InventoryRecords {
    List(Vec<StoredAgentArtifact>),
    Show(StoredAgentArtifact),
}

#[derive(Debug)]
pub(crate) struct InventoryOutput {
    pub(crate) project_id: ProjectId,
    pub(crate) cursor_global_rules_status: CursorGlobalRulesStatus,
    pub(crate) drift: SkillInventoryDrift,
    pub(crate) records: InventoryRecords,
}

pub(crate) async fn run_inventory(
    request: InventoryRequest<'_>,
    selection: InventorySelection,
) -> Result<InventoryOutput, SkillsError> {
    let report = scan_local_inventory(request.roots, ScanLimits::default())
        .map_err(SkillsError::LocalInventory)?;
    if !report.complete() {
        return Err(SkillsError::IncompleteScan(report.diagnostics().to_vec()));
    }
    let cursor_global_rules_status = report.cursor_global_rules_status();
    let store = Store::open(request.state_path).map_err(SkillsError::Store)?;
    let operation = async {
        let drift = store
            .rescan_skill_inventory(
                request.project_id.clone(),
                report.into_scan_report(),
                request.observed_at_ms,
            )
            .await?;
        let records = match selection {
            InventorySelection::List => {
                InventoryRecords::List(store.skill_artifacts(request.project_id.clone()).await?)
            }
            InventorySelection::Show(artifact_id) => InventoryRecords::Show(
                store
                    .skill_artifact(request.project_id.clone(), artifact_id)
                    .await?,
            ),
        };
        Ok::<_, StoreError>((drift, records))
    }
    .await;
    let shutdown = store.shutdown().await;
    let (drift, records) = operation.map_err(SkillsError::Store)?;
    shutdown.map_err(SkillsError::Store)?;
    Ok(InventoryOutput {
        project_id: request.project_id.clone(),
        cursor_global_rules_status,
        drift,
        records,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonDrift {
    added: Vec<String>,
    changed: Vec<String>,
    removed: Vec<String>,
    resurrected: Vec<String>,
}

impl From<&SkillInventoryDrift> for JsonDrift {
    fn from(drift: &SkillInventoryDrift) -> Self {
        Self {
            added: sorted_ids(&drift.added),
            changed: sorted_ids(&drift.changed),
            removed: sorted_ids(&drift.removed),
            resurrected: sorted_ids(&drift.resurrected),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonArtifact {
    id: String,
    name: String,
    logical_path: String,
    kind: String,
    scope: String,
    origin: String,
    load_semantics: String,
    content_hash: String,
    first_seen_at_ms: u64,
    last_changed_at_ms: u64,
    removed_at_ms: Option<u64>,
}

impl From<&StoredAgentArtifact> for JsonArtifact {
    fn from(record: &StoredAgentArtifact) -> Self {
        Self {
            id: record.id.to_string(),
            name: record.artifact.name().to_owned(),
            logical_path: record.artifact.logical_path().to_owned(),
            kind: record.artifact.kind().as_str().to_owned(),
            scope: record.artifact.scope().as_str().to_owned(),
            origin: record.artifact.origin().as_str().to_owned(),
            load_semantics: record.artifact.load_semantics().as_str().to_owned(),
            content_hash: record.artifact.content_hash().to_string(),
            first_seen_at_ms: record.first_seen_at_ms,
            last_changed_at_ms: record.last_changed_at_ms,
            removed_at_ms: record.removed_at_ms,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonList {
    schema_version: u32,
    project_id: String,
    cursor_global_rules_status: CursorGlobalRulesStatus,
    drift: JsonDrift,
    artifacts: Vec<JsonArtifact>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonShow {
    schema_version: u32,
    project_id: String,
    cursor_global_rules_status: CursorGlobalRulesStatus,
    drift: JsonDrift,
    artifact: JsonArtifact,
}

pub(crate) fn render_inventory(
    output: &InventoryOutput,
    json: bool,
) -> Result<String, SkillsError> {
    if json {
        return match &output.records {
            InventoryRecords::List(records) => serde_json::to_string_pretty(&JsonList {
                schema_version: JSON_SCHEMA_VERSION,
                project_id: output.project_id.to_string(),
                cursor_global_rules_status: output.cursor_global_rules_status,
                drift: JsonDrift::from(&output.drift),
                artifacts: records.iter().map(JsonArtifact::from).collect(),
            }),
            InventoryRecords::Show(record) => serde_json::to_string_pretty(&JsonShow {
                schema_version: JSON_SCHEMA_VERSION,
                project_id: output.project_id.to_string(),
                cursor_global_rules_status: output.cursor_global_rules_status,
                drift: JsonDrift::from(&output.drift),
                artifact: JsonArtifact::from(record),
            }),
        }
        .map_err(SkillsError::Json);
    }
    Ok(match &output.records {
        InventoryRecords::List(records) => render_human_list(output, records),
        InventoryRecords::Show(record) => render_human_show(output, record),
    })
}

fn render_human_list(output: &InventoryOutput, records: &[StoredAgentArtifact]) -> String {
    let mut lines = header_lines(output);
    if records.is_empty() {
        lines.push("No active skill artifacts discovered.".to_owned());
    } else {
        lines.push(format!("Active artifacts: {}", records.len()));
        for record in records {
            lines.push(format!(
                "{}  {}  {}  {}  {}  {}  {}",
                record.id,
                record.artifact.origin().as_str(),
                record.artifact.kind().as_str(),
                record.artifact.scope().as_str(),
                record.artifact.load_semantics().as_str(),
                escape_text(record.artifact.logical_path()),
                record.artifact.content_hash(),
            ));
        }
    }
    lines.join("\n")
}

fn render_human_show(output: &InventoryOutput, record: &StoredAgentArtifact) -> String {
    let mut lines = header_lines(output);
    lines.extend([
        format!("ID: {}", record.id),
        format!("Name: {}", escape_text(record.artifact.name())),
        format!("Path: {}", escape_text(record.artifact.logical_path())),
        format!("Kind: {}", record.artifact.kind().as_str()),
        format!("Scope: {}", record.artifact.scope().as_str()),
        format!("Origin: {}", record.artifact.origin().as_str()),
        format!(
            "Load semantics: {}",
            record.artifact.load_semantics().as_str()
        ),
        format!("Content hash: {}", record.artifact.content_hash()),
        format!("First seen (ms): {}", record.first_seen_at_ms),
        format!("Last changed (ms): {}", record.last_changed_at_ms),
    ]);
    lines.join("\n")
}

fn header_lines(output: &InventoryOutput) -> Vec<String> {
    vec![
        format!("Project: {}", output.project_id),
        format!(
            "Cursor global rules: {}",
            cursor_status_label(output.cursor_global_rules_status)
        ),
        format!(
            "Drift: added={} changed={} removed={} resurrected={}",
            output.drift.added.len(),
            output.drift.changed.len(),
            output.drift.removed.len(),
            output.drift.resurrected.len()
        ),
    ]
}

fn cursor_status_label(status: CursorGlobalRulesStatus) -> &'static str {
    match status {
        CursorGlobalRulesStatus::NotLocallyDiscoverable => "not_locally_discoverable",
        CursorGlobalRulesStatus::ExplicitlyConfigured => "explicitly_configured",
    }
}

fn sorted_ids(records: &[StoredAgentArtifact]) -> Vec<String> {
    let mut ids = records
        .iter()
        .map(|record| record.id.to_string())
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids
}

fn now_ms() -> Result<u64, SkillsError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SkillsError::Clock)?;
    u64::try_from(duration.as_millis()).map_err(|_| SkillsError::Clock)
}

fn report_error(error: &SkillsError) -> i32 {
    eprintln!("{error}");
    if let SkillsError::IncompleteScan(diagnostics) = error {
        for diagnostic in diagnostics.iter().take(20) {
            eprintln!(
                "  {:?}: {}",
                diagnostic.kind(),
                escape_text(diagnostic.logical_path())
            );
        }
        if diagnostics.len() > 20 {
            eprintln!("  ... and {} more diagnostics", diagnostics.len() - 20);
        }
    }
    EXIT_OPERATION_FAILED
}

#[derive(Debug)]
pub(crate) enum SkillsError {
    CurrentDirectory(io::Error),
    Identity(IdentityError),
    HomeUnavailable,
    Clock,
    LocalInventory(LocalInventoryError),
    IncompleteScan(Vec<ScanDiagnostic>),
    Store(StoreError),
    Json(serde_json::Error),
}

impl std::fmt::Display for SkillsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CurrentDirectory(_) => {
                formatter.write_str("PAM could not locate the current working directory.")
            }
            Self::Identity(error) => error.fmt(formatter),
            Self::HomeUnavailable => {
                formatter.write_str("PAM could not locate the current user's home directory.")
            }
            Self::Clock => formatter.write_str("PAM could not read the current system time."),
            Self::LocalInventory(error) => write!(formatter, "Skill scan failed: {error}."),
            Self::IncompleteScan(diagnostics) => write!(
                formatter,
                "Skill scan is incomplete ({} diagnostics); inventory was not changed.",
                diagnostics.len()
            ),
            Self::Store(error) => write!(formatter, "Skill inventory store failed: {error}."),
            Self::Json(_) => formatter.write_str("PAM could not encode skill inventory JSON."),
        }
    }
}

impl std::error::Error for SkillsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CurrentDirectory(error) => Some(error),
            Self::Identity(error) => Some(error),
            Self::LocalInventory(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::HomeUnavailable | Self::Clock | Self::IncompleteScan(_) => None,
        }
    }
}
