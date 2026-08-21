use std::{
    env,
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use directories::BaseDirs;
use pam_core::{ContentDigest, ProjectId};
use pam_platform::{IdentityError, ProjectIdentity, discover_project, user_data_dir};
use pam_skills::{
    AgentArtifactId, CursorGlobalRulesStatus, EvaluatorKind, EvaluatorRunConfig,
    LocalInventoryError, LocalInventoryRoots, ScanDiagnostic, ScanLimits, SkillsAuditError,
    SkillsAuditEvaluationStatus, SkillsAuditFailureReason, SkillsAuditReport, run_skills_audit,
    scan_local_inventory,
};
use pam_store::{SkillInventoryDrift, Store, StoreError, StoredAgentArtifact};
use serde::Serialize;

use crate::{
    command::{SkillsAgentArg, SkillsInstallSourceArg},
    render::{EXIT_OPERATION_FAILED, escape_text},
};

use pam_skills::{
    ArtifactInstallError, ArtifactInstallProvenance, ArtifactInstallSource, CanonicalEntryId,
    CanonicalLibrary, CanonicalLibrarySnapshot, InvalidLibraryProjectKey, LibraryEnablementKey,
    LibraryError, LibraryInsertDisposition, LibraryManagedRootId, LibraryProjectKey,
    ManagedCopyCleanupDisposition, MaterializationAction, MaterializationDriftConflict,
    MaterializationDriftState, MaterializationError, MaterializationPlan,
    apply_managed_materialization, apply_materialization_resync, disable_materialization,
    inspect_materialization_drift, install_artifact, plan_managed_materialization,
    plan_materialization_resync,
};

const JSON_SCHEMA_VERSION: u32 = 1;

pub(crate) async fn list(json: bool) -> i32 {
    execute(InventorySelection::List, json).await
}

pub(crate) fn library_list(json: bool) -> i32 {
    execute_library(LibraryOperation::List, json)
}

pub(crate) async fn show(artifact_id: AgentArtifactId, json: bool) -> i32 {
    execute(InventorySelection::Show(artifact_id), json).await
}

pub(crate) async fn audit(json: bool) -> i32 {
    let environment = match SkillsEnvironment::discover() {
        Ok(environment) => environment,
        Err(error) => return report_error(&error),
    };
    let injected_path = env::var_os("PATH").unwrap_or_default();
    let observed_at_ms = match now_ms() {
        Ok(now) => now,
        Err(error) => return report_error(&error),
    };
    let output = match run_audit(AuditRequest {
        roots: environment.roots(),
        project_id: environment.project.id(),
        state_path: &environment.state_path,
        observed_at_ms,
        injected_path: &injected_path,
        evaluator_config: EvaluatorRunConfig::default(),
    })
    .await
    {
        Ok(output) => output,
        Err(error) => return report_error(&error),
    };
    let rendered = render_audit(&output, json);
    println!("{rendered}");
    0
}

pub(crate) fn adopt(entry_id: CanonicalEntryId, artifact_id: AgentArtifactId, json: bool) -> i32 {
    execute_library(
        LibraryOperation::Adopt {
            entry_id,
            artifact_id,
        },
        json,
    )
}

pub(crate) fn install(
    entry_id: CanonicalEntryId,
    source: SkillsInstallSourceArg,
    json: bool,
) -> i32 {
    execute_library(LibraryOperation::Install { entry_id, source }, json)
}

pub(crate) fn enable(
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    agent: SkillsAgentArg,
    json: bool,
) -> i32 {
    execute_library(
        LibraryOperation::Enable {
            entry_id,
            version,
            agent,
        },
        json,
    )
}

pub(crate) fn disable(
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    agent: SkillsAgentArg,
    root: Option<PathBuf>,
    json: bool,
) -> i32 {
    execute_library(
        LibraryOperation::Disable {
            entry_id,
            version,
            agent,
            root,
        },
        json,
    )
}

pub(crate) fn materialize(
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    agent: SkillsAgentArg,
    root: Option<PathBuf>,
    apply: bool,
    json: bool,
) -> i32 {
    execute_library(
        LibraryOperation::Materialize {
            entry_id,
            version,
            agent,
            root,
            apply,
        },
        json,
    )
}

pub(crate) fn drift(
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    agent: SkillsAgentArg,
    root: Option<PathBuf>,
    json: bool,
) -> i32 {
    execute_library(
        LibraryOperation::Drift {
            entry_id,
            version,
            agent,
            root,
        },
        json,
    )
}

pub(crate) fn resync(
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    agent: SkillsAgentArg,
    root: Option<PathBuf>,
    apply: bool,
    json: bool,
) -> i32 {
    execute_library(
        LibraryOperation::Resync {
            entry_id,
            version,
            agent,
            root,
            apply,
        },
        json,
    )
}

fn execute_library(operation: LibraryOperation, json: bool) -> i32 {
    let environment = match SkillsEnvironment::discover() {
        Ok(environment) => environment,
        Err(error) => return report_error(&error),
    };
    let output = match run_library_operation(&environment, operation) {
        Ok(output) => output,
        Err(error) => return report_error(&error),
    };
    let rendered = match render_library_operation(&output, json) {
        Ok(rendered) => rendered,
        Err(error) => return report_error(&error),
    };
    println!("{rendered}");
    0
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
    ptrack_home: PathBuf,
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
        let ptrack_home = resolve_ptrack_home(&user_home, env::var_os("PTRACK_HOME"));
        Ok(Self {
            project,
            user_home,
            claude_plugin_registry_root,
            codex_system_config_root,
            codex_home,
            state_path,
            ptrack_home,
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
        let ptrack_home = user_home.join(".ptrack");
        Ok(Self {
            project: discover_project(current_working_directory).map_err(SkillsError::Identity)?,
            user_home,
            claude_plugin_registry_root: None,
            codex_system_config_root: None,
            codex_home,
            state_path,
            ptrack_home,
        })
    }

    fn project_key(&self) -> Result<LibraryProjectKey, SkillsError> {
        LibraryProjectKey::parse(self.project.id().as_str().to_ascii_lowercase())
            .map_err(SkillsError::ProjectKey)
    }

    fn ptrack_home(&self) -> Result<&Path, SkillsError> {
        bounded_absolute_path(&self.ptrack_home)
            .then_some(self.ptrack_home.as_path())
            .ok_or(SkillsError::PTrackHomeUnavailable)
    }

    fn agent_root(
        &self,
        agent: SkillsAgentArg,
        explicit: Option<PathBuf>,
    ) -> Result<PathBuf, SkillsError> {
        let root = explicit.unwrap_or_else(|| match agent {
            SkillsAgentArg::Claude => self.project.root().join(".claude"),
            SkillsAgentArg::Codex => self
                .codex_home
                .clone()
                .unwrap_or_else(|| self.user_home.join(".codex")),
            SkillsAgentArg::Cursor => self.project.root().join(".cursor"),
        });
        let safe_directory = fs::symlink_metadata(&root)
            .is_ok_and(|metadata| !metadata.file_type().is_symlink() && metadata.is_dir());
        if !bounded_absolute_path(&root) || !safe_directory {
            return Err(SkillsError::AgentRootUnavailable(agent));
        }
        Ok(root)
    }
}

pub(crate) fn resolve_ptrack_home(
    user_home: &Path,
    override_path: Option<std::ffi::OsString>,
) -> PathBuf {
    override_path
        .filter(|path| !path.is_empty())
        .map_or_else(|| user_home.join(".ptrack"), PathBuf::from)
}

fn bounded_absolute_path(path: &Path) -> bool {
    const MAX_CLI_PATH_BYTES: usize = 4_096;
    path.is_absolute()
        && path.as_os_str().as_encoded_bytes().len() <= MAX_CLI_PATH_BYTES
        && path
            .to_str()
            .is_some_and(|value| !value.chars().any(char::is_control))
}

pub(crate) struct InventoryRequest<'a> {
    pub(crate) roots: LocalInventoryRoots<'a>,
    pub(crate) project_id: &'a ProjectId,
    pub(crate) state_path: &'a Path,
    pub(crate) observed_at_ms: u64,
}

pub(crate) struct AuditRequest<'a> {
    pub(crate) roots: LocalInventoryRoots<'a>,
    pub(crate) project_id: &'a ProjectId,
    pub(crate) state_path: &'a Path,
    pub(crate) observed_at_ms: u64,
    pub(crate) injected_path: &'a OsStr,
    pub(crate) evaluator_config: EvaluatorRunConfig,
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

#[derive(Debug)]
pub(crate) struct AuditOutput {
    pub(crate) project_id: ProjectId,
    pub(crate) observed_at_ms: u64,
    pub(crate) report: SkillsAuditReport,
    pub(crate) report_json: String,
}

pub(crate) enum LibraryOperation {
    List,
    Adopt {
        entry_id: CanonicalEntryId,
        artifact_id: AgentArtifactId,
    },
    Install {
        entry_id: CanonicalEntryId,
        source: SkillsInstallSourceArg,
    },
    Enable {
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillsAgentArg,
    },
    Disable {
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillsAgentArg,
        root: Option<PathBuf>,
    },
    Materialize {
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillsAgentArg,
        root: Option<PathBuf>,
        apply: bool,
    },
    Drift {
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillsAgentArg,
        root: Option<PathBuf>,
    },
    Resync {
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillsAgentArg,
        root: Option<PathBuf>,
        apply: bool,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LibraryVersionOutput {
    version: String,
    enabled_agents: Vec<String>,
    managed_agents: Vec<String>,
    install_source: Option<String>,
    git_commit: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LibraryEntryOutput {
    entry_id: String,
    versions: Vec<LibraryVersionOutput>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LibraryPlanStepOutput {
    entry_id: String,
    version: String,
    agent: String,
    action: String,
    backup: bool,
}

#[derive(Debug, Serialize)]
#[serde(
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    tag = "action"
)]
enum LibraryOperationResult {
    List {
        entries: Vec<LibraryEntryOutput>,
    },
    Adopt {
        entry_id: String,
        version: String,
        artifact_id: String,
        disposition: String,
    },
    Install {
        entry_id: String,
        version: String,
        source: String,
        git_commit: Option<String>,
        disposition: String,
    },
    Enable {
        entry_id: String,
        version: String,
        agent: String,
        changed: bool,
    },
    Disable {
        entry_id: String,
        version: String,
        agent: String,
        changed: bool,
        cleanup: String,
    },
    Materialize {
        applied: bool,
        steps: Vec<LibraryPlanStepOutput>,
    },
    Drift {
        entry_id: String,
        version: String,
        agent: String,
        state: String,
        actual_digest: Option<String>,
        conflict: Option<String>,
    },
    Resync {
        applied: bool,
        steps: Vec<LibraryPlanStepOutput>,
    },
}

#[derive(Debug)]
pub(crate) struct LibraryCommandOutput {
    project_key: LibraryProjectKey,
    result: LibraryOperationResult,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonLibraryCommand<'a> {
    schema_version: u32,
    project_key: &'a str,
    result: &'a LibraryOperationResult,
}

pub(crate) fn run_library_operation(
    environment: &SkillsEnvironment,
    operation: LibraryOperation,
) -> Result<LibraryCommandOutput, SkillsError> {
    let project_key = environment.project_key()?;
    let library =
        CanonicalLibrary::open(environment.ptrack_home()?).map_err(SkillsError::Library)?;
    let result = match operation {
        LibraryOperation::List => list_library(environment, &library, &project_key)?,
        LibraryOperation::Adopt {
            entry_id,
            artifact_id,
        } => adopt_artifact(environment, &library, entry_id, artifact_id)?,
        LibraryOperation::Install { entry_id, source } => {
            install_source(&library, entry_id, source)?
        }
        LibraryOperation::Enable {
            entry_id,
            version,
            agent,
        } => enable_version(&library, &project_key, &entry_id, &version, agent)?,
        LibraryOperation::Disable {
            entry_id,
            version,
            agent,
            root,
        } => disable_version(
            environment,
            &library,
            &project_key,
            &entry_id,
            &version,
            agent,
            root,
        )?,
        LibraryOperation::Materialize {
            entry_id,
            version,
            agent,
            root,
            apply,
        } => materialize_version(
            environment,
            &library,
            &project_key,
            &entry_id,
            &version,
            agent,
            root,
            apply,
        )?,
        LibraryOperation::Drift {
            entry_id,
            version,
            agent,
            root,
        } => inspect_drift(
            environment,
            &library,
            &project_key,
            &entry_id,
            &version,
            agent,
            root,
        )?,
        LibraryOperation::Resync {
            entry_id,
            version,
            agent,
            root,
            apply,
        } => resync_version(
            environment,
            &library,
            &project_key,
            entry_id,
            version,
            agent,
            root,
            apply,
        )?,
    };
    Ok(LibraryCommandOutput {
        project_key,
        result,
    })
}

fn list_library(
    environment: &SkillsEnvironment,
    library: &CanonicalLibrary,
    project_key: &LibraryProjectKey,
) -> Result<LibraryOperationResult, SkillsError> {
    let snapshot = library.snapshot().map_err(SkillsError::Library)?;
    let enablements = snapshot.enablements();
    let mut entries = Vec::new();
    for entry in snapshot.entries() {
        let mut versions = Vec::new();
        for version in entry.versions() {
            let mut enabled_agents =
                agents_for_version(enablements, project_key, entry.id(), version);
            let mut managed_agents = managed_agents_for_version(
                environment,
                &snapshot,
                project_key,
                entry.id(),
                version,
            );
            enabled_agents.sort_unstable();
            managed_agents.sort_unstable();
            let provenance = snapshot.installations().iter().find(|installation| {
                installation.entry_id() == entry.id() && installation.version() == version
            });
            let (install_source, git_commit) = provenance_labels(
                provenance.map(pam_skills::CanonicalLibraryInstallation::provenance),
            );
            versions.push(LibraryVersionOutput {
                version: version.to_string(),
                enabled_agents,
                managed_agents,
                install_source,
                git_commit,
            });
        }
        entries.push(LibraryEntryOutput {
            entry_id: entry.id().to_string(),
            versions,
        });
    }
    Ok(LibraryOperationResult::List { entries })
}

fn managed_agents_for_version(
    environment: &SkillsEnvironment,
    snapshot: &CanonicalLibrarySnapshot,
    project_key: &LibraryProjectKey,
    entry_id: &CanonicalEntryId,
    version: &ContentDigest,
) -> Vec<String> {
    [
        SkillsAgentArg::Claude,
        SkillsAgentArg::Codex,
        SkillsAgentArg::Cursor,
    ]
    .into_iter()
    .filter(|agent| {
        let key = enablement_key(project_key, entry_id.clone(), version.clone(), *agent);
        current_managed_root(environment, *agent)
            .is_some_and(|root| snapshot.is_managed_at(&key, &root))
    })
    .map(|agent| agent.materialization_agent().as_str().to_owned())
    .collect()
}

fn current_managed_root(
    environment: &SkillsEnvironment,
    agent: SkillsAgentArg,
) -> Option<LibraryManagedRootId> {
    let root = environment.agent_root(agent, None).ok()?;
    let canonical = fs::canonicalize(root).ok()?;
    LibraryManagedRootId::from_canonical_path(&canonical).ok()
}

fn agents_for_version(
    keys: &[LibraryEnablementKey],
    project_key: &LibraryProjectKey,
    entry_id: &CanonicalEntryId,
    version: &ContentDigest,
) -> Vec<String> {
    keys.iter()
        .filter(|key| {
            key.project() == project_key && key.entry_id() == entry_id && key.version() == version
        })
        .map(|key| key.agent().as_str().to_owned())
        .collect()
}

fn provenance_labels(
    provenance: Option<&ArtifactInstallProvenance>,
) -> (Option<String>, Option<String>) {
    match provenance {
        None => (None, None),
        Some(ArtifactInstallProvenance::Local) => (Some("local".to_owned()), None),
        Some(ArtifactInstallProvenance::Git(git)) => {
            (Some("git".to_owned()), Some(git.commit().to_owned()))
        }
    }
}

fn adopt_artifact(
    environment: &SkillsEnvironment,
    library: &CanonicalLibrary,
    entry_id: CanonicalEntryId,
    artifact_id: AgentArtifactId,
) -> Result<LibraryOperationResult, SkillsError> {
    let report = scan_local_inventory(environment.roots(), ScanLimits::default())
        .map_err(SkillsError::LocalInventory)?;
    let adopted = library
        .adopt(entry_id, artifact_id, &report.into_scan_report())
        .map_err(SkillsError::Library)?;
    Ok(LibraryOperationResult::Adopt {
        entry_id: adopted.entry_id().to_string(),
        version: adopted.version().to_string(),
        artifact_id: adopted.artifact_id().to_string(),
        disposition: disposition_label(adopted.disposition()).to_owned(),
    })
}

fn install_source(
    library: &CanonicalLibrary,
    entry_id: CanonicalEntryId,
    source: SkillsInstallSourceArg,
) -> Result<LibraryOperationResult, SkillsError> {
    let source = match source {
        SkillsInstallSourceArg::Local(path) => ArtifactInstallSource::local_file(path),
        SkillsInstallSourceArg::Git { url, artifact_path } => {
            ArtifactInstallSource::git(url, artifact_path).map_err(SkillsError::Install)?
        }
    };
    let installed = install_artifact(library, entry_id, &source).map_err(SkillsError::Install)?;
    let (source, git_commit) = provenance_labels(Some(installed.provenance()));
    Ok(LibraryOperationResult::Install {
        entry_id: installed.entry_id().to_string(),
        version: installed.version().to_string(),
        source: source.expect("an installation always has provenance"),
        git_commit,
        disposition: disposition_label(installed.disposition()).to_owned(),
    })
}

fn enable_version(
    library: &CanonicalLibrary,
    project_key: &LibraryProjectKey,
    entry_id: &CanonicalEntryId,
    version: &ContentDigest,
    agent: SkillsAgentArg,
) -> Result<LibraryOperationResult, SkillsError> {
    let change = library
        .enable(enablement_key(
            project_key,
            entry_id.clone(),
            version.clone(),
            agent,
        ))
        .map_err(SkillsError::Library)?;
    Ok(LibraryOperationResult::Enable {
        entry_id: entry_id.to_string(),
        version: version.to_string(),
        agent: agent.materialization_agent().as_str().to_owned(),
        changed: change.changed(),
    })
}

#[allow(clippy::too_many_arguments)]
fn disable_version(
    environment: &SkillsEnvironment,
    library: &CanonicalLibrary,
    project_key: &LibraryProjectKey,
    entry_id: &CanonicalEntryId,
    version: &ContentDigest,
    agent: SkillsAgentArg,
    root: Option<PathBuf>,
) -> Result<LibraryOperationResult, SkillsError> {
    let root = environment.agent_root(agent, root)?;
    let outcome = disable_materialization(
        library,
        &enablement_key(project_key, entry_id.clone(), version.clone(), agent),
        &root,
    )
    .map_err(SkillsError::Materialize)?;
    Ok(LibraryOperationResult::Disable {
        entry_id: entry_id.to_string(),
        version: version.to_string(),
        agent: agent.materialization_agent().as_str().to_owned(),
        changed: outcome.state_changed(),
        cleanup: cleanup_label(outcome.cleanup()).to_owned(),
    })
}

#[allow(clippy::too_many_arguments)]
fn materialize_version(
    environment: &SkillsEnvironment,
    library: &CanonicalLibrary,
    project_key: &LibraryProjectKey,
    entry_id: &CanonicalEntryId,
    version: &ContentDigest,
    agent: SkillsAgentArg,
    root: Option<PathBuf>,
    apply: bool,
) -> Result<LibraryOperationResult, SkillsError> {
    let key = enablement_key(project_key, entry_id.clone(), version.clone(), agent);
    if !library.is_enabled(&key).map_err(SkillsError::Library)? {
        return Err(SkillsError::NotEnabled);
    }
    let root = environment.agent_root(agent, root)?;
    let plan =
        plan_managed_materialization(library, &key, &root).map_err(SkillsError::Materialize)?;
    let steps = plan_steps(&plan);
    if apply {
        apply_managed_materialization(library, &key, &plan).map_err(SkillsError::Materialize)?;
    }
    Ok(LibraryOperationResult::Materialize {
        applied: apply,
        steps,
    })
}

#[allow(clippy::too_many_arguments)]
fn inspect_drift(
    environment: &SkillsEnvironment,
    library: &CanonicalLibrary,
    project_key: &LibraryProjectKey,
    entry_id: &CanonicalEntryId,
    version: &ContentDigest,
    agent: SkillsAgentArg,
    root: Option<PathBuf>,
) -> Result<LibraryOperationResult, SkillsError> {
    let root = environment.agent_root(agent, root)?;
    let inspection = inspect_materialization_drift(
        library,
        &enablement_key(project_key, entry_id.clone(), version.clone(), agent),
        &root,
    )
    .map_err(SkillsError::Materialize)?;
    let (state, actual_digest, conflict) = drift_labels(inspection.state());
    Ok(LibraryOperationResult::Drift {
        entry_id: entry_id.to_string(),
        version: version.to_string(),
        agent: agent.materialization_agent().as_str().to_owned(),
        state: state.to_owned(),
        actual_digest,
        conflict,
    })
}

#[allow(clippy::too_many_arguments)]
fn resync_version(
    environment: &SkillsEnvironment,
    library: &CanonicalLibrary,
    project_key: &LibraryProjectKey,
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    agent: SkillsAgentArg,
    root: Option<PathBuf>,
    apply: bool,
) -> Result<LibraryOperationResult, SkillsError> {
    let root = environment.agent_root(agent, root)?;
    let key = enablement_key(project_key, entry_id, version, agent);
    let plan =
        plan_materialization_resync(library, &key, &root).map_err(SkillsError::Materialize)?;
    let steps = plan_steps(&plan);
    if apply {
        apply_materialization_resync(library, &key, &plan).map_err(SkillsError::Materialize)?;
    }
    Ok(LibraryOperationResult::Resync {
        applied: apply,
        steps,
    })
}

fn enablement_key(
    project_key: &LibraryProjectKey,
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    agent: SkillsAgentArg,
) -> LibraryEnablementKey {
    LibraryEnablementKey::new(entry_id, version, agent.origin(), project_key.clone())
}

fn plan_steps(plan: &MaterializationPlan) -> Vec<LibraryPlanStepOutput> {
    plan.items()
        .iter()
        .map(|item| LibraryPlanStepOutput {
            entry_id: item.entry_id().to_string(),
            version: item.version().to_string(),
            agent: item.agent().as_str().to_owned(),
            action: materialization_action_label(item.action()).to_owned(),
            backup: item.backup_destination().is_some(),
        })
        .collect()
}

fn drift_labels(
    state: &MaterializationDriftState,
) -> (&'static str, Option<String>, Option<String>) {
    match state {
        MaterializationDriftState::Clean => ("clean", None, None),
        MaterializationDriftState::Missing => ("missing", None, None),
        MaterializationDriftState::Modified(actual) => ("modified", Some(actual.to_string()), None),
        MaterializationDriftState::Conflict(conflict) => (
            "conflict",
            None,
            Some(drift_conflict_label(*conflict).to_owned()),
        ),
    }
}

const fn drift_conflict_label(conflict: MaterializationDriftConflict) -> &'static str {
    match conflict {
        MaterializationDriftConflict::Disabled => "disabled",
        MaterializationDriftConflict::Unowned => "unowned",
        MaterializationDriftConflict::UnsafeRoot => "unsafe_root",
        MaterializationDriftConflict::UnsafePath => "unsafe_path",
        MaterializationDriftConflict::Symlink => "symlink",
        MaterializationDriftConflict::NonRegular => "non_regular",
        MaterializationDriftConflict::Unreadable => "unreadable",
        MaterializationDriftConflict::TooLarge => "too_large",
        MaterializationDriftConflict::PlanMismatch => "plan_mismatch",
    }
}

const fn materialization_action_label(action: MaterializationAction) -> &'static str {
    match action {
        MaterializationAction::NoOp => "no_op",
        MaterializationAction::Create => "create",
        MaterializationAction::Replace => "replace",
    }
}

const fn cleanup_label(cleanup: ManagedCopyCleanupDisposition) -> &'static str {
    match cleanup {
        ManagedCopyCleanupDisposition::Removed => "removed",
        ManagedCopyCleanupDisposition::Missing => "missing",
        ManagedCopyCleanupDisposition::PreservedModified => "preserved_modified",
        ManagedCopyCleanupDisposition::PreservedSymlink => "preserved_symlink",
        ManagedCopyCleanupDisposition::PreservedUnowned => "preserved_unowned",
    }
}

const fn disposition_label(disposition: LibraryInsertDisposition) -> &'static str {
    match disposition {
        LibraryInsertDisposition::Inserted => "inserted",
        LibraryInsertDisposition::AlreadyPresent => "already_present",
    }
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

pub(crate) async fn run_audit(request: AuditRequest<'_>) -> Result<AuditOutput, SkillsError> {
    let inventory = scan_local_inventory(request.roots, ScanLimits::default())
        .map_err(SkillsError::LocalInventory)?;
    if !inventory.complete() {
        return Err(SkillsError::IncompleteScan(
            inventory.diagnostics().to_vec(),
        ));
    }
    let report = run_skills_audit(
        inventory.scan_report(),
        request.roots.project_root,
        request.injected_path,
        request.evaluator_config,
    )
    .map_err(SkillsError::Audit)?;
    let report_json = serde_json::to_string_pretty(&report).map_err(SkillsError::Json)?;
    let schema_version = report.schema_version();
    let store = Store::open(request.state_path).map_err(SkillsError::Store)?;
    let operation = store
        .put_skills_audit_snapshot(
            request.project_id.clone(),
            inventory.into_scan_report(),
            request.observed_at_ms,
            schema_version,
            report_json,
        )
        .await;
    let shutdown = store.shutdown().await;
    let stored = operation.map_err(SkillsError::Store)?;
    shutdown.map_err(SkillsError::Store)?;
    Ok(AuditOutput {
        project_id: request.project_id.clone(),
        observed_at_ms: request.observed_at_ms,
        report,
        report_json: stored.report_json,
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

pub(crate) fn render_library_operation(
    output: &LibraryCommandOutput,
    json: bool,
) -> Result<String, SkillsError> {
    if json {
        return serde_json::to_string_pretty(&JsonLibraryCommand {
            schema_version: JSON_SCHEMA_VERSION,
            project_key: output.project_key.as_str(),
            result: &output.result,
        })
        .map_err(SkillsError::Json);
    }
    Ok(render_human_library_operation(output))
}

#[allow(clippy::too_many_lines)]
fn render_human_library_operation(output: &LibraryCommandOutput) -> String {
    let mut lines = vec![format!("Project: {}", output.project_key)];
    match &output.result {
        LibraryOperationResult::List { entries } => {
            if entries.is_empty() {
                lines.push("Canonical library is empty.".to_owned());
            } else {
                lines.push(format!("Canonical entries: {}", entries.len()));
                for entry in entries {
                    for version in &entry.versions {
                        lines.push(format!(
                            "{}@{}  enabled={}  managed={}  source={}",
                            entry.entry_id,
                            version.version,
                            joined_or_none(&version.enabled_agents),
                            joined_or_none(&version.managed_agents),
                            version.install_source.as_deref().unwrap_or("adopted")
                        ));
                    }
                }
            }
        }
        LibraryOperationResult::Adopt {
            entry_id,
            version,
            artifact_id,
            disposition,
        } => lines.push(format!(
            "Adopted {artifact_id} as {entry_id}@{version} ({disposition})."
        )),
        LibraryOperationResult::Install {
            entry_id,
            version,
            source,
            disposition,
            ..
        } => lines.push(format!(
            "Installed {entry_id}@{version} from {source} ({disposition})."
        )),
        LibraryOperationResult::Enable {
            entry_id,
            version,
            agent,
            changed,
        } => lines.push(format!(
            "{} {entry_id}@{version} for {agent}.",
            if *changed {
                "Enabled"
            } else {
                "Already enabled"
            }
        )),
        LibraryOperationResult::Disable {
            entry_id,
            version,
            agent,
            changed,
            cleanup,
        } => lines.push(format!(
            "{} {entry_id}@{version} for {agent}; cleanup={cleanup}.",
            if *changed {
                "Disabled"
            } else {
                "Already disabled"
            }
        )),
        LibraryOperationResult::Materialize { applied, steps } => {
            render_plan_lines(&mut lines, "Materialization", *applied, steps);
        }
        LibraryOperationResult::Drift {
            entry_id,
            version,
            agent,
            state,
            actual_digest,
            conflict,
        } => {
            let detail = actual_digest
                .as_deref()
                .or(conflict.as_deref())
                .map_or(String::new(), |detail| format!(" ({detail})"));
            lines.push(format!(
                "Drift {entry_id}@{version} for {agent}: {state}{detail}."
            ));
        }
        LibraryOperationResult::Resync { applied, steps } => {
            render_plan_lines(&mut lines, "Resync", *applied, steps);
        }
    }
    lines.join("\n")
}

fn render_plan_lines(
    lines: &mut Vec<String>,
    label: &str,
    applied: bool,
    steps: &[LibraryPlanStepOutput],
) {
    lines.push(format!(
        "{label} {}: {} action(s).",
        if applied { "applied" } else { "dry run" },
        steps.len()
    ));
    for step in steps {
        lines.push(format!(
            "  {} {}@{} for {}{}",
            step.action,
            step.entry_id,
            step.version,
            step.agent,
            if step.backup { " (backup)" } else { "" }
        ));
    }
}

fn joined_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_owned()
    } else {
        values.join(",")
    }
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

pub(crate) fn render_audit(output: &AuditOutput, json: bool) -> String {
    if json {
        return output.report_json.clone();
    }
    render_human_audit(output)
}

fn render_human_audit(output: &AuditOutput) -> String {
    let footprint = output.report.footprint();
    let mut lines = vec![
        format!("Project: {}", escape_text(output.project_id.as_str())),
        format!("Observed at (ms): {}", output.observed_at_ms),
        "Agent session totals:".to_owned(),
    ];
    if footprint.origin_agent_session_totals().is_empty() {
        lines.push("  none".to_owned());
    } else {
        for totals in footprint.origin_agent_session_totals() {
            lines.push(format!(
                "  {}  artifacts={} raw_bytes={} estimated_tokens={}",
                escape_text(totals.origin().as_str()),
                totals.artifact_count(),
                totals.raw_bytes(),
                totals.estimated_tokens(),
            ));
        }
    }
    lines.push(format!(
        "All sessions: artifacts={} raw_bytes={} estimated_tokens={}",
        footprint.always_loaded_artifact_count(),
        footprint.all_session_raw_bytes(),
        footprint.all_session_estimated_tokens(),
    ));
    lines.push("All-session scope totals:".to_owned());
    if footprint.all_session_scope_totals().is_empty() {
        lines.push("  none".to_owned());
    } else {
        for totals in footprint.all_session_scope_totals() {
            lines.push(format!(
                "  {}  artifacts={} raw_bytes={} estimated_tokens={}",
                escape_text(totals.scope().as_str()),
                totals.artifact_count(),
                totals.raw_bytes(),
                totals.estimated_tokens(),
            ));
        }
    }
    lines.push("Ranked always-loaded artifacts:".to_owned());
    if footprint.artifacts().is_empty() {
        lines.push("  none".to_owned());
    } else {
        for artifact in footprint.artifacts() {
            lines.push(format!(
                "  #{}  estimated_tokens={} raw_bytes={} origin={} scope={} path={}",
                artifact.rank(),
                artifact.estimated_tokens(),
                artifact.raw_bytes(),
                escape_text(artifact.origin().as_str()),
                escape_text(artifact.scope().as_str()),
                escape_text(artifact.logical_path()),
            ));
        }
    }
    render_evaluation(&mut lines, output.report.evaluation());
    lines.join("\n")
}

fn render_evaluation(lines: &mut Vec<String>, evaluation: &SkillsAuditEvaluationStatus) {
    match evaluation {
        SkillsAuditEvaluationStatus::NoEvaluator => {
            lines.push("Evaluation: no_evaluator".to_owned());
            lines
                .push("Deterministic footprint only; no supported evaluator was found.".to_owned());
        }
        SkillsAuditEvaluationStatus::Failed { evaluator, reason } => {
            lines.push("Evaluation: failed".to_owned());
            lines.push(format!("Evaluator: {}", evaluator_label(*evaluator)));
            lines.push(format!("Failure reason: {}", failure_label(*reason)));
        }
        SkillsAuditEvaluationStatus::Evaluated { evaluator, verdict } => {
            lines.push("Evaluation: evaluated".to_owned());
            lines.push(format!("Evaluator: {}", evaluator_label(*evaluator)));
            lines.push(format!(
                "Saturation grade: {}",
                escape_text(verdict.saturation_grade().as_str())
            ));
            lines.push(format!(
                "Overall summary: {}",
                escape_text(verdict.overall_summary())
            ));
            lines.push("Overlaps:".to_owned());
            if verdict.overlaps().is_empty() {
                lines.push("  none".to_owned());
            } else {
                for overlap in verdict.overlaps() {
                    lines.push(format!(
                        "  artifacts={}  summary={}",
                        escaped_artifact_ids(overlap.artifact_ids()),
                        escape_text(overlap.summary()),
                    ));
                }
            }
            lines.push("Conflicts:".to_owned());
            if verdict.conflicts().is_empty() {
                lines.push("  none".to_owned());
            } else {
                for conflict in verdict.conflicts() {
                    lines.push(format!(
                        "  artifacts={}  summary={}",
                        escaped_artifact_ids(conflict.artifact_ids()),
                        escape_text(conflict.summary()),
                    ));
                }
            }
            lines.push("Stale candidates:".to_owned());
            if verdict.stale_candidates().is_empty() {
                lines.push("  none".to_owned());
            } else {
                for candidate in verdict.stale_candidates() {
                    lines.push(format!(
                        "  artifact={}  reason={}",
                        escape_text(candidate.artifact_id().as_str()),
                        escape_text(candidate.reason()),
                    ));
                }
            }
        }
    }
}

fn escaped_artifact_ids(ids: &[AgentArtifactId]) -> String {
    ids.iter()
        .map(|id| escape_text(id.as_str()))
        .collect::<Vec<_>>()
        .join(",")
}

fn evaluator_label(evaluator: EvaluatorKind) -> String {
    escape_text(evaluator.as_str())
}

fn failure_label(reason: SkillsAuditFailureReason) -> String {
    escape_text(reason.as_str())
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
    Audit(SkillsAuditError),
    Store(StoreError),
    PTrackHomeUnavailable,
    ProjectKey(InvalidLibraryProjectKey),
    AgentRootUnavailable(SkillsAgentArg),
    NotEnabled,
    Library(LibraryError),
    Install(ArtifactInstallError),
    Materialize(MaterializationError),
    Json(serde_json::Error),
}

impl std::fmt::Display for SkillsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CurrentDirectory(_) => {
                formatter.write_str("PAM could not locate the current working directory.")
            }
            Self::Identity(_) => {
                formatter.write_str("PAM could not resolve the current project identity.")
            }
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
            Self::Audit(error) => write!(formatter, "Skills audit failed: {error}."),
            Self::Store(error) => write!(formatter, "Skills store failed: {error}."),
            Self::PTrackHomeUnavailable => {
                formatter.write_str("PAM could not resolve a safe p-track home directory.")
            }
            Self::ProjectKey(error) => error.fmt(formatter),
            Self::AgentRootUnavailable(agent) => write!(
                formatter,
                "PAM could not resolve a safe {} agent root.",
                agent.materialization_agent().as_str()
            ),
            Self::NotEnabled => {
                formatter.write_str("The exact library version is not enabled for this project.")
            }
            Self::Library(error) => write!(formatter, "Skill library failed: {error}."),
            Self::Install(error) => write!(formatter, "Skill install failed: {error}."),
            Self::Materialize(_) => formatter
                .write_str("Skill materialization failed; no local path details were emitted."),
            Self::Json(_) => formatter.write_str("PAM could not encode skills JSON."),
        }
    }
}

impl std::error::Error for SkillsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CurrentDirectory(error) => Some(error),
            Self::Identity(error) => Some(error),
            Self::LocalInventory(error) => Some(error),
            Self::Audit(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::ProjectKey(error) => Some(error),
            Self::Library(error) => Some(error),
            Self::Install(error) => Some(error),
            Self::Materialize(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::HomeUnavailable
            | Self::Clock
            | Self::IncompleteScan(_)
            | Self::PTrackHomeUnavailable
            | Self::AgentRootUnavailable(_)
            | Self::NotEnabled => None,
        }
    }
}
