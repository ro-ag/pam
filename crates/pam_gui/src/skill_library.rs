use std::{
    env, fs,
    path::{Path, PathBuf},
};

use directories::BaseDirs;
use pam_core::{ContentDigest, ProjectId};
use pam_skills::{
    AgentArtifactId, ArtifactInstallProvenance, ArtifactInstallSource, CanonicalEntryId,
    CanonicalLibrary, LibraryEnablementKey, LibraryInsertDisposition, LibraryProjectKey,
    ManagedCopyCleanupDisposition, MaterializationAction, MaterializationAgent,
    MaterializationDriftConflict, MaterializationDriftInspection, MaterializationDriftState,
    MaterializationOutcome, MaterializationPlan, OriginAgent, ScanLimits,
    apply_managed_materialization, apply_materialization_resync, disable_materialization,
    inspect_materialization_drift, install_artifact, plan_managed_materialization,
    plan_materialization_resync, scan_local_inventory,
};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::{
    CommandFence, GenerationId, OperationId, ProjectHandle,
    desktop::{DesktopErrorDto, DesktopErrorKind, DesktopResult},
    skill_inventory::SkillInventoryEnvironment,
};

pub const SKILL_LIBRARY_DTO_SCHEMA_VERSION: u32 = 1;

const MAX_LIBRARY_PATH_BYTES: usize = 4 * 1024;

#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(
    tag = "action",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SkillLibraryRequest {
    Load {
        project_handle: ProjectHandle,
        generation: GenerationId,
        operation_id: OperationId,
    },
    Adopt {
        project_handle: ProjectHandle,
        generation: GenerationId,
        operation_id: OperationId,
        entry_id: CanonicalEntryId,
        artifact_id: AgentArtifactId,
    },
    InstallLocal {
        project_handle: ProjectHandle,
        generation: GenerationId,
        operation_id: OperationId,
        entry_id: CanonicalEntryId,
        #[serde(deserialize_with = "deserialize_local_source")]
        source_path: PathBuf,
    },
    InstallGit {
        project_handle: ProjectHandle,
        generation: GenerationId,
        operation_id: OperationId,
        entry_id: CanonicalEntryId,
        #[serde(deserialize_with = "deserialize_git_url")]
        url: String,
        #[serde(deserialize_with = "deserialize_git_artifact_path")]
        artifact_path: String,
    },
    Enable {
        project_handle: ProjectHandle,
        generation: GenerationId,
        operation_id: OperationId,
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillLibraryAgentDto,
    },
    Disable {
        project_handle: ProjectHandle,
        generation: GenerationId,
        operation_id: OperationId,
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillLibraryAgentDto,
    },
    PreviewMaterialization {
        project_handle: ProjectHandle,
        generation: GenerationId,
        operation_id: OperationId,
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillLibraryAgentDto,
    },
    ApplyMaterialization {
        project_handle: ProjectHandle,
        generation: GenerationId,
        operation_id: OperationId,
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillLibraryAgentDto,
    },
    InspectDrift {
        project_handle: ProjectHandle,
        generation: GenerationId,
        operation_id: OperationId,
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillLibraryAgentDto,
    },
    PreviewResync {
        project_handle: ProjectHandle,
        generation: GenerationId,
        operation_id: OperationId,
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillLibraryAgentDto,
    },
    ApplyResync {
        project_handle: ProjectHandle,
        generation: GenerationId,
        operation_id: OperationId,
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillLibraryAgentDto,
    },
}

impl SkillLibraryRequest {
    pub(crate) fn fence(&self) -> CommandFence {
        let (project, generation, operation) = match self {
            Self::Load {
                project_handle,
                generation,
                operation_id,
            }
            | Self::Adopt {
                project_handle,
                generation,
                operation_id,
                ..
            }
            | Self::InstallLocal {
                project_handle,
                generation,
                operation_id,
                ..
            }
            | Self::InstallGit {
                project_handle,
                generation,
                operation_id,
                ..
            }
            | Self::Enable {
                project_handle,
                generation,
                operation_id,
                ..
            }
            | Self::Disable {
                project_handle,
                generation,
                operation_id,
                ..
            }
            | Self::PreviewMaterialization {
                project_handle,
                generation,
                operation_id,
                ..
            }
            | Self::ApplyMaterialization {
                project_handle,
                generation,
                operation_id,
                ..
            }
            | Self::InspectDrift {
                project_handle,
                generation,
                operation_id,
                ..
            }
            | Self::PreviewResync {
                project_handle,
                generation,
                operation_id,
                ..
            }
            | Self::ApplyResync {
                project_handle,
                generation,
                operation_id,
                ..
            } => (project_handle, generation, operation_id),
        };
        CommandFence::new(project.clone(), generation.clone(), operation.clone())
    }

    pub(crate) fn into_action(self) -> SkillLibraryAction {
        match self {
            Self::Load { .. } => SkillLibraryAction::Load,
            Self::Adopt {
                entry_id,
                artifact_id,
                ..
            } => SkillLibraryAction::Adopt {
                entry_id,
                artifact_id,
            },
            Self::InstallLocal {
                entry_id,
                source_path,
                ..
            } => SkillLibraryAction::InstallLocal {
                entry_id,
                source_path,
            },
            Self::InstallGit {
                entry_id,
                url,
                artifact_path,
                ..
            } => SkillLibraryAction::InstallGit {
                entry_id,
                url,
                artifact_path,
            },
            Self::Enable {
                entry_id,
                version,
                agent,
                ..
            } => SkillLibraryAction::Enable {
                entry_id,
                version,
                agent,
            },
            Self::Disable {
                entry_id,
                version,
                agent,
                ..
            } => SkillLibraryAction::Disable {
                entry_id,
                version,
                agent,
            },
            Self::PreviewMaterialization {
                entry_id,
                version,
                agent,
                ..
            } => SkillLibraryAction::PreviewMaterialization {
                entry_id,
                version,
                agent,
            },
            Self::ApplyMaterialization {
                entry_id,
                version,
                agent,
                ..
            } => SkillLibraryAction::ApplyMaterialization {
                entry_id,
                version,
                agent,
            },
            Self::InspectDrift {
                entry_id,
                version,
                agent,
                ..
            } => SkillLibraryAction::InspectDrift {
                entry_id,
                version,
                agent,
            },
            Self::PreviewResync {
                entry_id,
                version,
                agent,
                ..
            } => SkillLibraryAction::PreviewResync {
                entry_id,
                version,
                agent,
            },
            Self::ApplyResync {
                entry_id,
                version,
                agent,
                ..
            } => SkillLibraryAction::ApplyResync {
                entry_id,
                version,
                agent,
            },
        }
    }
}

pub(crate) enum SkillLibraryAction {
    Load,
    Adopt {
        entry_id: CanonicalEntryId,
        artifact_id: AgentArtifactId,
    },
    InstallLocal {
        entry_id: CanonicalEntryId,
        source_path: PathBuf,
    },
    InstallGit {
        entry_id: CanonicalEntryId,
        url: String,
        artifact_path: String,
    },
    Enable {
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillLibraryAgentDto,
    },
    Disable {
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillLibraryAgentDto,
    },
    PreviewMaterialization {
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillLibraryAgentDto,
    },
    ApplyMaterialization {
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillLibraryAgentDto,
    },
    InspectDrift {
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillLibraryAgentDto,
    },
    PreviewResync {
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillLibraryAgentDto,
    },
    ApplyResync {
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: SkillLibraryAgentDto,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillLibraryAgentDto {
    Claude,
    Codex,
    Cursor,
}

impl SkillLibraryAgentDto {
    const fn origin(self) -> OriginAgent {
        match self {
            Self::Claude => OriginAgent::ClaudeCode,
            Self::Codex => OriginAgent::Codex,
            Self::Cursor => OriginAgent::Cursor,
        }
    }

    const fn from_origin(origin: OriginAgent) -> Option<Self> {
        match origin {
            OriginAgent::ClaudeCode => Some(Self::Claude),
            OriginAgent::Codex => Some(Self::Codex),
            OriginAgent::Cursor => Some(Self::Cursor),
            OriginAgent::Pam => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillLibraryDto {
    pub fence: CommandFence,
    pub data: SkillLibraryDataDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "action",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SkillLibraryDataDto {
    Load {
        schema_version: u32,
        entries: Vec<SkillLibraryEntryDto>,
    },
    Adopt {
        schema_version: u32,
        entry_id: String,
        version: String,
        artifact_id: String,
        disposition: SkillLibraryDispositionDto,
    },
    InstallLocal {
        schema_version: u32,
        entry_id: String,
        version: String,
        disposition: SkillLibraryDispositionDto,
    },
    InstallGit {
        schema_version: u32,
        entry_id: String,
        version: String,
        disposition: SkillLibraryDispositionDto,
    },
    Enable {
        schema_version: u32,
        key: SkillLibraryKeyDto,
        enabled: bool,
        changed: bool,
    },
    Disable {
        schema_version: u32,
        key: SkillLibraryKeyDto,
        state_changed: bool,
        cleanup: SkillLibraryCleanupDto,
    },
    PreviewMaterialization {
        schema_version: u32,
        items: Vec<SkillLibraryPlanItemDto>,
    },
    ApplyMaterialization {
        schema_version: u32,
        outcomes: Vec<SkillLibraryOutcomeDto>,
    },
    InspectDrift {
        schema_version: u32,
        inspection: SkillLibraryDriftDto,
    },
    PreviewResync {
        schema_version: u32,
        items: Vec<SkillLibraryPlanItemDto>,
    },
    ApplyResync {
        schema_version: u32,
        outcomes: Vec<SkillLibraryOutcomeDto>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillLibraryEntryDto {
    pub entry_id: String,
    pub versions: Vec<SkillLibraryVersionDto>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillLibraryVersionDto {
    pub version: String,
    pub installation: Option<SkillLibraryInstallationDto>,
    pub enabled_agents: Vec<SkillLibraryAgentDto>,
    pub managed_agents: Vec<SkillLibraryAgentDto>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SkillLibraryInstallationDto {
    Local,
    Git { commit: String },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillLibraryDispositionDto {
    Inserted,
    AlreadyPresent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillLibraryKeyDto {
    pub entry_id: String,
    pub version: String,
    pub agent: SkillLibraryAgentDto,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillLibraryMaterializationActionDto {
    NoOp,
    Create,
    Replace,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillLibraryFileMetadataDto {
    pub byte_len: u64,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillLibraryPlanItemDto {
    pub key: SkillLibraryKeyDto,
    pub action: SkillLibraryMaterializationActionDto,
    pub existing: Option<SkillLibraryFileMetadataDto>,
    pub backup_planned: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillLibraryOutcomeDto {
    pub key: SkillLibraryKeyDto,
    pub action: SkillLibraryMaterializationActionDto,
    pub backup: Option<SkillLibraryFileMetadataDto>,
    pub ownership_recorded: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillLibraryCleanupDto {
    Removed,
    Missing,
    PreservedModified,
    PreservedSymlink,
    PreservedUnowned,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillLibraryDriftDto {
    pub key: SkillLibraryKeyDto,
    pub expected_digest: String,
    pub state: SkillLibraryDriftStateDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SkillLibraryDriftStateDto {
    Clean,
    Missing,
    Modified {
        actual_digest: String,
    },
    Conflict {
        reason: SkillLibraryDriftConflictDto,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillLibraryDriftConflictDto {
    Disabled,
    Unowned,
    UnsafeRoot,
    UnsafePath,
    Symlink,
    NonRegular,
    Unreadable,
    TooLarge,
    PlanMismatch,
}

#[derive(Clone, Debug)]
pub(crate) struct SkillLibraryEnvironment {
    ptrack_home: PathBuf,
    inventory: SkillInventoryEnvironment,
    claude_root: PathBuf,
    codex_root: PathBuf,
    cursor_root: PathBuf,
}

impl SkillLibraryEnvironment {
    pub(crate) fn discover(project_root: &Path) -> DesktopResult<Self> {
        let home = BaseDirs::new()
            .map(|directories| directories.home_dir().to_path_buf())
            .ok_or_else(|| {
                DesktopErrorDto::unavailable(
                    "PAM could not resolve the user home for the skill library.",
                    None,
                )
            })?;
        let (ptrack_home, codex_root) = resolve_library_roots(
            &home,
            env::var_os("PTRACK_HOME").map(PathBuf::from),
            env::var_os("CODEX_HOME").map(PathBuf::from),
        )?;
        let inventory = SkillInventoryEnvironment::discover(project_root.to_path_buf())?;
        Ok(Self {
            ptrack_home,
            inventory,
            claude_root: project_root.join(".claude"),
            codex_root,
            cursor_root: project_root.join(".cursor"),
        })
    }

    fn root(&self, agent: SkillLibraryAgentDto) -> &Path {
        match agent {
            SkillLibraryAgentDto::Claude => &self.claude_root,
            SkillLibraryAgentDto::Codex => &self.codex_root,
            SkillLibraryAgentDto::Cursor => &self.cursor_root,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(ptrack_home: PathBuf, project_root: &Path, user_home: &Path) -> Self {
        let state = ptrack_home.join("unused-state.sqlite3");
        Self {
            ptrack_home,
            inventory: SkillInventoryEnvironment::for_test(
                user_home.to_path_buf(),
                project_root.to_path_buf(),
                state,
                1,
            ),
            claude_root: project_root.join(".claude"),
            codex_root: user_home.join(".codex"),
            cursor_root: project_root.join(".cursor"),
        }
    }
}

pub(crate) fn execute_skill_library(
    environment: &SkillLibraryEnvironment,
    project: LibraryProjectKey,
    action: SkillLibraryAction,
) -> DesktopResult<SkillLibraryDataDto> {
    let library = CanonicalLibrary::open(&environment.ptrack_home).map_err(library_error)?;
    match action {
        SkillLibraryAction::Load => load_library(environment, &library, &project),
        SkillLibraryAction::Adopt {
            entry_id,
            artifact_id,
        } => adopt_action(environment, &library, entry_id, artifact_id),
        SkillLibraryAction::InstallLocal {
            entry_id,
            source_path,
        } => install_local_action(&library, entry_id, source_path),
        SkillLibraryAction::InstallGit {
            entry_id,
            url,
            artifact_path,
        } => install_git_action(&library, entry_id, url, artifact_path),
        SkillLibraryAction::Enable {
            entry_id,
            version,
            agent,
        } => enable_action(&library, project, entry_id, version, agent),
        SkillLibraryAction::Disable {
            entry_id,
            version,
            agent,
        } => disable_action(environment, &library, project, entry_id, version, agent),
        SkillLibraryAction::PreviewMaterialization {
            entry_id,
            version,
            agent,
        } => {
            preview_materialization_action(environment, &library, project, entry_id, version, agent)
        }
        SkillLibraryAction::ApplyMaterialization {
            entry_id,
            version,
            agent,
        } => {
            apply_materialization_action(environment, &library, &project, entry_id, version, agent)
        }
        SkillLibraryAction::InspectDrift {
            entry_id,
            version,
            agent,
        } => inspect_drift_action(environment, &library, project, entry_id, version, agent),
        SkillLibraryAction::PreviewResync {
            entry_id,
            version,
            agent,
        } => preview_resync_action(environment, &library, project, entry_id, version, agent),
        SkillLibraryAction::ApplyResync {
            entry_id,
            version,
            agent,
        } => apply_resync_action(environment, &library, project, entry_id, version, agent),
    }
}

fn adopt_action(
    environment: &SkillLibraryEnvironment,
    library: &CanonicalLibrary,
    entry_id: CanonicalEntryId,
    artifact_id: AgentArtifactId,
) -> DesktopResult<SkillLibraryDataDto> {
    let report = scan_local_inventory(environment.inventory.roots(), ScanLimits::default())
        .map_err(|_| library_unavailable())?;
    let outcome = library
        .adopt(entry_id, artifact_id, &report.into_scan_report())
        .map_err(library_error)?;
    Ok(SkillLibraryDataDto::Adopt {
        schema_version: SKILL_LIBRARY_DTO_SCHEMA_VERSION,
        entry_id: outcome.entry_id().to_string(),
        version: outcome.version().to_string(),
        artifact_id: outcome.artifact_id().to_string(),
        disposition: disposition(outcome.disposition()),
    })
}

fn install_local_action(
    library: &CanonicalLibrary,
    entry_id: CanonicalEntryId,
    source_path: PathBuf,
) -> DesktopResult<SkillLibraryDataDto> {
    let outcome = install_artifact(
        library,
        entry_id,
        &ArtifactInstallSource::local_file(source_path),
    )
    .map_err(|_| library_unavailable())?;
    Ok(SkillLibraryDataDto::InstallLocal {
        schema_version: SKILL_LIBRARY_DTO_SCHEMA_VERSION,
        entry_id: outcome.entry_id().to_string(),
        version: outcome.version().to_string(),
        disposition: disposition(outcome.disposition()),
    })
}

fn install_git_action(
    library: &CanonicalLibrary,
    entry_id: CanonicalEntryId,
    url: String,
    artifact_path: String,
) -> DesktopResult<SkillLibraryDataDto> {
    let source = ArtifactInstallSource::git(url, artifact_path)
        .map_err(|_| DesktopErrorDto::invalid_input("The Git install source is invalid."))?;
    let outcome =
        install_artifact(library, entry_id, &source).map_err(|_| library_unavailable())?;
    Ok(SkillLibraryDataDto::InstallGit {
        schema_version: SKILL_LIBRARY_DTO_SCHEMA_VERSION,
        entry_id: outcome.entry_id().to_string(),
        version: outcome.version().to_string(),
        disposition: disposition(outcome.disposition()),
    })
}

fn enable_action(
    library: &CanonicalLibrary,
    project: LibraryProjectKey,
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    agent: SkillLibraryAgentDto,
) -> DesktopResult<SkillLibraryDataDto> {
    let change = library
        .enable(enablement_key(project, entry_id, version, agent))
        .map_err(library_error)?;
    Ok(SkillLibraryDataDto::Enable {
        schema_version: SKILL_LIBRARY_DTO_SCHEMA_VERSION,
        key: key_dto(change.key()),
        enabled: change.enabled(),
        changed: change.changed(),
    })
}

fn disable_action(
    environment: &SkillLibraryEnvironment,
    library: &CanonicalLibrary,
    project: LibraryProjectKey,
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    agent: SkillLibraryAgentDto,
) -> DesktopResult<SkillLibraryDataDto> {
    let key = enablement_key(project, entry_id, version, agent);
    let outcome = disable_materialization(library, &key, environment.root(agent))
        .map_err(materialization_error)?;
    Ok(SkillLibraryDataDto::Disable {
        schema_version: SKILL_LIBRARY_DTO_SCHEMA_VERSION,
        key: key_dto(outcome.key()),
        state_changed: outcome.state_changed(),
        cleanup: cleanup_dto(outcome.cleanup()),
    })
}

fn preview_materialization_action(
    environment: &SkillLibraryEnvironment,
    library: &CanonicalLibrary,
    project: LibraryProjectKey,
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    agent: SkillLibraryAgentDto,
) -> DesktopResult<SkillLibraryDataDto> {
    let key = enablement_key(project, entry_id, version, agent);
    require_enabled(library, &key)?;
    let plan = plan_managed_materialization(library, &key, environment.root(agent))
        .map_err(materialization_error)?;
    Ok(SkillLibraryDataDto::PreviewMaterialization {
        schema_version: SKILL_LIBRARY_DTO_SCHEMA_VERSION,
        items: plan_dto(&plan, agent),
    })
}

fn apply_materialization_action(
    environment: &SkillLibraryEnvironment,
    library: &CanonicalLibrary,
    project: &LibraryProjectKey,
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    agent: SkillLibraryAgentDto,
) -> DesktopResult<SkillLibraryDataDto> {
    let key = enablement_key(project.clone(), entry_id, version, agent);
    require_enabled(library, &key)?;
    let plan = plan_managed_materialization(library, &key, environment.root(agent))
        .map_err(materialization_error)?;
    let applied =
        apply_managed_materialization(library, &key, &plan).map_err(materialization_error)?;
    let outcomes = applied
        .outcomes()
        .iter()
        .map(|outcome| outcome_dto(outcome, outcome.ownership_recorded()))
        .collect();
    Ok(SkillLibraryDataDto::ApplyMaterialization {
        schema_version: SKILL_LIBRARY_DTO_SCHEMA_VERSION,
        outcomes,
    })
}

fn inspect_drift_action(
    environment: &SkillLibraryEnvironment,
    library: &CanonicalLibrary,
    project: LibraryProjectKey,
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    agent: SkillLibraryAgentDto,
) -> DesktopResult<SkillLibraryDataDto> {
    let key = enablement_key(project, entry_id, version, agent);
    let inspection = inspect_materialization_drift(library, &key, environment.root(agent))
        .map_err(materialization_error)?;
    Ok(SkillLibraryDataDto::InspectDrift {
        schema_version: SKILL_LIBRARY_DTO_SCHEMA_VERSION,
        inspection: drift_dto(&inspection),
    })
}

fn preview_resync_action(
    environment: &SkillLibraryEnvironment,
    library: &CanonicalLibrary,
    project: LibraryProjectKey,
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    agent: SkillLibraryAgentDto,
) -> DesktopResult<SkillLibraryDataDto> {
    let key = enablement_key(project, entry_id, version, agent);
    let plan = plan_materialization_resync(library, &key, environment.root(agent))
        .map_err(materialization_error)?;
    Ok(SkillLibraryDataDto::PreviewResync {
        schema_version: SKILL_LIBRARY_DTO_SCHEMA_VERSION,
        items: plan_dto(&plan, agent),
    })
}

fn apply_resync_action(
    environment: &SkillLibraryEnvironment,
    library: &CanonicalLibrary,
    project: LibraryProjectKey,
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    agent: SkillLibraryAgentDto,
) -> DesktopResult<SkillLibraryDataDto> {
    let key = enablement_key(project, entry_id, version, agent);
    let plan = plan_materialization_resync(library, &key, environment.root(agent))
        .map_err(materialization_error)?;
    let applied =
        apply_materialization_resync(library, &key, &plan).map_err(materialization_error)?;
    Ok(SkillLibraryDataDto::ApplyResync {
        schema_version: SKILL_LIBRARY_DTO_SCHEMA_VERSION,
        outcomes: applied
            .outcomes()
            .iter()
            .map(|outcome| outcome_dto(outcome, true))
            .collect(),
    })
}

fn load_library(
    environment: &SkillLibraryEnvironment,
    library: &CanonicalLibrary,
    project: &LibraryProjectKey,
) -> DesktopResult<SkillLibraryDataDto> {
    let snapshot = library.snapshot().map_err(library_error)?;
    let enablements = snapshot.enablements();
    let mut result = Vec::with_capacity(snapshot.entries().len());
    for entry in snapshot.entries() {
        let mut versions = Vec::with_capacity(entry.versions().len());
        for version in entry.versions() {
            let installation = snapshot
                .installations()
                .iter()
                .find(|installation| {
                    installation.entry_id() == entry.id() && installation.version() == version
                })
                .map(|installation| installation_dto(installation.provenance().clone()));
            let mut enabled_agents = agents_for(enablements, project, entry.id(), version);
            let mut managed_agents =
                managed_agents_for(environment, &snapshot, project, entry.id(), version);
            enabled_agents.sort();
            managed_agents.sort();
            versions.push(SkillLibraryVersionDto {
                version: version.to_string(),
                installation,
                enabled_agents,
                managed_agents,
            });
        }
        result.push(SkillLibraryEntryDto {
            entry_id: entry.id().to_string(),
            versions,
        });
    }
    Ok(SkillLibraryDataDto::Load {
        schema_version: SKILL_LIBRARY_DTO_SCHEMA_VERSION,
        entries: result,
    })
}

fn managed_agents_for(
    environment: &SkillLibraryEnvironment,
    snapshot: &pam_skills::CanonicalLibrarySnapshot,
    project: &LibraryProjectKey,
    entry_id: &CanonicalEntryId,
    version: &ContentDigest,
) -> Vec<SkillLibraryAgentDto> {
    [
        SkillLibraryAgentDto::Claude,
        SkillLibraryAgentDto::Codex,
        SkillLibraryAgentDto::Cursor,
    ]
    .into_iter()
    .filter(|agent| {
        let key = enablement_key(project.clone(), entry_id.clone(), version.clone(), *agent);
        current_managed_root(environment.root(*agent))
            .is_some_and(|root| snapshot.is_managed_at(&key, &root))
    })
    .collect()
}

fn current_managed_root(root: &Path) -> Option<pam_skills::LibraryManagedRootId> {
    let metadata = fs::symlink_metadata(root).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return None;
    }
    let canonical = fs::canonicalize(root).ok()?;
    pam_skills::LibraryManagedRootId::from_canonical_path(&canonical).ok()
}

fn agents_for(
    keys: &[LibraryEnablementKey],
    project: &LibraryProjectKey,
    entry_id: &CanonicalEntryId,
    version: &ContentDigest,
) -> Vec<SkillLibraryAgentDto> {
    keys.iter()
        .filter(|key| {
            key.project() == project && key.entry_id() == entry_id && key.version() == version
        })
        .filter_map(|key| SkillLibraryAgentDto::from_origin(key.agent()))
        .collect()
}

fn installation_dto(provenance: ArtifactInstallProvenance) -> SkillLibraryInstallationDto {
    match provenance {
        ArtifactInstallProvenance::Local => SkillLibraryInstallationDto::Local,
        ArtifactInstallProvenance::Git(git) => SkillLibraryInstallationDto::Git {
            commit: git.commit().to_owned(),
        },
    }
}

fn enablement_key(
    project: LibraryProjectKey,
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    agent: SkillLibraryAgentDto,
) -> LibraryEnablementKey {
    LibraryEnablementKey::new(entry_id, version, agent.origin(), project)
}

fn require_enabled(library: &CanonicalLibrary, key: &LibraryEnablementKey) -> DesktopResult<()> {
    if library.is_enabled(key).map_err(library_error)? {
        Ok(())
    } else {
        Err(DesktopErrorDto::new(
            DesktopErrorKind::Conflict,
            "The exact library version is not enabled for this project and agent.",
            Some("Enable this exact version before materializing it.".to_owned()),
        ))
    }
}

fn plan_dto(
    plan: &MaterializationPlan,
    agent: SkillLibraryAgentDto,
) -> Vec<SkillLibraryPlanItemDto> {
    plan.items()
        .iter()
        .map(|item| SkillLibraryPlanItemDto {
            key: SkillLibraryKeyDto {
                entry_id: item.entry_id().to_string(),
                version: item.version().to_string(),
                agent,
            },
            action: action_dto(item.action()),
            existing: item.existing().map(|metadata| SkillLibraryFileMetadataDto {
                byte_len: metadata.byte_len(),
                digest: metadata.digest().to_string(),
            }),
            backup_planned: item.backup_destination().is_some(),
        })
        .collect()
}

fn outcome_dto(
    outcome: &MaterializationOutcome,
    ownership_recorded: bool,
) -> SkillLibraryOutcomeDto {
    SkillLibraryOutcomeDto {
        key: SkillLibraryKeyDto {
            entry_id: outcome.entry_id().to_string(),
            version: outcome.version().to_string(),
            agent: SkillLibraryAgentDto::from_origin(match outcome.agent() {
                MaterializationAgent::Claude => OriginAgent::ClaudeCode,
                MaterializationAgent::Codex => OriginAgent::Codex,
                MaterializationAgent::Cursor => OriginAgent::Cursor,
            })
            .expect("every materialization agent has a DTO"),
        },
        action: action_dto(outcome.action()),
        backup: outcome.backup().map(|backup| SkillLibraryFileMetadataDto {
            byte_len: backup.byte_len(),
            digest: backup.digest().to_string(),
        }),
        ownership_recorded,
    }
}

fn drift_dto(inspection: &MaterializationDriftInspection) -> SkillLibraryDriftDto {
    SkillLibraryDriftDto {
        key: key_dto(inspection.key()),
        expected_digest: inspection.expected_digest().to_string(),
        state: match inspection.state() {
            MaterializationDriftState::Clean => SkillLibraryDriftStateDto::Clean,
            MaterializationDriftState::Missing => SkillLibraryDriftStateDto::Missing,
            MaterializationDriftState::Modified(actual) => SkillLibraryDriftStateDto::Modified {
                actual_digest: actual.to_string(),
            },
            MaterializationDriftState::Conflict(reason) => SkillLibraryDriftStateDto::Conflict {
                reason: drift_conflict_dto(*reason),
            },
        },
    }
}

fn key_dto(key: &LibraryEnablementKey) -> SkillLibraryKeyDto {
    SkillLibraryKeyDto {
        entry_id: key.entry_id().to_string(),
        version: key.version().to_string(),
        agent: SkillLibraryAgentDto::from_origin(key.agent())
            .expect("skill library actions create only materializable agent keys"),
    }
}

const fn action_dto(action: MaterializationAction) -> SkillLibraryMaterializationActionDto {
    match action {
        MaterializationAction::NoOp => SkillLibraryMaterializationActionDto::NoOp,
        MaterializationAction::Create => SkillLibraryMaterializationActionDto::Create,
        MaterializationAction::Replace => SkillLibraryMaterializationActionDto::Replace,
    }
}

const fn cleanup_dto(cleanup: ManagedCopyCleanupDisposition) -> SkillLibraryCleanupDto {
    match cleanup {
        ManagedCopyCleanupDisposition::Removed => SkillLibraryCleanupDto::Removed,
        ManagedCopyCleanupDisposition::Missing => SkillLibraryCleanupDto::Missing,
        ManagedCopyCleanupDisposition::PreservedModified => {
            SkillLibraryCleanupDto::PreservedModified
        }
        ManagedCopyCleanupDisposition::PreservedSymlink => SkillLibraryCleanupDto::PreservedSymlink,
        ManagedCopyCleanupDisposition::PreservedUnowned => SkillLibraryCleanupDto::PreservedUnowned,
    }
}

const fn drift_conflict_dto(
    conflict: MaterializationDriftConflict,
) -> SkillLibraryDriftConflictDto {
    match conflict {
        MaterializationDriftConflict::Disabled => SkillLibraryDriftConflictDto::Disabled,
        MaterializationDriftConflict::Unowned => SkillLibraryDriftConflictDto::Unowned,
        MaterializationDriftConflict::UnsafeRoot => SkillLibraryDriftConflictDto::UnsafeRoot,
        MaterializationDriftConflict::UnsafePath => SkillLibraryDriftConflictDto::UnsafePath,
        MaterializationDriftConflict::Symlink => SkillLibraryDriftConflictDto::Symlink,
        MaterializationDriftConflict::NonRegular => SkillLibraryDriftConflictDto::NonRegular,
        MaterializationDriftConflict::Unreadable => SkillLibraryDriftConflictDto::Unreadable,
        MaterializationDriftConflict::TooLarge => SkillLibraryDriftConflictDto::TooLarge,
        MaterializationDriftConflict::PlanMismatch => SkillLibraryDriftConflictDto::PlanMismatch,
    }
}

const fn disposition(value: LibraryInsertDisposition) -> SkillLibraryDispositionDto {
    match value {
        LibraryInsertDisposition::Inserted => SkillLibraryDispositionDto::Inserted,
        LibraryInsertDisposition::AlreadyPresent => SkillLibraryDispositionDto::AlreadyPresent,
    }
}

fn library_error(_error: pam_skills::LibraryError) -> DesktopErrorDto {
    library_unavailable()
}

fn library_unavailable() -> DesktopErrorDto {
    DesktopErrorDto::unavailable(
        "PAM could not safely complete the canonical skill library action.",
        Some(
            "Verify the global p-track home and selected agent installation, then retry."
                .to_owned(),
        ),
    )
}

fn materialization_error(_error: pam_skills::MaterializationError) -> DesktopErrorDto {
    DesktopErrorDto::new(
        DesktopErrorKind::Conflict,
        "The exact skill materialization state could not satisfy this action.",
        Some("Inspect drift or preview the action again before retrying.".to_owned()),
    )
}

fn deserialize_local_source<'de, D>(deserializer: D) -> Result<PathBuf, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let path = PathBuf::from(value);
    if !bounded_absolute_path(&path) {
        return Err(D::Error::custom(
            "local source path must be bounded, UTF-8, control-free, and absolute",
        ));
    }
    Ok(path)
}

fn deserialize_git_url<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    ArtifactInstallSource::git(value.clone(), "artifact.md")
        .map_err(|_| D::Error::custom("Git install URL is invalid"))?;
    Ok(value)
}

fn deserialize_git_artifact_path<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    ArtifactInstallSource::git("https://example.invalid/repository", value.clone())
        .map_err(|_| D::Error::custom("Git artifact path is invalid"))?;
    Ok(value)
}

pub(crate) fn project_key(project: &ProjectId) -> DesktopResult<LibraryProjectKey> {
    LibraryProjectKey::parse(project.as_str().to_ascii_lowercase()).map_err(|_| {
        DesktopErrorDto::invalid_input(
            "The stable active project identity cannot identify library ownership.",
        )
    })
}

fn resolve_library_roots(
    home: &Path,
    ptrack_override: Option<PathBuf>,
    codex_override: Option<PathBuf>,
) -> DesktopResult<(PathBuf, PathBuf)> {
    let ptrack_home = ptrack_override
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| home.join(".ptrack"));
    if !bounded_absolute_path(&ptrack_home) {
        return Err(DesktopErrorDto::unavailable(
            "PAM could not resolve the global p-track home safely.",
            None,
        ));
    }
    let codex_home = codex_override
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| home.join(".codex"));
    if !bounded_absolute_path(&codex_home) {
        return Err(DesktopErrorDto::unavailable(
            "PAM could not resolve the Codex home safely.",
            None,
        ));
    }
    Ok((ptrack_home, codex_home))
}

fn bounded_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.as_os_str().as_encoded_bytes().len() <= MAX_LIBRARY_PATH_BYTES
        && path
            .to_str()
            .is_some_and(|value| !value.chars().any(char::is_control))
}

#[cfg(test)]
pub(crate) fn resolve_library_roots_for_test(
    home: &Path,
    ptrack_override: Option<PathBuf>,
    codex_override: Option<PathBuf>,
) -> DesktopResult<(PathBuf, PathBuf)> {
    resolve_library_roots(home, ptrack_override, codex_override)
}

#[cfg(test)]
pub(crate) fn empty_load_for_test() -> SkillLibraryDataDto {
    SkillLibraryDataDto::Load {
        schema_version: SKILL_LIBRARY_DTO_SCHEMA_VERSION,
        entries: Vec::new(),
    }
}
