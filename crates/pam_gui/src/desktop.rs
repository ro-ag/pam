use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    future::Future,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use pam_core::{CallerCredential, CallerId, EvidenceHandle as ProtocolEvidenceHandle, ProjectId};
use pam_daemon::registered_projects;
use pam_platform::{CallerKind, caller_id, discover_project};
use pam_protocol::{
    ActivityEventSummary, ActivityResult, ApprovalDecision, CallerListResult, CallerSummary,
    FailureCode, ProjectRequestState, ProjectRequestSummary,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{
    access_config::{AccessConfigState, AccessConfigView},
    control_center::{
        HealthState, MAX_PROJECTS, bounded_name, load_credential, load_project_health_access,
        load_project_surfaces, project_name, request_daemon_stop_authenticated,
    },
    current::{
        ApprovalDecisionFailure, ApprovalDecisionView, CurrentState, CurrentUnavailableCode,
        CurrentView, EvidencePreview, EvidenceState, OutcomeView, PendingApproval, RunView,
        TimelineFact, TimelineKind, decide_current_approval, load_evidence,
    },
    flow_editor::{
        ActionAuthority, DaemonAuthority, DryRunCondition, FlowDryRunPlan, FlowEditorDocument,
        FlowEditorError, FlowEditorModel, FlowIdentity, FlowVersionDiff, FlowVersionDiffLineKind,
    },
    observatory::{ObservatoryState, load_caller_registry, load_daemon_activity},
    skill_audit::{SkillAuditDto, load_persisted_skill_audit, run_skill_audit_report},
    skill_inventory::{SkillInventoryDto, SkillInventoryEnvironment, load_skill_inventory},
    skill_library::{
        SkillLibraryAction, SkillLibraryDataDto, SkillLibraryDto, SkillLibraryEnvironment,
        SkillLibraryRequest, execute_skill_library, project_key,
    },
};

const MAX_OPERATIONS: usize = 256;
const MAX_DETAILS_BYTES: usize = 4 * 1024;
const MAX_PROJECT_PATH_BYTES: usize = 4 * 1024;
const MAX_TIMELINE_FACTS: usize = 256;
const MAX_EVIDENCE_HANDLES: usize = 256;
const STARTUP_DELAY: Duration = Duration::from_millis(500);
const GUI_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(15);
const GUI_REGISTRATION_ARGS: [&str; 4] = ["caller", "register", "--kind", "gui"];
const GUI_REGISTRATION_RECOVERY: &str = "Use Register GUI caller in PAM.";

macro_rules! uuid_handle {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(|_| {
                    serde::de::Error::custom("desktop handles must be canonical UUID strings")
                })
            }
        }

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4().to_string())
            }

            /// Parses one canonical UUID handle.
            ///
            /// # Errors
            ///
            /// Rejects malformed or non-canonical UUID text.
            pub fn parse(value: impl Into<String>) -> DesktopResult<Self> {
                let value = value.into();
                validate_uuid(&value)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            fn validate(&self) -> DesktopResult<()> {
                validate_uuid(&self.0)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

uuid_handle!(ProjectHandle);
uuid_handle!(GenerationId);
uuid_handle!(OperationId);
uuid_handle!(ApprovalHandle);
uuid_handle!(EvidenceHandleDto);
uuid_handle!(FlowDefinitionHandle);
uuid_handle!(FlowDocumentHandle);

fn validate_uuid(value: &str) -> DesktopResult<()> {
    let parsed = Uuid::parse_str(value).map_err(|_| {
        DesktopErrorDto::invalid_input("Desktop handles must be canonical UUID strings.")
    })?;
    if parsed.hyphenated().to_string() != value {
        return Err(DesktopErrorDto::invalid_input(
            "Desktop handles must be canonical UUID strings.",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommandFence {
    pub project_handle: ProjectHandle,
    pub generation: GenerationId,
    pub operation_id: OperationId,
}

impl CommandFence {
    #[must_use]
    pub const fn new(
        project_handle: ProjectHandle,
        generation: GenerationId,
        operation_id: OperationId,
    ) -> Self {
        Self {
            project_handle,
            generation,
            operation_id,
        }
    }

    fn validate(&self) -> DesktopResult<()> {
        self.project_handle.validate()?;
        self.generation.validate()?;
        self.operation_id.validate()
    }
}

pub type SnapshotFence = CommandFence;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopErrorKind {
    InvalidInput,
    NotFound,
    Stale,
    Conflict,
    Unavailable,
    Internal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DesktopErrorDto {
    pub kind: DesktopErrorKind,
    pub message: String,
    pub recovery: Option<String>,
}

impl DesktopErrorDto {
    pub(crate) fn new(
        kind: DesktopErrorKind,
        message: impl Into<String>,
        recovery: Option<String>,
    ) -> Self {
        Self {
            kind,
            message: bounded_detail(message.into()),
            recovery: recovery.map(bounded_detail),
        }
    }

    pub(crate) fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(DesktopErrorKind::InvalidInput, message, None)
    }

    fn stale(message: impl Into<String>) -> Self {
        Self::new(
            DesktopErrorKind::Stale,
            message,
            Some("Refresh the active project and retry with its new fence.".to_owned()),
        )
    }

    pub(crate) fn unavailable(message: impl Into<String>, recovery: Option<String>) -> Self {
        Self::new(DesktopErrorKind::Unavailable, message, recovery)
    }
}

impl fmt::Display for DesktopErrorDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for DesktopErrorDto {}

pub type DesktopResult<T> = Result<T, DesktopErrorDto>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogDto {
    pub projects: Vec<ProjectSummaryDto>,
    pub warning: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectSummaryDto {
    pub handle: ProjectHandle,
    pub name: String,
    pub location: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotDto {
    pub fence: CommandFence,
    pub data: SnapshotDataDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotDataDto {
    pub project: ProjectSummaryDto,
    pub health: HealthDto,
    pub current: CurrentDto,
    pub access: AccessConfigDto,
    pub catalog_warning: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "status",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum HealthDto {
    Healthy {
        daemon_version: String,
        queue_depth: u64,
    },
    Offline,
    Degraded {
        detail: String,
        recovery: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKindDto {
    Blocked,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureDto {
    pub kind: FailureKindDto,
    pub code: Option<String>,
    pub detail: String,
    pub recovery: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "status",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum AccessConfigDto {
    Available {
        truth: String,
        platform_roots_enabled: bool,
        system_proxy_discovery_enabled: bool,
        proxy_environment: String,
        no_proxy: String,
        pac: String,
    },
    Blocked {
        failure: FailureDto,
        approval_id: Option<String>,
        expires_at_ms: Option<u64>,
    },
    Unavailable {
        failure: FailureDto,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "status",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum CurrentDto {
    Available {
        queued: Vec<RequestSummaryDto>,
        truncated: bool,
        run: Option<RunDto>,
    },
    ApprovalRequired {
        approval: ApprovalHandle,
        expires_at_ms: u64,
    },
    Blocked {
        failure: FailureDto,
    },
    Unavailable {
        failure: FailureDto,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestSummaryDto {
    pub request_id: String,
    pub operation_kind: String,
    pub state: String,
    pub queue_sequence: u64,
    pub accepted_at_ms: u64,
    pub completed_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunDto {
    pub request: RequestSummaryDto,
    pub timeline: Vec<TimelineFactDto>,
    pub outcome: Option<OutcomeDto>,
    pub detail_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimelineFactDto {
    pub kind: TimelineKindDto,
    pub label: String,
    pub summary: String,
    pub verified: bool,
    pub evidence: Vec<EvidenceHandleDto>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineKindDto {
    Request,
    Evidence,
    Change,
    Verification,
    Failure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeDto {
    pub heading: String,
    pub solved: bool,
    pub sections: Vec<OutcomeSectionDto>,
    pub evidence: Vec<EvidenceHandleDto>,
    pub evidence_truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeSectionDto {
    pub label: String,
    pub summary: String,
    pub satisfied: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecisionDto {
    Approve,
    Deny,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecisionDispositionDto {
    Approved,
    Denied,
    Expired,
}

impl From<pam_protocol::ApprovalDecisionDisposition> for ApprovalDecisionDispositionDto {
    fn from(value: pam_protocol::ApprovalDecisionDisposition) -> Self {
        match value {
            pam_protocol::ApprovalDecisionDisposition::Approved => Self::Approved,
            pam_protocol::ApprovalDecisionDisposition::Denied => Self::Denied,
            pam_protocol::ApprovalDecisionDisposition::Expired => Self::Expired,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalDecisionResponseDto {
    pub disposition: ApprovalDecisionDispositionDto,
    pub snapshot: SnapshotDto,
}

impl From<ApprovalDecisionDto> for ApprovalDecision {
    fn from(value: ApprovalDecisionDto) -> Self {
        match value {
            ApprovalDecisionDto::Approve => Self::Approve,
            ApprovalDecisionDto::Deny => Self::Deny,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDto {
    pub fence: CommandFence,
    pub data: EvidenceDataDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDataDto {
    pub handle: EvidenceHandleDto,
    pub digest: String,
    pub size_bytes: u64,
    pub media_type: String,
    pub body: Option<String>,
    pub truncated: bool,
    pub truth: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowWorkspaceDto {
    pub fence: CommandFence,
    pub data: FlowWorkspaceDataDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowWorkspaceDataDto {
    pub definitions: Vec<FlowDefinitionDto>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowDefinitionDto {
    pub handle: FlowDefinitionHandle,
    pub identity: FlowIdentityDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowIdentityDto {
    pub file_name: String,
    pub id: String,
    pub revision: u64,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowDocumentDto {
    pub fence: CommandFence,
    pub data: FlowDocumentDataDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowDocumentDataDto {
    pub handle: FlowDocumentHandle,
    pub identity: Option<FlowIdentityDto>,
    pub source: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowReviewDto {
    pub fence: CommandFence,
    pub data: FlowReviewDataDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowReviewDataDto {
    pub document: FlowDocumentHandle,
    pub identity: FlowIdentityDto,
    pub normalized_toml: String,
    pub dry_run: FlowDryRunDto,
    pub diff: FlowVersionDiffDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowDryRunDto {
    pub daemon_definition_eligible: bool,
    pub steps: Vec<FlowDryRunStepDto>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowDryRunStepDto {
    pub index: usize,
    pub id: String,
    pub semantic_role: String,
    pub condition: String,
    pub approval: String,
    pub effect: String,
    pub max_attempts: u8,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub action: String,
    pub daemon_authority: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowVersionDiffDto {
    pub changed: bool,
    pub truncated: bool,
    pub lines: Vec<FlowVersionDiffLineDto>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowVersionDiffLineDto {
    pub kind: String,
    pub text: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowSaveDto {
    pub fence: CommandFence,
    pub data: FlowSaveDataDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowSaveDataDto {
    pub document: FlowDocumentHandle,
    pub identity: FlowIdentityDto,
    pub created: bool,
    pub durability_confirmed: bool,
    pub cleanup_complete: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "status",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ActivityDto {
    Ok {
        events: Vec<ActivityEventDto>,
        truncated: bool,
    },
    Blocked {
        failure: FailureDto,
    },
    Unavailable {
        failure: FailureDto,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivityEventDto {
    pub sequence: u64,
    pub project_id: String,
    pub caller_id: String,
    pub action: String,
    pub decision: String,
    pub outcome: String,
    pub occurred_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "status",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum CallersDto {
    Ok { callers: Vec<CallerDto> },
    Blocked { failure: FailureDto },
    Unavailable { failure: FailureDto },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CallerDto {
    pub caller_id: String,
    pub registered_at_ms: u64,
    pub revoked_at_ms: Option<u64>,
}

#[derive(Clone)]
pub struct DesktopCore {
    inner: Arc<Mutex<DesktopState>>,
    command_gate: Arc<Mutex<()>>,
}

impl fmt::Debug for DesktopCore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DesktopCore { authority: [REDACTED] }")
    }
}

struct DesktopState {
    startup_root: PathBuf,
    daemon_executable: PathBuf,
    catalog: HashMap<ProjectHandle, CatalogProject>,
    active: Option<ActiveProject>,
    activation_operation: Option<OperationId>,
    used_operations: VecDeque<OperationId>,
    approvals: HashMap<ApprovalHandle, PendingApproval>,
    evidence: HashMap<EvidenceHandleDto, ProtocolEvidenceHandle>,
    flow_workspace: Option<FlowWorkspaceState>,
    daemon_child: Option<Child>,
    catalog_warning: Option<String>,
}

#[derive(Clone)]
struct CatalogProject {
    handle: ProjectHandle,
    name: String,
    root: PathBuf,
}

#[derive(Clone)]
struct ActiveProject {
    catalog: CatalogProject,
    project_id: ProjectId,
    generation: GenerationId,
}

struct FlowWorkspaceState {
    project: ProjectHandle,
    generation: GenerationId,
    model: FlowEditorModel,
    definitions: HashMap<FlowDefinitionHandle, String>,
    documents: HashMap<FlowDocumentHandle, FlowEditorDocument>,
}

impl DesktopCore {
    #[must_use]
    pub fn new(startup_root: impl Into<PathBuf>) -> Self {
        let daemon_executable = default_daemon_executable();
        Self::with_daemon_executable(startup_root, daemon_executable)
    }

    #[must_use]
    pub fn with_daemon_executable(
        startup_root: impl Into<PathBuf>,
        daemon_executable: impl Into<PathBuf>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(DesktopState {
                startup_root: startup_root.into(),
                daemon_executable: daemon_executable.into(),
                catalog: HashMap::new(),
                active: None,
                activation_operation: None,
                used_operations: VecDeque::new(),
                approvals: HashMap::new(),
                evidence: HashMap::new(),
                flow_workspace: None,
                daemon_child: None,
                catalog_warning: None,
            })),
            command_gate: Arc::new(Mutex::new(())),
        }
    }

    /// Loads direct discovery and optional ptrack hints without activating a
    /// hint or exposing its path as a filesystem authority.
    pub async fn catalog(&self) -> CatalogDto {
        let startup_root = self.inner.lock().await.startup_root.clone();
        let direct = discover_project(&startup_root)
            .ok()
            .map(|identity| (project_name(identity.root()), identity.root().to_path_buf()));
        let registered = registered_projects(&startup_root).await;
        let warning = registered.as_ref().err().cloned().map(bounded_detail);

        let mut candidates = Vec::new();
        if let Some(candidate) = direct {
            candidates.push(candidate);
        }
        if let Ok(entries) = registered {
            for entry in entries {
                let Ok(root) = entry.path().canonicalize() else {
                    continue;
                };
                if root.is_dir() {
                    candidates.push((bounded_name(entry.name(), &root), root));
                }
            }
        }

        let mut seen = HashSet::new();
        candidates.retain(|(_, root)| seen.insert(root.clone()));
        candidates.truncate(MAX_PROJECTS);

        let mut state = self.inner.lock().await;
        let old_by_root = state
            .catalog
            .values()
            .map(|candidate| (candidate.root.clone(), candidate.handle.clone()))
            .collect::<HashMap<_, _>>();
        let mut catalog = HashMap::new();
        let mut projects = Vec::with_capacity(candidates.len());
        for (name, root) in candidates {
            let handle = old_by_root
                .get(&root)
                .cloned()
                .unwrap_or_else(ProjectHandle::new);
            let candidate = CatalogProject {
                handle: handle.clone(),
                name: bounded_name(&name, &root),
                root,
            };
            projects.push(project_dto(&candidate));
            catalog.insert(handle, candidate);
        }
        state.catalog = catalog;
        state.catalog_warning.clone_from(&warning);
        CatalogDto { projects, warning }
    }

    /// Discovers and activates the first valid startup project, preferring the
    /// direct launch context before ordered ptrack catalog hints.
    ///
    /// # Errors
    ///
    /// Returns a bounded error when no project can be discovered, authority
    /// setup fails, or a concurrent activation supersedes this operation.
    pub async fn bootstrap(&self, operation: OperationId) -> DesktopResult<SnapshotDto> {
        operation.validate()?;
        let catalog = self.catalog().await;
        let _command = self.command_gate.lock().await;
        let candidates = {
            let mut state = self.inner.lock().await;
            if state.activation_operation.is_some() {
                return Err(DesktopErrorDto::new(
                    DesktopErrorKind::Conflict,
                    "A project activation is already running.",
                    None,
                ));
            }
            state.activation_operation = Some(operation.clone());
            catalog
                .projects
                .iter()
                .filter_map(|project| state.catalog.get(&project.handle).cloned())
                .collect::<Vec<_>>()
        };

        let mut last_error = None;
        let mut selected = None;
        for candidate in candidates {
            match discover_project(&candidate.root) {
                Ok(identity) => {
                    selected = Some((candidate, identity));
                    break;
                }
                Err(error) => last_error = Some(error.to_string()),
            }
        }
        let Some((candidate, identity)) = selected else {
            let mut state = self.inner.lock().await;
            if state.activation_operation.as_ref() == Some(&operation) {
                state.activation_operation = None;
            }
            return Err(DesktopErrorDto::unavailable(
                last_error.unwrap_or_else(|| {
                    "PAM could not find a project in the launch context or ptrack catalog."
                        .to_owned()
                }),
                Some("Open PAM from a Git repository or initialized PAM project.".to_owned()),
            ));
        };
        let surfaces = load_surfaces(identity.id().clone()).await;
        let mut state = self.inner.lock().await;
        if state.activation_operation.as_ref() != Some(&operation) {
            return Err(DesktopErrorDto::stale(
                "A newer project activation replaced bootstrap.",
            ));
        }
        let generation = GenerationId::new();
        let active = ActiveProject {
            catalog: CatalogProject {
                root: identity.root().to_path_buf(),
                ..candidate
            },
            project_id: identity.id().clone(),
            generation,
        };
        state.active = Some(active.clone());
        state.activation_operation = None;
        state.used_operations.clear();
        state.approvals.clear();
        state.evidence.clear();
        state.flow_workspace = None;
        Ok(snapshot_from_surfaces(
            &mut state, &active, operation, surfaces,
        ))
    }

    /// Activates one opaque catalog entry and loads one authenticated snapshot.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for an invalid/stale handle, project discovery
    /// failure, or a concurrent activation.
    pub async fn activate(
        &self,
        project: ProjectHandle,
        operation: OperationId,
    ) -> DesktopResult<SnapshotDto> {
        let _command = self.command_gate.lock().await;
        project.validate()?;
        operation.validate()?;
        let candidate = {
            let mut state = self.inner.lock().await;
            if state.activation_operation.is_some() {
                return Err(DesktopErrorDto::new(
                    DesktopErrorKind::Conflict,
                    "A project activation is already running.",
                    None,
                ));
            }
            let candidate = state.catalog.get(&project).cloned().ok_or_else(|| {
                DesktopErrorDto::new(
                    DesktopErrorKind::NotFound,
                    "The selected project handle is not in the current catalog.",
                    Some("Reload the project catalog and select it again.".to_owned()),
                )
            })?;
            state.activation_operation = Some(operation.clone());
            candidate
        };

        let identity = match discover_project(&candidate.root) {
            Ok(identity) => identity,
            Err(error) => {
                let mut state = self.inner.lock().await;
                if state.activation_operation.as_ref() == Some(&operation) {
                    state.activation_operation = None;
                }
                return Err(DesktopErrorDto::unavailable(
                    error.to_string(),
                    Some("Choose a Git repository or initialized PAM project.".to_owned()),
                ));
            }
        };
        let surfaces = load_surfaces(identity.id().clone()).await;

        let mut state = self.inner.lock().await;
        if state.activation_operation.as_ref() != Some(&operation) {
            return Err(DesktopErrorDto::stale(
                "A newer project activation replaced this operation.",
            ));
        }
        let generation = GenerationId::new();
        let active = ActiveProject {
            catalog: CatalogProject {
                root: identity.root().to_path_buf(),
                ..candidate
            },
            project_id: identity.id().clone(),
            generation: generation.clone(),
        };
        state.active = Some(active.clone());
        state.activation_operation = None;
        state.used_operations.clear();
        state.approvals.clear();
        state.evidence.clear();
        state.flow_workspace = None;
        Ok(snapshot_from_surfaces(
            &mut state, &active, operation, surfaces,
        ))
    }

    /// Refreshes all authenticated project surfaces under one credential read.
    ///
    /// # Errors
    ///
    /// Returns a bounded error when the fence is invalid, stale, or reused.
    pub async fn refresh(&self, fence: CommandFence) -> DesktopResult<SnapshotDto> {
        let _command = self.command_gate.lock().await;
        let active = self.begin(&fence).await?;
        let surfaces = load_surfaces(active.project_id.clone()).await;
        self.finish_snapshot(fence, active, surfaces).await
    }

    /// Starts the configured PAM daemon and returns a newly fenced snapshot.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for stale authority or process startup failure.
    pub async fn start_daemon(&self, fence: CommandFence) -> DesktopResult<SnapshotDto> {
        let _command = self.command_gate.lock().await;
        let active = self.begin(&fence).await?;
        let executable = self.inner.lock().await.daemon_executable.clone();
        // The daemon starts only with a control-center launch grant, and runs
        // detached in its own process group: closing the UI never stops it.
        let endpoint = pam_platform::LocalEndpoint::default_for_user();
        let grant = pam_platform::issue_launch_grant(endpoint.runtime_dir()).map_err(|error| {
            DesktopErrorDto::unavailable(
                "PAM could not authorize a daemon launch.",
                Some(error.to_string()),
            )
        })?;
        let mut command = Command::new(executable);
        command
            // --recover is idempotent: it only clears a stale socket, and a
            // live daemon still holds the ownership lock.
            .args(["daemon", "--recover"])
            .env(pam_platform::LAUNCH_GRANT_ENV, grant)
            .current_dir(&active.catalog.root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(unix)]
        command.process_group(0);
        let mut child = command.spawn().map_err(|error| {
            DesktopErrorDto::unavailable(
                "PAM could not start the local daemon.",
                Some(error.to_string()),
            )
        })?;
        tokio::time::sleep(STARTUP_DELAY).await;
        if let Some(status) = child.try_wait().map_err(|error| {
            DesktopErrorDto::unavailable(
                "PAM could not inspect the local daemon process.",
                Some(error.to_string()),
            )
        })? {
            return Err(DesktopErrorDto::unavailable(
                format!("The local daemon exited during startup with {status}."),
                None,
            ));
        }
        let surfaces = load_surfaces(active.project_id.clone()).await;
        let mut state = self.inner.lock().await;
        ensure_active_matches(&state, &active, &fence)?;
        state.daemon_child = Some(child);
        finish_snapshot_locked(&mut state, fence, active, surfaces)
    }

    /// Requests an authenticated daemon stop and returns a newly fenced snapshot.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for stale authority, missing credentials, or a
    /// rejected/failed daemon lifecycle exchange.
    pub async fn stop_daemon(&self, fence: CommandFence) -> DesktopResult<SnapshotDto> {
        let _command = self.command_gate.lock().await;
        let active = self.begin(&fence).await?;
        let caller = caller_id(CallerKind::Gui)
            .map_err(|error| DesktopErrorDto::unavailable(error.to_string(), None))?;
        let credential = load_credential(caller.clone()).await.map_err(|detail| {
            DesktopErrorDto::unavailable(detail, Some(GUI_REGISTRATION_RECOVERY.to_owned()))
        })?;
        request_daemon_stop_authenticated(
            caller.clone(),
            credential.clone(),
            active.project_id.clone(),
        )
        .await
        .map_err(|detail| DesktopErrorDto::unavailable(detail, None))?;
        let surfaces =
            load_surfaces_with_credential(caller, credential, active.project_id.clone()).await;
        let mut state = self.inner.lock().await;
        ensure_active_matches(&state, &active, &fence)?;
        reap_daemon_child(&mut state);
        finish_snapshot_locked(&mut state, fence, active, surfaces)
    }

    /// Registers the GUI caller through the bundled PAM helper and refreshes
    /// the authenticated project snapshot.
    ///
    /// # Errors
    ///
    /// Returns a bounded error when the fence is stale, the fixed helper
    /// cannot be started, registration fails, or the helper exceeds its
    /// deadline.
    pub async fn register_gui_caller(&self, fence: CommandFence) -> DesktopResult<SnapshotDto> {
        let _command = self.command_gate.lock().await;
        let active = self.begin(&fence).await?;
        let (executable, root) = {
            let state = self.inner.lock().await;
            ensure_active_matches(&state, &active, &fence)?;
            (state.daemon_executable.clone(), active.catalog.root.clone())
        };
        run_gui_registration(&executable, &root).await?;
        let surfaces = load_surfaces(active.project_id.clone()).await;
        self.finish_snapshot(fence, active, surfaces).await
    }

    /// Applies a decision to the exact retained approval request.
    ///
    /// # Errors
    ///
    /// Returns a bounded error when any fence or approval handle is stale, or
    /// when the authenticated refresh cannot be completed.
    pub async fn decide_approval(
        &self,
        fence: CommandFence,
        approval: ApprovalHandle,
        decision: ApprovalDecisionDto,
    ) -> DesktopResult<ApprovalDecisionResponseDto> {
        self.decide_approval_with(fence, approval, decision, decide_current_approval)
            .await
    }

    async fn decide_approval_with<F, Fut>(
        &self,
        fence: CommandFence,
        approval: ApprovalHandle,
        decision: ApprovalDecisionDto,
        decide: F,
    ) -> DesktopResult<ApprovalDecisionResponseDto>
    where
        F: FnOnce(PendingApproval, ApprovalDecision) -> Fut,
        Fut: Future<Output = Result<ApprovalDecisionView, ApprovalDecisionFailure>>,
    {
        let _command = self.command_gate.lock().await;
        approval.validate()?;
        let active = self.begin(&fence).await?;
        let pending = {
            let state = self.inner.lock().await;
            ensure_active_matches(&state, &active, &fence)?;
            state.approvals.get(&approval).cloned().ok_or_else(|| {
                DesktopErrorDto::stale("The approval handle is no longer current.")
            })?
        };
        if pending.project_id() != &active.project_id {
            return Err(DesktopErrorDto::stale(
                "The approval belongs to another project.",
            ));
        }
        let decision = decide(pending, decision.into())
            .await
            .map_err(|failure| DesktopErrorDto::unavailable(failure.detail, failure.recovery))?;
        let disposition = decision.disposition.into();
        let project_id = active.project_id.clone();
        let surfaces = approval_surfaces_with(decision.current, || async move {
            load_health_access(project_id).await
        })
        .await;
        let snapshot = self.finish_snapshot(fence, active, surfaces).await?;
        Ok(ApprovalDecisionResponseDto {
            disposition,
            snapshot,
        })
    }

    /// Loads a bounded 4 KiB preview through an opaque evidence handle.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for stale authority, unavailable credentials,
    /// or an unexpected evidence protocol response.
    pub async fn load_evidence(
        &self,
        fence: CommandFence,
        handle: EvidenceHandleDto,
    ) -> DesktopResult<EvidenceDto> {
        let _command = self.command_gate.lock().await;
        handle.validate()?;
        let active = self.begin(&fence).await?;
        let protocol_handle = {
            let state = self.inner.lock().await;
            ensure_active_matches(&state, &active, &fence)?;
            state.evidence.get(&handle).cloned().ok_or_else(|| {
                DesktopErrorDto::stale("The evidence handle is no longer current.")
            })?
        };
        let caller = caller_id(CallerKind::Gui)
            .map_err(|error| DesktopErrorDto::unavailable(error.to_string(), None))?;
        let credential = load_credential(caller.clone()).await.map_err(|detail| {
            DesktopErrorDto::unavailable(detail, Some(GUI_REGISTRATION_RECOVERY.to_owned()))
        })?;
        let evidence = load_evidence(
            caller,
            credential,
            active.project_id.clone(),
            protocol_handle,
        )
        .await;
        let data = evidence_data(handle, evidence)?;
        let state = self.inner.lock().await;
        ensure_active_matches(&state, &active, &fence)?;
        Ok(EvidenceDto { fence, data })
    }

    /// Loads the active project's bounded flow catalog.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for stale authority or an unsafe/invalid catalog.
    pub async fn flow_workspace(&self, fence: CommandFence) -> DesktopResult<FlowWorkspaceDto> {
        let _command = self.command_gate.lock().await;
        let active = self.begin(&fence).await?;
        let root = active.catalog.root.clone();
        let model = tokio::task::spawn_blocking(move || FlowEditorModel::open(root))
            .await
            .map_err(|_| {
                DesktopErrorDto::new(
                    DesktopErrorKind::Internal,
                    "PAM could not join the flow catalog worker.",
                    None,
                )
            })?
            .map_err(|error| flow_error(&error))?;
        let mut definitions = HashMap::new();
        let mut result = Vec::with_capacity(model.entries().len());
        for entry in model.entries() {
            let handle = FlowDefinitionHandle::new();
            definitions.insert(handle.clone(), entry.identity().file_name().to_owned());
            result.push(FlowDefinitionDto {
                handle,
                identity: identity_dto(entry.identity()),
            });
        }
        let mut state = self.inner.lock().await;
        ensure_active_matches(&state, &active, &fence)?;
        state.flow_workspace = Some(FlowWorkspaceState {
            project: active.catalog.handle.clone(),
            generation: active.generation.clone(),
            model,
            definitions,
            documents: HashMap::new(),
        });
        Ok(FlowWorkspaceDto {
            fence,
            data: FlowWorkspaceDataDto {
                definitions: result,
            },
        })
    }

    /// Loads the bounded newest-first daemon activity feed.
    ///
    /// A `None` limit requests the daemon default; the daemon clamps any limit
    /// to its bounded maximum. Daemon failures are classified in the returned
    /// DTO: an explicit policy deny is blocked, everything else unavailable.
    ///
    /// # Errors
    ///
    /// Returns a bounded error when the fence is invalid, stale, or reused.
    pub async fn daemon_activity(
        &self,
        fence: CommandFence,
        limit: Option<u32>,
    ) -> DesktopResult<ActivityDto> {
        let _command = self.command_gate.lock().await;
        let active = self.begin(&fence).await?;
        let observed = match observatory_credential().await {
            Ok((caller, credential)) => {
                load_daemon_activity(
                    caller,
                    credential,
                    active.project_id.clone(),
                    limit.unwrap_or(0),
                )
                .await
            }
            Err(state) => state,
        };
        let data = activity_dto(observed);
        let state = self.inner.lock().await;
        ensure_active_matches(&state, &active, &fence)?;
        Ok(data)
    }

    /// Loads the complete caller registry, including revoked callers.
    ///
    /// Daemon failures are classified in the returned DTO: an explicit policy
    /// deny is blocked, everything else unavailable.
    ///
    /// # Errors
    ///
    /// Returns a bounded error when the fence is invalid, stale, or reused.
    pub async fn caller_registry(&self, fence: CommandFence) -> DesktopResult<CallersDto> {
        let _command = self.command_gate.lock().await;
        let active = self.begin(&fence).await?;
        let observed = match observatory_credential().await {
            Ok((caller, credential)) => {
                load_caller_registry(caller, credential, active.project_id.clone()).await
            }
            Err(state) => state,
        };
        let data = callers_dto(observed);
        let state = self.inner.lock().await;
        ensure_active_matches(&state, &active, &fence)?;
        Ok(data)
    }

    /// Scans and persists the active project's bounded local agent artifact inventory.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for stale authority, incomplete filesystem scans,
    /// malformed plugin registries, or unavailable durable state.
    pub async fn skill_inventory(&self, fence: CommandFence) -> DesktopResult<SkillInventoryDto> {
        let _command = self.command_gate.lock().await;
        let active = self.begin(&fence).await?;
        let environment = SkillInventoryEnvironment::discover(active.catalog.root.clone())?;
        let data = load_skill_inventory(active.project_id.clone(), environment).await?;
        let state = self.inner.lock().await;
        ensure_active_matches(&state, &active, &fence)?;
        Ok(SkillInventoryDto { fence, data })
    }

    /// Executes one exact metadata-only canonical skill-library action.
    ///
    /// # Errors
    ///
    /// Returns a bounded error when the fence is stale or reused, the global p-track home or
    /// derived agent root is unsafe, or the exact library action cannot be completed.
    pub async fn manage_skill_library(
        &self,
        request: SkillLibraryRequest,
    ) -> DesktopResult<SkillLibraryDto> {
        self.manage_skill_library_with(request, |active, action| async move {
            let root = active.catalog.root.clone();
            let project = project_key(&active.project_id)?;
            tokio::task::spawn_blocking(move || {
                let environment = SkillLibraryEnvironment::discover(&root)?;
                execute_skill_library(&environment, project, action)
            })
            .await
            .map_err(|_| {
                DesktopErrorDto::unavailable(
                    "PAM could not join the bounded skill library action.",
                    Some("Retry the exact skill library action.".to_owned()),
                )
            })?
        })
        .await
    }

    async fn manage_skill_library_with<F, Fut>(
        &self,
        request: SkillLibraryRequest,
        work: F,
    ) -> DesktopResult<SkillLibraryDto>
    where
        F: FnOnce(ActiveProject, SkillLibraryAction) -> Fut,
        Fut: Future<Output = DesktopResult<SkillLibraryDataDto>>,
    {
        let _command = self.command_gate.lock().await;
        let fence = request.fence();
        let action = request.into_action();
        let active = self.begin(&fence).await?;
        let result = work(active.clone(), action).await;
        let state = self.inner.lock().await;
        ensure_active_matches(&state, &active, &fence)?;
        let data = result?;
        Ok(SkillLibraryDto { fence, data })
    }

    /// Loads the latest durable audit for the active project without running an evaluator.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for stale authority or invalid/unavailable durable state.
    pub async fn load_skill_audit(&self, fence: CommandFence) -> DesktopResult<SkillAuditDto> {
        let _command = self.command_gate.lock().await;
        let active = self.begin(&fence).await?;
        let environment = SkillInventoryEnvironment::discover(active.catalog.root.clone())?;
        let data =
            load_persisted_skill_audit(active.project_id.clone(), environment.state_path()).await?;
        let state = self.inner.lock().await;
        ensure_active_matches(&state, &active, &fence)?;
        Ok(SkillAuditDto { fence, data })
    }

    /// Runs and persists one fresh bounded audit for the active project.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for stale authority, incomplete scans, evaluator setup failures,
    /// or invalid/unavailable durable state.
    pub async fn run_skill_audit(&self, fence: CommandFence) -> DesktopResult<SkillAuditDto> {
        let _command = self.command_gate.lock().await;
        let active = self.begin(&fence).await?;
        let environment = SkillInventoryEnvironment::discover(active.catalog.root.clone())?;
        let data = run_skill_audit_report(active.project_id.clone(), environment).await?;
        let state = self.inner.lock().await;
        ensure_active_matches(&state, &active, &fence)?;
        Ok(SkillAuditDto {
            fence,
            data: Some(data),
        })
    }

    /// Opens one flow selected only by an opaque catalog handle.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for stale handles or unsafe catalog state.
    pub async fn open_flow(
        &self,
        fence: CommandFence,
        definition: FlowDefinitionHandle,
    ) -> DesktopResult<FlowDocumentDto> {
        let _command = self.command_gate.lock().await;
        definition.validate()?;
        let active = self.begin(&fence).await?;
        let mut state = self.inner.lock().await;
        ensure_active_matches(&state, &active, &fence)?;
        let workspace = workspace_mut(&mut state, &active)?;
        let selector = workspace.definitions.get(&definition).ok_or_else(|| {
            DesktopErrorDto::stale("The flow definition handle is no longer current.")
        })?;
        let document = workspace
            .model
            .open_document(selector)
            .map_err(|error| flow_error(&error))?;
        let handle = FlowDocumentHandle::new();
        let data = FlowDocumentDataDto {
            handle: handle.clone(),
            identity: document.saved_identity().map(identity_dto),
            source: document.source().to_owned(),
        };
        workspace.documents.insert(handle, document);
        Ok(FlowDocumentDto { fence, data })
    }

    /// Validates, dry-runs, and diffs a retained flow document.
    ///
    /// # Errors
    ///
    /// Returns bounded stale, size, syntax, schema, or revision feedback.
    pub async fn validate_flow(
        &self,
        fence: CommandFence,
        document: FlowDocumentHandle,
        source: String,
    ) -> DesktopResult<FlowReviewDto> {
        let _command = self.command_gate.lock().await;
        document.validate()?;
        let active = self.begin(&fence).await?;
        let mut state = self.inner.lock().await;
        ensure_active_matches(&state, &active, &fence)?;
        let workspace = workspace_mut(&mut state, &active)?;
        let draft = workspace.documents.get_mut(&document).ok_or_else(|| {
            DesktopErrorDto::stale("The flow document handle is no longer current.")
        })?;
        draft
            .replace_source(source)
            .map_err(|error| flow_error(&error))?;
        let validation = draft.validate().map_err(|error| flow_error(&error))?;
        let dry_run = draft.dry_run().map_err(|error| flow_error(&error))?;
        let diff = draft.version_diff().map_err(|error| flow_error(&error))?;
        let data = FlowReviewDataDto {
            document,
            identity: identity_dto(validation.identity()),
            normalized_toml: validation.normalized_toml().to_owned(),
            dry_run: dry_run_dto(&dry_run),
            diff: diff_dto(&diff),
        };
        Ok(FlowReviewDto { fence, data })
    }

    /// Atomically saves a retained, validated flow document.
    ///
    /// # Errors
    ///
    /// Returns bounded stale, conflict, validation, publication, or I/O errors.
    pub async fn save_flow(
        &self,
        fence: CommandFence,
        document: FlowDocumentHandle,
        source: String,
    ) -> DesktopResult<FlowSaveDto> {
        let _command = self.command_gate.lock().await;
        document.validate()?;
        let active = self.begin(&fence).await?;
        let mut state = self.inner.lock().await;
        ensure_active_matches(&state, &active, &fence)?;
        let workspace = workspace_mut(&mut state, &active)?;
        let draft = workspace.documents.get_mut(&document).ok_or_else(|| {
            DesktopErrorDto::stale("The flow document handle is no longer current.")
        })?;
        draft
            .replace_source(source)
            .map_err(|error| flow_error(&error))?;
        let interaction = draft.prepare_save().map_err(|error| flow_error(&error))?;
        let saved = draft
            .commit_save(interaction)
            .map_err(|error| flow_error(&error))?;
        workspace
            .model
            .reload()
            .map_err(|error| post_save_reload_error(&error))?;
        let data = FlowSaveDataDto {
            document,
            identity: identity_dto(saved.identity()),
            created: saved.created(),
            durability_confirmed: saved.durability_confirmed(),
            cleanup_complete: saved.cleanup_complete(),
        };
        Ok(FlowSaveDto { fence, data })
    }

    async fn begin(&self, fence: &CommandFence) -> DesktopResult<ActiveProject> {
        fence.validate()?;
        let mut state = self.inner.lock().await;
        let active = state
            .active
            .as_ref()
            .ok_or_else(|| DesktopErrorDto::stale("No project is active."))?
            .clone();
        if active.catalog.handle != fence.project_handle || active.generation != fence.generation {
            return Err(DesktopErrorDto::stale(
                "The project or generation fence is stale.",
            ));
        }
        if state
            .used_operations
            .iter()
            .any(|operation| operation == &fence.operation_id)
        {
            return Err(DesktopErrorDto::new(
                DesktopErrorKind::Conflict,
                "This operation UUID was already used for the active generation.",
                Some("Create a new operation UUID and retry.".to_owned()),
            ));
        }
        state.used_operations.push_back(fence.operation_id.clone());
        while state.used_operations.len() > MAX_OPERATIONS {
            state.used_operations.pop_front();
        }
        Ok(active)
    }

    async fn finish_snapshot(
        &self,
        fence: CommandFence,
        active: ActiveProject,
        surfaces: SurfaceBundle,
    ) -> DesktopResult<SnapshotDto> {
        let mut state = self.inner.lock().await;
        ensure_active_matches(&state, &active, &fence)?;
        finish_snapshot_locked(&mut state, fence, active, surfaces)
    }
}

fn default_daemon_executable() -> PathBuf {
    // Single-binary product: the daemon is this same executable in
    // `pam daemon` mode.
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from(executable_name("pam")))
}

fn gui_registration_command(executable: &Path, root: &Path) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(executable);
    command
        .args(GUI_REGISTRATION_ARGS)
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    command
}

async fn run_gui_registration(executable: &Path, root: &Path) -> DesktopResult<()> {
    let mut command = gui_registration_command(executable, root);
    let status = tokio::time::timeout(GUI_REGISTRATION_TIMEOUT, command.status())
        .await
        .map_err(|_| {
            DesktopErrorDto::unavailable(
                "PAM GUI caller registration exceeded its 15 second deadline.",
                Some("Retry GUI caller registration.".to_owned()),
            )
        })?
        .map_err(|error| {
            DesktopErrorDto::unavailable(
                "PAM could not start its bundled caller-registration helper.",
                Some(error.to_string()),
            )
        })?;
    if !status.success() {
        return Err(DesktopErrorDto::unavailable(
            format!("PAM GUI caller registration failed with {status}."),
            Some("Retry registration or inspect the local PAM data store.".to_owned()),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn executable_name(stem: &str) -> String {
    format!("{stem}.exe")
}

#[cfg(not(windows))]
fn executable_name(stem: &str) -> String {
    stem.to_owned()
}

struct SurfaceBundle {
    health: HealthState,
    current: CurrentState,
    access: AccessConfigState,
}

async fn load_surfaces(project_id: ProjectId) -> SurfaceBundle {
    let caller = match caller_id(CallerKind::Gui) {
        Ok(caller) => caller,
        Err(error) => return unavailable_bundle(error.to_string(), None, None),
    };
    let credential = match load_credential(caller.clone()).await {
        Ok(credential) => credential,
        Err(detail) => return gui_registration_required_bundle(detail),
    };
    load_surfaces_with_credential(caller, credential, project_id).await
}

async fn load_surfaces_with_credential(
    caller: CallerId,
    credential: CallerCredential,
    project_id: ProjectId,
) -> SurfaceBundle {
    let (health, current, access) = load_project_surfaces(caller, credential, project_id).await;
    SurfaceBundle {
        health,
        current,
        access,
    }
}

async fn load_health_access(project_id: ProjectId) -> (HealthState, AccessConfigState) {
    let caller = match caller_id(CallerKind::Gui) {
        Ok(caller) => caller,
        Err(error) => {
            return unavailable_health_access(error.to_string(), None);
        }
    };
    let credential = match load_credential(caller.clone()).await {
        Ok(credential) => credential,
        Err(detail) => {
            return unavailable_health_access(detail, Some(GUI_REGISTRATION_RECOVERY.to_owned()));
        }
    };
    load_project_health_access(caller, credential, project_id).await
}

async fn approval_surfaces_with<F, Fut>(current: CurrentState, load: F) -> SurfaceBundle
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = (HealthState, AccessConfigState)>,
{
    let (health, access) = load().await;
    SurfaceBundle {
        health,
        current,
        access,
    }
}

fn unavailable_health_access(
    detail: String,
    recovery: Option<String>,
) -> (HealthState, AccessConfigState) {
    (
        HealthState::Degraded {
            detail: detail.clone(),
            recovery: recovery.clone(),
        },
        AccessConfigState::Unavailable {
            code: None,
            detail,
            recovery,
        },
    )
}

fn gui_registration_required_bundle(detail: String) -> SurfaceBundle {
    unavailable_bundle(
        detail,
        Some(GUI_REGISTRATION_RECOVERY.to_owned()),
        Some(CurrentUnavailableCode::GuiRegistrationRequired),
    )
}

fn unavailable_bundle(
    detail: String,
    recovery: Option<String>,
    current_code: Option<CurrentUnavailableCode>,
) -> SurfaceBundle {
    SurfaceBundle {
        health: HealthState::Degraded {
            detail: detail.clone(),
            recovery: recovery.clone(),
        },
        current: CurrentState::Degraded {
            code: current_code,
            detail: detail.clone(),
            recovery: recovery.clone(),
        },
        access: AccessConfigState::Unavailable {
            code: None,
            detail,
            recovery,
        },
    }
}

fn ensure_active_matches(
    state: &DesktopState,
    active: &ActiveProject,
    fence: &CommandFence,
) -> DesktopResult<()> {
    let Some(current) = state.active.as_ref() else {
        return Err(DesktopErrorDto::stale("No project is active."));
    };
    if current.catalog.handle != active.catalog.handle
        || current.catalog.handle != fence.project_handle
        || current.generation != active.generation
        || current.generation != fence.generation
    {
        return Err(DesktopErrorDto::stale(
            "The project changed while this operation was running.",
        ));
    }
    Ok(())
}

fn finish_snapshot_locked(
    state: &mut DesktopState,
    fence: CommandFence,
    mut active: ActiveProject,
    surfaces: SurfaceBundle,
) -> DesktopResult<SnapshotDto> {
    ensure_active_matches(state, &active, &fence)?;
    active.generation = GenerationId::new();
    state.active = Some(active.clone());
    state.used_operations.clear();
    state.approvals.clear();
    state.evidence.clear();
    state.flow_workspace = None;
    Ok(snapshot_from_surfaces(
        state,
        &active,
        fence.operation_id,
        surfaces,
    ))
}

fn snapshot_from_surfaces(
    state: &mut DesktopState,
    active: &ActiveProject,
    operation: OperationId,
    surfaces: SurfaceBundle,
) -> SnapshotDto {
    let project = project_dto(&active.catalog);
    let health = health_dto(surfaces.health);
    let current = current_dto(state, surfaces.current);
    let access = access_dto(surfaces.access);
    SnapshotDto {
        fence: CommandFence::new(
            active.catalog.handle.clone(),
            active.generation.clone(),
            operation,
        ),
        data: SnapshotDataDto {
            project,
            health,
            current,
            access,
            catalog_warning: state.catalog_warning.clone(),
        },
    }
}

fn project_dto(project: &CatalogProject) -> ProjectSummaryDto {
    ProjectSummaryDto {
        handle: project.handle.clone(),
        name: bounded_name(&project.name, &project.root),
        location: bounded_path(&project.root),
    }
}

fn health_dto(state: HealthState) -> HealthDto {
    match state {
        HealthState::Healthy {
            daemon_version,
            queue_depth,
        } => HealthDto::Healthy {
            daemon_version: bounded_detail(daemon_version),
            queue_depth,
        },
        HealthState::Offline => HealthDto::Offline,
        HealthState::Degraded { detail, recovery } => HealthDto::Degraded {
            detail: bounded_detail(detail),
            recovery: recovery.map(bounded_detail),
        },
    }
}

fn current_dto(state: &mut DesktopState, current: CurrentState) -> CurrentDto {
    match current {
        CurrentState::Available(view) => current_available_dto(state, view),
        CurrentState::ApprovalRequired(pending) => {
            let expires_at_ms = pending.challenge.expires_at_unix_ms;
            let handle = ApprovalHandle::new();
            state.approvals.insert(handle.clone(), pending);
            CurrentDto::ApprovalRequired {
                approval: handle,
                expires_at_ms,
            }
        }
        CurrentState::Blocked {
            code,
            detail,
            recovery,
        } => CurrentDto::Blocked {
            failure: failure_dto(&code, detail, recovery),
        },
        CurrentState::Degraded {
            code,
            detail,
            recovery,
        } => CurrentDto::Unavailable {
            failure: unavailable_failure(
                code.map(|code| code.as_str().to_owned()),
                detail,
                recovery,
            ),
        },
    }
}

fn current_available_dto(state: &mut DesktopState, view: CurrentView) -> CurrentDto {
    CurrentDto::Available {
        queued: view.queued.iter().map(request_dto).collect(),
        truncated: view.truncated,
        run: view.run.map(|run| run_dto(state, run)),
    }
}

fn request_dto(request: &ProjectRequestSummary) -> RequestSummaryDto {
    RequestSummaryDto {
        request_id: bounded_detail(request.request_id.as_str().to_owned()),
        operation_kind: bounded_detail(request.operation_kind().to_owned()),
        state: request_state_label(request.state).to_owned(),
        queue_sequence: request.queue_sequence,
        accepted_at_ms: request.accepted_at_ms,
        completed_at_ms: request.completed_at_ms,
    }
}

fn run_dto(state: &mut DesktopState, run: RunView) -> RunDto {
    RunDto {
        request: request_dto(&run.request),
        timeline: run
            .timeline
            .into_iter()
            .take(MAX_TIMELINE_FACTS)
            .map(|fact| timeline_dto(state, fact))
            .collect(),
        outcome: run.outcome.map(|outcome| outcome_dto(state, outcome)),
        detail_error: run.detail_error.map(bounded_detail),
    }
}

const fn request_state_label(state: ProjectRequestState) -> &'static str {
    match state {
        ProjectRequestState::Queued => "queued",
        ProjectRequestState::Leased => "leased",
        ProjectRequestState::CancellationRequested => "cancellation_requested",
        ProjectRequestState::Succeeded => "succeeded",
        ProjectRequestState::Failed => "failed",
        ProjectRequestState::Cancelled => "cancelled",
    }
}

fn timeline_dto(state: &mut DesktopState, fact: TimelineFact) -> TimelineFactDto {
    TimelineFactDto {
        kind: timeline_kind_dto(fact.kind),
        label: bounded_detail(fact.label),
        summary: bounded_detail(fact.summary),
        verified: fact.verified,
        evidence: fact
            .evidence
            .into_iter()
            .take(MAX_EVIDENCE_HANDLES)
            .map(|handle| register_evidence(state, handle))
            .collect(),
    }
}

const fn timeline_kind_dto(kind: TimelineKind) -> TimelineKindDto {
    match kind {
        TimelineKind::Request => TimelineKindDto::Request,
        TimelineKind::Evidence => TimelineKindDto::Evidence,
        TimelineKind::Change => TimelineKindDto::Change,
        TimelineKind::Verification => TimelineKindDto::Verification,
        TimelineKind::Failure => TimelineKindDto::Failure,
    }
}

fn outcome_dto(state: &mut DesktopState, outcome: OutcomeView) -> OutcomeDto {
    OutcomeDto {
        heading: outcome.heading.to_owned(),
        solved: outcome.solved,
        sections: outcome
            .sections
            .into_iter()
            .map(|section| OutcomeSectionDto {
                label: section.label.to_owned(),
                summary: bounded_detail(section.summary),
                satisfied: section.satisfied,
            })
            .collect(),
        evidence: outcome
            .evidence
            .into_iter()
            .take(MAX_EVIDENCE_HANDLES)
            .map(|handle| register_evidence(state, handle))
            .collect(),
        evidence_truncated: outcome.evidence_truncated,
    }
}

fn register_evidence(
    state: &mut DesktopState,
    protocol: ProtocolEvidenceHandle,
) -> EvidenceHandleDto {
    if let Some((handle, _)) = state
        .evidence
        .iter()
        .find(|(_, candidate)| candidate == &&protocol)
    {
        return handle.clone();
    }
    let handle = EvidenceHandleDto::new();
    state.evidence.insert(handle.clone(), protocol);
    handle
}

fn access_dto(state: AccessConfigState) -> AccessConfigDto {
    match state {
        AccessConfigState::Available(view) => available_access_dto(&view),
        AccessConfigState::Blocked {
            code,
            detail,
            recovery,
            approval_id,
            expires_at_ms,
        } => AccessConfigDto::Blocked {
            failure: failure_dto(&code, detail, recovery),
            approval_id: approval_id.map(bounded_detail),
            expires_at_ms,
        },
        AccessConfigState::Unavailable {
            code,
            detail,
            recovery,
        } => AccessConfigDto::Unavailable {
            failure: match code {
                Some(code) => failure_dto(&code, detail, recovery),
                None => unavailable_failure(None, detail, recovery),
            },
        },
    }
}

fn available_access_dto(view: &AccessConfigView) -> AccessConfigDto {
    AccessConfigDto::Available {
        truth: format!("{:?}", view.truth).to_ascii_lowercase(),
        platform_roots_enabled: view.platform_roots_enabled,
        system_proxy_discovery_enabled: view.system_proxy_discovery_enabled,
        proxy_environment: view.proxy_environment.to_owned(),
        no_proxy: view.no_proxy.to_owned(),
        pac: view.pac.to_owned(),
    }
}

async fn observatory_credential<T>() -> Result<(CallerId, CallerCredential), ObservatoryState<T>> {
    let caller = caller_id(CallerKind::Gui).map_err(|error| ObservatoryState::Unavailable {
        code: None,
        detail: error.to_string(),
        recovery: None,
    })?;
    let credential =
        load_credential(caller.clone())
            .await
            .map_err(|detail| ObservatoryState::Unavailable {
                code: Some(
                    CurrentUnavailableCode::GuiRegistrationRequired
                        .as_str()
                        .to_owned(),
                ),
                detail,
                recovery: Some(GUI_REGISTRATION_RECOVERY.to_owned()),
            })?;
    Ok((caller, credential))
}

fn activity_dto(state: ObservatoryState<ActivityResult>) -> ActivityDto {
    match state {
        ObservatoryState::Available(result) => ActivityDto::Ok {
            events: result.events.into_iter().map(activity_event_dto).collect(),
            truncated: result.truncated,
        },
        ObservatoryState::Blocked {
            code,
            detail,
            recovery,
        } => ActivityDto::Blocked {
            failure: failure_dto(&code, detail, recovery),
        },
        ObservatoryState::Unavailable {
            code,
            detail,
            recovery,
        } => ActivityDto::Unavailable {
            failure: unavailable_failure(code, detail, recovery),
        },
    }
}

fn activity_event_dto(event: ActivityEventSummary) -> ActivityEventDto {
    ActivityEventDto {
        sequence: event.sequence,
        project_id: bounded_detail(event.project_id.as_str().to_owned()),
        caller_id: bounded_detail(event.caller_id.as_str().to_owned()),
        action: bounded_detail(event.action),
        decision: bounded_detail(event.decision),
        outcome: bounded_detail(event.outcome),
        occurred_at_ms: event.occurred_at_ms,
    }
}

fn callers_dto(state: ObservatoryState<CallerListResult>) -> CallersDto {
    match state {
        ObservatoryState::Available(result) => CallersDto::Ok {
            callers: result.callers.iter().map(caller_dto).collect(),
        },
        ObservatoryState::Blocked {
            code,
            detail,
            recovery,
        } => CallersDto::Blocked {
            failure: failure_dto(&code, detail, recovery),
        },
        ObservatoryState::Unavailable {
            code,
            detail,
            recovery,
        } => CallersDto::Unavailable {
            failure: unavailable_failure(code, detail, recovery),
        },
    }
}

fn caller_dto(caller: &CallerSummary) -> CallerDto {
    CallerDto {
        caller_id: bounded_detail(caller.caller_id.as_str().to_owned()),
        registered_at_ms: caller.registered_at_ms,
        revoked_at_ms: caller.revoked_at_ms,
    }
}

fn failure_dto(code: &FailureCode, detail: String, recovery: Option<String>) -> FailureDto {
    FailureDto {
        kind: failure_kind(code),
        code: Some(failure_code(code).to_owned()),
        detail: bounded_detail(detail),
        recovery: recovery.map(bounded_detail),
    }
}

fn unavailable_failure(
    code: Option<String>,
    detail: impl Into<String>,
    recovery: Option<String>,
) -> FailureDto {
    FailureDto {
        kind: FailureKindDto::Unavailable,
        code,
        detail: bounded_detail(detail.into()),
        recovery: recovery.map(bounded_detail),
    }
}

const fn failure_kind(code: &FailureCode) -> FailureKindDto {
    match code {
        FailureCode::Forbidden | FailureCode::ApprovalRequired => FailureKindDto::Blocked,
        _ => FailureKindDto::Unavailable,
    }
}

const fn failure_code(code: &FailureCode) -> &'static str {
    match code {
        FailureCode::Unauthenticated => "unauthenticated",
        FailureCode::Forbidden => "forbidden",
        FailureCode::ApprovalRequired => "approval_required",
        FailureCode::ApprovalDenied => "approval_denied",
        FailureCode::ApprovalExpired => "approval_expired",
        FailureCode::UnsupportedProtocolVersion => "unsupported_protocol_version",
        FailureCode::InvalidRequest => "invalid_request",
        FailureCode::FrameTooLarge => "frame_too_large",
        FailureCode::NotFound => "not_found",
        FailureCode::Pending => "pending",
        FailureCode::IdempotencyConflict => "idempotency_conflict",
        FailureCode::Cancelled => "cancelled",
        FailureCode::LeaseConflict => "lease_conflict",
        FailureCode::Busy => "busy",
        FailureCode::Internal => "internal",
    }
}

fn evidence_data(
    handle: EvidenceHandleDto,
    state: EvidenceState,
) -> DesktopResult<EvidenceDataDto> {
    match state {
        EvidenceState::Available(preview) => Ok(evidence_preview_dto(handle, preview)),
        EvidenceState::Failed { detail, .. } => Err(DesktopErrorDto::unavailable(detail, None)),
    }
}

fn evidence_preview_dto(handle: EvidenceHandleDto, preview: EvidencePreview) -> EvidenceDataDto {
    EvidenceDataDto {
        handle,
        digest: bounded_detail(preview.digest),
        size_bytes: preview.size_bytes,
        media_type: bounded_detail(preview.media_type),
        body: preview.body.map(bounded_detail),
        truncated: preview.truncated,
        truth: format!("{:?}", preview.truth).to_ascii_lowercase(),
    }
}

fn workspace_mut<'a>(
    state: &'a mut DesktopState,
    active: &ActiveProject,
) -> DesktopResult<&'a mut FlowWorkspaceState> {
    let workspace = state.flow_workspace.as_mut().ok_or_else(|| {
        DesktopErrorDto::stale("Load the flow workspace before using a flow handle.")
    })?;
    if workspace.project != active.catalog.handle || workspace.generation != active.generation {
        return Err(DesktopErrorDto::stale(
            "The flow workspace belongs to a stale project generation.",
        ));
    }
    Ok(workspace)
}

fn identity_dto(identity: &FlowIdentity) -> FlowIdentityDto {
    FlowIdentityDto {
        file_name: identity.file_name().to_owned(),
        id: identity.id().to_owned(),
        revision: identity.revision(),
        digest: identity.digest().to_string(),
    }
}

fn dry_run_dto(plan: &FlowDryRunPlan) -> FlowDryRunDto {
    FlowDryRunDto {
        daemon_definition_eligible: plan.daemon_definition_eligible(),
        steps: plan
            .steps()
            .iter()
            .map(|step| {
                let retry = step.retry();
                FlowDryRunStepDto {
                    index: step.index(),
                    id: step.id().to_owned(),
                    semantic_role: semantic_role_label(step.semantic_role()).to_owned(),
                    condition: condition_label(step.condition()),
                    approval: approval_label(step.approval()).to_owned(),
                    effect: effect_label(step.effect()).to_owned(),
                    max_attempts: retry.max_attempts(),
                    initial_backoff_ms: retry.initial_backoff_ms(),
                    max_backoff_ms: retry.max_backoff_ms(),
                    action: action_label(step.action()),
                    daemon_authority: daemon_authority_label(step.daemon_authority()),
                }
            })
            .collect(),
    }
}

fn condition_label(condition: &DryRunCondition) -> String {
    match condition {
        DryRunCondition::Always => "always".to_owned(),
        DryRunCondition::Succeeded { step_id } => format!("succeeded:{step_id}"),
        DryRunCondition::Failed { step_id } => format!("failed:{step_id}"),
    }
}

const fn semantic_role_label(role: pam_flow::StepSemanticRole) -> &'static str {
    match role {
        pam_flow::StepSemanticRole::Observe => "observe",
        pam_flow::StepSemanticRole::Verify => "verify",
        pam_flow::StepSemanticRole::Change => "change",
    }
}

const fn approval_label(approval: pam_flow::ApprovalMode) -> &'static str {
    match approval {
        pam_flow::ApprovalMode::None => "none",
        pam_flow::ApprovalMode::Required => "required",
    }
}

const fn effect_label(effect: pam_flow::EffectKind) -> &'static str {
    match effect {
        pam_flow::EffectKind::ReadOnly => "read_only",
        pam_flow::EffectKind::Stateful => "stateful",
    }
}

fn action_label(action: &ActionAuthority) -> String {
    match action {
        ActionAuthority::Command {
            program,
            arguments,
            working_directory,
        } => bounded_detail(format!(
            "command:{program} {} @ {working_directory}",
            arguments.join(" ")
        )),
        ActionAuthority::Connector {
            connector,
            capability,
            resource_kind,
            resource_id,
        } => bounded_detail(format!(
            "connector:{connector}.{capability} {resource_kind}:{resource_id}"
        )),
    }
}

fn daemon_authority_label(authority: DaemonAuthority) -> String {
    match authority {
        DaemonAuthority::EligibleAfterRuntimeChecks => "eligible_after_runtime_checks".to_owned(),
        DaemonAuthority::Unsupported(reason) => format!(
            "unsupported:{}",
            match reason {
                crate::flow_editor::UnsupportedDaemonAuthority::Connector => "connector",
                crate::flow_editor::UnsupportedDaemonAuthority::StatefulEffect => {
                    "stateful_effect"
                }
                crate::flow_editor::UnsupportedDaemonAuthority::Approval => "approval",
                crate::flow_editor::UnsupportedDaemonAuthority::Program => "program",
                crate::flow_editor::UnsupportedDaemonAuthority::WorkingDirectory => {
                    "working_directory"
                }
                crate::flow_editor::UnsupportedDaemonAuthority::GitArguments => "git_arguments",
                crate::flow_editor::UnsupportedDaemonAuthority::SemanticRole => "semantic_role",
            }
        ),
    }
}

fn diff_dto(diff: &FlowVersionDiff) -> FlowVersionDiffDto {
    FlowVersionDiffDto {
        changed: diff.changed(),
        truncated: diff.truncated(),
        lines: diff
            .lines()
            .iter()
            .map(|line| FlowVersionDiffLineDto {
                kind: match line.kind() {
                    FlowVersionDiffLineKind::Context => "context",
                    FlowVersionDiffLineKind::Removed => "removed",
                    FlowVersionDiffLineKind::Added => "added",
                }
                .to_owned(),
                text: line.text().to_owned(),
            })
            .collect(),
    }
}

fn flow_error(error: &FlowEditorError) -> DesktopErrorDto {
    let kind = match error {
        FlowEditorError::NotFound(_) => DesktopErrorKind::NotFound,
        FlowEditorError::StaleSaveInteraction | FlowEditorError::SaveConflict => {
            DesktopErrorKind::Conflict
        }
        FlowEditorError::InvalidSelector
        | FlowEditorError::DocumentTooLarge { .. }
        | FlowEditorError::NormalizedDocumentTooLarge { .. }
        | FlowEditorError::InvalidToml(_)
        | FlowEditorError::InvalidDefinition { .. }
        | FlowEditorError::IdentityChanged { .. }
        | FlowEditorError::RevisionNotAdvanced { .. } => DesktopErrorKind::InvalidInput,
        _ => DesktopErrorKind::Unavailable,
    };
    DesktopErrorDto::new(kind, error.to_string(), None)
}

fn post_save_reload_error(error: &FlowEditorError) -> DesktopErrorDto {
    DesktopErrorDto::new(
        DesktopErrorKind::Unavailable,
        format!("The flow was saved, but PAM could not refresh the flow workspace: {error}"),
        Some("Reload the flow workspace before opening or saving another definition.".to_owned()),
    )
}

fn bounded_detail(value: String) -> String {
    bounded_utf8(value, MAX_DETAILS_BYTES)
}

fn bounded_path(path: &Path) -> String {
    bounded_utf8(path.to_string_lossy().into_owned(), MAX_PROJECT_PATH_BYTES)
}

fn bounded_utf8(mut value: String, maximum: usize) -> String {
    if value.len() <= maximum {
        return value;
    }
    let mut end = maximum.saturating_sub(3);
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value.truncate(end);
    value.push_str("...");
    value
}

fn reap_daemon_child(state: &mut DesktopState) {
    let exited = state
        .daemon_child
        .as_mut()
        .is_some_and(|child| child.try_wait().ok().flatten().is_some());
    if exited {
        state.daemon_child = None;
    }
}

#[cfg(test)]
pub(crate) fn failure_kind_for_test(code: &FailureCode) -> FailureKindDto {
    failure_kind(code)
}

#[cfg(test)]
pub(crate) fn bounded_detail_for_test(value: String) -> String {
    bounded_detail(value)
}

#[cfg(test)]
pub(crate) fn post_save_reload_error_for_test(error: &FlowEditorError) -> DesktopErrorDto {
    post_save_reload_error(error)
}

#[cfg(test)]
pub(crate) fn current_dto_for_test(current: CurrentState) -> CurrentDto {
    let mut state = test_state();
    current_dto(&mut state, current)
}

#[cfg(test)]
pub(crate) fn access_dto_for_test(access: AccessConfigState) -> AccessConfigDto {
    access_dto(access)
}

#[cfg(test)]
pub(crate) fn activity_dto_for_test(state: ObservatoryState<ActivityResult>) -> ActivityDto {
    activity_dto(state)
}

#[cfg(test)]
pub(crate) fn callers_dto_for_test(state: ObservatoryState<CallerListResult>) -> CallersDto {
    callers_dto(state)
}

#[cfg(test)]
pub(crate) fn evidence_dto_for_test(
    handle: EvidenceHandleDto,
    preview: EvidencePreview,
) -> EvidenceDataDto {
    evidence_preview_dto(handle, preview)
}

#[cfg(test)]
pub(crate) async fn approval_current_for_test(
    current: CurrentState,
    calls: &std::sync::atomic::AtomicUsize,
) -> CurrentState {
    approval_surfaces_with(current, || async {
        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        (
            HealthState::Offline,
            AccessConfigState::Unavailable {
                code: None,
                detail: "test access".to_owned(),
                recovery: None,
            },
        )
    })
    .await
    .current
}

#[cfg(test)]
pub(crate) fn gui_registration_current_for_test(detail: String) -> CurrentDto {
    let mut state = test_state();
    current_dto(&mut state, gui_registration_required_bundle(detail).current)
}

#[cfg(test)]
pub(crate) async fn approval_failure_retains_handle_for_test(
    core: &DesktopCore,
    fence: CommandFence,
    approval: ApprovalHandle,
    pending: PendingApproval,
) -> (DesktopErrorDto, bool, bool) {
    let retry_fence = CommandFence::new(
        fence.project_handle.clone(),
        fence.generation.clone(),
        OperationId::new(),
    );
    core.inner
        .lock()
        .await
        .approvals
        .insert(approval.clone(), pending);
    let error = core
        .decide_approval_with(
            fence,
            approval.clone(),
            ApprovalDecisionDto::Approve,
            |_, _| async {
                Err::<ApprovalDecisionView, _>(ApprovalDecisionFailure {
                    detail: "The approval response was not observed.".to_owned(),
                    recovery: Some("Retry the exact decision.".to_owned()),
                })
            },
        )
        .await
        .expect_err("the injected transport failure must be returned");
    let retained = core.inner.lock().await.approvals.contains_key(&approval);
    let retry_authorized = core.begin(&retry_fence).await.is_ok()
        && core.inner.lock().await.approvals.contains_key(&approval);
    (error, retained, retry_authorized)
}

#[cfg(test)]
pub(crate) fn registration_contract_for_test(
    executable: &Path,
    root: &Path,
) -> (
    PathBuf,
    Vec<std::ffi::OsString>,
    Option<PathBuf>,
    bool,
    Duration,
) {
    let command = gui_registration_command(executable, root);
    (
        command.as_std().get_program().into(),
        command.as_std().get_args().map(Into::into).collect(),
        command.as_std().get_current_dir().map(PathBuf::from),
        command.get_kill_on_drop(),
        GUI_REGISTRATION_TIMEOUT,
    )
}

#[cfg(test)]
pub(crate) fn active_core_for_test(
    project: &ProjectHandle,
    generation: GenerationId,
) -> DesktopCore {
    active_core_at_for_test(project, generation, Path::new("/bounded/test/project"))
}

#[cfg(test)]
pub(crate) fn active_core_at_for_test(
    project: &ProjectHandle,
    generation: GenerationId,
    root: &Path,
) -> DesktopCore {
    let catalog = CatalogProject {
        handle: project.clone(),
        name: "project".to_owned(),
        root: root.to_path_buf(),
    };
    let mut state = test_state();
    state.catalog.insert(project.clone(), catalog.clone());
    state.active = Some(ActiveProject {
        catalog,
        project_id: ProjectId::new("internal-project-authority"),
        generation,
    });
    DesktopCore {
        inner: Arc::new(Mutex::new(state)),
        command_gate: Arc::new(Mutex::new(())),
    }
}

#[cfg(test)]
pub(crate) async fn manage_skill_library_without_io_for_test(
    core: &DesktopCore,
    request: SkillLibraryRequest,
    switch_after_work: Option<(ProjectHandle, GenerationId)>,
) -> DesktopResult<SkillLibraryDto> {
    let inner = Arc::clone(&core.inner);
    core.manage_skill_library_with(request, move |_, _| async move {
        if let Some((project, generation)) = switch_after_work {
            let mut state = inner.lock().await;
            let catalog = CatalogProject {
                handle: project,
                name: "other".to_owned(),
                root: PathBuf::from("/bounded/test/other"),
            };
            state.active = Some(ActiveProject {
                catalog,
                project_id: ProjectId::new("other-internal-authority"),
                generation,
            });
            state.used_operations.clear();
        }
        Ok(crate::skill_library::empty_load_for_test())
    })
    .await
}

#[cfg(test)]
pub(crate) async fn reserve_for_test(
    core: &DesktopCore,
    fence: &CommandFence,
) -> DesktopResult<()> {
    core.begin(fence).await.map(drop)
}

#[cfg(test)]
pub(crate) async fn switch_authority_for_test(
    core: &DesktopCore,
    project: ProjectHandle,
    generation: GenerationId,
) {
    let mut state = core.inner.lock().await;
    let catalog = CatalogProject {
        handle: project,
        name: "other".to_owned(),
        root: PathBuf::from("/bounded/test/other"),
    };
    state.active = Some(ActiveProject {
        catalog,
        project_id: ProjectId::new("other-internal-authority"),
        generation,
    });
    state.used_operations.clear();
}

#[cfg(test)]
fn test_state() -> DesktopState {
    DesktopState {
        startup_root: PathBuf::from("/bounded/test"),
        daemon_executable: PathBuf::from("pam"),
        catalog: HashMap::new(),
        active: None,
        activation_operation: None,
        used_operations: VecDeque::new(),
        approvals: HashMap::new(),
        evidence: HashMap::new(),
        flow_workspace: None,
        daemon_child: None,
        catalog_warning: None,
    }
}
