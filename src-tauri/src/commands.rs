use std::sync::Arc;

use pam_gui::{
    ApprovalDecisionDto, ApprovalDecisionResponseDto, ApprovalHandle, CatalogDto, CommandFence,
    DesktopCore, DesktopErrorDto, EvidenceDto, EvidenceHandleDto, FlowDefinitionHandle,
    FlowDocumentDto, FlowDocumentHandle, FlowReviewDto, FlowSaveDto, FlowWorkspaceDto,
    GenerationId, OperationId, ProjectHandle, SkillAuditDto, SkillInventoryDto, SkillLibraryDto,
    SkillLibraryRequest, SnapshotDto,
};
use serde::{Deserialize, Deserializer, de::Error as _};
use tauri::State;

trait CanonicalHandle: Sized {
    fn parse(value: String) -> Result<Self, DesktopErrorDto>;
}

macro_rules! canonical_handle {
    ($($handle:ty),+ $(,)?) => {
        $(
            impl CanonicalHandle for $handle {
                fn parse(value: String) -> Result<Self, DesktopErrorDto> {
                    <$handle>::parse(value)
                }
            }
        )+
    };
}

canonical_handle!(
    ProjectHandle,
    GenerationId,
    OperationId,
    ApprovalHandle,
    EvidenceHandleDto,
    FlowDefinitionHandle,
    FlowDocumentHandle,
);

fn canonical_uuid<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: CanonicalHandle,
{
    T::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
}

pub(crate) struct DesktopState {
    core: Arc<DesktopCore>,
}

impl DesktopState {
    pub(crate) fn new(core: DesktopCore) -> Self {
        Self {
            core: Arc::new(core),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ActivateProjectRequest {
    #[serde(deserialize_with = "canonical_uuid")]
    project_handle: ProjectHandle,
    #[serde(deserialize_with = "canonical_uuid")]
    operation_id: OperationId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BootstrapRequest {
    #[serde(deserialize_with = "canonical_uuid")]
    operation_id: OperationId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FencedRequest {
    #[serde(deserialize_with = "canonical_uuid")]
    project_handle: ProjectHandle,
    #[serde(deserialize_with = "canonical_uuid")]
    generation: GenerationId,
    #[serde(deserialize_with = "canonical_uuid")]
    operation_id: OperationId,
}

impl FencedRequest {
    fn into_fence(self) -> CommandFence {
        CommandFence::new(self.project_handle, self.generation, self.operation_id)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ApprovalRequest {
    #[serde(deserialize_with = "canonical_uuid")]
    project_handle: ProjectHandle,
    #[serde(deserialize_with = "canonical_uuid")]
    generation: GenerationId,
    #[serde(deserialize_with = "canonical_uuid")]
    operation_id: OperationId,
    #[serde(deserialize_with = "canonical_uuid")]
    approval_handle: ApprovalHandle,
    decision: ApprovalDecisionDto,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EvidenceRequest {
    #[serde(deserialize_with = "canonical_uuid")]
    project_handle: ProjectHandle,
    #[serde(deserialize_with = "canonical_uuid")]
    generation: GenerationId,
    #[serde(deserialize_with = "canonical_uuid")]
    operation_id: OperationId,
    #[serde(deserialize_with = "canonical_uuid")]
    evidence_handle: EvidenceHandleDto,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OpenFlowRequest {
    #[serde(deserialize_with = "canonical_uuid")]
    project_handle: ProjectHandle,
    #[serde(deserialize_with = "canonical_uuid")]
    generation: GenerationId,
    #[serde(deserialize_with = "canonical_uuid")]
    operation_id: OperationId,
    #[serde(deserialize_with = "canonical_uuid")]
    flow_handle: FlowDefinitionHandle,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReviewFlowRequest {
    #[serde(deserialize_with = "canonical_uuid")]
    project_handle: ProjectHandle,
    #[serde(deserialize_with = "canonical_uuid")]
    generation: GenerationId,
    #[serde(deserialize_with = "canonical_uuid")]
    operation_id: OperationId,
    #[serde(deserialize_with = "canonical_uuid")]
    document_handle: FlowDocumentHandle,
    source: String,
}

fn fence(
    project_handle: ProjectHandle,
    generation: GenerationId,
    operation_id: OperationId,
) -> CommandFence {
    CommandFence::new(project_handle, generation, operation_id)
}

#[tauri::command]
pub(crate) async fn bootstrap(
    state: State<'_, DesktopState>,
    request: BootstrapRequest,
) -> Result<SnapshotDto, DesktopErrorDto> {
    state.core.bootstrap(request.operation_id).await
}

#[tauri::command]
pub(crate) async fn catalog(state: State<'_, DesktopState>) -> Result<CatalogDto, DesktopErrorDto> {
    Ok(state.core.catalog().await)
}

#[tauri::command]
pub(crate) async fn activate_project(
    state: State<'_, DesktopState>,
    request: ActivateProjectRequest,
) -> Result<SnapshotDto, DesktopErrorDto> {
    state
        .core
        .activate(request.project_handle, request.operation_id)
        .await
}

#[tauri::command]
pub(crate) async fn refresh_project(
    state: State<'_, DesktopState>,
    request: FencedRequest,
) -> Result<SnapshotDto, DesktopErrorDto> {
    state.core.refresh(request.into_fence()).await
}

#[tauri::command]
pub(crate) async fn start_daemon(
    state: State<'_, DesktopState>,
    request: FencedRequest,
) -> Result<SnapshotDto, DesktopErrorDto> {
    state.core.start_daemon(request.into_fence()).await
}

#[tauri::command]
pub(crate) async fn stop_daemon(
    state: State<'_, DesktopState>,
    request: FencedRequest,
) -> Result<SnapshotDto, DesktopErrorDto> {
    state.core.stop_daemon(request.into_fence()).await
}

#[tauri::command]
pub(crate) async fn register_gui_caller(
    state: State<'_, DesktopState>,
    request: FencedRequest,
) -> Result<SnapshotDto, DesktopErrorDto> {
    state.core.register_gui_caller(request.into_fence()).await
}

#[tauri::command]
pub(crate) async fn decide_approval(
    state: State<'_, DesktopState>,
    request: ApprovalRequest,
) -> Result<ApprovalDecisionResponseDto, DesktopErrorDto> {
    state
        .core
        .decide_approval(
            fence(
                request.project_handle,
                request.generation,
                request.operation_id,
            ),
            request.approval_handle,
            request.decision,
        )
        .await
}

#[tauri::command]
pub(crate) async fn load_evidence(
    state: State<'_, DesktopState>,
    request: EvidenceRequest,
) -> Result<EvidenceDto, DesktopErrorDto> {
    state
        .core
        .load_evidence(
            fence(
                request.project_handle,
                request.generation,
                request.operation_id,
            ),
            request.evidence_handle,
        )
        .await
}

#[tauri::command]
pub(crate) async fn load_flow_workspace(
    state: State<'_, DesktopState>,
    request: FencedRequest,
) -> Result<FlowWorkspaceDto, DesktopErrorDto> {
    state.core.flow_workspace(request.into_fence()).await
}

#[tauri::command]
pub(crate) async fn load_skill_inventory(
    state: State<'_, DesktopState>,
    request: FencedRequest,
) -> Result<SkillInventoryDto, DesktopErrorDto> {
    state.core.skill_inventory(request.into_fence()).await
}

#[tauri::command]
pub(crate) async fn manage_skill_library(
    state: State<'_, DesktopState>,
    request: SkillLibraryRequest,
) -> Result<SkillLibraryDto, DesktopErrorDto> {
    state.core.manage_skill_library(request).await
}

#[tauri::command]
pub(crate) async fn load_skill_audit(
    state: State<'_, DesktopState>,
    request: FencedRequest,
) -> Result<SkillAuditDto, DesktopErrorDto> {
    state.core.load_skill_audit(request.into_fence()).await
}

#[tauri::command]
pub(crate) async fn run_skill_audit(
    state: State<'_, DesktopState>,
    request: FencedRequest,
) -> Result<SkillAuditDto, DesktopErrorDto> {
    state.core.run_skill_audit(request.into_fence()).await
}

#[tauri::command]
pub(crate) async fn open_flow(
    state: State<'_, DesktopState>,
    request: OpenFlowRequest,
) -> Result<FlowDocumentDto, DesktopErrorDto> {
    state
        .core
        .open_flow(
            fence(
                request.project_handle,
                request.generation,
                request.operation_id,
            ),
            request.flow_handle,
        )
        .await
}

#[tauri::command]
pub(crate) async fn validate_flow(
    state: State<'_, DesktopState>,
    request: ReviewFlowRequest,
) -> Result<FlowReviewDto, DesktopErrorDto> {
    state
        .core
        .validate_flow(
            fence(
                request.project_handle,
                request.generation,
                request.operation_id,
            ),
            request.document_handle,
            request.source,
        )
        .await
}

#[tauri::command]
pub(crate) async fn save_flow(
    state: State<'_, DesktopState>,
    request: ReviewFlowRequest,
) -> Result<FlowSaveDto, DesktopErrorDto> {
    state
        .core
        .save_flow(
            fence(
                request.project_handle,
                request.generation,
                request.operation_id,
            ),
            request.document_handle,
            request.source,
        )
        .await
}
