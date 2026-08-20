#![forbid(unsafe_code)]

mod access_config;
mod control_center;
mod current;
mod desktop;
mod flow_editor;

#[cfg(test)]
mod access_config_test;
#[cfg(test)]
mod control_center_test;
#[cfg(test)]
mod current_test;
#[cfg(test)]
mod desktop_test;
#[cfg(test)]
mod flow_editor_test;

pub use desktop::{
    AccessConfigDto, ApprovalDecisionDispositionDto, ApprovalDecisionDto,
    ApprovalDecisionResponseDto, ApprovalHandle, CatalogDto, CommandFence, CurrentDto, DesktopCore,
    DesktopErrorDto, DesktopErrorKind, DesktopResult, EvidenceDataDto, EvidenceDto,
    EvidenceHandleDto, FailureDto, FailureKindDto, FlowDefinitionDto, FlowDefinitionHandle,
    FlowDocumentDataDto, FlowDocumentDto, FlowDocumentHandle, FlowDryRunDto, FlowDryRunStepDto,
    FlowIdentityDto, FlowReviewDataDto, FlowReviewDto, FlowSaveDataDto, FlowSaveDto,
    FlowVersionDiffDto, FlowVersionDiffLineDto, FlowWorkspaceDataDto, FlowWorkspaceDto,
    GenerationId, HealthDto, OperationId, OutcomeDto, OutcomeSectionDto, ProjectHandle,
    ProjectSummaryDto, RequestSummaryDto, RunDto, SnapshotDataDto, SnapshotDto, SnapshotFence,
    TimelineFactDto, TimelineKindDto,
};

pub use flow_editor::{
    ActionAuthority, DaemonAuthority, DryRunCondition, DryRunStep, FlowCatalogEntry,
    FlowDryRunPlan, FlowEditorDocument, FlowEditorError, FlowEditorModel, FlowEditorValidation,
    FlowIdentity, FlowSaveInteraction, FlowSaveResult, FlowVersionDiff, FlowVersionDiffLine,
    FlowVersionDiffLineKind, MAX_FLOW_CATALOG_BYTES, MAX_FLOW_CATALOG_ENTRIES,
    MAX_VERSION_DIFF_LINES, UnsupportedDaemonAuthority,
};
