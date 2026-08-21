#![forbid(unsafe_code)]

mod audit;
mod claude;
mod codex;
mod codex_trust;
mod cursor;
mod evaluator;
mod install;
mod library;
mod local;
mod materialize;
mod model;
mod report;
mod scan;
mod verdict;

#[cfg(test)]
mod audit_test;
#[cfg(test)]
mod claude_test;
#[cfg(test)]
mod codex_test;
#[cfg(test)]
mod codex_trust_test;
#[cfg(test)]
mod cursor_test;
#[cfg(test)]
mod evaluator_test;
#[cfg(test)]
mod fixture_test;
#[cfg(test)]
mod install_test;
#[cfg(test)]
mod library_test;
#[cfg(test)]
mod local_test;
#[cfg(test)]
mod materialize_test;
#[cfg(test)]
mod model_test;
#[cfg(test)]
mod report_test;
#[cfg(test)]
mod scan_test;
#[cfg(test)]
mod verdict_test;

pub use audit::{
    AllSessionScopeTotals, OriginAgentSessionTotals, STATIC_FOOTPRINT_SCHEMA_VERSION,
    StaticFootprintArtifact, StaticFootprintError, StaticFootprintReport, TokenEstimator,
    build_static_footprint,
};
pub use claude::{ClaudePluginRoot, ClaudeScanRoots, scan_claude_code};
pub use codex::{CodexScanRoots, scan_codex};
pub use codex_trust::{CodexProjectTrust, CodexProjectTrustError, resolve_codex_project_trust};
pub use cursor::{
    CursorGlobalRuleSource, CursorGlobalRulesStatus, CursorScanReport, CursorScanRoots, scan_cursor,
};
pub use evaluator::{
    DetectedEvaluator, EvaluatorDetectionError, EvaluatorKind, EvaluatorRunConfig,
    EvaluatorRunError, detect_evaluator, run_evaluator,
};
pub use install::{
    ArtifactInstallError, ArtifactInstallOutcome, ArtifactInstallProvenance, ArtifactInstallSource,
    GitArtifactSource, GitInstallProvenance, MAX_GIT_ARTIFACT_PATH_BYTES,
    MAX_GIT_ARTIFACT_PATH_DEPTH, MAX_GIT_PRIVATE_WORKSPACE_BYTES, MAX_GIT_SOURCE_URL_BYTES,
    install_artifact,
};
pub use library::{
    CanonicalEntryId, CanonicalLibrary, CanonicalLibraryEntry, CanonicalLibraryInstallation,
    CanonicalLibrarySnapshot, InvalidCanonicalEntryId, InvalidLibraryManagedRoot,
    InvalidLibraryProjectKey, LIBRARY_MANIFEST_SCHEMA_VERSION, LibraryAdoptionOutcome,
    LibraryEnablementChange, LibraryEnablementKey, LibraryError, LibraryInsertDisposition,
    LibraryInsertOutcome, LibraryIoOperation, LibraryManagedCopyChange, LibraryManagedRootId,
    LibraryProjectKey, MAX_CANONICAL_ENTRY_ID_BYTES, MAX_LIBRARY_ARTIFACT_BYTES,
    MAX_LIBRARY_ENABLEMENTS, MAX_LIBRARY_ENTRIES, MAX_LIBRARY_INSTALLATIONS,
    MAX_LIBRARY_MANAGED_COPIES, MAX_LIBRARY_MANAGED_ROOT_BYTES, MAX_LIBRARY_MANIFEST_BYTES,
    MAX_LIBRARY_PROJECT_KEY_BYTES, MAX_LIBRARY_VERSIONS_PER_ENTRY,
};
pub use local::{
    LocalInventoryError, LocalInventoryReport, LocalInventoryRoots, scan_local_inventory,
};
pub use materialize::{
    DisableMaterializationOutcome, MAX_MATERIALIZATION_BATCH_BYTES,
    MAX_MATERIALIZATION_BATCH_ENTRIES, ManagedCopyCleanupDisposition, MaterializationAction,
    MaterializationAgent, MaterializationBackup, MaterializationBatchOutcome,
    MaterializationDestinationMetadata, MaterializationDriftConflict,
    MaterializationDriftInspection, MaterializationDriftState, MaterializationError,
    MaterializationIoOperation, MaterializationOutcome, MaterializationPlan,
    MaterializationPlanItem, MaterializationRequest, apply_managed_materialization,
    apply_materialization_resync, disable_materialization, inspect_materialization_drift,
    plan_managed_materialization, plan_materialization, plan_materialization_resync,
};
pub use model::{
    AgentArtifact, AgentArtifactId, AgentArtifactIdentity, ArtifactKind, ArtifactScope,
    InvalidAgentArtifact, InvalidAgentArtifactId, InvalidArtifactEnum, LoadSemantics,
    MAX_ARTIFACT_LOGICAL_PATH_BYTES, MAX_ARTIFACT_NAME_BYTES, OriginAgent,
};
pub use report::{
    SKILLS_AUDIT_REPORT_SCHEMA_VERSION, SkillsAuditError, SkillsAuditEvaluationStatus,
    SkillsAuditFailureReason, SkillsAuditReport, run_skills_audit,
};
pub use scan::{ScanDiagnostic, ScanDiagnosticKind, ScanLimits, ScanReport};
pub use verdict::{
    MAX_VERDICT_ARTIFACT_IDS_PER_FINDING, MAX_VERDICT_FINDING_TEXT_BYTES,
    MAX_VERDICT_FINDINGS_PER_CATEGORY, MAX_VERDICT_JSON_BYTES, MAX_VERDICT_OVERALL_SUMMARY_BYTES,
    MIN_VERDICT_ARTIFACT_IDS_PER_FINDING, SaturationGrade, SkillsAuditVerdict, VerdictConflict,
    VerdictOverlap, VerdictParseError, VerdictStaleCandidate, parse_skills_audit_verdict,
    skills_audit_verdict_json_schema,
};
