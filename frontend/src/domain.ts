export type ViewId = "activity" | "callers" | "flows" | "options";
export type ApprovalDecision = "approve" | "deny";
export type BridgeMode = "native" | "fixture";

export interface CommandFence {
  projectHandle: string;
  generation: string;
  operationId: string;
}

export interface FencedResponse<T> {
  fence: CommandFence;
  data: T;
}

export interface ProjectSummaryDto {
  handle: string;
  name: string;
  location: string;
}

export interface CatalogDto {
  projects: ProjectSummaryDto[];
  warning: string | null;
}

export type HealthDto =
  | { status: "healthy"; daemonVersion: string; queueDepth: number }
  | { status: "offline" }
  | { status: "degraded"; detail: string; recovery: string | null };

export interface FailureDto {
  kind: "blocked" | "unavailable";
  code: string | null;
  detail: string;
  recovery: string | null;
}

export type AccessConfigDto =
  | {
      status: "available";
      truth: string;
      platformRootsEnabled: boolean;
      systemProxyDiscoveryEnabled: boolean;
      proxyEnvironment: string;
      noProxy: string;
      pac: string;
    }
  | { status: "blocked"; failure: FailureDto; approvalId: string | null; expiresAtMs: number | null }
  | { status: "unavailable"; failure: FailureDto };

export interface RequestSummaryDto {
  requestId: string;
  operationKind: string;
  state: string;
  queueSequence: number;
  acceptedAtMs: number;
  completedAtMs: number | null;
}

export interface TimelineFactDto {
  kind: "request" | "evidence" | "change" | "verification" | "failure";
  label: string;
  summary: string;
  verified: boolean;
  evidence: string[];
}

export interface OutcomeSectionDto {
  label: string;
  summary: string;
  satisfied: boolean;
}

export interface OutcomeDto {
  heading: string;
  solved: boolean;
  sections: OutcomeSectionDto[];
  evidence: string[];
  evidenceTruncated: boolean;
}

export interface RunDto {
  request: RequestSummaryDto;
  timeline: TimelineFactDto[];
  outcome: OutcomeDto | null;
  detailError: string | null;
}

export type CurrentDto =
  | { status: "available"; queued: RequestSummaryDto[]; truncated: boolean; run: RunDto | null }
  | { status: "approval_required"; approval: string; expiresAtMs: number }
  | { status: "blocked"; failure: FailureDto }
  | { status: "unavailable"; failure: FailureDto };

export interface SnapshotDataDto {
  project: ProjectSummaryDto;
  health: HealthDto;
  current: CurrentDto;
  access: AccessConfigDto;
  catalogWarning: string | null;
}

export type SnapshotDto = FencedResponse<SnapshotDataDto>;
export type BootstrapResponse = SnapshotDto;

export interface ApprovalDecisionResponseDto {
  disposition: "approved" | "denied" | "expired";
  snapshot: SnapshotDto;
}

export interface EvidenceDataDto {
  handle: string;
  digest: string;
  sizeBytes: number;
  mediaType: string;
  body: string | null;
  truncated: boolean;
  truth: string;
}

export type EvidenceDto = FencedResponse<EvidenceDataDto>;

export interface FlowIdentityDto {
  fileName: string;
  id: string;
  revision: number;
  digest: string;
}

export interface FlowDefinitionDto {
  handle: string;
  identity: FlowIdentityDto;
}

export interface FlowWorkspaceDataDto {
  definitions: FlowDefinitionDto[];
}

export type FlowWorkspaceDto = FencedResponse<FlowWorkspaceDataDto>;

export interface FlowDocumentDataDto {
  handle: string;
  identity: FlowIdentityDto | null;
  source: string;
}

export type FlowDocumentDto = FencedResponse<FlowDocumentDataDto>;

export interface FlowDryRunStepDto {
  index: number;
  id: string;
  semanticRole: string;
  condition: string;
  approval: string;
  effect: string;
  maxAttempts: number;
  initialBackoffMs: number;
  maxBackoffMs: number;
  action: string;
  daemonAuthority: string;
}

export interface FlowDryRunDto {
  daemonDefinitionEligible: boolean;
  steps: FlowDryRunStepDto[];
}

export interface FlowVersionDiffLineDto {
  kind: string;
  text: string;
}

export interface FlowVersionDiffDto {
  changed: boolean;
  truncated: boolean;
  lines: FlowVersionDiffLineDto[];
}

export interface FlowReviewDataDto {
  document: string;
  identity: FlowIdentityDto;
  normalizedToml: string;
  dryRun: FlowDryRunDto;
  diff: FlowVersionDiffDto;
}

export type FlowReviewDto = FencedResponse<FlowReviewDataDto>;

export interface FlowSaveDataDto {
  document: string;
  identity: FlowIdentityDto;
  created: boolean;
  durabilityConfirmed: boolean;
  cleanupComplete: boolean;
}

export type FlowSaveDto = FencedResponse<FlowSaveDataDto>;

export interface SkillArtifactDto {
  id: string;
  name: string;
  logicalPath: string;
  kind: string;
  scope: string;
  origin: string;
  loadSemantics: string;
  contentHash: string;
  firstSeenAtMs: number;
  lastChangedAtMs: number;
}

export interface SkillInventoryDriftDto {
  added: number;
  changed: number;
  removed: number;
  resurrected: number;
}

export interface SkillInventoryDataDto {
  artifacts: SkillArtifactDto[];
  total: number;
  truncated: boolean;
  drift: SkillInventoryDriftDto;
  cursorGlobalRulesStatus: "not_locally_discoverable" | "explicitly_configured";
}

export type SkillInventoryDto = FencedResponse<SkillInventoryDataDto>;

export type SkillLibraryAgentDto = "claude" | "codex" | "cursor";
export type SkillLibraryDispositionDto = "inserted" | "already_present";
export type SkillLibraryMaterializationActionDto = "no_op" | "create" | "replace";
export type SkillLibraryCleanupDto =
  | "removed"
  | "missing"
  | "preserved_modified"
  | "preserved_symlink"
  | "preserved_unowned";

export type SkillLibraryInstallationDto =
  | { kind: "local" }
  | { kind: "git"; commit: string };

export type SkillLibraryDriftStateDto =
  | { state: "clean" }
  | { state: "missing" }
  | { state: "modified"; actualDigest: string }
  | {
      state: "conflict";
      reason:
        | "disabled"
        | "unowned"
        | "unsafe_root"
        | "unsafe_path"
        | "symlink"
        | "non_regular"
        | "unreadable"
        | "too_large"
        | "plan_mismatch";
    };

export interface SkillLibraryVersionDto {
  version: string;
  installation: SkillLibraryInstallationDto | null;
  enabledAgents: SkillLibraryAgentDto[];
  managedAgents: SkillLibraryAgentDto[];
}

export interface SkillLibraryEntryDto {
  entryId: string;
  versions: SkillLibraryVersionDto[];
}

export interface SkillLibraryKeyDto {
  entryId: string;
  version: string;
  agent: SkillLibraryAgentDto;
}

export interface SkillLibraryFileMetadataDto {
  byteLen: number;
  digest: string;
}

export interface SkillLibraryPlanItemDto {
  key: SkillLibraryKeyDto;
  action: SkillLibraryMaterializationActionDto;
  existing: SkillLibraryFileMetadataDto | null;
  backupPlanned: boolean;
}

export interface SkillLibraryOutcomeDto {
  key: SkillLibraryKeyDto;
  action: SkillLibraryMaterializationActionDto;
  backup: SkillLibraryFileMetadataDto | null;
  ownershipRecorded: boolean;
}

export interface SkillLibraryDriftDto {
  key: SkillLibraryKeyDto;
  expectedDigest: string;
  state: SkillLibraryDriftStateDto;
}

export type SkillLibraryActionRequest =
  | { action: "load" }
  | { action: "adopt"; entryId: string; artifactId: string }
  | { action: "install_local"; entryId: string; sourcePath: string }
  | { action: "install_git"; entryId: string; url: string; artifactPath: string }
  | ({ action: "enable" | "disable" | "preview_materialization" | "apply_materialization" | "inspect_drift" | "preview_resync" | "apply_resync" } & SkillLibraryKeyDto);

export type SkillLibraryActionResultDto =
  | { schemaVersion: 1; action: "load"; entries: SkillLibraryEntryDto[] }
  | { schemaVersion: 1; action: "adopt"; entryId: string; version: string; artifactId: string; disposition: SkillLibraryDispositionDto }
  | { schemaVersion: 1; action: "install_local" | "install_git"; entryId: string; version: string; disposition: SkillLibraryDispositionDto }
  | { schemaVersion: 1; action: "enable"; key: SkillLibraryKeyDto; enabled: boolean; changed: boolean }
  | { schemaVersion: 1; action: "disable"; key: SkillLibraryKeyDto; stateChanged: boolean; cleanup: SkillLibraryCleanupDto }
  | { schemaVersion: 1; action: "preview_materialization" | "preview_resync"; items: SkillLibraryPlanItemDto[] }
  | { schemaVersion: 1; action: "apply_materialization" | "apply_resync"; outcomes: SkillLibraryOutcomeDto[] }
  | { schemaVersion: 1; action: "inspect_drift"; inspection: SkillLibraryDriftDto };

export type SkillLibraryDto = FencedResponse<SkillLibraryActionResultDto>;

export interface SkillAuditOriginSessionDto {
  origin: string;
  artifactCount: number;
  rawBytes: number;
  estimatedTokens: number;
}

export interface SkillAuditScopeTotalDto {
  scope: string;
  artifactCount: number;
  rawBytes: number;
  estimatedTokens: number;
}

export interface SkillAuditArtifactDto {
  rank: number;
  id: string;
  name: string;
  logicalPath: string;
  kind: string;
  scope: string;
  origin: string;
  loadSemantics: string;
  contentHash: string;
  rawBytes: number;
  estimatedTokens: number;
}

export interface SkillAuditFootprintDto {
  estimator: string;
  alwaysLoadedArtifactCount: number;
  allSessionRawBytes: number;
  allSessionEstimatedTokens: number;
  originSessions: SkillAuditOriginSessionDto[];
  scopeTotals: SkillAuditScopeTotalDto[];
  rankedArtifacts: SkillAuditArtifactDto[];
  rankedArtifactsTotal: number;
  rankedArtifactsTruncated: boolean;
}

export interface SkillAuditMultiArtifactFindingDto {
  artifactIds: string[];
  summary: string;
}

export interface SkillAuditStaleCandidateDto {
  artifactId: string;
  reason: string;
}

export interface SkillAuditVerdictDto {
  overlaps: SkillAuditMultiArtifactFindingDto[];
  conflicts: SkillAuditMultiArtifactFindingDto[];
  staleCandidates: SkillAuditStaleCandidateDto[];
  saturationGrade: "healthy" | "elevated" | "high" | "critical";
  overallSummary: string;
}

export type SkillAuditEvaluatorDto = "claude" | "codex" | "cursor_agent";
export type SkillAuditFailureDto = "invalid_corpus" | "prompt_too_large" | "invocation_failed" | "invalid_verdict";

export type SkillAuditEvaluationDto =
  | { status: "no_evaluator" }
  | { status: "failed"; evaluator: SkillAuditEvaluatorDto; failure: SkillAuditFailureDto }
  | { status: "evaluated"; evaluator: SkillAuditEvaluatorDto; verdict: SkillAuditVerdictDto };

export interface SkillAuditDataDto {
  observedAtMs: number;
  footprint: SkillAuditFootprintDto;
  evaluation: SkillAuditEvaluationDto;
}

export type SkillAuditDto = FencedResponse<SkillAuditDataDto | null>;

export interface BridgeFailureDto {
  code: string;
  detail: string;
  recovery: string | null;
}

export interface ActivityEventDto {
  sequence: number;
  projectId: string | null;
  callerId: string;
  action: string;
  decision: string;
  outcome: string | null;
  occurredAtMs: number;
}

export type ActivityDto =
  | { status: "ok"; events: ActivityEventDto[]; truncated: boolean }
  | { status: "blocked" | "unavailable"; failure: BridgeFailureDto };

export interface CallerDto {
  callerId: string;
  registeredAtMs: number;
  revokedAtMs: number | null;
}

export type CallersDto =
  | { status: "ok"; callers: CallerDto[] }
  | { status: "blocked" | "unavailable"; failure: BridgeFailureDto };

export interface PamBridge {
  readonly mode: BridgeMode;
  bootstrap(): Promise<SnapshotDto>;
  catalog(): Promise<CatalogDto>;
  daemonActivity(fence: CommandFence, limit?: number): Promise<ActivityDto>;
  callerRegistry(fence: CommandFence): Promise<CallersDto>;
  activateProject(projectHandle: string, operationId: string): Promise<SnapshotDto>;
  refreshProject(fence: CommandFence): Promise<SnapshotDto>;
  startDaemon(fence: CommandFence): Promise<SnapshotDto>;
  stopDaemon(fence: CommandFence): Promise<SnapshotDto>;
  registerGuiCaller(fence: CommandFence): Promise<SnapshotDto>;
  decideApproval(fence: CommandFence, approvalHandle: string, decision: ApprovalDecision): Promise<ApprovalDecisionResponseDto>;
  loadEvidence(fence: CommandFence, evidenceHandle: string): Promise<EvidenceDto>;
  loadFlowWorkspace(fence: CommandFence): Promise<FlowWorkspaceDto>;
  loadSkillInventory(fence: CommandFence): Promise<SkillInventoryDto>;
  manageSkillLibrary(fence: CommandFence, action: SkillLibraryActionRequest): Promise<SkillLibraryDto>;
  loadSkillAudit(fence: CommandFence): Promise<SkillAuditDto>;
  runSkillAudit(fence: CommandFence): Promise<SkillAuditDto>;
  openFlow(fence: CommandFence, flowHandle: string): Promise<FlowDocumentDto>;
  validateFlow(fence: CommandFence, documentHandle: string, source: string): Promise<FlowReviewDto>;
  saveFlow(fence: CommandFence, documentHandle: string, source: string): Promise<FlowSaveDto>;
}

export const MAX_EVIDENCE_TEXT = 4_096;
export const MAX_FLOW_SOURCE = 128_000;
