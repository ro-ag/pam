export type ViewId = "current" | "flows" | "access";
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

export interface PamBridge {
  readonly mode: BridgeMode;
  bootstrap(): Promise<SnapshotDto>;
  catalog(): Promise<CatalogDto>;
  activateProject(projectHandle: string, operationId: string): Promise<SnapshotDto>;
  refreshProject(fence: CommandFence): Promise<SnapshotDto>;
  startDaemon(fence: CommandFence): Promise<SnapshotDto>;
  stopDaemon(fence: CommandFence): Promise<SnapshotDto>;
  registerGuiCaller(fence: CommandFence): Promise<SnapshotDto>;
  decideApproval(fence: CommandFence, approvalHandle: string, decision: ApprovalDecision): Promise<ApprovalDecisionResponseDto>;
  loadEvidence(fence: CommandFence, evidenceHandle: string): Promise<EvidenceDto>;
  loadFlowWorkspace(fence: CommandFence): Promise<FlowWorkspaceDto>;
  loadSkillInventory(fence: CommandFence): Promise<SkillInventoryDto>;
  openFlow(fence: CommandFence, flowHandle: string): Promise<FlowDocumentDto>;
  validateFlow(fence: CommandFence, documentHandle: string, source: string): Promise<FlowReviewDto>;
  saveFlow(fence: CommandFence, documentHandle: string, source: string): Promise<FlowSaveDto>;
}

export const MAX_EVIDENCE_TEXT = 4_096;
export const MAX_FLOW_SOURCE = 128_000;
