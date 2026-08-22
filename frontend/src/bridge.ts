import { invoke } from "@tauri-apps/api/core";
import type {
  ActivityDto,
  BootstrapResponse,
  ApprovalDecisionResponseDto,
  CallersDto,
  CatalogDto,
  CommandFence,
  EvidenceDto,
  FlowDocumentDto,
  FlowReviewDto,
  FlowSaveDto,
  FlowWorkspaceDto,
  PamBridge,
  SkillAuditDto,
  SkillInventoryDto,
  SkillLibraryDto,
  SnapshotDto,
} from "./domain";
import { fixtureBridge, type FixtureScenario } from "./fixtures";

type Invoke = <T>(command: string, args?: Record<string, unknown>) => Promise<T>;

const flatFence = ({ projectHandle, generation, operationId }: CommandFence) => ({
  projectHandle,
  generation,
  operationId,
});

const request = (payload: Record<string, unknown>) => ({ request: payload });

export function nextOperationId(): string {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  const bytes = new Uint8Array(16);
  globalThis.crypto?.getRandomValues?.(bytes);
  if (!bytes.some(Boolean)) {
    for (let index = 0; index < bytes.length; index += 1) bytes[index] = Math.floor(Math.random() * 256);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function sameFence(left: CommandFence | null | undefined, right: CommandFence | null | undefined): boolean {
  return Boolean(
    left &&
      right &&
      left.projectHandle === right.projectHandle &&
      left.generation === right.generation &&
      left.operationId === right.operationId,
  );
}

export function withOperation(fence: CommandFence): CommandFence {
  return { ...fence, operationId: nextOperationId() };
}

export function createTauriBridge(invokeCommand: Invoke = invoke): PamBridge {
  return {
    mode: "native",
    bootstrap: () => invokeCommand<BootstrapResponse>("bootstrap", request({ operationId: nextOperationId() })),
    catalog: () => invokeCommand<CatalogDto>("catalog"),
    daemonActivity: (fence, limit) =>
      invokeCommand<ActivityDto>("daemon_activity", request({
        ...flatFence(fence),
        limit: limit ?? null,
      })),
    callerRegistry: (fence) =>
      invokeCommand<CallersDto>("caller_registry", request(flatFence(fence))),
    activateProject: (projectHandle, operationId) =>
      invokeCommand<SnapshotDto>(
        "activate_project",
        request({ projectHandle, operationId }),
      ),
    refreshProject: (fence) =>
      invokeCommand<SnapshotDto>("refresh_project", request(flatFence(fence))),
    startDaemon: (fence) =>
      invokeCommand<SnapshotDto>("start_daemon", request(flatFence(fence))),
    stopDaemon: (fence) =>
      invokeCommand<SnapshotDto>("stop_daemon", request(flatFence(fence))),
    registerGuiCaller: (fence) =>
      invokeCommand<SnapshotDto>("register_gui_caller", request(flatFence(fence))),
    decideApproval: (fence, approvalHandle, decision) =>
      invokeCommand<ApprovalDecisionResponseDto>("decide_approval", request({
        ...flatFence(fence),
        approvalHandle,
        decision,
      })),
    loadEvidence: (fence, evidenceHandle) =>
      invokeCommand<EvidenceDto>("load_evidence", request({
        ...flatFence(fence),
        evidenceHandle,
      })),
    loadFlowWorkspace: (fence) =>
      invokeCommand<FlowWorkspaceDto>("load_flow_workspace", request(flatFence(fence))),
    loadSkillInventory: (fence) =>
      invokeCommand<SkillInventoryDto>("load_skill_inventory", request(flatFence(fence))),
    manageSkillLibrary: (fence, action) =>
      invokeCommand<SkillLibraryDto>("manage_skill_library", request({
        ...flatFence(fence),
        ...action,
      })),
    loadSkillAudit: (fence) =>
      invokeCommand<SkillAuditDto>("load_skill_audit", request(flatFence(fence))),
    runSkillAudit: (fence) =>
      invokeCommand<SkillAuditDto>("run_skill_audit", request(flatFence(fence))),
    openFlow: (fence, flowHandle) =>
      invokeCommand<FlowDocumentDto>(
        "open_flow",
        request({ ...flatFence(fence), flowHandle }),
      ),
    validateFlow: (fence, documentHandle, source) =>
      invokeCommand<FlowReviewDto>("validate_flow", request({
        ...flatFence(fence),
        documentHandle,
        source,
      })),
    saveFlow: (fence, documentHandle, source) =>
      invokeCommand<FlowSaveDto>("save_flow", request({
        ...flatFence(fence),
        documentHandle,
        source,
      })),
  };
}

export function createFixtureBridge(scenario: FixtureScenario = "solved"): PamBridge {
  return fixtureBridge(scenario);
}
