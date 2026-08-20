import { describe, expect, it } from "vitest";
import { createTauriBridge, sameFence } from "./bridge";
import type { CommandFence } from "./domain";

const fence: CommandFence = {
  projectHandle: "project:opaque",
  generation: "11111111-1111-4111-8111-111111111111",
  operationId: "22222222-2222-4222-8222-222222222222",
};

describe("Tauri bridge ABI", () => {
  it("wraps typed payloads once under request and uses exact camelCase keys", async () => {
    const calls: Array<[string, Record<string, unknown> | undefined]> = [];
    const invoke = async <T,>(command: string, args?: Record<string, unknown>) => {
      calls.push([command, args]);
      return { fence, data: {} } as T;
    };
    const bridge = createTauriBridge(invoke);

    await bridge.refreshProject(fence);
    await bridge.decideApproval(fence, "approval:opaque", "deny");
    await bridge.loadEvidence(fence, "evidence://bounded/1");
    await bridge.validateFlow(fence, "document:opaque", "schema_version = 2");

    expect(calls[0]).toEqual(["refresh_project", {
      request: { projectHandle: fence.projectHandle, generation: fence.generation, operationId: fence.operationId },
    }]);
    expect(calls[1]).toEqual(["decide_approval", {
      request: { ...fence, approvalHandle: "approval:opaque", decision: "deny" },
    }]);
    expect(calls[2]).toEqual(["load_evidence", {
      request: { ...fence, evidenceHandle: "evidence://bounded/1" },
    }]);
    expect(calls[3]).toEqual(["validate_flow", {
      request: { ...fence, documentHandle: "document:opaque", source: "schema_version = 2" },
    }]);
  });

  it("supplies bootstrap with only a canonical operation id", async () => {
    const calls: Array<[string, Record<string, unknown> | undefined]> = [];
    const invoke = async <T,>(command: string, args?: Record<string, unknown>) => {
      calls.push([command, args]);
      return { fence, data: {} } as T;
    };
    const bridge = createTauriBridge(invoke);
    await bridge.bootstrap();

    expect(calls).toHaveLength(1);
    const [command, args] = calls[0];
    expect(command).toBe("bootstrap");
    expect(args).toEqual({ request: { operationId: expect.stringMatching(/^[0-9a-f-]{36}$/) } });
  });

  it("keeps lifecycle and flow commands narrow", async () => {
    const calls: Array<[string, Record<string, unknown> | undefined]> = [];
    const invoke = async <T,>(command: string, args?: Record<string, unknown>) => {
      calls.push([command, args]);
      return { fence, data: {} } as T;
    };
    const bridge = createTauriBridge(invoke);

    await bridge.catalog();
    await bridge.activateProject(fence.projectHandle, fence.operationId);
    await bridge.startDaemon(fence);
    await bridge.stopDaemon(fence);
    await bridge.registerGuiCaller(fence);
    await bridge.loadFlowWorkspace(fence);
    await bridge.openFlow(fence, "55555555-5555-4555-8555-555555555555");
    await bridge.saveFlow(fence, "66666666-6666-4666-8666-666666666666", "schema_version = 2");

    expect(calls.map(([command]) => command)).toEqual([
      "catalog", "activate_project", "start_daemon", "stop_daemon", "register_gui_caller", "load_flow_workspace", "open_flow", "save_flow",
    ]);
    expect(calls[0][1]).toBeUndefined();
    expect(calls[1][1]).toEqual({ request: { projectHandle: fence.projectHandle, operationId: fence.operationId } });
    expect(calls[4][1]).toEqual({ request: fence });
    expect(calls[5][1]).toEqual({ request: fence });
    expect(calls[6][1]).toEqual({ request: { ...fence, flowHandle: "55555555-5555-4555-8555-555555555555" } });
    expect(calls[7][1]).toEqual({ request: { ...fence, documentHandle: "66666666-6666-4666-8666-666666666666", source: "schema_version = 2" } });
  });

  it("compares all three fence fields", () => {
    expect(sameFence(fence, { ...fence })).toBe(true);
    expect(sameFence(fence, { ...fence, generation: "33333333-3333-4333-8333-333333333333" })).toBe(false);
    expect(sameFence(fence, { ...fence, operationId: "44444444-4444-4444-8444-444444444444" })).toBe(false);
    expect(sameFence(fence, { ...fence, projectHandle: "project:other" })).toBe(false);
  });
});
