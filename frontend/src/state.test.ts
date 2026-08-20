import { describe, expect, it } from "vitest";
import { fixtureBridge } from "./fixtures";
import { appReducer, clampSidebarWidth, initialState, presentError } from "./state";

describe("app reducer", () => {
  it("discards a stale response instead of changing the active project", async () => {
    const response = await fixtureBridge().bootstrap();
    const catalog = await fixtureBridge().catalog();
    const ready = appReducer(initialState, { type: "bootstrapSucceeded", response, catalog });
    const pendingFence = { ...response.fence, operationId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" };
    const pending = appReducer(ready, { type: "commandStarted", fence: pendingFence });
    const stale = {
      ...response,
      fence: { ...response.fence, operationId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" },
    };

    expect(appReducer(pending, { type: "commandSucceeded", response: stale })).toBe(pending);
  });

  it("accepts activation only when opaque handle and operation match", async () => {
    const bridge = fixtureBridge();
    const bootstrap = await bridge.bootstrap();
    const catalog = await bridge.catalog();
    const ready = appReducer(initialState, { type: "bootstrapSucceeded", response: bootstrap, catalog });
    const project = catalog.projects[1];
    const operationId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const pendingFence = { projectHandle: project.handle, generation: "", operationId };
    const pending = appReducer(ready, { type: "commandStarted", fence: pendingFence });
    const activated = await bridge.activateProject(project.handle, operationId);
    const next = appReducer(pending, { type: "commandSucceeded", response: activated });

    expect(next.data?.project.handle).toBe(project.handle);
    expect(next.activeFence?.generation).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("keeps sidebar width within the p-track bounds", () => {
    expect(clampSidebarWidth(40)).toBe(208);
    expect(clampSidebarWidth(279.6)).toBe(280);
    expect(clampSidebarWidth(800)).toBe(368);
  });

  it("bounds and strips control characters from displayed errors", () => {
    expect(presentError("bad\u0000\nstate")).toBe("bad state");
    expect(presentError("x".repeat(500))).toHaveLength(280);
  });
});
