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

  it("keeps sidebar width within the responsive layout bounds", () => {
    expect(clampSidebarWidth(40, 1_400)).toBe(180);
    expect(clampSidebarWidth(280.6, 1_400)).toBe(281);
    expect(clampSidebarWidth(800, 1_400)).toBe(420);
    expect(clampSidebarWidth(800, 640)).toBe(288);

    const resized = appReducer(
      { ...initialState, sidebarCollapsed: true },
      { type: "resizeSidebar", width: 800, viewportWidth: 640 },
    );
    expect(resized.sidebarWidth).toBe(288);
    expect(resized.sidebarCollapsed).toBe(false);
  });

  it("sets sidebar collapse state explicitly without changing its width", () => {
    const collapsed = appReducer(initialState, { type: "setSidebarCollapsed", collapsed: true });
    const expanded = appReducer(collapsed, { type: "setSidebarCollapsed", collapsed: false });

    expect(collapsed.sidebarCollapsed).toBe(true);
    expect(collapsed.sidebarWidth).toBe(initialState.sidebarWidth);
    expect(expanded.sidebarCollapsed).toBe(false);
  });

  it("bounds and strips control characters from displayed errors", () => {
    expect(presentError("bad\u0000\nstate")).toBe("bad state");
    expect(presentError("x".repeat(500))).toHaveLength(280);
  });
});
