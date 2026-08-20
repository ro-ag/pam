import { describe, expect, it } from "vitest";
import { fixtureBridge } from "./fixtures";
import { selectControlCenter } from "./selectors";

describe("native DTO selectors", () => {
  it("derives display state without widening the native wire contract", async () => {
    const bridge = fixtureBridge();
    const snapshot = await bridge.bootstrap();
    const catalog = await bridge.catalog();
    const view = selectControlCenter(snapshot.data, catalog, bridge.mode === "fixture");

    expect(Object.keys(snapshot.data).sort()).toEqual(["access", "catalogWarning", "current", "health", "project"]);
    expect(view.project.name).toBe("payments-api");
    expect(view.project.rootLabel).toBe("/work/payments-api");
    expect(view.daemon.state).toBe("running");
    expect(view.current.queue).toHaveLength(2);
    expect(view.current.latestOutcome?.brief?.verified).toContain("CI pipeline passed");
  });

  it("preserves exact blocked recovery text", async () => {
    const bridge = fixtureBridge();
    const snapshot = await bridge.bootstrap();
    const catalog = await bridge.catalog();
    snapshot.data.current = {
      status: "blocked",
      failure: { kind: "blocked", code: "policy_denied", detail: "Project policy denied the request.", recovery: "Review the project policy." },
    };
    const view = selectControlCenter(snapshot.data, catalog, false);
    expect(view.current.failure).toBe("Project policy denied the request. Review the project policy.");
  });
});
