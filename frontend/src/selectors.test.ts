import { describe, expect, it } from "vitest";
import { fixtureBridge } from "./fixtures";
import { runState, selectControlCenter } from "./selectors";

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
    expect(view.current.latestOutcome?.brief?.sections.find(({ label }) => label === "VERIFIED")?.summary)
      .toContain("integration checks");
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
    expect(view.current.recoveryAction).toBeNull();

    snapshot.data.health = { status: "offline" };
    expect(selectControlCenter(snapshot.data, catalog, false).current.recoveryAction).toBe("start-daemon");
  });

  it("preserves policy-blocked access separately from unavailable configuration", async () => {
    const bridge = fixtureBridge("access-blocked");
    const snapshot = await bridge.bootstrap();
    const catalog = await bridge.catalog();
    const blocked = selectControlCenter(snapshot.data, catalog, false).access[0];
    expect(blocked).toMatchObject({ name: "Access policy", state: "policy-gated" });
    expect(blocked?.summary).toContain("Policy gated.");

    snapshot.data.access = {
      status: "unavailable",
      failure: { kind: "unavailable", code: "transport", detail: "Diagnostics unavailable.", recovery: "Retry." },
    };
    expect(selectControlCenter(snapshot.data, catalog, false).access[0]?.state).toBe("unavailable");
  });

  it("maps durable leased, cancellation, and cancelled request states exactly", async () => {
    const bridge = fixtureBridge("active");
    const snapshot = await bridge.bootstrap();
    const catalog = await bridge.catalog();
    expect(selectControlCenter(snapshot.data, catalog, true).current.activeRun?.state).toBe("running");

    if (snapshot.data.current.status !== "available" || !snapshot.data.current.run) {
      throw new Error("active fixture missing run");
    }
    snapshot.data.current.run.request.state = "cancellation_requested";
    expect(selectControlCenter(snapshot.data, catalog, true).current.activeRun?.state).toBe("cancelling");
    snapshot.data.current.run.request.state = "cancelled";
    const cancelled = selectControlCenter(snapshot.data, catalog, true).current;
    expect(cancelled.activeRun).toBeNull();
    expect(cancelled.failure).toContain("cancelled request has no terminal outcome");
    expect(runState("completed")).toBe("unknown");
    expect(runState("actively_running")).toBe("unknown");
  });

  it("uses authoritative timeline kinds instead of inferring semantics from labels or evidence", async () => {
    const bridge = fixtureBridge();
    const snapshot = await bridge.bootstrap();
    const catalog = await bridge.catalog();
    if (snapshot.data.current.status !== "available" || !snapshot.data.current.run) {
      throw new Error("solved fixture missing run");
    }
    snapshot.data.current.run.timeline[0] = {
      kind: "failure",
      label: "Request received",
      summary: "The backend category remains authoritative.",
      verified: true,
      evidence: ["opaque-evidence"],
    };

    const timeline = selectControlCenter(snapshot.data, catalog, true).current.latestOutcome?.timeline;
    expect(timeline?.[0].kind).toBe("failure");
    expect(timeline?.[2]).toMatchObject({ title: "Fix applied", kind: "change" });
  });
});
