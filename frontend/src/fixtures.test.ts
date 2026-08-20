import { describe, expect, it } from "vitest";
import { fixtureBridge, fixtureScenario } from "./fixtures";

describe("visual QA fixture scenarios", () => {
  it("normalizes unknown scenarios to the approved solved composition", () => {
    expect(fixtureScenario("active")).toBe("active");
    expect(fixtureScenario("not-a-state")).toBe("solved");
    expect(fixtureScenario(null)).toBe("solved");
  });

  it("keeps loading pending and reports missing credentials through the production surface shape", async () => {
    let loadingResolved = false;
    void fixtureBridge("loading").bootstrap().then(() => { loadingResolved = true; });
    await Promise.resolve();
    expect(loadingResolved).toBe(false);
    const missing = await fixtureBridge("missing-credential").bootstrap();
    expect(missing.data.health).toMatchObject({
      status: "degraded",
      recovery: "Use Register GUI caller in PAM.",
    });
    expect(missing.data.current).toMatchObject({
      status: "unavailable",
      failure: { code: "gui_registration_required" },
    });
    expect(missing.data.current.status).toBe("unavailable");
    expect(missing.data.access.status).toBe("unavailable");
  });

  it("renders distinct offline, approval, queued, and active wire states", async () => {
    const offline = await fixtureBridge("offline").bootstrap();
    const approval = await fixtureBridge("approval").bootstrap();
    const queued = await fixtureBridge("queued").bootstrap();
    const active = await fixtureBridge("active").bootstrap();

    expect(offline.data.health.status).toBe("offline");
    expect(offline.data.current.status).toBe("unavailable");
    expect(approval.data.current.status).toBe("approval_required");
    expect(queued.data.current).toMatchObject({ status: "available", run: null });
    expect(active.data.current).toMatchObject({
      status: "available",
      run: { request: { state: "leased", completedAtMs: null }, outcome: null },
    });
    expect(approval.data.current).toMatchObject({ expiresAtMs: 2_000_000_000_000 });
  });

  it("keeps unresolved, blocked, and cancelled terminal reports distinct from solved", async () => {
    const unresolved = await fixtureBridge("unresolved").bootstrap();
    const blocked = await fixtureBridge("blocked").bootstrap();
    const cancelled = await fixtureBridge("cancelled").bootstrap();
    const outcome = (value: typeof unresolved) => value.data.current.status === "available"
      ? value.data.current.run?.outcome
      : null;

    expect(outcome(unresolved)).toMatchObject({ heading: "Run needs follow-up", solved: false });
    expect(outcome(blocked)).toMatchObject({ heading: "Run is blocked", solved: false });
    expect(outcome(cancelled)).toMatchObject({ heading: "Run was cancelled", solved: false });
  });

  it("keeps Access policy denial separate from available diagnostics", async () => {
    const available = await fixtureBridge("access-available").bootstrap();
    const blocked = await fixtureBridge("access-blocked").bootstrap();

    expect(available.data.access.status).toBe("available");
    expect(blocked.data.access).toMatchObject({
      status: "blocked",
      failure: { kind: "blocked", code: "Forbidden" },
    });
  });

  it("covers bounded text, failure, binary metadata, and truncation evidence", async () => {
    const solved = await fixtureBridge("solved").bootstrap();
    const handle = solved.data.current.status === "available"
      ? solved.data.current.run?.outcome?.evidence[0]
      : null;
    expect(handle).toBeTruthy();
    const fence = solved.fence;

    const available = await fixtureBridge("evidence-available").loadEvidence(fence, handle!);
    const binary = await fixtureBridge("evidence-binary").loadEvidence(fence, handle!);
    const truncated = await fixtureBridge("evidence-truncated").loadEvidence(fence, handle!);

    expect(available.data).toMatchObject({ mediaType: "text/plain", truncated: false });
    expect(binary.data).toMatchObject({ mediaType: "application/octet-stream", body: null });
    expect(truncated.data.truncated).toBe(true);
    expect(truncated.data.body?.length).toBeGreaterThan(4_096);
    await expect(fixtureBridge("evidence-failed").loadEvidence(fence, handle!)).rejects.toThrow(
      "bounded evidence preview",
    );
  });
});
