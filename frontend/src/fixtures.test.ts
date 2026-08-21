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

  it("renders distinct offline, approval, queued, empty, blocked, and active wire states", async () => {
    const offline = await fixtureBridge("offline").bootstrap();
    const approval = await fixtureBridge("approval").bootstrap();
    const queued = await fixtureBridge("queued").bootstrap();
    const empty = await fixtureBridge("empty").bootstrap();
    const currentBlocked = await fixtureBridge("current-blocked").bootstrap();
    const active = await fixtureBridge("active").bootstrap();

    expect(offline.data.health.status).toBe("offline");
    expect(offline.data.current.status).toBe("unavailable");
    expect(approval.data.current.status).toBe("approval_required");
    expect(queued.data.current).toMatchObject({ status: "available", run: null });
    expect(empty.data.current).toEqual({ status: "available", queued: [], truncated: false, run: null });
    expect(currentBlocked.data.current).toMatchObject({
      status: "blocked",
      failure: { kind: "blocked", code: "project_current_blocked" },
    });
    expect(active.data.current).toMatchObject({
      status: "available",
      run: { request: { state: "leased", completedAtMs: null }, outcome: null },
    });
    expect(approval.data.current).toMatchObject({ expiresAtMs: 2_000_000_000_000 });
  });

  it("keeps startup transport failure separate from protocol snapshots", async () => {
    await expect(fixtureBridge("startup-error").bootstrap()).rejects.toThrow(
      "The PAM daemon fixture is unavailable.",
    );
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

  it("provides evaluated, deterministic-only, failed, and empty skill-audit fixtures", async () => {
    const evaluatedBridge = fixtureBridge("solved");
    const evaluatedSnapshot = await evaluatedBridge.bootstrap();
    const evaluated = await evaluatedBridge.loadSkillAudit(evaluatedSnapshot.fence);
    const deterministicBridge = fixtureBridge("skill-audit-no-evaluator");
    const deterministicSnapshot = await deterministicBridge.bootstrap();
    const deterministic = await deterministicBridge.loadSkillAudit(deterministicSnapshot.fence);
    const failedBridge = fixtureBridge("skill-audit-failed");
    const failedSnapshot = await failedBridge.bootstrap();
    const failed = await failedBridge.loadSkillAudit(failedSnapshot.fence);
    const emptyBridge = fixtureBridge("skill-audit-empty");
    const emptySnapshot = await emptyBridge.bootstrap();
    const empty = await emptyBridge.loadSkillAudit(emptySnapshot.fence);

    expect(evaluated.data?.footprint.rankedArtifacts[0]).toMatchObject({
      rank: 1,
      name: "Project instructions",
      logicalPath: "AGENTS.md",
      estimatedTokens: 2_048,
    });
    expect(evaluated.data?.footprint.estimator).toBe("raw_bytes_div_4_ceil_v1");
    const ranked = evaluated.data?.footprint.rankedArtifacts ?? [];
    const rankedIds = new Set(ranked.map((artifact) => artifact.id));
    expect(ranked.every((artifact) => artifact.loadSemantics === "always")).toBe(true);
    expect(evaluated.data?.footprint.alwaysLoadedArtifactCount).toBe(ranked.length);
    expect(evaluated.data?.footprint.rankedArtifactsTotal).toBe(ranked.length);
    expect(evaluated.data?.footprint.rankedArtifactsTruncated).toBe(false);
    expect(evaluated.data?.footprint.allSessionRawBytes).toBe(
      ranked.reduce((total, artifact) => total + artifact.rawBytes, 0),
    );
    expect(evaluated.data?.footprint.allSessionEstimatedTokens).toBe(
      ranked.reduce((total, artifact) => total + artifact.estimatedTokens, 0),
    );
    expect(evaluated.data?.footprint.originSessions.reduce((total, origin) => total + origin.artifactCount, 0)).toBe(ranked.length);
    expect(evaluated.data?.footprint.scopeTotals.reduce((total, scope) => total + scope.artifactCount, 0)).toBe(ranked.length);
    for (const origin of evaluated.data?.footprint.originSessions ?? []) {
      const artifacts = ranked.filter((artifact) => artifact.origin === origin.origin);
      expect(origin).toMatchObject({
        artifactCount: artifacts.length,
        rawBytes: artifacts.reduce((total, artifact) => total + artifact.rawBytes, 0),
        estimatedTokens: artifacts.reduce((total, artifact) => total + artifact.estimatedTokens, 0),
      });
    }
    for (const scope of evaluated.data?.footprint.scopeTotals ?? []) {
      const artifacts = ranked.filter((artifact) => artifact.scope === scope.scope);
      expect(scope).toMatchObject({
        artifactCount: artifacts.length,
        rawBytes: artifacts.reduce((total, artifact) => total + artifact.rawBytes, 0),
        estimatedTokens: artifacts.reduce((total, artifact) => total + artifact.estimatedTokens, 0),
      });
    }
    expect(evaluated.data?.evaluation).toMatchObject({
      status: "evaluated",
      evaluator: "codex",
      verdict: {
        saturationGrade: "elevated",
        overlaps: [{ summary: expect.any(String) }],
        conflicts: [{ summary: expect.any(String) }],
        staleCandidates: [{ reason: expect.any(String) }],
      },
    });
    if (evaluated.data?.evaluation.status === "evaluated") {
      const referencedIds = [
        ...evaluated.data.evaluation.verdict.overlaps.flatMap((finding) => finding.artifactIds),
        ...evaluated.data.evaluation.verdict.conflicts.flatMap((finding) => finding.artifactIds),
        ...evaluated.data.evaluation.verdict.staleCandidates.map((finding) => finding.artifactId),
      ];
      expect(referencedIds.every((artifactId) => rankedIds.has(artifactId))).toBe(true);
    }
    expect(deterministic.data?.evaluation).toEqual({ status: "no_evaluator" });
    expect(failed.data?.evaluation).toEqual({ status: "failed", evaluator: "cursor_agent", failure: "invalid_verdict" });
    expect(empty.data).toBeNull();
  });
});
