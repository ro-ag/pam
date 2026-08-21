import type {
  ApprovalDecision,
  CatalogDto,
  CommandFence,
  EvidenceDataDto,
  FlowDocumentDataDto,
  FlowReviewDataDto,
  FlowSaveDataDto,
  FlowWorkspaceDataDto,
  PamBridge,
  ProjectSummaryDto,
  SnapshotDataDto,
  SkillAuditDataDto,
  SkillInventoryDataDto,
} from "./domain";

const projects: ProjectSummaryDto[] = [
  { handle: "11111111-1111-4111-8111-111111111111", name: "payments-api", location: "/work/payments-api" },
  { handle: "22222222-2222-4222-8222-222222222222", name: "ledger-web", location: "/work/ledger-web" },
  { handle: "33333333-3333-4333-8333-333333333333", name: "docs", location: "/work/docs" },
];

const evidenceHandles = [
  "44444444-4444-4444-8444-444444444444",
  "55555555-5555-4555-8555-555555555555",
];

const flowSource = `schema_version = 2
id = "after-merge-checks"
name = "After merge checks"
description = "Observe the merged revision and verify the worktree."
revision = 4

[outcome]
solved = "Whether every declared check completed successfully."
changed = "This read-only flow does not change project state."
verified = "Whether the tracked worktree matches the index."
unresolved = "Which check still needs investigation."
blocked = "Which policy or workspace boundary stopped the flow."

[[steps]]
id = "observe-revision"
description = "Record the checked-out revision as evidence."
depends_on = []
condition = { kind = "always" }
approval = "none"
timeout_seconds = 30
effect = "read_only"
semantic = "observe"
action = { type = "command", program = "git", args = ["rev-parse", "--verify", "HEAD"], working_directory = "." }

[[steps]]
id = "verify-worktree"
description = "Verify tracked files match the index."
depends_on = ["observe-revision"]
condition = { kind = "succeeded", step = "observe-revision" }
approval = "none"
timeout_seconds = 30
effect = "read_only"
semantic = "verify"
action = { type = "command", program = "git", args = ["diff", "--quiet"], working_directory = "." }
`;

const definitionHandle = "66666666-6666-4666-8666-666666666666";
const secondDefinitionHandle = "77777777-7777-4777-8777-777777777777";
const documentHandle = "88888888-8888-4888-8888-888888888888";

export const fixtureScenarios = [
  "loading",
  "offline",
  "missing-credential",
  "approval",
  "queued",
  "empty",
  "active",
  "solved",
  "unresolved",
  "blocked",
  "current-blocked",
  "cancelled",
  "access-available",
  "access-blocked",
  "evidence-loading",
  "evidence-available",
  "evidence-failed",
  "evidence-binary",
  "evidence-truncated",
  "startup-error",
  "skill-audit-empty",
  "skill-audit-no-evaluator",
  "skill-audit-failed",
  "skill-audit-load-error",
] as const;

export type FixtureScenario = typeof fixtureScenarios[number];

export function fixtureScenario(value: string | null | undefined): FixtureScenario {
  return fixtureScenarios.find((scenario) => scenario === value) ?? "solved";
}

const unavailableFailure = {
  kind: "unavailable" as const,
  code: null,
  detail: "The authenticated daemon is unavailable for this project.",
  recovery: "Start PAM, then retry the authenticated project refresh.",
};

function solvedSnapshot(project: ProjectSummaryDto, daemonRunning: boolean): SnapshotDataDto {
  const data: SnapshotDataDto = {
    project,
    health: daemonRunning
      ? { status: "healthy", daemonVersion: "fixture-0.1.0", queueDepth: 2 }
      : { status: "offline" },
    current: {
      status: "available",
      queued: [
        { requestId: "fixture-request-2", operationKind: "after-merge-checks", state: "queued", queueSequence: 2, acceptedAtMs: 1_777_000_000_000, completedAtMs: null },
        { requestId: "fixture-request-3", operationKind: "staging-smoke", state: "queued", queueSequence: 3, acceptedAtMs: 1_777_000_060_000, completedAtMs: null },
      ],
      truncated: false,
      run: {
        request: { requestId: "fixture-request-1", operationKind: "merge-repair", state: "succeeded", queueSequence: 1, acceptedAtMs: 1_777_000_000_000, completedAtMs: 1_777_001_440_000 },
        detailError: null,
        timeline: [
          { kind: "request", label: "Request received", summary: "Investigate failing merge in PR #1842", verified: false, evidence: [] },
          { kind: "evidence", label: "Evidence found", summary: "CI failure and merge base identified", verified: false, evidence: [evidenceHandles[0]] },
          { kind: "change", label: "Fix applied", summary: "Resolved conflicting idempotency logic", verified: false, evidence: [evidenceHandles[1]] },
          { kind: "verification", label: "Verification passed", summary: "All checks green on PR #1842", verified: true, evidence: evidenceHandles },
        ],
        outcome: {
          heading: "Ready for the next agent",
          solved: true,
          sections: [
            { label: "SOLVED", summary: "The merge conflict was repaired and the original request completed.", satisfied: true },
            { label: "CHANGED", summary: "Conflicting idempotency logic was consolidated in the service layer.", satisfied: true },
            { label: "VERIFIED", summary: "Unit and integration checks completed successfully.", satisfied: true },
            { label: "UNRESOLVED", summary: "No unresolved work was reported.", satisfied: false },
            { label: "BLOCKED", summary: "No blocker was reported.", satisfied: false },
          ],
          evidence: evidenceHandles,
          evidenceTruncated: false,
        },
      },
    },
    access: {
      status: "available",
      truth: "System trust and proxy discovery are available to the active project.",
      platformRootsEnabled: true,
      systemProxyDiscoveryEnabled: true,
      proxyEnvironment: "not configured",
      noProxy: "configured",
      pac: "not detected",
    },
    catalogWarning: null,
  };

  if (!daemonRunning) {
    data.current = { status: "unavailable", failure: unavailableFailure };
    data.access = { status: "unavailable", failure: unavailableFailure };
  }

  return data;
}

function skillInventory(empty: boolean): SkillInventoryDataDto {
  const artifacts = empty
    ? []
    : [
        {
          id: "artifact:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          name: "Review changes",
          logicalPath: ".claude/skills/review/SKILL.md",
          kind: "skill",
          scope: "project",
          origin: "claude_code",
          loadSemantics: "model_selected",
          contentHash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          firstSeenAtMs: 1_777_000_000_000,
          lastChangedAtMs: 1_777_000_000_000,
        },
        {
          id: "artifact:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
          name: "Project instructions",
          logicalPath: "AGENTS.md",
          kind: "instruction",
          scope: "project",
          origin: "codex",
          loadSemantics: "always",
          contentHash: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
          firstSeenAtMs: 1_777_000_000_000,
          lastChangedAtMs: 1_777_000_000_000,
        },
      ];
  return {
    artifacts,
    total: artifacts.length,
    truncated: false,
    drift: { added: artifacts.length, changed: 0, removed: 0, resurrected: 0 },
    cursorGlobalRulesStatus: "not_locally_discoverable",
  };
}

function skillAudit(evaluation: SkillAuditDataDto["evaluation"] = {
  status: "evaluated",
  evaluator: "codex",
  verdict: {
    saturationGrade: "elevated",
    overallSummary: "The always-loaded footprint is usable, with one overlapping review pair and one stale candidate to inspect.",
    overlaps: [{
      artifactIds: [
        "artifact:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "artifact:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      ],
      summary: "Two review instructions cover the same change-verification responsibility.",
    }],
    conflicts: [{
      artifactIds: [
        "artifact:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "artifact:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      ],
      summary: "The project instructions and review skill disagree about when local checks may be skipped.",
    }],
    staleCandidates: [{
      artifactId: "artifact:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      reason: "This review skill references a command no longer present in the project.",
    }],
  },
}): SkillAuditDataDto {
  return {
    observedAtMs: 1_777_001_800_000,
    footprint: {
      estimator: "raw_bytes_div_4_ceil_v1",
      alwaysLoadedArtifactCount: 2,
      allSessionRawBytes: 14_336,
      allSessionEstimatedTokens: 3_584,
      originSessions: [
        { origin: "codex", artifactCount: 1, rawBytes: 8_192, estimatedTokens: 2_048 },
        { origin: "claude_code", artifactCount: 1, rawBytes: 6_144, estimatedTokens: 1_536 },
      ],
      scopeTotals: [
        { scope: "project", artifactCount: 2, rawBytes: 14_336, estimatedTokens: 3_584 },
      ],
      rankedArtifacts: [
        {
          rank: 1,
          id: "artifact:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
          name: "Project instructions",
          logicalPath: "AGENTS.md",
          kind: "instruction",
          scope: "project",
          origin: "codex",
          loadSemantics: "always",
          contentHash: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
          rawBytes: 8_192,
          estimatedTokens: 2_048,
        },
        {
          rank: 2,
          id: "artifact:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          name: "Review changes",
          logicalPath: ".claude/skills/review/SKILL.md",
          kind: "skill",
          scope: "project",
          origin: "claude_code",
          loadSemantics: "always",
          contentHash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          rawBytes: 6_144,
          estimatedTokens: 1_536,
        },
      ],
      rankedArtifactsTotal: 2,
      rankedArtifactsTruncated: false,
    },
    evaluation,
  };
}

function snapshot(project: ProjectSummaryDto, daemonRunning: boolean, scenario: FixtureScenario): SnapshotDataDto {
  const data = solvedSnapshot(project, daemonRunning);
  if (!daemonRunning || scenario === "solved" || scenario.startsWith("evidence-")) return data;

  if (["unresolved", "blocked", "cancelled"].includes(scenario) && data.current.status === "available" && data.current.run?.outcome) {
    const outcome = data.current.run.outcome;
    outcome.solved = false;
    outcome.heading = scenario === "unresolved"
      ? "Run needs follow-up"
      : scenario === "blocked"
        ? "Run is blocked"
        : "Run was cancelled";
    outcome.sections = outcome.sections.map((section) => ({
      ...section,
      satisfied: section.label === "CHANGED"
        || (scenario === "unresolved" && section.label === "UNRESOLVED")
        || (scenario === "blocked" && section.label === "BLOCKED"),
      summary: section.label === "UNRESOLVED" && scenario === "unresolved"
        ? "The staging verification still needs investigation."
        : section.label === "BLOCKED" && scenario === "blocked"
          ? "Project policy blocked the declared write effect."
          : section.summary,
    }));
    data.current.run.timeline[data.current.run.timeline.length - 1] = {
      kind: "failure",
      label: scenario === "unresolved" ? "Unresolved" : scenario === "blocked" ? "Blocked" : "Run cancelled",
      summary: outcome.heading,
      verified: false,
      evidence: [],
    };
    return data;
  }

  if (scenario === "missing-credential") {
    const detail = "PAM has no native caller credential for this caller.";
    const recovery = "Use Register GUI caller in PAM.";
    const failure = { kind: "unavailable" as const, code: "gui_registration_required", detail, recovery };
    data.health = { status: "degraded", detail, recovery };
    data.current = { status: "unavailable", failure };
    data.access = { status: "unavailable", failure };
  }
  if (scenario === "offline") {
    return solvedSnapshot(project, false);
  }
  if (scenario === "approval") {
    data.health = { status: "healthy", daemonVersion: "fixture-0.1.0", queueDepth: 0 };
    data.current = {
      status: "approval_required",
      approval: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
      expiresAtMs: 2_000_000_000_000,
    };
  }
  if (scenario === "queued") {
    data.current = { status: "available", queued: data.current.status === "available" ? data.current.queued : [], truncated: false, run: null };
  }
  if (scenario === "empty") {
    data.current = { status: "available", queued: [], truncated: false, run: null };
  }
  if (scenario === "current-blocked") {
    data.current = {
      status: "blocked",
      failure: {
        kind: "blocked",
        code: "project_current_blocked",
        detail: "Project policy blocked access to the bounded current state.",
        recovery: "Grant project.current for this GUI caller and project, then retry.",
      },
    };
  }
  if (scenario === "active" && data.current.status === "available" && data.current.run) {
    data.current = {
      ...data.current,
      queued: data.current.queued.slice(0, 1),
      run: {
        ...data.current.run,
        request: { ...data.current.run.request, state: "leased", completedAtMs: null },
        timeline: data.current.run.timeline.slice(0, 2),
        outcome: null,
      },
    };
  }
  if (scenario === "access-blocked") {
    data.access = {
      status: "blocked",
      failure: {
        kind: "blocked",
        code: "Forbidden",
        detail: "Network diagnostics are blocked by the selected project's policy.",
        recovery: "Grant network.diagnostics for this GUI caller and project, then retry.",
      },
      approvalId: null,
      expiresAtMs: null,
    };
  }
  return data;
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

export function fixtureBridge(scenario: FixtureScenario = "solved"): PamBridge {
  let active = projects[0];
  let generation = "99999999-9999-4999-8999-999999999999";
  let daemonRunning = true;
  let savedSource = flowSource;
  const fenceResponse = <T,>(fence: CommandFence, data: T) => ({ fence: clone(fence), data: clone(data) });
  const currentFence = (operationId: string): CommandFence => ({ projectHandle: active.handle, generation, operationId });
  const identity = { fileName: "after-merge-checks.toml", id: "after-merge-checks", revision: 4, digest: "sha256:fixture-after-merge" };
  const workspace = (): FlowWorkspaceDataDto => ({
    definitions: [
      { handle: definitionHandle, identity },
      { handle: secondDefinitionHandle, identity: { fileName: "release-confidence.toml", id: "release-confidence", revision: 3, digest: "sha256:fixture-release" } },
    ],
  });
  const document = (): FlowDocumentDataDto => ({ handle: documentHandle, identity, source: savedSource });

  return {
    mode: "fixture",
    async bootstrap() {
      if (scenario === "loading") return new Promise(() => {});
      if (scenario === "startup-error") throw new Error("The PAM daemon fixture is unavailable.");
      return fenceResponse(currentFence("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), snapshot(active, daemonRunning, scenario));
    },
    async catalog(): Promise<CatalogDto> {
      return { projects: clone(projects), warning: null };
    },
    async activateProject(projectHandle, operationId) {
      const selected = projects.find((project) => project.handle === projectHandle);
      if (!selected) throw new Error("The selected fixture project is unavailable.");
      active = selected;
      generation = projectHandle === projects[1].handle
        ? "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        : projectHandle === projects[2].handle
          ? "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
          : "99999999-9999-4999-8999-999999999999";
      return fenceResponse(currentFence(operationId), snapshot(active, daemonRunning, scenario));
    },
    async refreshProject(fence) { return fenceResponse(fence, snapshot(active, daemonRunning, scenario)); },
    async startDaemon(fence) { daemonRunning = true; return fenceResponse(fence, snapshot(active, daemonRunning, scenario)); },
    async stopDaemon(fence) { daemonRunning = false; return fenceResponse(fence, snapshot(active, daemonRunning, scenario)); },
    async registerGuiCaller(fence) { return fenceResponse(fence, solvedSnapshot(active, daemonRunning)); },
    async decideApproval(fence, _approvalHandle: string, decision: ApprovalDecision) {
      const data = solvedSnapshot(active, daemonRunning);
      if (decision === "deny") {
        data.current = {
          status: "unavailable",
          failure: {
            kind: "unavailable",
            code: "approval_denied",
            detail: "This exact project-current request was denied.",
            recovery: null,
          },
        };
      }
      return { disposition: decision === "approve" ? "approved" : "denied", snapshot: fenceResponse(fence, data) };
    },
    async loadEvidence(fence, evidenceHandle) {
      if (scenario === "evidence-loading") return new Promise(() => {});
      if (scenario === "evidence-failed") throw new Error("The bounded evidence preview could not be loaded. Retry from the retained handle.");
      const binary = scenario === "evidence-binary";
      const truncated = scenario === "evidence-truncated";
      const data: EvidenceDataDto = {
        handle: evidenceHandle,
        digest: evidenceHandle === evidenceHandles[0] ? "sha256:fixture-ci" : "sha256:fixture-git",
        sizeBytes: binary ? 32_768 : truncated ? 19_212 : 108,
        mediaType: binary ? "application/octet-stream" : "text/plain",
        body: binary
          ? null
          : truncated
            ? `${"retained evidence line\n".repeat(220)}preview stops at the bounded read limit`
            : evidenceHandle === evidenceHandles[0]
              ? "GitHub Actions · integration-test · exit 1\nNull currency in fixture triggers 500 at CurrencyService.java:142"
              : "2 files changed\nAll checks green\nguard currency before invoking conversion pipeline",
        truncated,
        truth: binary ? "Binary evidence metadata" : evidenceHandle === evidenceHandles[0] ? "CI failure output" : "Verified Git patch",
      };
      return fenceResponse(fence, data);
    },
    async loadFlowWorkspace(fence) { return fenceResponse(fence, workspace()); },
    async loadSkillInventory(fence) { return fenceResponse(fence, skillInventory(scenario === "empty")); },
    async loadSkillAudit(fence) {
      if (scenario === "skill-audit-load-error") throw new Error("The latest skill audit could not be loaded.");
      if (scenario === "skill-audit-empty" || scenario === "empty") return fenceResponse(fence, null);
      if (scenario === "skill-audit-no-evaluator") return fenceResponse(fence, skillAudit({ status: "no_evaluator" }));
      if (scenario === "skill-audit-failed") {
        return fenceResponse(fence, skillAudit({ status: "failed", evaluator: "cursor_agent", failure: "invalid_verdict" }));
      }
      return fenceResponse(fence, skillAudit());
    },
    async runSkillAudit(fence) { return fenceResponse(fence, skillAudit()); },
    async openFlow(fence, flowHandle) {
      if (flowHandle !== definitionHandle) throw new Error("This fixture definition has no editable document.");
      return fenceResponse(fence, document());
    },
    async validateFlow(fence, _documentHandle, source) {
      if (!source.includes("schema_version = 2") || !source.includes("[[steps]]")) {
        throw new Error("The fixture validator requires schema version 2 and at least one step.");
      }
      const data: FlowReviewDataDto = {
        document: documentHandle,
        identity,
        normalizedToml: `${source.trimEnd()}\n`,
        dryRun: {
          daemonDefinitionEligible: true,
          steps: [
            { index: 0, id: "observe-revision", semanticRole: "observe", condition: "always", approval: "none", effect: "read_only", maxAttempts: 1, initialBackoffMs: 0, maxBackoffMs: 0, action: "git rev-parse --verify HEAD", daemonAuthority: "supported" },
          ],
        },
        diff: {
          changed: source !== savedSource,
          truncated: false,
          lines: source === savedSource
            ? []
            : [
                { kind: "removed", text: `revision = ${identity.revision}` },
                { kind: "added", text: `revision = ${identity.revision + 1}` },
              ],
        },
      };
      return fenceResponse(fence, data);
    },
    async saveFlow(fence, _documentHandle, source) {
      savedSource = `${source.trimEnd()}\n`;
      const data: FlowSaveDataDto = { document: documentHandle, identity, created: false, durabilityConfirmed: true, cleanupComplete: true };
      return fenceResponse(fence, data);
    },
  };
}
