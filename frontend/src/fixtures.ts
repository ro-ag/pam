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

function snapshot(project: ProjectSummaryDto, daemonRunning: boolean): SnapshotDataDto {
  return {
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
          { label: "Request received", summary: "Investigate failing merge in PR #1842", verified: false, evidence: [] },
          { label: "Evidence found", summary: "CI failure and merge base identified", verified: false, evidence: [evidenceHandles[0]] },
          { label: "Fix applied", summary: "Resolved conflicting idempotency logic", verified: false, evidence: [evidenceHandles[1]] },
          { label: "Verification passed", summary: "All checks green on PR #1842", verified: true, evidence: evidenceHandles },
        ],
        outcome: {
          heading: "Ready for the next agent",
          solved: true,
          sections: [
            { label: "Goal", summary: "Unblock PR #1842 by repairing the failing merge and restoring green CI.", satisfied: true },
            { label: "Decisions", summary: "Kept the idempotency check in the service layer; removed the duplicate guard in the controller.", satisfied: true },
            { label: "Verified", summary: "CI pipeline passed; unit and integration tests are green; no regressions were detected.", satisfied: true },
            { label: "Next", summary: "Request review from Payments; monitor the staging smoke for 30 minutes.", satisfied: true },
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
      proxyEnvironment: "No explicit proxy environment variables",
      noProxy: "localhost,127.0.0.1",
      pac: "No PAC URL configured",
    },
    catalogWarning: null,
  };
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

export function fixtureBridge(): PamBridge {
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
      return fenceResponse(currentFence("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), snapshot(active, daemonRunning));
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
      return fenceResponse(currentFence(operationId), snapshot(active, daemonRunning));
    },
    async refreshProject(fence) { return fenceResponse(fence, snapshot(active, daemonRunning)); },
    async startDaemon(fence) { daemonRunning = true; return fenceResponse(fence, snapshot(active, daemonRunning)); },
    async stopDaemon(fence) { daemonRunning = false; return fenceResponse(fence, snapshot(active, daemonRunning)); },
    async decideApproval(fence, _approvalHandle: string, _decision: ApprovalDecision) { return fenceResponse(fence, snapshot(active, daemonRunning)); },
    async loadEvidence(fence, evidenceHandle) {
      const data: EvidenceDataDto = {
        handle: evidenceHandle,
        digest: evidenceHandle === evidenceHandles[0] ? "sha256:fixture-ci" : "sha256:fixture-git",
        sizeBytes: 108,
        mediaType: "text/plain",
        body: evidenceHandle === evidenceHandles[0]
          ? "GitHub Actions · integration-test · exit 1\nNull currency in fixture triggers 500 at CurrencyService.java:142"
          : "2 files changed\nAll checks green\nguard currency before invoking conversion pipeline",
        truncated: false,
        truth: evidenceHandle === evidenceHandles[0] ? "CI failure output" : "Verified Git patch",
      };
      return fenceResponse(fence, data);
    },
    async loadFlowWorkspace(fence) { return fenceResponse(fence, workspace()); },
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
        normalizedToml: source,
        dryRun: {
          daemonDefinitionEligible: true,
          steps: [
            { index: 0, id: "observe-revision", semanticRole: "observe", condition: "always", approval: "none", effect: "read_only", maxAttempts: 1, initialBackoffMs: 0, maxBackoffMs: 0, action: "git rev-parse --verify HEAD", daemonAuthority: "supported" },
          ],
        },
        diff: { changed: source !== savedSource, truncated: false, lines: [] },
      };
      return fenceResponse(fence, data);
    },
    async saveFlow(fence, _documentHandle, source) {
      savedSource = source;
      const data: FlowSaveDataDto = { document: documentHandle, identity, created: false, durabilityConfirmed: true, cleanupComplete: true };
      return fenceResponse(fence, data);
    },
  };
}
