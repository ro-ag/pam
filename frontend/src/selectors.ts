import type {
  AccessConfigDto,
  CatalogDto,
  CurrentDto,
  HealthDto,
  OutcomeDto,
  ProjectSummaryDto,
  RequestSummaryDto,
  RunDto,
  SnapshotDataDto,
  TimelineFactDto,
} from "./domain";

export type DaemonState = "running" | "stopped" | "unavailable";
export type ProjectHealth = "ready" | "busy" | "attention" | "offline" | "unknown";
export type RunState = "queued" | "running" | "approval" | "succeeded" | "failed" | "blocked";
export type TimelineKind = "request" | "evidence" | "change" | "verification" | "failure";

export interface ProjectView {
  handle: string;
  name: string;
  rootLabel: string;
  branch: string | null;
  health: ProjectHealth;
  queuedCount: number | null;
}

export interface DaemonView {
  state: DaemonState;
  detail: string;
  model: string | null;
  modelMemory: string | null;
}

export interface QueueItemView {
  requestId: string;
  operationKind: string;
  state: RunState;
  submittedAt: string;
}

export interface TimelineItemView {
  id: string;
  kind: TimelineKind;
  title: string;
  description: string;
  occurredAt: string | null;
  relativeLabel: string;
}

export interface AgentBriefView {
  goal: string;
  decisions: string;
  verified: string;
  next: string;
  evidenceHandles: string[];
}

export interface OutcomeView {
  runId: string;
  title: string;
  state: RunState;
  timeline: TimelineItemView[];
  brief: AgentBriefView | null;
}

export interface ActiveRunView {
  runId: string;
  operationKind: string;
  state: RunState;
  summary: string;
  startedAt: string;
  timeline: TimelineItemView[];
}

export interface ApprovalView {
  approvalHandle: string;
  requestId: string;
  title: string;
  reason: string;
  effect: string;
}

export interface AccessGrantView {
  id: string;
  name: string;
  summary: string;
  state: "allowed" | "scoped" | "unavailable";
}

export interface ControlCenterView {
  nowIso: string;
  project: ProjectView;
  catalog: ProjectView[];
  catalogWarning: string | null;
  daemon: DaemonView;
  current: {
    queue: QueueItemView[];
    activeRun: ActiveRunView | null;
    latestOutcome: OutcomeView | null;
    approval: ApprovalView | null;
    queueTruncated: boolean;
    failure: string | null;
  };
  access: AccessGrantView[];
  fixture: boolean;
}

function runState(raw: string): RunState {
  const value = raw.toLowerCase();
  if (value.includes("succeed") || value.includes("complete")) return "succeeded";
  if (value.includes("fail")) return "failed";
  if (value.includes("block")) return "blocked";
  if (value.includes("approval")) return "approval";
  if (value.includes("run") || value.includes("active")) return "running";
  return "queued";
}

function queueItem(request: RequestSummaryDto): QueueItemView {
  return {
    requestId: request.requestId,
    operationKind: request.operationKind,
    state: runState(request.state),
    submittedAt: new Date(request.acceptedAtMs).toISOString(),
  };
}

function timelineKind(fact: TimelineFactDto): TimelineKind {
  const label = fact.label.toLowerCase();
  if (fact.verified) return "verification";
  if (label.includes("fail") || label.includes("block")) return "failure";
  if (label.includes("evidence") || fact.evidence.length > 0) return "evidence";
  if (label.includes("fix") || label.includes("change") || label.includes("applied")) return "change";
  return "request";
}

function timeline(run: RunDto): TimelineItemView[] {
  return run.timeline.map((fact, index) => ({
    id: `${run.request.requestId}:${index}`,
    kind: timelineKind(fact),
    title: fact.label,
    description: fact.summary,
    occurredAt: null,
    relativeLabel: `Sequence ${index + 1}`,
  }));
}

function section(outcome: OutcomeDto, label: string): string {
  return outcome.sections.find((item) => item.label.toLowerCase() === label.toLowerCase())?.summary
    ?? `No ${label.toLowerCase()} section was reported.`;
}

function currentView(current: CurrentDto) {
  if (current.status === "approval_required") {
    return {
      queue: [],
      activeRun: null,
      latestOutcome: null,
      approval: {
        approvalHandle: current.approval,
        requestId: "Current project request",
        title: "The daemon requires an exact approval",
        reason: `This approval expires at ${new Date(current.expiresAtMs).toLocaleString()}.`,
        effect: "The exact pending project request only",
      },
      queueTruncated: false,
      failure: null,
    };
  }
  if (current.status === "blocked" || current.status === "unavailable") {
    return {
      queue: [], activeRun: null, latestOutcome: null, approval: null, queueTruncated: false,
      failure: [current.failure.detail, current.failure.recovery].filter(Boolean).join(" "),
    };
  }
  const run = current.run;
  const events = run ? timeline(run) : [];
  const outcome = run?.outcome;
  return {
    queue: current.queued.map(queueItem),
    activeRun: run && !outcome ? {
      runId: run.request.requestId,
      operationKind: run.request.operationKind,
      state: runState(run.request.state),
      summary: run.detailError ?? run.request.operationKind,
      startedAt: new Date(run.request.acceptedAtMs).toISOString(),
      timeline: events,
    } : null,
    latestOutcome: run && outcome ? {
      runId: run.request.requestId,
      title: outcome.heading,
      state: outcome.solved ? "succeeded" as const : "failed" as const,
      timeline: events,
      brief: {
        goal: section(outcome, "Goal"),
        decisions: section(outcome, "Decisions"),
        verified: section(outcome, "Verified"),
        next: section(outcome, "Next"),
        evidenceHandles: outcome.evidence,
      },
    } : null,
    approval: null,
    queueTruncated: current.truncated,
    failure: run?.detailError ?? null,
  };
}

function healthView(health: HealthDto) {
  if (health.status === "healthy") {
    return {
      health: health.queueDepth > 0 ? "busy" as const : "ready" as const,
      daemon: { state: "running" as const, detail: "PAM is on watch", model: `Daemon ${health.daemonVersion}`, modelMemory: null },
    };
  }
  if (health.status === "offline") {
    return { health: "offline" as const, daemon: { state: "stopped" as const, detail: "PAM is paused", model: null, modelMemory: null } };
  }
  return { health: "attention" as const, daemon: { state: "unavailable" as const, detail: health.detail, model: null, modelMemory: null } };
}

function accessView(access: AccessConfigDto): AccessGrantView[] {
  if (access.status !== "available") {
    return [{ id: "access-recovery", name: "Access configuration", summary: [access.failure.detail, access.failure.recovery].filter(Boolean).join(" "), state: "unavailable" }];
  }
  return [
    { id: "truth", name: "Effective configuration", summary: access.truth, state: "allowed" },
    { id: "roots", name: "Platform trust roots", summary: access.platformRootsEnabled ? "Enabled for authenticated project requests" : "Not enabled", state: access.platformRootsEnabled ? "allowed" : "scoped" },
    { id: "proxy", name: "Network discovery", summary: [access.proxyEnvironment, access.noProxy, access.pac].filter(Boolean).join(" · "), state: access.systemProxyDiscoveryEnabled ? "allowed" : "scoped" },
  ];
}

function projectView(project: ProjectSummaryDto, active: SnapshotDataDto, projectHealth: ProjectHealth): ProjectView {
  const selected = project.handle === active.project.handle;
  return {
    handle: project.handle,
    name: project.name,
    rootLabel: project.location,
    branch: null,
    health: selected ? projectHealth : "unknown",
    queuedCount: selected && active.current.status === "available" ? active.current.queued.length : null,
  };
}

export function selectControlCenter(data: SnapshotDataDto, catalog: CatalogDto, fixture: boolean): ControlCenterView {
  const health = healthView(data.health);
  const projects = catalog.projects.length > 0 ? catalog.projects : [data.project];
  return {
    nowIso: new Date().toISOString(),
    project: projectView(data.project, data, health.health),
    catalog: projects.map((project) => projectView(project, data, health.health)),
    catalogWarning: catalog.warning ?? data.catalogWarning,
    daemon: health.daemon,
    current: currentView(data.current),
    access: accessView(data.access),
    fixture,
  };
}
