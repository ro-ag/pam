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
export type RunState = "queued" | "running" | "cancelling" | "succeeded" | "failed" | "cancelled" | "unknown";
export type TimelineKind = TimelineFactDto["kind"];

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
  queueDepth: number | null;
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
  title: string;
  solved: boolean;
  sections: Array<{
    label: string;
    summary: string;
    satisfied: boolean;
  }>;
  evidenceHandles: string[];
  evidenceTruncated: boolean;
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
  title: string;
  reason: string;
  effect: string;
  projectName: string;
  policyCapability: string;
  expiresAt: string;
}

export interface AccessGrantView {
  id: string;
  name: string;
  summary: string;
  state: "observed" | "policy-gated" | "unavailable";
}

export interface ControlCenterView {
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
    recoveryAction: "register-caller" | "start-daemon" | null;
  };
  access: AccessGrantView[];
  fixture: boolean;
}

export function runState(raw: string): RunState {
  switch (raw) {
    case "queued":
      return "queued";
    case "leased":
      return "running";
    case "cancellation_requested":
      return "cancelling";
    case "succeeded":
      return "succeeded";
    case "failed":
      return "failed";
    case "cancelled":
      return "cancelled";
    default:
      return "unknown";
  }
}

function queueItem(request: RequestSummaryDto): QueueItemView {
  return {
    requestId: request.requestId,
    operationKind: request.operationKind,
    state: runState(request.state),
    submittedAt: new Date(request.acceptedAtMs).toISOString(),
  };
}

function timeline(run: RunDto): TimelineItemView[] {
  return run.timeline.map((fact, index) => ({
    id: `${run.request.requestId}:${index}`,
    kind: fact.kind,
    title: fact.label,
    description: fact.summary,
    occurredAt: null,
    relativeLabel: `Sequence ${index + 1}`,
  }));
}

function currentView(current: CurrentDto, projectName: string, health: HealthDto): ControlCenterView["current"] {
  if (current.status === "approval_required") {
    return {
      queue: [],
      activeRun: null,
      latestOutcome: null,
      approval: {
        approvalHandle: current.approval,
        title: "The daemon requires an exact approval",
        reason: "PAM needs approval before reading retained state for the selected project.",
        effect: "Read the selected project's bounded current queue and latest run",
        projectName,
        policyCapability: "project.current · exact project policy",
        expiresAt: new Date(current.expiresAtMs).toLocaleString(),
      },
      queueTruncated: false,
      failure: null,
      recoveryAction: null,
    };
  }
  if (current.status === "blocked" || current.status === "unavailable") {
    const registrationRequired = current.failure.code === "gui_registration_required";
    return {
      queue: [], activeRun: null, latestOutcome: null, approval: null, queueTruncated: false,
      failure: [current.failure.detail, current.failure.recovery].filter(Boolean).join(" "),
      recoveryAction: registrationRequired ? "register-caller" : health.status === "offline" ? "start-daemon" : null,
    };
  }
  const run = current.run;
  const events = run ? timeline(run) : [];
  const outcome = run?.outcome;
  const state = run ? runState(run.request.state) : null;
  const active = state === "queued" || state === "running" || state === "cancelling";
  const missingTerminalOutcome = run && !outcome && !active
    ? `The ${state ?? "terminal"} request has no terminal outcome available. Refresh the project state before acting on it.`
    : null;
  return {
    queue: current.queued.map(queueItem),
    activeRun: run && !outcome && active ? {
      runId: run.request.requestId,
      operationKind: run.request.operationKind,
      state: state ?? "unknown",
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
        title: outcome.heading,
        solved: outcome.solved,
        sections: outcome.sections.map(({ label, summary, satisfied }) => ({ label, summary, satisfied })),
        evidenceHandles: outcome.evidence,
        evidenceTruncated: outcome.evidenceTruncated,
      },
    } : null,
    approval: null,
    queueTruncated: current.truncated,
    failure: run?.detailError ?? missingTerminalOutcome,
    recoveryAction: null,
  };
}

function healthView(health: HealthDto) {
  if (health.status === "healthy") {
    return {
      health: health.queueDepth > 0 ? "busy" as const : "ready" as const,
      daemon: { state: "running" as const, detail: "PAM is on watch", model: `Daemon ${health.daemonVersion}`, modelMemory: null, queueDepth: health.queueDepth },
    };
  }
  if (health.status === "offline") {
    return { health: "offline" as const, daemon: { state: "stopped" as const, detail: "PAM is paused", model: null, modelMemory: null, queueDepth: null } };
  }
  return { health: "attention" as const, daemon: { state: "unavailable" as const, detail: health.detail, model: null, modelMemory: null, queueDepth: null } };
}

function accessView(access: AccessConfigDto): AccessGrantView[] {
  if (access.status === "blocked") {
    return [{
      id: "access-recovery",
      name: "Access policy",
      summary: `Policy gated. ${[access.failure.detail, access.failure.recovery].filter(Boolean).join(" ")}`,
      state: "policy-gated",
    }];
  }
  if (access.status === "unavailable") {
    return [{ id: "access-recovery", name: "Access configuration", summary: [access.failure.detail, access.failure.recovery].filter(Boolean).join(" "), state: "unavailable" }];
  }
  const truthSeparator = /\p{P}$/u.test(access.truth) ? " " : ". ";
  return [
    {
      id: "model",
      name: "Model access",
      summary: "Current model identity is not reported by protocol. Model requests remain authenticated and project-policy gated.",
      state: "policy-gated",
    },
    {
      id: "policy",
      name: "Access policy",
      summary: `${access.truth}${truthSeparator}The network.diagnostics capability was observed; no other capability is inferred.`,
      state: "observed",
    },
    {
      id: "certificates",
      name: "Certificates",
      summary: access.platformRootsEnabled
        ? "Operating-system certificate verifier enabled. No certificate-bypass mode."
        : "Operating-system certificate verifier reported disabled. No certificate-bypass mode.",
      state: "observed",
    },
    {
      id: "network",
      name: "Network configuration",
      summary: `Proxy environment ${access.proxyEnvironment} · NO_PROXY ${access.noProxy} · PAC ${access.pac} · system discovery ${access.systemProxyDiscoveryEnabled ? "enabled" : "not enabled"}.`,
      state: "observed",
    },
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
    project: projectView(data.project, data, health.health),
    catalog: projects.map((project) => projectView(project, data, health.health)),
    catalogWarning: catalog.warning ?? data.catalogWarning,
    daemon: health.daemon,
    current: currentView(data.current, data.project.name, data.health),
    access: accessView(data.access),
    fixture,
  };
}
