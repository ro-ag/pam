import type { Edge, Node } from "@xyflow/react";
import type {
  FlowSpec,
  FlowStep,
  FlowStepStatus,
  FlowWhen,
  OutcomeName,
  RawFlow,
  RawFlowStep,
} from "../../lib/ipc";

/**
 * The pure canvas model: the resolved flow JSON in, xyflow nodes and edges
 * out, and every edit as a function from one spec to the next. Nothing here
 * touches React or the DOM, and no function mutates its input — the Flows
 * screen owns the state and swaps whole specs.
 *
 * The step array is the truth: steps run in file order and `needs` / `when`
 * may only point backwards (flows spec), so a connection drawn against that
 * order repairs the array (`connect`) or is refused with a cause and a fix.
 */

/** A step's state while a run is on: the daemon's word, or `running`. */
export type RunStatus = "running" | FlowStepStatus;

/** The first validation error, pointed at the node it belongs to. */
export interface Marker {
  path: string;
  message: string;
  /** The path below the node prefix (`run[0]`, `repo.default`). */
  field: string;
}

export interface StepNodeData extends Record<string, unknown> {
  step: FlowStep;
  /** Index in `steps`; the order chip shows `index + 1`. */
  index: number;
  status: RunStatus | null;
  marker: Marker | null;
  selected?: boolean;
}

export interface InputsNodeData extends Record<string, unknown> {
  inputs: FlowSpec["inputs"];
  marker: Marker | null;
}

export interface VerdictNodeData extends Record<string, unknown> {
  outcome: OutcomeName | null;
}

export type StepNode = Node<StepNodeData, "step">;
export type InputsNode = Node<InputsNodeData, "inputs">;
export type VerdictNode = Node<VerdictNodeData, "verdict">;
export type CanvasNode = StepNode | InputsNode | VerdictNode;

/** `terminal` is the implicit, unselectable edge into the Verdict frame. */
export type EdgeKind = "needs" | "succeeded" | "failed" | "terminal";
export type EditableEdgeKind = Exclude<EdgeKind, "terminal">;

export interface FlowEdgeData extends Record<string, unknown> {
  kind: EdgeKind;
  running: boolean;
}

export type CanvasEdge = Edge<FlowEdgeData, "flow">;

export const INPUTS_NODE = "inputs";
export const VERDICT_NODE = "verdict";

export type Refused = { cause: string; fix: string };
export type Edit = { ok: true; spec: FlowSpec } | { ok: false; refused: Refused };

const STEP_ID = /^[a-z0-9-]{1,64}$/;

/** `[a-z0-9-]{1,64}` — the id shape `pam_flow` accepts. */
export function isStepId(id: string): boolean {
  return STEP_ID.test(id);
}

export function edgeId(kind: EditableEdgeKind, source: string, target: string): string {
  return `${kind}:${source}->${target}`;
}

interface ParsedEdge {
  kind: EdgeKind;
  source: string;
  target: string;
}

function parseEdgeId(id: string): ParsedEdge | null {
  const match = /^(needs|succeeded|failed|terminal):(.+)->(.+)$/.exec(id);
  if (!match) return null;
  return { kind: match[1] as EdgeKind, source: match[2], target: match[3] };
}

/** The `when` reference of a step, if it names one. */
function whenRef(when: FlowWhen): { kind: "succeeded" | "failed"; step: string } | null {
  if (typeof when === "string") return null;
  if ("succeeded" in when) return { kind: "succeeded", step: when.succeeded };
  return { kind: "failed", step: when.failed };
}

/** Every earlier step this one waits on, through `needs` or `when`. */
function references(step: FlowStep): string[] {
  const ref = whenRef(step.when);
  return ref ? [...step.needs, ref.step] : [...step.needs];
}

function indexOf(spec: FlowSpec, id: string): number {
  return spec.steps.findIndex((step) => step.id === id);
}

function replaceStep(
  spec: FlowSpec,
  id: string,
  update: (step: FlowStep) => FlowStep,
): FlowSpec {
  return { ...spec, steps: spec.steps.map((step) => (step.id === id ? update(step) : step)) };
}

// --- flow → graph ------------------------------------------------------------

/** Which node a validation path points at, and the path below it. */
function locate(path: string, spec: FlowSpec): { node: string | null; field: string } {
  const step = /^steps\[(\d+)\](?:\.(.*))?$/.exec(path);
  if (step) {
    return { node: spec.steps[Number(step[1])]?.id ?? null, field: step[2] ?? "" };
  }
  const inputs = /^inputs(?:\.(.*))?$/.exec(path);
  if (inputs) return { node: INPUTS_NODE, field: inputs[1] ?? "" };
  return { node: null, field: path };
}

/**
 * Turns the first validation error into a marker plus the node that wears
 * it: the step for `steps[N]…`, the Inputs frame for `inputs…`, nothing for
 * a flow-level path (`id`, `name`) — the toolbar note shows those.
 */
export function markerFor(
  error: { path: string; message: string } | null,
  spec: FlowSpec,
): { node: string | null; marker: Marker | null } {
  if (!error) return { node: null, marker: null };
  const { node, field } = locate(error.path, spec);
  return { node, marker: { path: error.path, message: error.message, field } };
}

/**
 * The nodes and edges for a spec. Positions are all `{0,0}` — the layout
 * store fills them in — and nothing is selected.
 */
export function toGraph(
  spec: FlowSpec,
  statuses: Record<string, RunStatus> = {},
  marker: Marker | null = null,
): { nodes: CanvasNode[]; edges: CanvasEdge[] } {
  const marked = marker ? locate(marker.path, spec).node : null;
  const origin = { x: 0, y: 0 };
  const known = new Set(spec.steps.map((step) => step.id));

  const inputs: InputsNode = {
    id: INPUTS_NODE,
    type: "inputs",
    position: origin,
    selected: false,
    data: { inputs: spec.inputs, marker: marked === INPUTS_NODE ? marker : null },
  };
  const steps: StepNode[] = spec.steps.map((step, index) => ({
    id: step.id,
    type: "step",
    position: origin,
    selected: false,
    data: {
      step,
      index,
      status: statuses[step.id] ?? null,
      marker: marked === step.id ? marker : null,
    },
  }));
  const verdict: VerdictNode = {
    id: VERDICT_NODE,
    type: "verdict",
    position: origin,
    selected: false,
    data: { outcome: null },
  };

  const edges: CanvasEdge[] = [];
  const sources = new Set<string>();
  const push = (kind: EditableEdgeKind, source: string, target: string) => {
    if (!known.has(source)) return;
    sources.add(source);
    edges.push({
      id: edgeId(kind, source, target),
      type: "flow",
      source,
      target,
      data: { kind, running: statuses[target] === "running" },
    });
  };
  for (const step of spec.steps) {
    for (const need of step.needs) push("needs", need, step.id);
    const ref = whenRef(step.when);
    if (ref) push(ref.kind, ref.step, step.id);
  }
  for (const step of spec.steps) {
    if (sources.has(step.id)) continue;
    edges.push({
      id: `terminal:${step.id}`,
      type: "flow",
      source: step.id,
      target: VERDICT_NODE,
      selectable: false,
      data: { kind: "terminal", running: false },
    });
  }

  return { nodes: [inputs, ...steps, verdict], edges };
}

// --- edges -------------------------------------------------------------------

/** `id` plus every step that waits on any member, transitively, in file order. */
function dependents(spec: FlowSpec, id: string): Set<string> {
  const members = new Set([id]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const step of spec.steps) {
      if (members.has(step.id)) continue;
      if (references(step).some((ref) => members.has(ref))) {
        members.add(step.id);
        grew = true;
      }
    }
  }
  return members;
}

/**
 * Draws a `needs` edge `source → target`. Forward connections just add the
 * entry; a backward one moves the target and its dependents to sit right
 * after the source, in their existing relative order, or is refused when
 * the source is itself one of those dependents (that would be a cycle).
 */
export function connect(spec: FlowSpec, source: string, target: string): Edit {
  if (source === target) {
    return refuse("a step cannot wait on itself", "connect two different steps");
  }
  const si = indexOf(spec, source);
  const ti = indexOf(spec, target);
  if (si < 0 || ti < 0) {
    const frame = [INPUTS_NODE, VERDICT_NODE].find((id) => id === source || id === target);
    return frame
      ? refuse(
          `the ${frame === INPUTS_NODE ? "Inputs" : "Verdict"} frame takes no edges`,
          "connect steps to each other; inputs and the verdict are implicit",
        )
      : refuse(`\`${si < 0 ? source : target}\` is not a step of this flow`, "pick a step");
  }
  if (references(spec.steps[ti]).includes(source)) return { ok: true, spec };

  let steps = spec.steps;
  if (ti < si) {
    const moving = dependents(spec, target);
    if (moving.has(source)) {
      return refuse(
        `\`${target}\` already runs before \`${source}\``,
        `remove the edge that makes \`${source}\` wait on \`${target}\` first`,
      );
    }
    const block = steps.filter((step) => moving.has(step.id));
    const rest = steps.filter((step) => !moving.has(step.id));
    const at = rest.findIndex((step) => step.id === source) + 1;
    steps = [...rest.slice(0, at), ...block, ...rest.slice(at)];
  }
  return {
    ok: true,
    spec: replaceStep({ ...spec, steps }, target, (step) => ({
      ...step,
      needs: [...step.needs, source],
    })),
  };
}

function refuse(cause: string, fix: string): Edit {
  return { ok: false, refused: { cause, fix } };
}

/** Removes a `needs` entry or resets a `when` edge to `needs_succeeded`. */
export function disconnect(spec: FlowSpec, id: string): FlowSpec {
  const edge = parseEdgeId(id);
  if (!edge || edge.kind === "terminal") return spec;
  return replaceStep(spec, edge.target, (step) => {
    if (edge.kind === "needs") {
      return { ...step, needs: step.needs.filter((need) => need !== edge.source) };
    }
    return whenRef(step.when)?.step === edge.source
      ? { ...step, when: "needs_succeeded" }
      : step;
  });
}

/**
 * Flips an edge between `needs` and a `when` condition. A `when` edge
 * replaces whatever `when` the step had — a step has one condition.
 */
export function setEdgeKind(spec: FlowSpec, id: string, kind: EditableEdgeKind): Edit {
  const edge = parseEdgeId(id);
  if (!edge || edge.kind === "terminal") {
    return refuse("that edge is implicit", "only needs and when edges change kind");
  }
  const target = spec.steps.find((step) => step.id === edge.target);
  if (!target || !references(target).includes(edge.source)) {
    return refuse(`no edge \`${edge.source}\` → \`${edge.target}\``, "select an edge first");
  }
  if (edge.kind === kind) return { ok: true, spec };
  const needs = target.needs.filter((need) => need !== edge.source);
  const next: FlowStep =
    kind === "needs"
      ? { ...target, needs: [...needs, edge.source], when: "needs_succeeded" }
      : { ...target, needs, when: { [kind]: edge.source } as FlowWhen };
  return { ok: true, spec: replaceStep(spec, edge.target, () => next) };
}

// --- steps -------------------------------------------------------------------

/** A step with every default `pam_flow` would resolve, ready to edit. */
export function defaultStep(id: string, kind: "command" | "connector"): FlowStep {
  return {
    id,
    action:
      kind === "command"
        ? { kind: "command", argv: ["git", "status"] }
        : { kind: "connector", connector: "github", call: "runs", with: {} },
    timeout: "5m",
    effect: "read_only",
    role: "observe",
    output: "compact",
    needs: [],
    when: "needs_succeeded",
    retry: { attempts: 1, backoff: "500ms" },
    approval: "none",
    env: {},
  };
}

/** Appends a default step under the first free `step-N` id. */
export function addStep(
  spec: FlowSpec,
  kind: "command" | "connector",
): { spec: FlowSpec; id: string } {
  const taken = new Set(spec.steps.map((step) => step.id));
  let n = 1;
  while (taken.has(`step-${n}`)) n += 1;
  const id = `step-${n}`;
  return { id, spec: { ...spec, steps: [...spec.steps, defaultStep(id, kind)] } };
}

/** Rewrites every reference to `from` as `to`; `to === null` drops it. */
function retarget(step: FlowStep, from: string, to: string | null): FlowStep {
  const needs = step.needs.flatMap((need) =>
    need !== from ? [need] : to === null ? [] : [to],
  );
  const ref = whenRef(step.when);
  let when = step.when;
  if (ref && ref.step === from) {
    when = to === null ? "needs_succeeded" : ({ [ref.kind]: to } as FlowWhen);
  }
  return { ...step, needs, when };
}

/** Drops a step and every `needs` / `when` reference to it. */
export function removeStep(spec: FlowSpec, id: string): FlowSpec {
  return {
    ...spec,
    steps: spec.steps.filter((step) => step.id !== id).map((step) => retarget(step, id, null)),
  };
}

/** Patches one step; renaming its id rewrites the references to it. */
export function updateStep(spec: FlowSpec, id: string, patch: Partial<FlowStep>): FlowSpec {
  const renamed = patch.id !== undefined && patch.id !== id ? patch.id : null;
  return {
    ...spec,
    steps: spec.steps.map((step) => {
      if (step.id === id) return { ...step, ...patch };
      return renamed === null ? step : retarget(step, id, renamed);
    }),
  };
}

/** Swaps a step with its neighbour, refusing when a reference would point forward. */
export function moveStep(spec: FlowSpec, id: string, direction: -1 | 1): Edit {
  const from = indexOf(spec, id);
  if (from < 0) return refuse(`\`${id}\` is not a step of this flow`, "pick a step");
  const to = from + direction;
  if (to < 0 || to >= spec.steps.length) {
    return refuse(
      `\`${id}\` is already ${direction < 0 ? "first" : "last"}`,
      "nothing to move it past",
    );
  }
  const steps = [...spec.steps];
  [steps[from], steps[to]] = [steps[to], steps[from]];
  const position = new Map(steps.map((step, index) => [step.id, index]));
  for (const step of steps) {
    const forward = references(step).find(
      (ref) => (position.get(ref) ?? -1) >= (position.get(step.id) ?? 0),
    );
    if (forward) {
      return refuse(
        `\`${step.id}\` waits on \`${forward}\`, which would then run after it`,
        `move \`${forward}\` too, or remove that edge first`,
      );
    }
  }
  return { ok: true, spec: { ...spec, steps } };
}

export function updateInputs(spec: FlowSpec, inputs: FlowSpec["inputs"]): FlowSpec {
  return { ...spec, inputs };
}

// --- graph → file ------------------------------------------------------------

function rawStep(step: FlowStep): RawFlowStep {
  const { action, ...rest } = step;
  if (action.kind === "command") return { ...rest, run: action.argv };
  return { ...rest, connector: action.connector, call: action.call, with: action.with };
}

/** The file's own shape — what `admin.flows.normalize { flow }` takes. */
export function toRaw(spec: FlowSpec): RawFlow {
  return {
    schema: 1,
    id: spec.id,
    name: spec.name,
    description: spec.description,
    inputs: spec.inputs,
    steps: spec.steps.map(rawStep),
  };
}

// --- argv --------------------------------------------------------------------

/** Splits on whitespace, keeping double-quoted tokens whole (quotes dropped). */
export function splitArgv(line: string): string[] {
  const argv: string[] = [];
  let token: string | null = null;
  let quoted = false;
  for (const char of line) {
    if (quoted) {
      if (char === '"') quoted = false;
      else token = (token ?? "") + char;
    } else if (char === '"') {
      quoted = true;
      token ??= "";
    } else if (/\s/.test(char)) {
      if (token !== null) argv.push(token);
      token = null;
    } else {
      token = (token ?? "") + char;
    }
  }
  if (token !== null) argv.push(token);
  return argv;
}

/** Joins with spaces, quoting tokens that are empty or contain whitespace. */
export function joinArgv(argv: string[]): string {
  return argv
    .map((token) => (token === "" || /\s/.test(token) ? `"${token}"` : token))
    .join(" ");
}
