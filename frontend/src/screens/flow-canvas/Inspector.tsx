import { ChevronDown, ChevronUp, Plus, X } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { FailureNote } from "../../components/ui/FailureNote";
import { fieldClasses, fieldLabelClasses } from "../../components/ui/field";
import { Panel } from "../../components/ui/Panel";
import { cn, cva } from "../../lib/cn";
import {
  FLOW_CONNECTORS,
  FLOW_CONNECTOR_CALLS,
  type FlowArgValue,
  type FlowConnectorId,
  type FlowSpec,
  type FlowSpecInput,
  type FlowStep,
} from "../../lib/ipc";
import type { Selection } from "./FlowCanvas";
import {
  INPUTS_NODE,
  edgeId,
  isStepId,
  joinArgv,
  markerFor,
  moveStep,
  setEdgeKind,
  splitArgv,
  updateInputs,
  updateStep,
  type EditableEdgeKind,
  type Refused,
} from "./graph";

/**
 * The selected thing, editable. One panel, four faces: the flow itself
 * when nothing is selected, the Inputs frame, a step, or an edge. Every
 * edit is a pure `graph.ts` function from one spec to the next; the two
 * checks the daemon would refuse anyway — a malformed or duplicate step
 * id, a move that puts a dependency after its dependent — stay here and
 * never reach the wire.
 */

export interface InspectorProps {
  spec: FlowSpec;
  selection: Selection;
  onChange: (spec: FlowSpec) => void;
  onSelect: (selection: Selection) => void;
  error: { path: string; message: string } | null;
}

const ID_RULE = "ids are [a-z0-9-], unique";

/** The two-state toggle the Flows tabs use, for the kind switch. */
const toggleVariants = cva(
  "h-8 rounded-control px-3 font-data text-xs transition-colors duration-150",
  {
    variants: {
      state: {
        active: "bg-accent-soft text-ink",
        idle: "text-ink-faint hover:text-ink",
      },
    },
    defaultVariants: { state: "idle" },
  },
);

const EFFECTS = ["read_only", "stateful"] as const;
const ROLES = ["observe", "verify", "change"] as const;
const OUTPUTS = ["compact", "summarize", "discard"] as const;
const APPROVALS = ["none", "required"] as const;
const EDGE_KINDS: readonly EditableEdgeKind[] = ["needs", "succeeded", "failed"];

// --- furniture ---------------------------------------------------------------

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block space-y-1">
      <span className={fieldLabelClasses}>{label}</span>
      {children}
    </label>
  );
}

function Eyebrow({ children }: { children: ReactNode }) {
  return (
    <p className="font-data text-xs tracking-widest text-ink-faint uppercase">{children}</p>
  );
}

function Group({ children }: { children: ReactNode }) {
  return <div className="space-y-3 border-t border-line pt-3">{children}</div>;
}

function Refusal({ refused, label }: { refused: Refused; label: string }) {
  return (
    <p aria-label={label} className="font-data text-xs text-danger">
      {refused.cause} — {refused.fix}
    </p>
  );
}

function Select<T extends string>({
  label,
  value,
  options,
  onChange,
  disabled,
}: {
  label: string;
  value: T;
  options: readonly T[];
  onChange: (value: T) => void;
  disabled?: boolean;
}) {
  return (
    <Field label={label}>
      <select
        aria-label={label}
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value as T)}
        className={cn(fieldClasses, "disabled:opacity-60")}
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </Field>
  );
}

/** Replaces one key of a record, keeping the others in place. */
function renameKey<V>(record: Record<string, V>, from: string, to: string): Record<string, V> {
  return Object.fromEntries(
    Object.entries(record).map(([key, value]) => [key === from ? to : key, value]),
  );
}

function withoutKey<V>(record: Record<string, V>, key: string): Record<string, V> {
  return Object.fromEntries(Object.entries(record).filter(([candidate]) => candidate !== key));
}

/** The first `prefix-N` (or `prefix_N`) not already taken. */
function freeName(taken: Iterable<string>, prefix: string, joint = "-"): string {
  const used = new Set(taken);
  let n = 1;
  while (used.has(`${prefix}${joint}${n}`)) n += 1;
  return `${prefix}${joint}${n}`;
}

// --- the flow ----------------------------------------------------------------

function FlowFields({
  spec,
  onChange,
}: {
  spec: FlowSpec;
  onChange: (spec: FlowSpec) => void;
}) {
  return (
    <>
      <Field label="flow name">
        <input
          aria-label="flow name"
          value={spec.name}
          onChange={(event) => onChange({ ...spec, name: event.target.value })}
          className={fieldClasses}
        />
      </Field>
      <Field label="flow description">
        <textarea
          aria-label="flow description"
          rows={3}
          value={spec.description}
          onChange={(event) => onChange({ ...spec, description: event.target.value })}
          className={cn(fieldClasses, "h-auto resize-y py-1.5 leading-relaxed")}
        />
      </Field>
      <p className="font-voice text-sm text-ink-muted italic">
        Pick a step to edit it; drag from one handle to another to make a step wait.
      </p>
    </>
  );
}

// --- the inputs frame --------------------------------------------------------

function InputsFields({
  spec,
  onChange,
}: {
  spec: FlowSpec;
  onChange: (spec: FlowSpec) => void;
}) {
  const inputs = spec.inputs;
  const write = (next: Record<string, FlowSpecInput>) => onChange(updateInputs(spec, next));
  const patch = (name: string, change: Partial<FlowSpecInput>) =>
    write({ ...inputs, [name]: { ...inputs[name], ...change } });
  const names = Object.keys(inputs);
  return (
    <>
      {names.length === 0 && (
        <p className="font-voice text-sm text-ink-muted italic">
          This flow takes no inputs; every step runs as written.
        </p>
      )}
      {names.map((name, index) => (
        <div key={index} className="space-y-2 rounded-card border border-line p-3">
          <div className="flex items-center gap-2">
            <input
              aria-label="input name"
              value={name}
              onChange={(event) => write(renameKey(inputs, name, event.target.value))}
              className={cn(fieldClasses, "flex-1")}
            />
            <Button
              variant="ghost"
              size="sm"
              aria-label={`remove ${name}`}
              onClick={() => write(withoutKey(inputs, name))}
              className="px-2"
            >
              <X size={14} aria-hidden="true" />
            </Button>
          </div>
          <input
            aria-label="input description"
            placeholder="what this input is for"
            value={inputs[name].description}
            onChange={(event) => patch(name, { description: event.target.value })}
            className={fieldClasses}
          />
          <input
            aria-label="input default"
            placeholder="default — empty means required"
            value={inputs[name].default ?? ""}
            onChange={(event) =>
              patch(name, { default: event.target.value === "" ? null : event.target.value })
            }
            className={fieldClasses}
          />
        </div>
      ))}
      <Button
        variant="ghost"
        size="sm"
        onClick={() =>
          write({ ...inputs, [freeName(names, "input")]: { description: "", default: null } })
        }
      >
        <Plus size={14} aria-hidden="true" />
        Add input
      </Button>
    </>
  );
}

// --- a step ------------------------------------------------------------------

function whenText(step: FlowStep): string {
  if (step.when === "always") return "runs always";
  if (step.when === "needs_succeeded") return "runs when needs succeeded";
  if ("succeeded" in step.when) return `runs when ${step.when.succeeded} succeeded`;
  return `runs when ${step.when.failed} failed`;
}

/** The `with` map a call starts with: every required argument, empty. */
function requiredWith(connector: FlowConnectorId, call: string): Record<string, FlowArgValue> {
  const spec = FLOW_CONNECTOR_CALLS[connector].find((candidate) => candidate.name === call);
  return Object.fromEntries(
    (spec?.args ?? []).filter((arg) => arg.required).map((arg) => [arg.name, ""]),
  );
}

function argValue(text: string): FlowArgValue {
  return /^-?\d+$/.test(text) ? Number(text) : text;
}

function clampAttempts(raw: string): number {
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed)) return 1;
  return Math.min(5, Math.max(1, parsed));
}

function ArgvLine({ step, commit }: { step: FlowStep; commit: (argv: string[]) => void }) {
  const current = step.action.kind === "command" ? joinArgv(step.action.argv) : "";
  const [line, setLine] = useState(current);
  useEffect(() => setLine(current), [current, step.id]);
  const flush = () => {
    if (line !== current) commit(splitArgv(line));
  };
  return (
    <Field label="argv">
      <input
        aria-label="argv"
        value={line}
        onChange={(event) => setLine(event.target.value)}
        onBlur={flush}
        onKeyDown={(event) => {
          if (event.key === "Enter") flush();
        }}
        placeholder='git status --porcelain  ·  quote "two words" to keep them whole'
        className={fieldClasses}
      />
    </Field>
  );
}

function ConnectorFields({
  step,
  patch,
}: {
  step: FlowStep;
  patch: (change: Partial<FlowStep>) => void;
}) {
  if (step.action.kind !== "connector") return null;
  const action = step.action;
  const calls = FLOW_CONNECTOR_CALLS[action.connector];
  const call = calls.find((candidate) => candidate.name === action.call);
  const known = (call?.args ?? []).map((arg) => arg.name);
  const extra = Object.keys(action.with).filter((name) => !known.includes(name));
  const rows = [...(call?.args ?? []), ...extra.map((name) => ({ name, required: false }))];
  const setWith = (name: string, required: boolean, text: string) => {
    const next = { ...action.with };
    if (text === "" && !required) delete next[name];
    else next[name] = argValue(text);
    patch({ action: { ...action, with: next } });
  };
  return (
    <>
      <Select
        label="connector"
        value={action.connector}
        options={FLOW_CONNECTORS}
        onChange={(connector) => {
          const first = FLOW_CONNECTOR_CALLS[connector][0]?.name ?? "";
          patch({
            action: {
              kind: "connector",
              connector,
              call: first,
              with: requiredWith(connector, first),
            },
          });
        }}
      />
      <Select
        label="call"
        value={action.call}
        options={calls.map((candidate) => candidate.name)}
        onChange={(name) => {
          const keep = Object.fromEntries(
            Object.entries(action.with).filter(([key]) =>
              FLOW_CONNECTOR_CALLS[action.connector]
                .find((candidate) => candidate.name === name)
                ?.args.some((arg) => arg.name === key),
            ),
          );
          patch({
            action: {
              ...action,
              call: name,
              with: { ...requiredWith(action.connector, name), ...keep },
            },
          });
        }}
      />
      {rows.length > 0 && (
        <div className="space-y-2">
          <span className={fieldLabelClasses}>with</span>
          {rows.map((arg) => (
            <div key={arg.name} className="flex items-center gap-2">
              <span className="w-20 shrink-0 truncate font-data text-xs text-ink-muted">
                {arg.name}
              </span>
              <input
                aria-label={`with ${arg.name}`}
                required={arg.required || undefined}
                placeholder={arg.required ? "required" : "optional"}
                value={String(action.with[arg.name] ?? "")}
                onChange={(event) => setWith(arg.name, arg.required, event.target.value)}
                className={cn(fieldClasses, "flex-1")}
              />
            </div>
          ))}
        </div>
      )}
    </>
  );
}

function EnvRows({
  step,
  patch,
}: {
  step: FlowStep;
  patch: (change: Partial<FlowStep>) => void;
}) {
  const names = Object.keys(step.env);
  const write = (env: Record<string, string>) => patch({ env });
  return (
    <div className="space-y-2">
      <span className={fieldLabelClasses}>env</span>
      {names.map((name, index) => (
        <div key={index} className="flex items-center gap-2">
          <input
            aria-label="env name"
            value={name}
            onChange={(event) => write(renameKey(step.env, name, event.target.value))}
            className={cn(fieldClasses, "w-28 shrink-0")}
          />
          <input
            aria-label="env value"
            value={step.env[name]}
            onChange={(event) => write({ ...step.env, [name]: event.target.value })}
            className={cn(fieldClasses, "flex-1")}
          />
          <Button
            variant="ghost"
            size="sm"
            aria-label={`remove ${name}`}
            onClick={() => write(withoutKey(step.env, name))}
            className="px-2"
          >
            <X size={14} aria-hidden="true" />
          </Button>
        </div>
      ))}
      <Button
        variant="ghost"
        size="sm"
        onClick={() => write({ ...step.env, [freeName(names, "VAR", "_")]: "" })}
      >
        <Plus size={14} aria-hidden="true" />
        Add env
      </Button>
    </div>
  );
}

function StepFields({
  spec,
  step,
  onChange,
  onSelect,
}: {
  spec: FlowSpec;
  step: FlowStep;
  onChange: (spec: FlowSpec) => void;
  onSelect: (selection: Selection) => void;
}) {
  const [draftId, setDraftId] = useState(step.id);
  useEffect(() => setDraftId(step.id), [step.id]);
  const patch = (change: Partial<FlowStep>) => onChange(updateStep(spec, step.id, change));

  const idTaken = (id: string) =>
    id !== step.id && spec.steps.some((candidate) => candidate.id === id);
  const idValid = isStepId(draftId) && !idTaken(draftId);
  const rename = (id: string) => {
    setDraftId(id);
    if (id === step.id || !isStepId(id) || idTaken(id)) return;
    onChange(updateStep(spec, step.id, { id }));
    onSelect({ kind: "step", id });
  };

  const stateful = step.effect === "stateful";
  const kind = step.action.kind;
  const flipKind = (next: "command" | "connector") => {
    if (next === kind) return;
    patch({
      action:
        next === "command"
          ? { kind: "command", argv: ["git", "status"] }
          : {
              kind: "connector",
              connector: "github",
              call: FLOW_CONNECTOR_CALLS.github[0].name,
              with: requiredWith("github", FLOW_CONNECTOR_CALLS.github[0].name),
            },
    });
  };

  return (
    <>
      <Field label="step id">
        <input
          aria-label="step id"
          value={draftId}
          onChange={(event) => rename(event.target.value)}
          className={cn(fieldClasses, !idValid && "border-danger")}
        />
      </Field>
      {!idValid && <p className="font-data text-xs text-danger">{ID_RULE}</p>}

      <div className="flex items-center gap-1" role="group" aria-label="kind">
        {(["command", "connector"] as const).map((candidate) => (
          <button
            key={candidate}
            type="button"
            aria-pressed={kind === candidate}
            onClick={() => flipKind(candidate)}
            className={toggleVariants({ state: kind === candidate ? "active" : "idle" })}
          >
            {candidate}
          </button>
        ))}
      </div>

      {kind === "command" ? (
        <ArgvLine step={step} commit={(argv) => patch({ action: { kind: "command", argv } })} />
      ) : (
        <ConnectorFields step={step} patch={patch} />
      )}

      <Group>
        <Field label="timeout">
          <input
            aria-label="timeout"
            value={step.timeout}
            onChange={(event) => patch({ timeout: event.target.value })}
            placeholder="5m"
            className={fieldClasses}
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Select
            label="effect"
            value={step.effect}
            options={EFFECTS}
            onChange={(effect) =>
              patch(effect === "stateful" ? { effect, approval: "required" } : { effect })
            }
          />
          <Select
            label="role"
            value={step.role}
            options={ROLES}
            onChange={(role) => patch({ role })}
          />
          <Select
            label="output"
            value={step.output}
            options={OUTPUTS}
            onChange={(output) => patch({ output })}
          />
          <Select
            label="approval"
            value={stateful ? "required" : step.approval}
            options={APPROVALS}
            disabled={stateful}
            onChange={(approval) => patch({ approval })}
          />
        </div>
        {stateful && (
          <p className="font-data text-xs text-ink-muted">
            stateful steps always need approval
          </p>
        )}
      </Group>

      <Group>
        <div className="grid grid-cols-2 gap-3">
          <Field label="retry attempts">
            <input
              aria-label="retry attempts"
              type="number"
              min={1}
              max={5}
              value={step.retry.attempts}
              onChange={(event) =>
                patch({ retry: { ...step.retry, attempts: clampAttempts(event.target.value) } })
              }
              className={fieldClasses}
            />
          </Field>
          <Field label="retry backoff">
            <input
              aria-label="retry backoff"
              value={step.retry.backoff}
              onChange={(event) =>
                patch({ retry: { ...step.retry, backoff: event.target.value } })
              }
              placeholder="500ms"
              className={fieldClasses}
            />
          </Field>
        </div>
        <p aria-label="when" className="font-voice text-sm text-ink-muted italic">
          {whenText(step)}
        </p>
      </Group>

      {kind === "command" && (
        <Group>
          <EnvRows step={step} patch={patch} />
        </Group>
      )}
    </>
  );
}

// --- the step list -----------------------------------------------------------

function StepList({
  spec,
  selection,
  onChange,
  onSelect,
}: {
  spec: FlowSpec;
  selection: Selection;
  onChange: (spec: FlowSpec) => void;
  onSelect: (selection: Selection) => void;
}) {
  const [refused, setRefused] = useState<Refused | null>(null);
  const move = (id: string, direction: -1 | 1) => {
    const edit = moveStep(spec, id, direction);
    if (edit.ok) {
      setRefused(null);
      onChange(edit.spec);
    } else {
      setRefused(edit.refused);
    }
  };
  const last = spec.steps.length - 1;
  return (
    <Group>
      <Eyebrow>steps · in order</Eyebrow>
      <ol className="space-y-1">
        {spec.steps.map((step, index) => {
          const selected = selection.kind === "step" && selection.id === step.id;
          return (
            <li key={step.id} className="flex items-center gap-1">
              <span className="w-5 font-display text-xs font-semibold text-ink-faint tabular-nums">
                {index + 1}
              </span>
              <button
                type="button"
                aria-label={`select ${step.id}`}
                aria-pressed={selected}
                onClick={() => onSelect({ kind: "step", id: step.id })}
                className={cn(
                  toggleVariants({ state: selected ? "active" : "idle" }),
                  "min-w-0 flex-1 truncate text-left",
                )}
              >
                {step.id}
              </button>
              <button
                type="button"
                aria-label={`move ${step.id} up`}
                disabled={index === 0}
                onClick={() => move(step.id, -1)}
                className="rounded-control p-1 text-ink-faint hover:text-ink disabled:opacity-30"
              >
                <ChevronUp size={14} aria-hidden="true" />
              </button>
              <button
                type="button"
                aria-label={`move ${step.id} down`}
                disabled={index === last}
                onClick={() => move(step.id, 1)}
                className="rounded-control p-1 text-ink-faint hover:text-ink disabled:opacity-30"
              >
                <ChevronDown size={14} aria-hidden="true" />
              </button>
            </li>
          );
        })}
      </ol>
      {refused && <Refusal refused={refused} label="move refused" />}
    </Group>
  );
}

// --- an edge -----------------------------------------------------------------

function parseEdge(
  id: string,
): { kind: EditableEdgeKind; source: string; target: string } | null {
  const match = /^(needs|succeeded|failed):(.+)->(.+)$/.exec(id);
  return match
    ? { kind: match[1] as EditableEdgeKind, source: match[2], target: match[3] }
    : null;
}

function EdgeFields({
  spec,
  id,
  onChange,
  onSelect,
}: {
  spec: FlowSpec;
  id: string;
  onChange: (spec: FlowSpec) => void;
  onSelect: (selection: Selection) => void;
}) {
  const [refused, setRefused] = useState<Refused | null>(null);
  const edge = parseEdge(id);
  if (!edge) {
    return <p className="font-voice text-sm text-ink-muted italic">That edge is implicit.</p>;
  }
  const flip = (kind: EditableEdgeKind) => {
    const edit = setEdgeKind(spec, id, kind);
    if (!edit.ok) {
      setRefused(edit.refused);
      return;
    }
    setRefused(null);
    onChange(edit.spec);
    onSelect({ kind: "edge", id: edgeId(kind, edge.source, edge.target) });
  };
  return (
    <>
      <p aria-label="edge" className="font-data text-sm text-ink">
        {edge.source} → {edge.target}
      </p>
      <fieldset className="space-y-2" aria-label="edge kind">
        {EDGE_KINDS.map((kind) => (
          <label key={kind} className="flex items-center gap-2 font-data text-xs text-ink">
            <input
              type="radio"
              name="edge-kind"
              aria-label={kind}
              value={kind}
              checked={edge.kind === kind}
              onChange={() => flip(kind)}
              className="accent-accent"
            />
            {kind}
            <span className="text-ink-faint">
              {kind === "needs" ? "wait for it to succeed" : `only if it ${kind}`}
            </span>
          </label>
        ))}
      </fieldset>
      {refused && <Refusal refused={refused} label="edge refused" />}
    </>
  );
}

// --- the panel ---------------------------------------------------------------

function title(selection: Selection): string {
  switch (selection.kind) {
    case "none":
      return "flow";
    case "inputs":
      return "inputs";
    case "step":
      return `step · ${selection.id}`;
    case "edge":
      return "edge";
  }
}

export function Inspector({ spec, selection, onChange, onSelect, error }: InspectorProps) {
  const { node } = markerFor(error, spec);
  const errorHere =
    error !== null &&
    ((selection.kind === "step" && node === selection.id) ||
      (selection.kind === "inputs" && node === INPUTS_NODE) ||
      (selection.kind === "none" && node === null));
  const step =
    selection.kind === "step"
      ? spec.steps.find((candidate) => candidate.id === selection.id)
      : undefined;

  return (
    <Panel ground="raised" aria-label="inspector" className="space-y-4 p-4">
      <div className="flex items-center gap-2">
        <Eyebrow>inspector</Eyebrow>
        <Badge tone={selection.kind === "none" ? "neutral" : "accent"}>
          {title(selection)}
        </Badge>
      </div>

      {errorHere && error && (
        <FailureNote
          label="flow"
          failure={{
            cause: error.message,
            detail: `at \`${error.path}\``,
            recovery: "fix it here and I will check the flow again",
          }}
        />
      )}

      {selection.kind === "inputs" ? (
        <InputsFields spec={spec} onChange={onChange} />
      ) : selection.kind === "edge" ? (
        <EdgeFields spec={spec} id={selection.id} onChange={onChange} onSelect={onSelect} />
      ) : step ? (
        <StepFields
          key={step.id}
          spec={spec}
          step={step}
          onChange={onChange}
          onSelect={onSelect}
        />
      ) : (
        <FlowFields spec={spec} onChange={onChange} />
      )}

      {selection.kind !== "edge" && (
        <StepList spec={spec} selection={selection} onChange={onChange} onSelect={onSelect} />
      )}
    </Panel>
  );
}
