import { Handle, Position, type NodeProps } from "@xyflow/react";
import { CircleAlert, Clock, Hand, Plug, RotateCw, Sparkles, Terminal } from "lucide-react";
import { memo } from "react";
import { Badge } from "../../components/ui/Badge";
import { FailureNote } from "../../components/ui/FailureNote";
import { Panel } from "../../components/ui/Panel";
import { cn, cva } from "../../lib/cn";
import type { FlowStep } from "../../lib/ipc";
import { joinArgv, type StepNode as StepNodeType, type StepNodeData } from "./graph";

/**
 * A step card: a raised Panel standing on the chrome, three rows deep.
 * The header names the step (kind glyph, id in the display voice, its
 * role as a mono eyebrow, the order chip); the body is the fact of what
 * runs, in the data voice, two lines and no more; the footer carries the
 * modifiers as chips. Everything a run or a validator has to say about
 * the step is a 2 px ring around the card — one ring, one meaning.
 */

export type Rim =
  | "none"
  | "selected"
  | "running"
  | "succeeded"
  | "failed"
  | "skipped"
  | "blocked"
  | "cancelled"
  | "invalid"
  | "approval";

/** The rim map: every state is a ring in a semantic color, nothing else. */
export const stepNodeVariants = cva(
  "relative w-56 p-0 ring-offset-2 ring-offset-chrome transition-shadow duration-150",
  {
    variants: {
      rim: {
        none: "ring-0",
        selected: "ring-2 ring-accent",
        running: "ring-2 ring-accent animate-breathe",
        succeeded: "ring-2 ring-success",
        failed: "ring-2 ring-danger",
        skipped: "ring-2 ring-ink-faint",
        blocked: "ring-2 ring-danger",
        cancelled: "ring-2 ring-warning",
        invalid: "ring-2 ring-danger",
        approval: "ring-2 ring-warning/60",
      },
    },
    defaultVariants: { rim: "none" },
  },
);

/** The kind glyph's tile: commands sit on the accent, connectors on copper. */
export const glyphVariants = cva(
  "flex size-6 shrink-0 items-center justify-center rounded-control",
  {
    variants: {
      kind: {
        command: "bg-accent-soft text-accent",
        connector: "bg-copper/15 text-copper",
      },
    },
    defaultVariants: { kind: "command" },
  },
);

/** Handles: 10 px pills in the line color, accent when the pointer finds them. */
export const HANDLE_CLASSES = "size-2.5 rounded-pill bg-line hover:bg-accent";

/**
 * Which ring the card wears. A validation marker outranks everything (the
 * flow will not run until it is fixed), a run status outranks selection
 * (the run is what the human is watching), selection outranks the standing
 * approval rim, and a card with nothing to say wears no ring at all.
 */
export function rimFor(data: StepNodeData, selected: boolean): Rim {
  if (data.marker) return "invalid";
  if (data.status) return data.status;
  if (selected) return "selected";
  if (data.step.approval === "required") return "approval";
  return "none";
}

const DEFAULT_TIMEOUT = "5m";
const DEFAULT_RETRY = { attempts: 1, backoff: "500ms" };

/** What the body says: the argv line, or `connector · call`. */
export function stepBody(step: FlowStep): string {
  return step.action.kind === "command"
    ? joinArgv(step.action.argv)
    : `${step.action.connector} · ${step.action.call}`;
}

function retryIsDefault(retry: FlowStep["retry"]): boolean {
  return retry.attempts === DEFAULT_RETRY.attempts && retry.backoff === DEFAULT_RETRY.backoff;
}

/** The footer chips, in the order the spec's modifier table lists them. */
function Modifiers({ step }: { step: FlowStep }) {
  const chips = [
    step.approval === "required" && (
      <Badge key="approval" tone="warning" aria-label="approval">
        <Hand size={12} aria-hidden="true" />
        approval
      </Badge>
    ),
    step.effect === "stateful" && (
      <Badge
        key="stateful"
        tone="neutral"
        aria-label="stateful"
        className="border-copper/40 bg-copper/10 text-copper"
      >
        changes
      </Badge>
    ),
    step.output === "summarize" && (
      <Badge key="summarize" tone="accent" aria-label="summarize">
        <Sparkles size={12} aria-hidden="true" />
        summarize
      </Badge>
    ),
    step.output === "discard" && (
      <Badge key="discard" tone="neutral" aria-label="discard">
        discard
      </Badge>
    ),
    !retryIsDefault(step.retry) && (
      <Badge key="retry" tone="neutral" aria-label="retry">
        <RotateCw size={12} aria-hidden="true" />×{step.retry.attempts} / {step.retry.backoff}
      </Badge>
    ),
    step.timeout !== DEFAULT_TIMEOUT && (
      <Badge key="timeout" tone="neutral" aria-label="timeout">
        <Clock size={12} aria-hidden="true" />
        {step.timeout}
      </Badge>
    ),
    step.when === "always" && (
      <Badge key="always" tone="neutral" aria-label="always">
        always
      </Badge>
    ),
  ].filter(Boolean);
  if (chips.length === 0) {
    return <span className="font-data text-xs text-ink-faint">defaults</span>;
  }
  return <>{chips}</>;
}

function StepNodeComponent({ data, selected }: NodeProps<StepNodeType>) {
  const { step, index, marker } = data;
  const kind = step.action.kind;
  const Glyph = kind === "command" ? Terminal : Plug;
  return (
    <Panel
      ground="raised"
      aria-label={`step ${step.id}`}
      data-kind={kind}
      className={cn(stepNodeVariants({ rim: rimFor(data, selected === true) }))}
    >
      <Handle type="target" position={Position.Left} className={HANDLE_CLASSES} />

      <header className="flex items-start gap-2.5 border-b border-line px-3 py-2.5">
        <span role="img" aria-label={kind} className={glyphVariants({ kind })}>
          <Glyph size={14} aria-hidden="true" />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate font-display text-sm font-semibold text-ink">
            {step.id}
          </span>
          <span className="block font-data text-xs tracking-widest text-ink-faint uppercase">
            {step.role}
          </span>
        </span>
        {marker && (
          <Badge tone="danger" aria-label="validation marker" title={marker.message}>
            <CircleAlert size={12} aria-hidden="true" />
          </Badge>
        )}
        <Badge tone="neutral" aria-label={`order ${index + 1}`} className="tabular-nums">
          {index + 1}
        </Badge>
      </header>

      <p className="line-clamp-2 px-3 py-2 font-data text-xs break-all text-ink-muted">
        {stepBody(step)}
      </p>

      <footer className="flex flex-wrap items-center gap-1.5 border-t border-line px-3 py-2">
        <Modifiers step={step} />
      </footer>

      {selected && marker && (
        <div className="px-3 pb-3">
          <FailureNote
            label="flow"
            failure={{
              cause: marker.message,
              detail: marker.field ? `at \`${marker.field}\`` : "on this step",
              recovery: "fix it in the inspector",
            }}
          />
        </div>
      )}

      <Handle type="source" position={Position.Right} className={HANDLE_CLASSES} />
    </Panel>
  );
}

export const StepNode = memo(StepNodeComponent);
