import { Handle, Position, type NodeProps } from "@xyflow/react";
import {
  CircleAlert,
  Clock,
  EyeOff,
  Hand,
  Pencil,
  Plug,
  RotateCw,
  Sparkles,
  Terminal,
  type LucideIcon,
} from "lucide-react";
import { memo } from "react";
import { Badge } from "../../components/ui/Badge";
import { FailureNote } from "../../components/ui/FailureNote";
import { Panel } from "../../components/ui/Panel";
import { cn, cva } from "../../lib/cn";
import type { FlowStep } from "../../lib/ipc";
import {
  NOTE_HANDLE,
  joinArgv,
  type RunStatus,
  type StepNode as StepNodeType,
  type StepNodeData,
} from "./graph";
import { HIDDEN_HANDLE_CLASSES } from "./NoteNode";

/**
 * A step as a rail card: a raised Panel two rows deep with a 4 px rail
 * down its left edge. The rail is the run's voice — it takes the status
 * color and breathes while the step runs — so a whole flow's progress
 * reads as a column of colored edges before a single word is read.
 *
 * The header names the step (kind glyph, id in the display voice, the
 * modifier glyphs, the order number); the second row is the fact of what
 * runs, in the data voice, one line. The role rides along as the id's
 * title. The ring means exactly one thing, selection — except that a
 * validation marker borrows it in danger, with the chip and the cause /
 * fix note saying why.
 */

export type Ring = "none" | "selected" | "invalid";
export type Rail = "none" | RunStatus;

/** The ring: selection, or the validator's danger. Nothing else touches it. */
export const stepNodeVariants = cva(
  "relative w-56 p-0 ring-offset-2 ring-offset-chrome transition-shadow duration-150",
  {
    variants: {
      ring: {
        none: "ring-0",
        selected: "ring-2 ring-accent",
        invalid: "ring-2 ring-danger",
      },
    },
    defaultVariants: { ring: "none" },
  },
);

/** The rail: one semantic color per run status, the hairline when idle. */
export const railVariants = cva("w-1 shrink-0 self-stretch transition-colors duration-300", {
  variants: {
    status: {
      none: "bg-line",
      running: "bg-accent animate-breathe",
      succeeded: "bg-success",
      failed: "bg-danger",
      blocked: "bg-danger",
      skipped: "bg-ink-faint",
      cancelled: "warm-marker bg-warning",
    },
  },
  defaultVariants: { status: "none" },
});

/** The kind glyph: commands in the accent, connectors in copper. */
export const glyphVariants = cva("flex shrink-0", {
  variants: {
    kind: {
      command: "text-accent",
      connector: "warm-label text-ink-muted",
    },
  },
  defaultVariants: { kind: "command" },
});

/** Fixed anchors; the token stylesheet expands hit/visible areas in screen pixels. */
export const HANDLE_CLASSES = "flow-connection-handle rounded-pill";

/** A validation marker outranks selection: the flow will not run until it is fixed. */
export function ringFor(data: StepNodeData, selected: boolean): Ring {
  if (data.marker) return "invalid";
  if (selected) return "selected";
  return "none";
}

export function railFor(data: StepNodeData): Rail {
  return data.status ?? "none";
}

const DEFAULT_TIMEOUT = "5m";
const DEFAULT_RETRY = { attempts: 1, backoff: "500ms" };

/** What the second row says: the argv line, or `connector · call`. */
export function stepBody(step: FlowStep): string {
  return step.action.kind === "command"
    ? joinArgv(step.action.argv)
    : `${step.action.connector} · ${step.action.call}`;
}

function retryIsDefault(retry: FlowStep["retry"]): boolean {
  return retry.attempts === DEFAULT_RETRY.attempts && retry.backoff === DEFAULT_RETRY.backoff;
}

export interface Modifier {
  /** The aria-label screen readers and the tests read. */
  label: string;
  /** The tooltip, carrying the value the glyph stands for. */
  title: string;
  tone: string;
  Icon: LucideIcon;
}

/** The modifier glyphs, in the order the spec's modifier table lists them. */
export function modifiersOf(step: FlowStep): Modifier[] {
  const glyphs: Modifier[] = [];
  if (step.approval === "required") {
    glyphs.push({
      label: "approval",
      title: "approval required",
      tone: "text-warning",
      Icon: Hand,
    });
  }
  if (step.effect === "stateful") {
    glyphs.push({
      label: "stateful",
      title: "changes state",
      tone: "warm-label text-ink-muted",
      Icon: Pencil,
    });
  }
  if (step.output === "summarize") {
    glyphs.push({
      label: "summarize",
      title: "output summarized",
      tone: "text-accent",
      Icon: Sparkles,
    });
  }
  if (step.output === "discard") {
    glyphs.push({
      label: "discard",
      title: "output discarded",
      tone: "text-ink-faint",
      Icon: EyeOff,
    });
  }
  if (!retryIsDefault(step.retry)) {
    glyphs.push({
      label: "retry",
      title: `retry ×${step.retry.attempts} / ${step.retry.backoff}`,
      tone: "text-ink-faint",
      Icon: RotateCw,
    });
  }
  if (step.timeout !== DEFAULT_TIMEOUT) {
    glyphs.push({
      label: "timeout",
      title: `timeout ${step.timeout}`,
      tone: "text-ink-faint",
      Icon: Clock,
    });
  }
  return glyphs;
}

function StepNodeComponent({ data, selected }: NodeProps<StepNodeType>) {
  const { step, index, marker } = data;
  const kind = step.action.kind;
  const Glyph = kind === "command" ? Terminal : Plug;
  const rail = railFor(data);
  const modifiers = modifiersOf(step);
  return (
    <Panel
      ground="raised"
      aria-label={`step ${step.id}`}
      data-kind={kind}
      data-status={rail}
      className={cn(stepNodeVariants({ ring: ringFor(data, selected === true) }))}
    >
      <Handle type="target" position={Position.Left} className={HANDLE_CLASSES} />
      <Handle
        type="target"
        id={NOTE_HANDLE}
        position={Position.Top}
        isConnectable={false}
        className={HIDDEN_HANDLE_CLASSES}
      />

      <div className="flex overflow-hidden rounded-card">
        <span
          data-testid="rail"
          aria-hidden="true"
          className={railVariants({ status: rail })}
        />

        <div className="min-w-0 flex-1 px-3 py-2.5">
          <header className="flex items-center gap-1.5">
            <span role="img" aria-label={kind} className={glyphVariants({ kind })}>
              <Glyph size={12} aria-hidden="true" />
            </span>
            <span
              title={step.role}
              className="min-w-0 flex-1 truncate font-display text-sm font-semibold text-ink"
            >
              {step.id}
            </span>
            {modifiers.length > 0 && (
              <span className="flex shrink-0 items-center gap-1">
                {modifiers.map(({ label, title, tone, Icon }) => (
                  <span
                    key={label}
                    role="img"
                    aria-label={label}
                    title={title}
                    className={cn("flex", tone)}
                  >
                    <Icon size={12} aria-hidden="true" />
                  </span>
                ))}
              </span>
            )}
            {marker && (
              <Badge
                tone="danger"
                aria-label="validation marker"
                title={marker.message}
                className="px-1.5"
              >
                <CircleAlert size={12} aria-hidden="true" />
              </Badge>
            )}
            <span
              aria-label={`order ${index + 1}`}
              className="shrink-0 font-data text-xs text-ink-faint tabular-nums"
            >
              {index + 1}
            </span>
          </header>

          <p className="mt-0.5 truncate font-data text-xs text-ink-muted">{stepBody(step)}</p>

          {selected && marker && (
            <div className="pt-2.5">
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
        </div>
      </div>

      <Handle type="source" position={Position.Right} className={HANDLE_CLASSES} />
    </Panel>
  );
}

export const StepNode = memo(StepNodeComponent);
