import { Handle, Position, type NodeProps } from "@xyflow/react";
import { CircleAlert, Flag, SlidersHorizontal } from "lucide-react";
import { memo, type ReactNode } from "react";
import { Badge } from "../../components/ui/Badge";
import { Panel } from "../../components/ui/Panel";
import { cn, cva } from "../../lib/cn";
import type { OutcomeName } from "../../lib/ipc";
import { OUTCOME_TONES } from "../FlowRunCard";
import type { InputsNode, VerdictNode } from "./graph";
import { HANDLE_CLASSES } from "./StepNode";

/**
 * The two fixed frames. They are surface Panels, not raised cards, so
 * they read as the deck the steps stand on: Inputs is where a run starts
 * (the declared inputs, `name = default`), Verdict is where it ends (the
 * five outcome chips, grey until a run paints one).
 */

export const frameVariants = cva("w-50 p-0 ring-offset-2 ring-offset-chrome", {
  variants: {
    rim: {
      none: "ring-0",
      selected: "ring-2 ring-accent",
      invalid: "ring-2 ring-danger",
    },
  },
  defaultVariants: { rim: "none" },
});

const OUTCOMES: readonly OutcomeName[] = [
  "solved",
  "changed",
  "verified",
  "unresolved",
  "blocked",
];

function FrameHeader({
  glyph,
  title,
  marker,
}: {
  glyph: ReactNode;
  title: string;
  marker?: { message: string } | null;
}) {
  return (
    <header className="flex items-center gap-2 border-b border-line px-3 py-2.5">
      <span className="flex size-6 shrink-0 items-center justify-center rounded-control bg-surface-raised text-ink-muted">
        {glyph}
      </span>
      <span className="flex-1 font-display text-sm font-semibold text-ink">{title}</span>
      {marker && (
        <Badge tone="danger" aria-label="validation marker" title={marker.message}>
          <CircleAlert size={12} aria-hidden="true" />
        </Badge>
      )}
    </header>
  );
}

function InputsFrame({ data, selected }: NodeProps<InputsNode>) {
  const names = Object.keys(data.inputs);
  const rim = data.marker ? "invalid" : selected ? "selected" : "none";
  return (
    <Panel aria-label="inputs frame" className={cn(frameVariants({ rim }))}>
      <FrameHeader
        glyph={<SlidersHorizontal size={14} aria-hidden="true" />}
        title="Inputs"
        marker={data.marker}
      />
      {names.length === 0 ? (
        <p className="px-3 py-2.5 font-voice text-sm text-ink-muted italic">no inputs</p>
      ) : (
        <ul className="space-y-1 px-3 py-2.5">
          {names.map((name) => {
            const fallback = data.inputs[name].default;
            return (
              <li key={name} className="truncate font-data text-xs text-ink-muted">
                <span className="text-ink">{name}</span>
                {fallback !== null && <span> = {fallback}</span>}
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}

function VerdictFrame({ data }: NodeProps<VerdictNode>) {
  return (
    <Panel aria-label="verdict frame" className={cn(frameVariants({ rim: "none" }))}>
      <Handle
        type="target"
        position={Position.Left}
        isConnectable={false}
        className={HANDLE_CLASSES}
      />
      <FrameHeader glyph={<Flag size={14} aria-hidden="true" />} title="Verdict" />
      <div className="flex flex-wrap gap-1.5 px-3 py-2.5">
        {OUTCOMES.map((name) => (
          <Badge
            key={name}
            tone={OUTCOME_TONES[name]}
            className={cn(
              "transition-opacity duration-300",
              data.outcome !== name && "opacity-40",
            )}
          >
            {name}
          </Badge>
        ))}
      </div>
    </Panel>
  );
}

function FrameNodeComponent(props: NodeProps<InputsNode | VerdictNode>) {
  return props.type === "verdict" ? (
    <VerdictFrame {...(props as NodeProps<VerdictNode>)} />
  ) : (
    <InputsFrame {...(props as NodeProps<InputsNode>)} />
  );
}

export const FrameNode = memo(FrameNodeComponent);
