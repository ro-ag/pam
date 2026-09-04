import { Handle, Position, type NodeProps } from "@xyflow/react";
import { memo } from "react";
import { Panel } from "../../components/ui/Panel";
import { cn, cva } from "../../lib/cn";
import type { NoteNode as NoteNodeType } from "./graph";

/**
 * A step's note: a small surface card in Pam's voice, sitting beside the
 * step it belongs to and tethered to it by a dotted curve. It reads as a
 * margin note, not as a step — no rail, no shadow, no order number — and
 * selecting it selects the step, so the inspector opens on the text.
 *
 * The source handle is rendered so the tether has an anchor, and hidden
 * so nobody mistakes a note for something a flow can wait on.
 */

export const noteVariants = cva(
  "w-48 rounded-control border bg-surface p-2.5 font-sans text-sm text-ink-muted shadow-none transition-colors duration-150",
  {
    variants: {
      selected: {
        true: "border-accent",
        false: "border-line",
      },
    },
    defaultVariants: { selected: false },
  },
);

/** The tether's anchor: present for the edge, invisible and untouchable. */
export const HIDDEN_HANDLE_CLASSES = "pointer-events-none opacity-0";

function NoteNodeComponent({ data, selected }: NodeProps<NoteNodeType>) {
  return (
    <Panel
      aria-label={`note ${data.stepId}`}
      className={cn(noteVariants({ selected: selected === true }))}
    >
      <Handle
        type="source"
        position={Position.Left}
        isConnectable={false}
        className={HIDDEN_HANDLE_CLASSES}
      />
      <p className="break-words whitespace-pre-wrap">{data.text}</p>
    </Panel>
  );
}

export const NoteNode = memo(NoteNodeComponent);
