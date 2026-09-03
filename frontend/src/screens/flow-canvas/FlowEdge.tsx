import { BaseEdge, getSmoothStepPath, type EdgeProps } from "@xyflow/react";
import { memo } from "react";
import { Badge } from "../../components/ui/Badge";
import { cva } from "../../lib/cn";
import type { CanvasEdge } from "./graph";

/**
 * One edge, four kinds: `needs` in the hairline, `succeeded` / `failed`
 * tinted and labelled with a pill, the implicit terminal edge faint. A
 * running edge marches its dashes toward the step that is running.
 *
 * The label sits in a `foreignObject` on the edge's own path so it needs
 * no inline transform: SVG `x`/`y` are geometry, not style.
 */

export const edgeVariants = cva("fill-none transition-colors duration-150", {
  variants: {
    kind: {
      needs: "stroke-line",
      succeeded: "stroke-success",
      failed: "stroke-danger",
      terminal: "stroke-line opacity-40",
    },
    running: {
      true: "flow-edge-running animate-dash stroke-accent",
      false: "",
    },
    selected: {
      true: "stroke-accent",
      false: "",
    },
  },
  defaultVariants: { kind: "needs", running: false, selected: false },
});

const LABEL_WIDTH = 96;
const LABEL_HEIGHT = 24;

function FlowEdgeComponent({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  selected,
}: EdgeProps<CanvasEdge>) {
  const kind = data?.kind ?? "needs";
  const running = data?.running ?? false;
  const [path, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
    borderRadius: 12,
  });
  const labelled = kind === "succeeded" || kind === "failed";
  return (
    <>
      <BaseEdge
        id={id}
        path={path}
        className={edgeVariants({ kind, running, selected: selected === true })}
        interactionWidth={kind === "terminal" ? 0 : 20}
      />
      {labelled && (
        <foreignObject
          x={labelX - LABEL_WIDTH / 2}
          y={labelY - LABEL_HEIGHT / 2}
          width={LABEL_WIDTH}
          height={LABEL_HEIGHT}
          className="overflow-visible"
        >
          <div className="flex h-full items-center justify-center">
            <Badge tone={kind === "succeeded" ? "success" : "danger"} className="shadow-raise">
              {kind}
            </Badge>
          </div>
        </foreignObject>
      )}
    </>
  );
}

export const FlowEdge = memo(FlowEdgeComponent);
