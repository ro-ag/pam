import { BaseEdge, getBezierPath, type EdgeProps } from "@xyflow/react";
import { memo } from "react";
import type { TetherEdge as TetherEdgeType } from "./graph";

/**
 * The line from a note to its step. It is the one curve on the canvas:
 * square paths carry execution, this bezier carries annotation, and the
 * dotted hairline (`.flow-edge-tether` in tokens.css) says so at a glance.
 * It has no hit area — a note is selected by its card, never its string.
 */

export const TETHER_CLASSES = "flow-edge-tether fill-none stroke-ink-faint stroke-1";

function TetherEdgeComponent({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
}: EdgeProps<TetherEdgeType>) {
  const [path] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });
  return <BaseEdge id={id} path={path} className={TETHER_CLASSES} interactionWidth={0} />;
}

export const TetherEdge = memo(TetherEdgeComponent);
