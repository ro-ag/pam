import type { CanvasEdge, CanvasNode } from "./graph";

/**
 * Where nodes sit. Hand-placed positions live in localStorage per flow;
 * ELK fills in whatever has no stored position, and "Tidy" relays every
 * node after clearing the store. The store is best-effort: a missing,
 * unreadable, or throwing localStorage simply means "auto".
 *
 * ELK arrives through a literal dynamic import so the bundler splits its
 * ~1.4 MB into a chunk that loads the first time a canvas needs a layout.
 */

export type Positions = Record<string, { x: number; y: number }>;

export const LAYOUT_KEY = (flowId: string): string => `pam.flow.layout.${flowId}`;

/** The footprint ELK plans with when the canvas has not measured a node yet. */
export const NODE_SIZE = {
  step: { width: 220, height: 112 },
  inputs: { width: 200, height: 96 },
  verdict: { width: 200, height: 96 },
} as const;

function isPosition(value: unknown): value is { x: number; y: number } {
  return (
    typeof value === "object" &&
    value !== null &&
    Number.isFinite((value as { x?: unknown }).x) &&
    Number.isFinite((value as { y?: unknown }).y)
  );
}

function isPositions(value: unknown): value is Positions {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.values(value).every(isPosition)
  );
}

/** The stored positions for a flow; `{}` when there are none or the store is unusable. */
export function loadPositions(flowId: string): Positions {
  try {
    const raw = window.localStorage.getItem(LAYOUT_KEY(flowId));
    if (raw === null) return {};
    const parsed: unknown = JSON.parse(raw);
    return isPositions(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

export function savePositions(flowId: string, positions: Positions): void {
  try {
    window.localStorage.setItem(LAYOUT_KEY(flowId), JSON.stringify(positions));
  } catch {
    // No store, no memory: the next open lays the flow out again.
  }
}

export function clearPositions(flowId: string): void {
  try {
    window.localStorage.removeItem(LAYOUT_KEY(flowId));
  } catch {
    // Nothing to clear when there is no store.
  }
}

/**
 * Lays the whole graph out left to right with ELK's layered algorithm and
 * answers a position per node ELK placed. `sizes` carries the measured
 * footprints; unmeasured nodes fall back to `NODE_SIZE` by type.
 */
export async function autoLayout(
  nodes: readonly CanvasNode[],
  edges: readonly CanvasEdge[],
  sizes: Record<string, { width: number; height: number }>,
): Promise<Positions> {
  const { default: ELK } = await import("elkjs/lib/elk.bundled.js");
  const elk = new ELK();
  const laid = await elk.layout({
    id: "root",
    layoutOptions: {
      "elk.algorithm": "layered",
      "elk.direction": "RIGHT",
      "elk.spacing.nodeNode": "48",
      "elk.layered.spacing.nodeNodeBetweenLayers": "96",
      "elk.portConstraints": "FIXED_SIDE",
    },
    children: nodes.map((node) => ({
      id: node.id,
      ...(sizes[node.id] ?? NODE_SIZE[node.type ?? "step"]),
    })),
    edges: edges.map((edge) => ({
      id: edge.id,
      sources: [edge.source],
      targets: [edge.target],
    })),
  });
  const positions: Positions = {};
  for (const child of laid.children ?? []) {
    if (typeof child.x === "number" && typeof child.y === "number") {
      positions[child.id] = { x: child.x, y: child.y };
    }
  }
  return positions;
}

/** Moves the nodes that have a stored position; the rest stay where they are. */
export function applyPositions(nodes: CanvasNode[], positions: Positions): CanvasNode[] {
  return nodes.map((node) => {
    const position = positions[node.id];
    return position ? { ...node, position: { ...position } } : node;
  }) as CanvasNode[];
}
