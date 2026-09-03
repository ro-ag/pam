import {
  Background,
  BackgroundVariant,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  applyEdgeChanges,
  applyNodeChanges,
  useReactFlow,
  type Connection,
  type EdgeChange,
  type NodeChange,
} from "@xyflow/react";
import { Maximize2, Plug, Terminal, Wand2 } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "../../components/ui/Button";
import { ConfirmButton } from "../../components/ui/ConfirmButton";
import { FailureNote } from "../../components/ui/FailureNote";
import type { FlowSpec, OutcomeName } from "../../lib/ipc";
import { FlowEdge } from "./FlowEdge";
import { FrameNode } from "./FrameNode";
import {
  INPUTS_NODE,
  VERDICT_NODE,
  addStep,
  connect,
  disconnect,
  markerFor,
  removeStep,
  toGraph,
  type CanvasEdge,
  type CanvasNode,
  type Refused,
  type RunStatus,
} from "./graph";
import {
  autoLayout,
  clearPositions,
  loadPositions,
  savePositions,
  type Positions,
} from "./layout";
import { StepNode } from "./StepNode";

/**
 * The canvas host: a toolbar, the xyflow viewport, the minimap. The flow
 * spec is the truth and lives in the Flows screen; this component derives
 * nodes and edges from it, keeps a local copy so xyflow can report
 * measurements and selection back, and turns every gesture into a pure
 * `graph.ts` edit handed up through `onChange`.
 *
 * Positions are the one thing the spec does not know. Stored ones win,
 * nodes the canvas has already placed keep their place, and only the rest
 * are laid out by ELK — so an added step lands next to the flow instead
 * of scattering everything the human arranged.
 *
 * Selection is owned by the screen (the inspector shares it) and mirrored
 * onto the nodes; the canvas reports back only what a gesture changed —
 * the `select` changes xyflow emits on a click or a drag-select — never
 * the store's own echo of the selection it was just handed, which lags a
 * render behind and would otherwise argue with the mirror forever.
 */

export type Selection =
  | { kind: "none" }
  | { kind: "step"; id: string }
  | { kind: "edge"; id: string }
  | { kind: "inputs" };

export interface FlowCanvasProps {
  flowId: string;
  spec: FlowSpec;
  statuses: Record<string, RunStatus>;
  outcome: OutcomeName | null;
  error: { path: string; message: string } | null;
  /** Every accepted edit, as the next whole spec. */
  onChange: (spec: FlowSpec) => void;
  selection: Selection;
  onSelect: (selection: Selection) => void;
}

const nodeTypes = { step: StepNode, inputs: FrameNode, verdict: FrameNode };
const edgeTypes = { flow: FlowEdge };

const FIT = { padding: 0.2 };
// Stable identities: xyflow syncs every tracked prop into its store when
// the reference changes, and a fresh array or object per render would
// keep that sync, the store's subscribers, and this component in a loop.
const SNAP_GRID: [number, number] = [16, 16];
const PRO_OPTIONS = { hideAttribution: true };

function sameSelection(a: Selection, b: Selection): boolean {
  if (a.kind !== b.kind) return false;
  return "id" in a && "id" in b ? a.id === b.id : true;
}

/** What the selected nodes and edges mean to the inspector. The Verdict frame is never selectable. */
export function selectionOf(
  nodes: readonly CanvasNode[],
  edges: readonly CanvasEdge[],
): Selection {
  const node = nodes.find((candidate) => candidate.selected);
  if (node) {
    if (node.id === INPUTS_NODE) return { kind: "inputs" };
    if (node.id !== VERDICT_NODE) return { kind: "step", id: node.id };
  }
  const edge = edges.find((candidate) => candidate.selected);
  if (edge && edge.data?.kind !== "terminal") return { kind: "edge", id: edge.id };
  return { kind: "none" };
}

function nodeSelected(selection: Selection, id: string): boolean {
  if (selection.kind === "step") return selection.id === id;
  if (selection.kind === "inputs") return id === INPUTS_NODE;
  return false;
}

function positionsOf(nodes: readonly CanvasNode[]): Positions {
  return Object.fromEntries(nodes.map((node) => [node.id, { ...node.position }]));
}

/** The minimap fills nodes by kind: commands accent, connectors copper, frames hairline. */
function minimapClass(node: CanvasNode): string {
  if (node.type !== "step") return "fill-line";
  return node.data.step.action.kind === "command" ? "fill-accent" : "fill-copper";
}

export function FlowCanvas(props: FlowCanvasProps) {
  return (
    <ReactFlowProvider>
      <Canvas {...props} />
    </ReactFlowProvider>
  );
}

function Canvas({
  flowId,
  spec,
  statuses,
  outcome,
  error,
  onChange,
  selection,
  onSelect,
}: FlowCanvasProps) {
  const { fitView } = useReactFlow<CanvasNode, CanvasEdge>();
  const [nodes, setNodes] = useState<CanvasNode[]>([]);
  const [edges, setEdges] = useState<CanvasEdge[]>([]);
  const [refused, setRefused] = useState<Refused | null>(null);
  const [saveTick, setSaveTick] = useState(0);
  const [selectTick, setSelectTick] = useState(0);

  // Refs let the rebuild effect read the latest canvas state without
  // re-running on every measurement or selection change.
  const nodesRef = useRef(nodes);
  nodesRef.current = nodes;
  const edgesRef = useRef(edges);
  edgesRef.current = edges;
  const selectionRef = useRef(selection);
  selectionRef.current = selection;
  const placedFor = useRef<string | null>(null);
  const layoutRun = useRef(0);

  const layout = useCallback(
    async (all: CanvasNode[], links: CanvasEdge[], targets: ReadonlySet<string>) => {
      const run = ++layoutRun.current;
      const sizes: Record<string, { width: number; height: number }> = {};
      for (const node of all) {
        if (node.measured?.width && node.measured?.height) {
          sizes[node.id] = { width: node.measured.width, height: node.measured.height };
        }
      }
      const positions = await autoLayout(all, links, sizes);
      if (run !== layoutRun.current) return;
      setNodes((prev) =>
        prev.map((node) =>
          targets.has(node.id) && positions[node.id]
            ? ({ ...node, position: positions[node.id] } as CanvasNode)
            : node,
        ),
      );
      window.requestAnimationFrame(() => void fitView(FIT));
    },
    [fitView],
  );

  // The spec (or what a run and the validator say about it) changed:
  // rebuild the graph, carry over what the canvas already knows, and lay
  // out only what is new.
  useEffect(() => {
    const sameFlow = placedFor.current === flowId;
    placedFor.current = flowId;
    const previous = new Map(sameFlow ? nodesRef.current.map((node) => [node.id, node]) : []);
    const stored = loadPositions(flowId);
    const { nodes: fresh, edges: links } = toGraph(
      spec,
      statuses,
      markerFor(error, spec).marker,
    );
    const current = selectionRef.current;
    const unplaced = new Set<string>();
    const merged = fresh.map((node) => {
      const base: CanvasNode =
        node.type === "verdict"
          ? { ...node, selectable: false, data: { outcome } }
          : { ...node, selected: nodeSelected(current, node.id) };
      const prev = previous.get(node.id);
      const carried: CanvasNode = prev
        ? ({ ...base, position: prev.position, measured: prev.measured } as CanvasNode)
        : base;
      const place = stored[node.id];
      if (place) return { ...carried, position: { ...place } } as CanvasNode;
      if (!prev) unplaced.add(node.id);
      return carried;
    });
    setNodes(merged);
    setEdges(
      links.map((edge) => ({
        ...edge,
        selected: current.kind === "edge" && current.id === edge.id,
      })),
    );
    setRefused(null);
    if (unplaced.size > 0) void layout(merged, links, unplaced);
  }, [flowId, spec, statuses, error, outcome, layout]);

  // The inspector's selection is the truth; mirror it onto the canvas.
  useEffect(() => {
    setNodes((prev) => {
      let changed = false;
      const next = prev.map((node) => {
        const want = node.id !== VERDICT_NODE && nodeSelected(selection, node.id);
        if ((node.selected === true) === want) return node;
        changed = true;
        return { ...node, selected: want } as CanvasNode;
      });
      return changed ? next : prev;
    });
    setEdges((prev) => {
      let changed = false;
      const next = prev.map((edge) => {
        const want = selection.kind === "edge" && selection.id === edge.id;
        if ((edge.selected === true) === want) return edge;
        changed = true;
        return { ...edge, selected: want };
      });
      return changed ? next : prev;
    });
  }, [selection]);

  // A drag ended: remember where everything sits now.
  useEffect(() => {
    if (saveTick === 0) return;
    savePositions(flowId, positionsOf(nodesRef.current));
  }, [saveTick, flowId]);

  // A gesture selected something: read the settled canvas state and tell
  // the screen, once, if it differs from what the screen already holds.
  useEffect(() => {
    if (selectTick === 0) return;
    const next = selectionOf(nodesRef.current, edgesRef.current);
    if (!sameSelection(next, selectionRef.current)) {
      selectionRef.current = next;
      onSelect(next);
    }
  }, [selectTick, onSelect]);

  const onNodesChange = useCallback((changes: NodeChange<CanvasNode>[]) => {
    setNodes((prev) => applyNodeChanges(changes, prev));
    if (changes.some((change) => change.type === "position" && change.dragging === false)) {
      setSaveTick((tick) => tick + 1);
    }
    if (changes.some((change) => change.type === "select")) {
      setSelectTick((tick) => tick + 1);
    }
  }, []);

  const onEdgesChange = useCallback((changes: EdgeChange<CanvasEdge>[]) => {
    setEdges((prev) => applyEdgeChanges(changes, prev));
    if (changes.some((change) => change.type === "select")) {
      setSelectTick((tick) => tick + 1);
    }
  }, []);

  const onConnect = useCallback(
    (connection: Connection) => {
      const edit = connect(spec, connection.source, connection.target);
      if (edit.ok) {
        setRefused(null);
        onChange(edit.spec);
      } else {
        setRefused(edit.refused);
      }
    },
    [spec, onChange],
  );

  const add = (kind: "command" | "connector") => {
    const added = addStep(spec, kind);
    onChange(added.spec);
    onSelect({ kind: "step", id: added.id });
  };

  const tidy = () => {
    clearPositions(flowId);
    void layout(nodesRef.current, edges, new Set(nodesRef.current.map((node) => node.id)));
  };

  const removable = selection.kind === "step" || selection.kind === "edge";
  const remove = () => {
    if (selection.kind === "step") onChange(removeStep(spec, selection.id));
    else if (selection.kind === "edge") onChange(disconnect(spec, selection.id));
    onSelect({ kind: "none" });
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="ghost" size="sm" onClick={() => add("command")}>
          <Terminal size={14} aria-hidden="true" />
          Add command
        </Button>
        <Button variant="ghost" size="sm" onClick={() => add("connector")}>
          <Plug size={14} aria-hidden="true" />
          Add connector
        </Button>
        <span className="flex-1" />
        <Button variant="ghost" size="sm" onClick={tidy}>
          <Wand2 size={14} aria-hidden="true" />
          Tidy
        </Button>
        <Button variant="ghost" size="sm" onClick={() => void fitView(FIT)}>
          <Maximize2 size={14} aria-hidden="true" />
          Fit
        </Button>
        <ConfirmButton
          label="Remove"
          confirmLabel="remove it?"
          disabled={!removable}
          onConfirm={remove}
        />
      </div>

      {refused && (
        <FailureNote
          label="canvas"
          failure={{
            cause: "connection refused",
            detail: refused.cause,
            recovery: refused.fix,
          }}
        />
      )}

      <div className="flow-canvas h-130 min-h-130 w-full overflow-hidden rounded-card border border-edge">
        <ReactFlow<CanvasNode, CanvasEdge>
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          snapToGrid
          snapGrid={SNAP_GRID}
          fitView
          fitViewOptions={FIT}
          minZoom={0.3}
          maxZoom={1.5}
          proOptions={PRO_OPTIONS}
          deleteKeyCode={null}
          className="font-sans"
        >
          <Background variant={BackgroundVariant.Dots} gap={16} size={1} />
          <MiniMap
            pannable
            zoomable
            position="bottom-right"
            nodeClassName={minimapClass}
            className="rounded-card border border-edge shadow-raise"
          />
        </ReactFlow>
      </div>
    </div>
  );
}
