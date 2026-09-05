import {
  Background,
  BackgroundVariant,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  applyEdgeChanges,
  applyNodeChanges,
  useReactFlow,
  useNodesInitialized,
  type Connection,
  type EdgeChange,
  type NodeChange,
  type Viewport,
} from "@xyflow/react";
import { Expand, Maximize2, Minimize2, Plug, Terminal, Wand2 } from "lucide-react";
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { cn } from "../../lib/cn";
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
  noteBeside,
  savePositions,
  type Positions,
} from "./layout";
import { NoteNode } from "./NoteNode";
import { StepNode } from "./StepNode";
import { TetherEdge } from "./TetherEdge";

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
 * of scattering everything the human arranged. ELK places notes too, as
 * comment boxes beside their step; only a note typed onto a step that is
 * already placed takes the fallback spot beside it until the next Tidy.
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

const nodeTypes = { step: StepNode, inputs: FrameNode, verdict: FrameNode, note: NoteNode };
const edgeTypes = { flow: FlowEdge, tether: TetherEdge };

const FIT = { padding: 0.2 };

/**
 * xyflow derives the minimap's viewBox from `style.width` / `style.height`
 * (its sizing API — a CSS box alone leaves the drawing scaled for 200×150
 * and clipped), so the size goes through the prop: small enough to leave
 * the flow's last column uncovered.
 */
const MINIMAP_SIZE = { width: 128, height: 96 };
// Stable identities: xyflow syncs every tracked prop into its store when
// the reference changes, and a fresh array or object per render would
// keep that sync, the store's subscribers, and this component in a loop.
const SNAP_GRID: [number, number] = [16, 16];
const PRO_OPTIONS = { hideAttribution: true };

function sameSelection(a: Selection, b: Selection): boolean {
  if (a.kind !== b.kind) return false;
  return "id" in a && "id" in b ? a.id === b.id : true;
}

/**
 * What the selected nodes and edges mean to the inspector. A note stands
 * for its step; the Verdict frame is never selectable.
 */
export function selectionOf(
  nodes: readonly CanvasNode[],
  edges: readonly CanvasEdge[],
): Selection {
  const node = nodes.find((candidate) => candidate.selected);
  if (node) {
    if (node.type === "note") return { kind: "step", id: node.data.stepId };
    if (node.id === INPUTS_NODE) return { kind: "inputs" };
    if (node.id !== VERDICT_NODE) return { kind: "step", id: node.id };
  }
  const edge = edges.find((candidate) => candidate.selected);
  if (edge && edge.type === "flow" && edge.data?.kind !== "terminal") {
    return { kind: "edge", id: edge.id };
  }
  return { kind: "none" };
}

/** Whether the screen's selection lands on this node; a step's note lights up with it. */
function nodeSelected(selection: Selection, node: CanvasNode): boolean {
  if (node.type === "verdict") return false;
  if (node.type === "note")
    return selection.kind === "step" && selection.id === node.data.stepId;
  if (selection.kind === "step") return selection.id === node.id;
  if (selection.kind === "inputs") return node.id === INPUTS_NODE;
  return false;
}

/** Every note among `nodes` that `targets` names, moved to the fallback spot beside its step. */
function settleNotes(nodes: CanvasNode[], targets: ReadonlySet<string>): CanvasNode[] {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  return nodes.map((node) => {
    if (node.type !== "note" || !targets.has(node.id)) return node;
    const step = byId.get(node.data.stepId);
    return step ? ({ ...node, position: noteBeside(step.position) } as CanvasNode) : node;
  });
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
  const [maximized, setMaximized] = useState(false);
  // The portal target never changes. Moving its DOM host keeps ReactFlow's
  // viewport, node selection and in-flight edits alive outside CSS containment.
  const [host] = useState(() => {
    const element = document.createElement("div");
    element.className = "canvas-host";
    return element;
  });
  const onViewportChange = useCallback(
    (viewport: Viewport) => {
      host.style.setProperty("--flow-zoom", String(viewport.zoom));
    },
    [host],
  );
  const dock = useRef<HTMLDivElement>(null);
  const dockHeight = useRef(0);
  useLayoutEffect(() => {
    const anchor = dock.current;
    if (!maximized) {
      if (host.parentNode !== anchor) anchor?.appendChild(host);
      return () => host.remove();
    }
    // Reserve the measured dock, including wrapped toolbar rows or errors.
    const previousMinHeight = anchor?.style.minHeight ?? "";
    if (anchor) anchor.style.minHeight = `${dockHeight.current}px`;
    const app = document.getElementById("root");
    const wasInert = app?.inert ?? false;
    document.body.appendChild(host);
    if (app) app.inert = true;
    const toggle = () => host.querySelector<HTMLButtonElement>("[data-canvas-maximize]");
    toggle()?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        setMaximized(false);
      } else if (event.key === "Tab") {
        const controls = [
          ...host.querySelectorAll<HTMLElement>(
            'button:not(:disabled), input:not(:disabled), textarea:not(:disabled), select:not(:disabled), a[href], [tabindex]:not([tabindex="-1"])',
          ),
        ].filter((element) => element.getClientRects().length > 0);
        const first = controls[0];
        const last = controls[controls.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last?.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first?.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey, true);
    return () => {
      document.removeEventListener("keydown", onKey, true);
      if (app) app.inert = wasInert;
      if (anchor?.isConnected) {
        anchor.appendChild(host);
        anchor.style.minHeight = previousMinHeight;
        toggle()?.focus();
      } else host.remove();
    };
  }, [host, maximized]);

  const { fitView } = useReactFlow<CanvasNode, CanvasEdge>();
  const nodesInitialized = useNodesInitialized();
  const viewport = useRef<HTMLDivElement>(null);
  const [showMinimap, setShowMinimap] = useState(false);
  useEffect(() => {
    const element = viewport.current;
    if (!element) return;
    let frame = 0;
    let settledFrame = 0;
    const resize = () => {
      const { width, height } = element.getBoundingClientRect();
      setShowMinimap(width >= 600 && height >= 400);
      window.cancelAnimationFrame(frame);
      window.cancelAnimationFrame(settledFrame);
      if (!nodesInitialized || width <= 0 || height <= 0) return;
      // Let ReactFlow consume its ResizeObserver measurement before fitting.
      // The portal may initially be measured before the dock's flex layout.
      frame = window.requestAnimationFrame(() => {
        settledFrame = window.requestAnimationFrame(() => void fitView(FIT));
      });
    };
    const observer = new ResizeObserver(resize);
    observer.observe(element);
    resize();
    return () => {
      observer.disconnect();
      window.cancelAnimationFrame(frame);
      window.cancelAnimationFrame(settledFrame);
    };
  }, [fitView, nodesInitialized]);
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
          : ({ ...node, selected: nodeSelected(current, node) } as CanvasNode);
      const prev = previous.get(node.id);
      const carried: CanvasNode = prev
        ? ({ ...base, position: prev.position, measured: prev.measured } as CanvasNode)
        : base;
      const place = stored[node.id];
      if (place) return { ...carried, position: { ...place } } as CanvasNode;
      if (!prev) unplaced.add(node.id);
      return carried;
    });
    // A note typed onto a step that is already placed takes the fallback
    // spot beside it, with no layout run; a note whose step is new too goes
    // to ELK with that step and comes back where ELK reserved room for it.
    const stepPlaced = (node: CanvasNode) =>
      node.type === "note" && unplaced.has(node.id) && !unplaced.has(node.data.stepId);
    const settled = settleNotes(merged, new Set(merged.filter(stepPlaced).map((n) => n.id)));
    for (const node of merged) if (stepPlaced(node)) unplaced.delete(node.id);
    setNodes(settled);
    setEdges(
      links.map((edge) => ({
        ...edge,
        selected: current.kind === "edge" && current.id === edge.id,
      })),
    );
    setRefused(null);
    if (unplaced.size > 0) void layout(settled, links, unplaced);
  }, [flowId, spec, statuses, error, outcome, layout]);

  // The inspector's selection is the truth; mirror it onto the canvas.
  useEffect(() => {
    setNodes((prev) => {
      let changed = false;
      const next = prev.map((node) => {
        const want = nodeSelected(selection, node);
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
    <div ref={dock} className="canvas-dock">
      {createPortal(
        <div
          role={maximized ? "dialog" : "region"}
          aria-label="Flow canvas"
          aria-modal={maximized || undefined}
          className={cn("canvas-workspace", maximized && "canvas-workspace-maximized")}
        >
          {maximized && (
            <div
              data-tauri-drag-region=""
              className="canvas-titlebar flex items-center justify-between gap-3 text-sm font-medium"
            >
              <span data-tauri-drag-region="">{spec.name || flowId}</span>
              <span className="text-xs font-normal text-ink-muted">
                Canvas · Escape to restore
              </span>
            </div>
          )}
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
            <Button
              variant="secondary"
              size="sm"
              data-canvas-maximize=""
              aria-label={maximized ? "Restore canvas" : "Maximize canvas"}
              aria-pressed={maximized}
              onClick={() => {
                // Measure before rendering the fixed canvas or detaching its host.
                if (!maximized)
                  dockHeight.current = dock.current?.getBoundingClientRect().height ?? 0;
                setMaximized((value) => !value);
              }}
            >
              {maximized ? (
                <Minimize2 size={14} aria-hidden="true" />
              ) : (
                <Expand size={14} aria-hidden="true" />
              )}
              {maximized ? "Restore" : "Maximize"}
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

          <div
            ref={viewport}
            className="flow-canvas canvas-viewport w-full overflow-hidden rounded-card border border-edge"
          >
            <ReactFlow<CanvasNode, CanvasEdge>
              nodes={nodes}
              edges={edges}
              nodeTypes={nodeTypes}
              edgeTypes={edgeTypes}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onConnect={onConnect}
              onViewportChange={onViewportChange}
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
              {showMinimap && (
                <MiniMap
                  pannable
                  zoomable
                  position="bottom-right"
                  nodeClassName={minimapClass}
                  style={MINIMAP_SIZE}
                  className="rounded-card border border-edge shadow-raise"
                />
              )}
            </ReactFlow>
          </div>
        </div>,
        host,
      )}
    </div>
  );
}
