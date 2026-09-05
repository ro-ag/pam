import { Position, getBezierPath, getSmoothStepPath } from "@xyflow/react";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { FlowSpec, FlowStep } from "../../lib/ipc";
import { FlowCanvas, type FlowCanvasProps, type Selection } from "./FlowCanvas";
import { edgeVariants } from "./FlowEdge";
import { defaultStep, type CanvasEdge, type CanvasNode } from "./graph";
import { LAYOUT_KEY, NOTE_OFFSET, savePositions } from "./layout";
import { railVariants, stepNodeVariants, type Rail, type Ring } from "./StepNode";

/**
 * The canvas against a stubbed ReactFlow: the real Handle, BaseEdge, path
 * math, provider and change reducers stay, only the viewport (ReactFlow,
 * Background, MiniMap) is replaced by a component that captures its props
 * and renders every node and edge through the given nodeTypes/edgeTypes.
 * That keeps the tests honest about what the canvas hands xyflow while
 * jsdom, which has no layout, never has to measure anything.
 */

interface CapturedProps {
  nodes: CanvasNode[];
  edges: CanvasEdge[];
  onConnect: (connection: {
    source: string;
    target: string;
    sourceHandle: string | null;
    targetHandle: string | null;
  }) => void;
  onNodesChange: (changes: unknown[]) => void;
  onEdgesChange: (changes: unknown[]) => void;
  snapToGrid: boolean;
  snapGrid: [number, number];
  proOptions: { hideAttribution: boolean };
  deleteKeyCode: string | null;
  onViewportChange: (viewport: { x: number; y: number; zoom: number }) => void;
}

const captured = vi.hoisted(() => ({ props: null as CapturedProps | null }));
const mocks = vi.hoisted(() => ({ autoLayout: vi.fn(), fitView: vi.fn() }));

vi.mock("./layout", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./layout")>();
  return { ...actual, autoLayout: mocks.autoLayout };
});

vi.mock("@xyflow/react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@xyflow/react")>();
  const React = await import("react");
  type Props = CapturedProps & {
    nodeTypes: Record<string, React.ComponentType<Record<string, unknown>>>;
    edgeTypes: Record<string, React.ComponentType<Record<string, unknown>>>;
    children?: React.ReactNode;
  };
  function ReactFlowStub(props: Props) {
    captured.props = props;
    const store = actual.useStoreApi();
    React.useEffect(() => {
      // Handles outside a real node wrapper have no node id; keep xyflow quiet.
      store.setState({ onError: () => {} });
    }, [store]);
    const nodes = props.nodes.map((node) =>
      React.createElement(props.nodeTypes[node.type ?? "step"], {
        key: node.id,
        id: node.id,
        type: node.type,
        data: node.data,
        selected: node.selected === true,
        isConnectable: true,
        zIndex: 0,
        positionAbsoluteX: node.position.x,
        positionAbsoluteY: node.position.y,
        dragging: false,
        draggable: true,
        selectable: node.selectable !== false,
        deletable: false,
        width: node.measured?.width,
        height: node.measured?.height,
      }),
    );
    const edges = props.edges.map((edge) =>
      React.createElement(
        "svg",
        { key: edge.id, "data-edge": edge.id },
        React.createElement(props.edgeTypes[edge.type ?? "flow"], {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          data: edge.data,
          selected: edge.selected === true,
          selectable: edge.selectable !== false,
          deletable: false,
          animated: false,
          sourceX: 0,
          sourceY: 0,
          targetX: 200,
          targetY: 40,
          sourcePosition: actual.Position.Right,
          targetPosition: actual.Position.Left,
          sourceHandleId: null,
          targetHandleId: null,
          interactionWidth: 20,
        }),
      ),
    );
    return React.createElement(
      "div",
      { "data-testid": "react-flow" },
      nodes,
      edges,
      props.children,
    );
  }
  return {
    ...actual,
    ReactFlow: ReactFlowStub,
    Background: () => null,
    MiniMap: () => React.createElement("div", { "data-testid": "minimap" }),
    useNodesInitialized: () => true,
    useReactFlow: () => ({ ...actual.useReactFlow(), fitView: mocks.fitView }),
  };
});

/** Three steps shaped like pr-readiness: observe, verify with retries, then a gated connector. */
function fixture(): FlowSpec {
  const a: FlowStep = {
    ...defaultStep("a", "command"),
    action: { kind: "command", argv: ["git", "status", "--porcelain"] },
  };
  const b: FlowStep = {
    ...defaultStep("b", "command"),
    action: { kind: "command", argv: ["cargo", "clippy", "--", "-D", "warnings"] },
    needs: ["a"],
    role: "verify",
    timeout: "10m",
    retry: { attempts: 3, backoff: "2s" },
    output: "summarize",
  };
  const c: FlowStep = {
    ...defaultStep("c", "connector"),
    action: { kind: "connector", connector: "github", call: "runs", with: { repo: "pam" } },
    when: { succeeded: "b" },
    role: "change",
    effect: "stateful",
    approval: "required",
    output: "discard",
  };
  return {
    id: "fx",
    name: "Fixture",
    description: "three steps",
    inputs: { repo: { description: "the repo", default: "{{ repo.root }}" } },
    steps: [a, b, c],
  };
}

function renderCanvas(overrides: Partial<FlowCanvasProps> = {}) {
  const props: FlowCanvasProps = {
    flowId: "fx",
    spec: fixture(),
    statuses: {},
    outcome: null,
    error: null,
    onChange: vi.fn(),
    selection: { kind: "none" },
    onSelect: vi.fn(),
    ...overrides,
  };
  const view = render(<FlowCanvas {...props} />);
  return { ...view, props };
}

const settle = () => act(async () => {});

function node(id: string): HTMLElement {
  return screen.getByLabelText(`step ${id}`);
}

function rail(id: string): HTMLElement {
  return within(node(id)).getByTestId("rail");
}

/** Where the stub draws every edge; the path math is xyflow's own. */
const EDGE_GEOMETRY = { sourceX: 0, sourceY: 0, targetX: 200, targetY: 40 };

function edgePath(id: string): SVGPathElement {
  const path = document.querySelector<SVGPathElement>(
    `[data-edge="${id}"] path.react-flow__edge-path`,
  );
  if (!path) throw new Error(`no edge path ${id}`);
  return path;
}

beforeEach(() => {
  window.localStorage.clear();
  captured.props = null;
  mocks.autoLayout.mockImplementation(async (nodes: CanvasNode[]) =>
    Object.fromEntries(
      nodes.map((candidate, index) => [candidate.id, { x: index * 300, y: 0 }]),
    ),
  );
});

describe("maximized canvas", () => {
  it("moves the same graph into a full-window view and restores it on Escape without resetting selection or positions", async () => {
    const { container, props } = renderCanvas({ selection: { kind: "step", id: "b" } });
    container.id = "root";
    await settle();
    const selected = node("b");
    const positions = captured.props?.nodes.map(({ id, position }) => ({ id, position }));
    const layoutCalls = mocks.autoLayout.mock.calls.length;
    const dock = container.querySelector<HTMLElement>(".canvas-dock")!;
    vi.spyOn(dock, "getBoundingClientRect").mockImplementation(
      () =>
        ({
          height:
            dock.querySelector(".canvas-workspace-maximized") || !dock.firstChild ? 564 : 640,
        }) as DOMRect,
    );
    fireEvent.click(screen.getByRole("button", { name: "Maximize canvas" }));
    expect(dock.style.minHeight).toBe("640px");
    const dialog = screen.getByRole("dialog", { name: "Flow canvas" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(container.inert).toBe(true);
    expect(container).not.toContainElement(selected);
    expect(within(dialog).getByLabelText("step b")).toBe(selected);
    expect(screen.getByRole("button", { name: "Restore canvas" })).toHaveFocus();
    expect(captured.props?.nodes.map(({ id, position }) => ({ id, position }))).toEqual(
      positions,
    );
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(container.inert).toBe(false);
    expect(container).toContainElement(selected);
    expect(dock.style.minHeight).toBe("");
    expect(screen.getByRole("button", { name: "Maximize canvas" })).toHaveFocus();
    expect(mocks.autoLayout.mock.calls).toHaveLength(layoutCalls);
    expect(props.onChange).not.toHaveBeenCalled();
    expect(props.onSelect).not.toHaveBeenCalled();
  });

  it("restores background interaction when an expanded canvas unmounts", async () => {
    const { container, unmount } = renderCanvas();
    container.id = "root";
    await settle();
    fireEvent.click(screen.getByRole("button", { name: "Maximize canvas" }));
    expect(container.inert).toBe(true);
    unmount();
    expect(container.inert).toBe(false);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});

describe("FlowCanvas nodes", () => {
  it("renders one node per step with its order chip and kind glyph", async () => {
    renderCanvas();
    await settle();
    for (const [id, order, kind] of [
      ["a", "1", "command"],
      ["b", "2", "command"],
      ["c", "3", "connector"],
    ]) {
      const card = node(id);
      expect(within(card).getByLabelText(`order ${order}`)).toHaveTextContent(order);
      expect(within(card).getByRole("img", { name: kind })).toBeInTheDocument();
    }
    expect(node("a")).toHaveTextContent("git status --porcelain");
    expect(node("c")).toHaveTextContent("github · runs");
    // The role rides as the id's title, not as a line of its own.
    expect(within(node("b")).getByText("b")).toHaveAttribute("title", "verify");
    expect(node("b")).not.toHaveTextContent("verify");
    expect(screen.getByLabelText("inputs frame")).toHaveTextContent("repo = {{ repo.root }}");
    expect(screen.getByLabelText("verdict frame")).toBeInTheDocument();
  });

  it("shows the modifiers as labelled glyphs in the header, with no chip footer", async () => {
    renderCanvas();
    await settle();
    const b = node("b");
    expect(within(b).getByLabelText("retry")).toHaveAttribute("title", "retry ×3 / 2s");
    expect(within(b).getByLabelText("timeout")).toHaveAttribute("title", "timeout 10m");
    expect(within(b).getByLabelText("summarize").className).toContain("text-accent");
    const c = node("c");
    expect(within(c).getByLabelText("approval").className).toContain("text-warning");
    expect(within(c).getByLabelText("stateful").className).toContain("warm-label");
    expect(within(c).getByLabelText("discard").className).toContain("text-ink-faint");
    for (const label of ["approval", "stateful", "discard"]) {
      expect(within(c).getByLabelText(label)).toHaveAttribute("role", "img");
      expect(within(c).getByLabelText(label).getAttribute("title")).toBeTruthy();
    }
    // A step at its defaults wears nothing but its kind glyph.
    const a = node("a");
    expect(within(a).queryByLabelText("retry")).toBeNull();
    expect(within(a).queryByLabelText("timeout")).toBeNull();
    expect(within(a).getAllByRole("img")).toHaveLength(1);
    expect(a).not.toHaveTextContent("defaults");
    for (const id of ["a", "b", "c"]) {
      expect(node(id).querySelector("footer")).toBeNull();
    }
  });

  it("paints the marker on the node named by the error path", async () => {
    renderCanvas({ error: { path: "steps[1].run[0]", message: "shells are refused" } });
    await settle();
    const marker = within(node("b")).getByLabelText("validation marker");
    expect(marker).toHaveAttribute("title", "shells are refused");
    expect(node("b").className).toContain("ring-danger");
    expect(within(node("a")).queryByLabelText("validation marker")).toBeNull();
  });

  it("opens the marker's cause and fix inside the selected node", async () => {
    renderCanvas({
      error: { path: "steps[1].run[0]", message: "shells are refused" },
      selection: { kind: "step", id: "b" },
    });
    await settle();
    expect(node("b")).toHaveTextContent("shells are refused");
    expect(node("b")).toHaveTextContent("fix it in the inspector");
  });

  it("paints the rail from statuses and the running dash on incoming edges", async () => {
    renderCanvas({ statuses: { a: "succeeded", b: "running" } });
    await settle();
    expect(rail("a").className).toContain("bg-success");
    expect(rail("b").className).toContain("bg-accent");
    expect(rail("b").className).toContain("animate-breathe");
    expect(rail("c").className).toContain("bg-line");
    expect(node("a")).toHaveAttribute("data-status", "succeeded");
    // A run never touches the ring; approval never paints a rim.
    for (const id of ["a", "b", "c"]) {
      expect(node(id).className).not.toContain("ring-2");
    }
    const running = edgePath("needs:a->b");
    expect(running.classList.contains("flow-edge-running")).toBe(true);
    expect(running.classList.contains("animate-dash")).toBe(true);
    expect(edgePath("succeeded:b->c").classList.contains("flow-edge-running")).toBe(false);
  });

  it("wears the ring for selection alone", async () => {
    renderCanvas({ selection: { kind: "step", id: "b" } });
    await settle();
    expect(node("b").className).toContain("ring-2");
    expect(node("b").className).toContain("ring-accent");
    expect(node("a").className).not.toContain("ring-2");
    // `c` requires approval: its Hand glyph says so, its ring stays off.
    expect(node("c").className).not.toContain("ring-2");
    expect(node("c").className).not.toContain("ring-warning");
  });

  it("gives every rail status a distinct, token-backed color and the ring three states", () => {
    const rails: Rail[] = [
      "none",
      "running",
      "succeeded",
      "failed",
      "skipped",
      "blocked",
      "cancelled",
    ];
    const rendered = new Map(rails.map((status) => [status, railVariants({ status })]));
    for (const classes of rendered.values()) {
      const colors = classes.split(/\s+/).filter((c) => c.startsWith("bg-"));
      expect(colors).toHaveLength(1);
      expect(colors[0]).toMatch(/^bg-(line|accent|success|danger|warning|ink-faint)$/);
    }
    // failed and blocked share danger on purpose; the other six rails all differ.
    expect(rendered.get("failed")).toBe(rendered.get("blocked"));
    const six = rails.filter((status) => status !== "blocked");
    expect(new Set(six.map((status) => rendered.get(status))).size).toBe(six.length);
    expect(rendered.get("running")).toContain("animate-breathe");

    const rings: Ring[] = ["none", "selected", "invalid"];
    const looks = rings.map((ring) => stepNodeVariants({ ring }));
    expect(new Set(looks).size).toBe(rings.length);
    for (const classes of looks) {
      for (const utility of classes.split(/\s+/).filter((c) => c.startsWith("ring-"))) {
        expect(utility).toMatch(/^ring-(0|2|accent|danger|offset-2|offset-chrome)$/);
      }
    }
    // Selected differs from idle by the ring and nothing else.
    const strip = (classes: string) =>
      classes
        .split(/\s+/)
        .filter((c) => !c.startsWith("ring-"))
        .join(" ");
    expect(strip(stepNodeVariants({ ring: "selected" }))).toBe(
      strip(stepNodeVariants({ ring: "none" })),
    );
  });
});

describe("FlowCanvas edges and frames", () => {
  it("tints conditional edges while keeping dependency and terminal strokes semantic", async () => {
    renderCanvas();
    await settle();
    expect(edgePath("needs:a->b").classList.contains("stroke-flow-edge")).toBe(true);
    const when = edgePath("succeeded:b->c");
    expect(when.classList.contains("stroke-success")).toBe(true);
    expect(
      within(document.querySelector('[data-edge="succeeded:b->c"]') as HTMLElement).getByText(
        "succeeded",
      ),
    ).toBeInTheDocument();
    const terminal = edgePath("terminal:c");
    expect(terminal.classList.contains("stroke-flow-edge")).toBe(true);
    expect(terminal.classList.contains("opacity-40")).toBe(false);
    expect(terminal.classList.contains("flow-edge-semantic")).toBe(true);
    expect(edgeVariants({ kind: "failed", running: false, selected: false })).toContain(
      "stroke-danger",
    );
  });

  it("draws every step edge as an orthogonal path with 8 px corners", async () => {
    renderCanvas();
    await settle();
    const [expected] = getSmoothStepPath({
      ...EDGE_GEOMETRY,
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
      borderRadius: 8,
    });
    for (const id of ["needs:a->b", "succeeded:b->c", "terminal:c"]) {
      const d = edgePath(id).getAttribute("d") ?? "";
      expect(d, id).toBe(expected);
      // Square: straight runs and quarter-turn corners, never a free curve.
      expect(d).not.toMatch(/C/);
    }
  });

  it("paints the verdict frame's outcome chip and fades the others", async () => {
    renderCanvas({ outcome: "solved" });
    await settle();
    const verdict = screen.getByLabelText("verdict frame");
    for (const name of ["solved", "changed", "verified", "unresolved", "blocked"]) {
      const chip = within(verdict).getByText(name);
      expect(chip.className.includes("opacity-40"), name).toBe(name !== "solved");
    }
  });

  it("wires handles as 10px pills in the line color, plus a hidden anchor for the note", async () => {
    renderCanvas();
    await settle();
    const handles = [...node("a").querySelectorAll(".react-flow__handle")];
    expect(handles.length).toBe(3);
    const hidden = handles.filter((handle) => handle.className.includes("opacity-0"));
    expect(hidden).toHaveLength(1);
    expect(hidden[0].className).toContain("pointer-events-none");
    expect(hidden[0].getAttribute("data-handleid")).toBe("note");
    for (const handle of handles.filter((handle) => !hidden.includes(handle))) {
      expect(handle.className).toContain("flow-connection-handle");
      expect(handle.className).toContain("rounded-pill");
    }
  });
});

describe("FlowCanvas notes", () => {
  function noted(): FlowSpec {
    const spec = fixture();
    spec.steps[0] = { ...spec.steps[0], note: "watch the exit code" };
    return spec;
  }

  it("draws a note beside its step, tethered by a dotted curve", async () => {
    renderCanvas({ spec: noted() });
    await settle();
    const note = screen.getByLabelText("note a");
    expect(note).toHaveTextContent("watch the exit code");
    expect(note.className).toContain("font-sans");
    expect(screen.queryByLabelText("note b")).toBeNull();
    const anchor = note.querySelector(".react-flow__handle");
    expect(anchor?.className).toContain("opacity-0");

    const tether = edgePath("note:a");
    expect(tether.classList.contains("flow-edge-tether")).toBe(true);
    expect(tether.classList.contains("stroke-ink-faint")).toBe(true);
    const [curve] = getBezierPath({
      ...EDGE_GEOMETRY,
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    });
    expect(tether.getAttribute("d")).toBe(curve);
    expect(tether.getAttribute("d")).toMatch(/C/);
    expect(edgePath("needs:a->b").getAttribute("d")).not.toMatch(/C/);
    const stored = captured.props?.edges.find((edge) => edge.id === "note:a");
    expect(stored).toMatchObject({ type: "tether", selectable: false, targetHandle: "note" });
  });

  it("selecting a note reports its step, and the step's selection lights the note", async () => {
    const { props, rerender } = renderCanvas({ spec: noted() });
    await settle();
    act(() =>
      captured.props?.onNodesChange([{ type: "select", id: "note:a", selected: true }]),
    );
    expect(props.onSelect).toHaveBeenLastCalledWith({ kind: "step", id: "a" });
    rerender(<FlowCanvas {...props} spec={noted()} selection={{ kind: "step", id: "a" }} />);
    await settle();
    const nodes = captured.props?.nodes ?? [];
    expect(nodes.find((candidate) => candidate.id === "a")?.selected).toBe(true);
    expect(nodes.find((candidate) => candidate.id === "note:a")?.selected).toBe(true);
    expect(screen.getByLabelText("note a").className).toContain("border-accent");
    expect(node("a").className).toContain("ring-accent");
  });

  it("places a typed note beside its placed step without a layout run; Tidy hands it to ELK", async () => {
    savePositions("fx", {
      inputs: { x: 0, y: 0 },
      a: { x: 300, y: 64 },
      b: { x: 600, y: 0 },
      c: { x: 900, y: 0 },
      verdict: { x: 1200, y: 0 },
    });
    renderCanvas({ spec: noted() });
    await settle();
    expect(mocks.autoLayout).not.toHaveBeenCalled();
    const at = (id: string) =>
      (captured.props?.nodes ?? []).find((candidate) => candidate.id === id)?.position;
    expect(at("note:a")).toEqual({ x: 300 + NOTE_OFFSET.x, y: 64 + NOTE_OFFSET.y });

    fireEvent.click(screen.getByRole("button", { name: "Tidy" }));
    await waitFor(() => expect(mocks.autoLayout).toHaveBeenCalledTimes(1));
    await settle();
    // The mock lays every node out by index, the note included (it is
    // node 4): ELK's own placement is taken as is, not offset from the step.
    const laid = mocks.autoLayout.mock.calls[0][0] as CanvasNode[];
    expect(laid.map((candidate) => candidate.id)).toContain("note:a");
    expect(at("a")).toEqual({ x: 300, y: 0 });
    expect(at("note:a")).toEqual({ x: 1200, y: 0 });
  });
});

describe("FlowCanvas toolbar", () => {
  it("passes the canvas its grid, minimap-free chrome, and no delete key", async () => {
    const { container } = renderCanvas();
    await settle();
    const host = container.querySelector(".flow-canvas");
    expect(host).not.toBeNull();
    for (const cls of [
      "canvas-viewport",
      "w-full",
      "overflow-hidden",
      "rounded-card",
      "border-edge",
    ]) {
      expect(host?.className).toContain(cls);
    }
    expect(captured.props?.snapToGrid).toBe(true);
    expect(captured.props?.snapGrid).toEqual([16, 16]);
    expect(captured.props?.proOptions).toEqual({ hideAttribution: true });
    expect(captured.props?.deleteKeyCode).toBeNull();
  });

  it("Add command appends a step and selects it", async () => {
    const { props } = renderCanvas();
    await settle();
    fireEvent.click(screen.getByRole("button", { name: "Add command" }));
    expect(props.onChange).toHaveBeenCalledTimes(1);
    const next = (props.onChange as ReturnType<typeof vi.fn>).mock.calls[0][0] as FlowSpec;
    expect(next.steps.map((step) => step.id)).toEqual(["a", "b", "c", "step-1"]);
    expect(next.steps[3].action).toEqual({ kind: "command", argv: ["git", "status"] });
    expect(props.onSelect).toHaveBeenCalledWith({ kind: "step", id: "step-1" });

    fireEvent.click(screen.getByRole("button", { name: "Add connector" }));
    const after = (props.onChange as ReturnType<typeof vi.fn>).mock.calls[1][0] as FlowSpec;
    expect(after.steps[3].action.kind).toBe("connector");
  });

  it("Remove is disabled with nothing selected and goes through the confirm tap", async () => {
    const idle = renderCanvas();
    await settle();
    expect(screen.getByRole("button", { name: "Remove" })).toBeDisabled();
    idle.unmount();

    const { props } = renderCanvas({ selection: { kind: "step", id: "b" } });
    await settle();
    const remove = screen.getByRole("button", { name: "Remove" });
    expect(remove).toBeEnabled();
    fireEvent.click(remove);
    expect(props.onChange).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "remove it?" }));
    expect(props.onChange).toHaveBeenCalledTimes(1);
    const next = (props.onChange as ReturnType<typeof vi.fn>).mock.calls[0][0] as FlowSpec;
    expect(next.steps.map((step) => step.id)).toEqual(["a", "c"]);
    expect(props.onSelect).toHaveBeenCalledWith({ kind: "none" });
  });

  it("Remove on a selected edge disconnects it", async () => {
    const { props } = renderCanvas({ selection: { kind: "edge", id: "needs:a->b" } });
    await settle();
    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    fireEvent.click(screen.getByRole("button", { name: "remove it?" }));
    const next = (props.onChange as ReturnType<typeof vi.fn>).mock.calls[0][0] as FlowSpec;
    expect(next.steps[1].needs).toEqual([]);
  });

  it("lays out only the nodes without a stored position on open", async () => {
    savePositions("fx", { a: { x: 999, y: 999 } });
    renderCanvas();
    await waitFor(() => expect(mocks.autoLayout).toHaveBeenCalledTimes(1));
    await settle();
    const laid = mocks.autoLayout.mock.calls[0][0] as CanvasNode[];
    expect(laid.map((candidate) => candidate.id)).toEqual(["inputs", "a", "b", "c", "verdict"]);
    const positions = Object.fromEntries(
      (captured.props?.nodes ?? []).map((candidate) => [candidate.id, candidate.position]),
    );
    expect(positions.a).toEqual({ x: 999, y: 999 });
    expect(positions.b).toEqual({ x: 600, y: 0 });
    expect(positions.verdict).toEqual({ x: 1200, y: 0 });
  });

  it("Tidy clears stored positions and relays every node", async () => {
    savePositions("fx", { a: { x: 999, y: 999 }, b: { x: 1, y: 1 } });
    renderCanvas();
    await settle();
    mocks.autoLayout.mockClear();
    fireEvent.click(screen.getByRole("button", { name: "Tidy" }));
    expect(window.localStorage.getItem(LAYOUT_KEY("fx"))).toBeNull();
    await waitFor(() => expect(mocks.autoLayout).toHaveBeenCalledTimes(1));
    expect((mocks.autoLayout.mock.calls[0][0] as CanvasNode[]).length).toBe(5);
    await settle();
    const a = captured.props?.nodes.find((candidate) => candidate.id === "a");
    expect(a?.position).toEqual({ x: 300, y: 0 });
  });

  it("saves every position when a drag ends", async () => {
    renderCanvas();
    await settle();
    act(() => {
      captured.props?.onNodesChange([
        { type: "position", id: "a", position: { x: 48, y: 64 }, dragging: true },
      ]);
    });
    expect(window.localStorage.getItem(LAYOUT_KEY("fx"))).toBeNull();
    act(() => {
      captured.props?.onNodesChange([
        { type: "position", id: "a", position: { x: 48, y: 64 }, dragging: false },
      ]);
    });
    const stored = JSON.parse(window.localStorage.getItem(LAYOUT_KEY("fx")) ?? "{}");
    expect(stored.a).toEqual({ x: 48, y: 64 });
    expect(Object.keys(stored).sort()).toEqual(["a", "b", "c", "inputs", "verdict"]);
  });

  it("a refused connection shows cause and fix above the canvas", async () => {
    const { props } = renderCanvas();
    await settle();
    act(() => {
      captured.props?.onConnect({
        source: "b",
        target: "a",
        sourceHandle: null,
        targetHandle: null,
      });
    });
    expect(props.onChange).not.toHaveBeenCalled();
    const note = screen.getByText(/connection refused/i).closest("div") as HTMLElement;
    expect(note).toHaveTextContent("`a` already runs before `b`");
    expect(note).toHaveTextContent("remove the edge");

    act(() => {
      captured.props?.onConnect({
        source: "a",
        target: "c",
        sourceHandle: null,
        targetHandle: null,
      });
    });
    expect(props.onChange).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(/connection refused/i)).toBeNull();
    const next = (props.onChange as ReturnType<typeof vi.fn>).mock.calls[0][0] as FlowSpec;
    expect(next.steps[2].needs).toEqual(["a"]);
  });

  it("reports a gesture's selection as a step, an edge, the inputs frame, or nothing", async () => {
    const { props, rerender } = renderCanvas();
    await settle();
    const select = (kind: "node" | "edge", id: string, selected: boolean) =>
      act(() => {
        const change = [{ type: "select", id, selected }];
        if (kind === "node") captured.props?.onNodesChange(change);
        else captured.props?.onEdgesChange(change);
      });
    // The screen answers every report by handing the selection back down.
    const expectSelection = (selected: Selection) => {
      expect(props.onSelect).toHaveBeenLastCalledWith(selected);
      rerender(<FlowCanvas {...props} selection={selected} />);
    };

    select("node", "b", true);
    expectSelection({ kind: "step", id: "b" });
    select("node", "b", false);
    select("node", "inputs", true);
    expectSelection({ kind: "inputs" });
    select("node", "inputs", false);
    select("edge", "needs:a->b", true);
    expectSelection({ kind: "edge", id: "needs:a->b" });
    select("edge", "needs:a->b", false);
    expectSelection({ kind: "none" });

    const verdict = (captured.props?.nodes ?? []).find((n) => n.id === "verdict");
    expect(verdict?.selectable).toBe(false);
  });

  it("does not echo the selection it was handed back to the screen", async () => {
    const { props } = renderCanvas({ selection: { kind: "step", id: "b" } });
    await settle();
    // The mirror put `b` on the nodes; a select change that merely agrees
    // (xyflow re-reporting the store) must not reach onSelect at all.
    act(() => captured.props?.onNodesChange([{ type: "select", id: "b", selected: true }]));
    expect(props.onSelect).not.toHaveBeenCalled();
  });
});

it("keeps inverse-zoom handle sizing attached to the stable host through maximize and restore", async () => {
  const { container } = renderCanvas();
  await settle();
  const host = container.querySelector<HTMLElement>(".canvas-host")!;
  for (const zoom of [0.3, 0.5, 1, 1.5]) {
    act(() => captured.props!.onViewportChange({ x: 0, y: 0, zoom }));
    expect(Number(host.style.getPropertyValue("--flow-zoom"))).toBe(zoom);
  }
  fireEvent.click(screen.getByRole("button", { name: "Maximize canvas" }));
  expect(document.body).toContainElement(host);
  expect(host.style.getPropertyValue("--flow-zoom")).toBe("1.5");
  fireEvent.click(screen.getByRole("button", { name: "Restore canvas" }));
  expect(container).toContainElement(host);
});

it("refits after canvas bounds settle and hides the minimap in compact viewports", async () => {
  let resize: (() => void) | undefined;
  let bounds = { width: 480, height: 264 };
  const measure = vi
    .spyOn(HTMLElement.prototype, "getBoundingClientRect")
    .mockImplementation(() => bounds as DOMRect);
  vi.stubGlobal(
    "ResizeObserver",
    class {
      constructor(private callback: () => void) {}
      observe(element: Element) {
        if (element.classList.contains("canvas-viewport")) resize = this.callback;
      }
      unobserve() {}
      disconnect() {}
    },
  );
  try {
    mocks.fitView.mockClear();
    const rendered = renderCanvas();
    await settle();
    await waitFor(() => expect(mocks.fitView).toHaveBeenCalled());
    expect(screen.queryByTestId("minimap")).not.toBeInTheDocument();
    mocks.fitView.mockClear();
    bounds = { width: 1000, height: 650 };
    act(() => resize?.());
    await waitFor(() => expect(mocks.fitView).toHaveBeenCalled());
    expect(screen.getByTestId("minimap")).toBeInTheDocument();
    mocks.fitView.mockClear();
    bounds = { width: 480, height: 200 };
    act(() => resize?.());
    await waitFor(() => expect(mocks.fitView).toHaveBeenCalled());
    expect(screen.queryByTestId("minimap")).not.toBeInTheDocument();
    rendered.unmount();
  } finally {
    measure.mockRestore();
    vi.unstubAllGlobals();
  }
});
