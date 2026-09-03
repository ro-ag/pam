import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { FlowSpec, FlowStep } from "../../lib/ipc";
import { FlowCanvas, type FlowCanvasProps, type Selection } from "./FlowCanvas";
import { edgeVariants } from "./FlowEdge";
import { defaultStep, type CanvasEdge, type CanvasNode } from "./graph";
import { LAYOUT_KEY, savePositions } from "./layout";
import { stepNodeVariants, type Rim } from "./StepNode";

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
}

const captured = vi.hoisted(() => ({ props: null as CapturedProps | null }));
const mocks = vi.hoisted(() => ({ autoLayout: vi.fn() }));

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
    MiniMap: () => null,
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
    expect(node("b")).toHaveTextContent("verify");
    expect(screen.getByLabelText("inputs frame")).toHaveTextContent("repo = {{ repo.root }}");
    expect(screen.getByLabelText("verdict frame")).toBeInTheDocument();
  });

  it("shows the modifier chips: approval hand, summarize sparkle, retry, timeout", async () => {
    renderCanvas();
    await settle();
    const b = node("b");
    expect(within(b).getByLabelText("retry")).toHaveTextContent("×3 / 2s");
    expect(within(b).getByLabelText("timeout")).toHaveTextContent("10m");
    expect(within(b).getByLabelText("summarize")).toBeInTheDocument();
    const c = node("c");
    expect(within(c).getByLabelText("approval")).toHaveTextContent("approval");
    expect(within(c).getByLabelText("stateful")).toHaveTextContent("changes");
    expect(within(c).getByLabelText("discard")).toHaveTextContent("discard");
    // Every default stays quiet; the footer says so instead of going blank.
    const a = node("a");
    expect(within(a).queryByLabelText("retry")).toBeNull();
    expect(within(a).queryByLabelText("timeout")).toBeNull();
    expect(a).toHaveTextContent("defaults");
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

  it("paints rims from statuses and the running dash on incoming edges", async () => {
    renderCanvas({ statuses: { a: "succeeded", b: "running" } });
    await settle();
    expect(node("a").className).toContain("ring-success");
    expect(node("b").className).toContain("animate-breathe");
    expect(node("b").className).toContain("ring-accent");
    expect(node("c").className).toContain("ring-warning");
    const running = edgePath("needs:a->b");
    expect(running.classList.contains("flow-edge-running")).toBe(true);
    expect(running.classList.contains("animate-dash")).toBe(true);
    expect(edgePath("succeeded:b->c").classList.contains("flow-edge-running")).toBe(false);
  });

  it("gives every rim a distinct, token-backed ring", () => {
    const rims: Rim[] = [
      "none",
      "selected",
      "running",
      "succeeded",
      "failed",
      "skipped",
      "blocked",
      "cancelled",
      "invalid",
      "approval",
    ];
    const rendered = rims.map((rim) => stepNodeVariants({ rim }));
    for (const classes of rendered) {
      for (const utility of classes
        .split(/\s+/)
        .filter((c) => c.startsWith("ring-"))
        .map((c) => c.split("/")[0])) {
        expect(utility).toMatch(
          /^ring-(0|2|accent|success|danger|warning|ink-faint|offset-2|offset-chrome)$/,
        );
      }
    }
    // failed / blocked / invalid share the danger ring on purpose (the marker
    // chip tells invalid apart); every other rim must look different.
    const visible = rims.filter(
      (rim) => !["none", "failed", "blocked", "invalid"].includes(rim),
    );
    const looks = new Set(visible.map((rim) => stepNodeVariants({ rim })));
    expect(looks.size).toBe(visible.length);
    expect(stepNodeVariants({ rim: "running" })).toContain("animate-breathe");
    expect(stepNodeVariants({ rim: "blocked" })).toContain("ring-danger");
    expect(stepNodeVariants({ rim: "invalid" })).toContain("ring-danger");
  });
});

describe("FlowCanvas edges and frames", () => {
  it("tints when edges with a pill label and fades the terminal edge", async () => {
    renderCanvas();
    await settle();
    expect(edgePath("needs:a->b").classList.contains("stroke-line")).toBe(true);
    const when = edgePath("succeeded:b->c");
    expect(when.classList.contains("stroke-success")).toBe(true);
    expect(
      within(document.querySelector('[data-edge="succeeded:b->c"]') as HTMLElement).getByText(
        "succeeded",
      ),
    ).toBeInTheDocument();
    const terminal = edgePath("terminal:c");
    expect(terminal.classList.contains("opacity-40")).toBe(true);
    expect(edgeVariants({ kind: "failed", running: false, selected: false })).toContain(
      "stroke-danger",
    );
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

  it("wires handles as 10px pills in the line color", async () => {
    renderCanvas();
    await settle();
    const handles = node("a").querySelectorAll(".react-flow__handle");
    expect(handles.length).toBe(2);
    for (const handle of handles) {
      expect(handle.className).toContain("size-2.5");
      expect(handle.className).toContain("rounded-pill");
      expect(handle.className).toContain("bg-line");
    }
  });
});

describe("FlowCanvas toolbar", () => {
  it("passes the canvas its grid, minimap-free chrome, and no delete key", async () => {
    const { container } = renderCanvas();
    await settle();
    const host = container.querySelector(".flow-canvas");
    expect(host).not.toBeNull();
    for (const cls of [
      "h-130",
      "min-h-130",
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
