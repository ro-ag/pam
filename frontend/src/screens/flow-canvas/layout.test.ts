import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { FlowSpec } from "../../lib/ipc";
import { defaultStep, toGraph } from "./graph";
import {
  COMMENT_BOX_OPTIONS,
  LAYOUT_KEY,
  NODE_SIZE,
  NOTE_OFFSET,
  applyPositions,
  autoLayout,
  clearPositions,
  loadPositions,
  noteBeside,
  savePositions,
} from "./layout";

interface ElkChild {
  id: string;
  width: number;
  height: number;
  layoutOptions?: Record<string, string>;
  x?: number;
  y?: number;
}
interface ElkGraph {
  id: string;
  layoutOptions: Record<string, string>;
  children: ElkChild[];
  edges: { id: string; sources: string[]; targets: string[] }[];
}

const elk = vi.hoisted(() => ({ layout: vi.fn<(graph: ElkGraph) => Promise<ElkGraph>>() }));

vi.mock("elkjs/lib/elk.bundled.js", () => ({
  default: class {
    layout = elk.layout;
  },
}));

const spec: FlowSpec = {
  id: "fixture",
  name: "Fixture",
  description: "",
  inputs: {},
  steps: [defaultStep("a", "command"), { ...defaultStep("b", "connector"), needs: ["a"] }],
};

describe("positions store", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it("round-trips positions through localStorage under the flow key", () => {
    expect(LAYOUT_KEY("pr-readiness")).toBe("pam.flow.layout.pr-readiness");
    expect(loadPositions("pr-readiness")).toEqual({});
    savePositions("pr-readiness", { a: { x: 12, y: 34 }, inputs: { x: -200, y: 0 } });
    expect(window.localStorage.getItem("pam.flow.layout.pr-readiness")).not.toBeNull();
    expect(loadPositions("pr-readiness")).toEqual({
      a: { x: 12, y: 34 },
      inputs: { x: -200, y: 0 },
    });
    expect(loadPositions("other")).toEqual({});
    clearPositions("pr-readiness");
    expect(loadPositions("pr-readiness")).toEqual({});
  });

  it("returns {} when the store holds junk", () => {
    window.localStorage.setItem("pam.flow.layout.x", "not json");
    expect(loadPositions("x")).toEqual({});
    window.localStorage.setItem("pam.flow.layout.x", "[1,2]");
    expect(loadPositions("x")).toEqual({});
    window.localStorage.setItem(
      "pam.flow.layout.x",
      JSON.stringify({ a: { x: "1", y: 2 }, b: 3 }),
    );
    expect(loadPositions("x")).toEqual({});
  });

  it("returns {} and stays quiet when the store throws", () => {
    const original = Object.getOwnPropertyDescriptor(window, "localStorage");
    Object.defineProperty(window, "localStorage", {
      get() {
        throw new Error("nope");
      },
      configurable: true,
    });
    try {
      expect(loadPositions("x")).toEqual({});
      expect(() => savePositions("x", { a: { x: 1, y: 1 } })).not.toThrow();
      expect(() => clearPositions("x")).not.toThrow();
    } finally {
      if (original) Object.defineProperty(window, "localStorage", original);
    }
  });
});

describe("autoLayout", () => {
  afterEach(() => {
    elk.layout.mockReset();
  });

  it("asks ELK for a layered RIGHT graph and maps x/y back", async () => {
    elk.layout.mockImplementation(async (graph) => ({
      ...graph,
      children: graph.children.map((child, index) => ({ ...child, x: index * 100, y: 10 })),
    }));
    const { nodes, edges } = toGraph(spec);
    const positions = await autoLayout(nodes, edges, { a: { width: 300, height: 50 } });

    expect(elk.layout).toHaveBeenCalledTimes(1);
    const graph = elk.layout.mock.calls[0][0];
    expect(graph.id).toBe("root");
    expect(graph.layoutOptions).toMatchObject({
      "elk.algorithm": "layered",
      "elk.direction": "RIGHT",
      "elk.spacing.nodeNode": "48",
      "elk.layered.spacing.nodeNodeBetweenLayers": "96",
      "elk.portConstraints": "FIXED_SIDE",
    });
    expect(graph.children).toEqual([
      { id: "inputs", ...NODE_SIZE.inputs },
      { id: "a", width: 300, height: 50 },
      { id: "b", ...NODE_SIZE.step },
      { id: "verdict", ...NODE_SIZE.verdict },
    ]);
    expect(graph.edges).toEqual([
      { id: "needs:a->b", sources: ["a"], targets: ["b"] },
      { id: "terminal:b", sources: ["b"], targets: ["verdict"] },
    ]);
    expect(positions).toEqual({
      inputs: { x: 0, y: 10 },
      a: { x: 100, y: 10 },
      b: { x: 200, y: 10 },
      verdict: { x: 300, y: 10 },
    });
  });

  const noted: FlowSpec = {
    ...spec,
    steps: [{ ...spec.steps[0], note: "watch the exit code" }, spec.steps[1]],
  };

  it("hands ELK each note as a comment box with its tether, and uses the spot ELK answers", async () => {
    elk.layout.mockImplementation(async (graph) => ({
      ...graph,
      children: graph.children.map((child) =>
        child.id === "note:a"
          ? { ...child, x: 116, y: 34 }
          : { ...child, x: graph.children.indexOf(child) * 100, y: 100 },
      ),
    }));
    const { nodes, edges } = toGraph(noted);
    const positions = await autoLayout(nodes, edges, {});

    const graph = elk.layout.mock.calls[0][0];
    expect(graph.children.map((child) => child.id)).toEqual([
      "inputs",
      "a",
      "b",
      "note:a",
      "verdict",
    ]);
    const note = graph.children.find((child) => child.id === "note:a");
    expect(note).toEqual({
      id: "note:a",
      ...NODE_SIZE.note,
      layoutOptions: COMMENT_BOX_OPTIONS,
    });
    expect(COMMENT_BOX_OPTIONS).toEqual({ "org.eclipse.elk.commentBox": "true" });
    for (const child of graph.children) {
      if (child.id !== "note:a") expect(child).not.toHaveProperty("layoutOptions");
    }
    expect(graph.edges).toContainEqual({ id: "note:a", sources: ["note:a"], targets: ["a"] });
    // ELK's answer wins outright: no offset is added on top of it.
    expect(positions["note:a"]).toEqual({ x: 116, y: 34 });
    expect(positions.a).toEqual({ x: 100, y: 100 });
  });

  it("falls back to the fixed offset only when ELK gives the note no coordinates", async () => {
    elk.layout.mockImplementation(async (graph) => ({
      ...graph,
      children: graph.children.map((child) =>
        child.id === "note:a"
          ? child
          : { ...child, x: graph.children.indexOf(child) * 100, y: 10 },
      ),
    }));
    const { nodes, edges } = toGraph(noted);
    const positions = await autoLayout(nodes, edges, {});
    expect(NOTE_OFFSET).toEqual({ x: 240, y: -8 });
    expect(noteBeside({ x: 100, y: 10 })).toEqual({ x: 340, y: 2 });
    expect(positions["note:a"]).toEqual(noteBeside(positions.a));
  });

  it("leaves out children ELK gave no coordinates", async () => {
    elk.layout.mockImplementation(async (graph) => ({
      ...graph,
      children: graph.children.map((child) =>
        child.id === "a" ? { ...child, x: 5, y: 6 } : child,
      ),
    }));
    const { nodes, edges } = toGraph(spec);
    expect(await autoLayout(nodes, edges, {})).toEqual({ a: { x: 5, y: 6 } });
  });
});

describe("applyPositions", () => {
  it("keeps nodes without a stored position at their current place", () => {
    const { nodes } = toGraph(spec);
    const placed = nodes.map((node) => ({ ...node, position: { x: 5, y: 5 } }));
    const after = applyPositions(placed, { a: { x: 50, y: 60 } });
    expect(after.map((node) => [node.id, node.position])).toEqual([
      ["inputs", { x: 5, y: 5 }],
      ["a", { x: 50, y: 60 }],
      ["b", { x: 5, y: 5 }],
      ["verdict", { x: 5, y: 5 }],
    ]);
    expect(placed[1].position).toEqual({ x: 5, y: 5 });
    expect(after[1].data).toBe(placed[1].data);
  });
});
