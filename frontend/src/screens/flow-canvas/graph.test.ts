import { describe, expect, it } from "vitest";
import type { FlowSpec, FlowStep } from "../../lib/ipc";
import {
  INPUTS_NODE,
  VERDICT_NODE,
  addStep,
  connect,
  defaultStep,
  disconnect,
  edgeId,
  isStepId,
  joinArgv,
  markerFor,
  moveStep,
  noteNodeId,
  removeStep,
  setEdgeKind,
  splitArgv,
  toGraph,
  toRaw,
  updateInputs,
  updateStep,
} from "./graph";

/** Three command steps `a`, `b`, `c`; `b` needs `a`. Patches override per step. */
function spec(patches: Partial<Record<"a" | "b" | "c", Partial<FlowStep>>> = {}): FlowSpec {
  const step = (id: "a" | "b" | "c", extra: Partial<FlowStep>): FlowStep => ({
    ...defaultStep(id, "command"),
    action: { kind: "command", argv: [id === "a" ? "git" : "cargo", id] },
    ...extra,
    ...patches[id],
  });
  return {
    id: "fixture",
    name: "Fixture",
    description: "three steps",
    inputs: { repo: { description: "the repo", default: "{{ repo.root }}" } },
    steps: [step("a", {}), step("b", { needs: ["a"] }), step("c", {})],
  };
}

function order(flow: FlowSpec): string[] {
  return flow.steps.map((step) => step.id);
}

function find(flow: FlowSpec, id: string): FlowStep {
  const step = flow.steps.find((candidate) => candidate.id === id);
  if (!step) throw new Error(`no step ${id}`);
  return step;
}

describe("toGraph", () => {
  it("derives one step node per step in file order plus the two frames", () => {
    const { nodes } = toGraph(spec());
    expect(nodes.map((node) => node.id)).toEqual([INPUTS_NODE, "a", "b", "c", VERDICT_NODE]);
    expect(nodes.map((node) => node.type)).toEqual([
      "inputs",
      "step",
      "step",
      "step",
      "verdict",
    ]);
    const steps = nodes.filter((node) => node.type === "step");
    expect(steps.map((node) => node.data.index)).toEqual([0, 1, 2]);
    for (const node of nodes) {
      expect(node.position).toEqual({ x: 0, y: 0 });
      expect(node.selected).toBe(false);
    }
    const inputs = nodes[0];
    expect(inputs.type === "inputs" && Object.keys(inputs.data.inputs)).toEqual(["repo"]);
    const verdict = nodes[4];
    expect(verdict.type === "verdict" && verdict.data.outcome).toBeNull();
  });

  it("derives needs edges, when edges with their kind, and terminal edges", () => {
    const flow = spec({ c: { when: { failed: "b" } } });
    const { edges } = toGraph(flow, { b: "running" });
    const byId = Object.fromEntries(edges.map((edge) => [edge.id, edge]));
    expect(Object.keys(byId).sort()).toEqual(["failed:b->c", "needs:a->b", "terminal:c"]);
    expect(byId["needs:a->b"]).toMatchObject({
      source: "a",
      target: "b",
      type: "flow",
      data: { kind: "needs", running: true },
    });
    expect(byId["failed:b->c"]).toMatchObject({
      source: "b",
      target: "c",
      data: { kind: "failed", running: false },
    });
    expect(byId["terminal:c"]).toMatchObject({
      source: "c",
      target: VERDICT_NODE,
      selectable: false,
      data: { kind: "terminal", running: false },
    });
    expect(edgeId("succeeded", "x", "y")).toBe("succeeded:x->y");
  });

  it("paints statuses and the marker onto the step nodes", () => {
    const marker = { path: "steps[1].run[0]", message: "shells are refused", field: "run[0]" };
    const { nodes } = toGraph(spec(), { a: "succeeded", b: "failed" }, marker);
    const step = (id: string) => {
      const node = nodes.find((candidate) => candidate.id === id);
      if (!node || node.type !== "step") throw new Error(`no step node ${id}`);
      return node.data;
    };
    expect(step("a").status).toBe("succeeded");
    expect(step("b").status).toBe("failed");
    expect(step("c").status).toBeNull();
    expect(step("a").marker).toBeNull();
    expect(step("b").marker).toEqual(marker);
  });

  it("derives a note node and a tether edge only for steps with a non-empty note", () => {
    const flow = spec({
      a: { note: "watch the exit code" },
      b: { note: "   " },
      c: { note: "last word" },
    });
    const { nodes, edges } = toGraph(flow);
    expect(noteNodeId("a")).toBe("note:a");
    expect(nodes.map((node) => node.id)).toEqual([
      INPUTS_NODE,
      "a",
      "b",
      "c",
      "note:a",
      "note:c",
      VERDICT_NODE,
    ]);
    const note = nodes.find((node) => node.id === "note:a");
    expect(note).toMatchObject({
      type: "note",
      position: { x: 0, y: 0 },
      selected: false,
      data: { stepId: "a", text: "watch the exit code" },
    });
    const tether = edges.find((edge) => edge.id === "note:a");
    expect(tether).toEqual({
      id: "note:a",
      type: "tether",
      source: "note:a",
      target: "a",
      targetHandle: "note",
      selectable: false,
      data: { kind: "note" },
    });
    // The tether is annotation, never execution: `c` still feeds the verdict.
    expect(edges.map((edge) => edge.id)).toContain("terminal:c");
    expect(toGraph(spec()).nodes.some((node) => node.type === "note")).toBe(false);
    expect(toGraph(spec()).edges.some((edge) => edge.type === "tether")).toBe(false);
  });

  it("drops the note node with its step", () => {
    const flow = spec({ a: { note: "gone with a" } });
    const { nodes, edges } = toGraph(removeStep(flow, "a"));
    expect(nodes.some((node) => node.id === "note:a")).toBe(false);
    expect(edges.some((edge) => edge.id === "note:a")).toBe(false);
  });
});

describe("connect", () => {
  it("adds a needs edge forward without reordering", () => {
    const edit = connect(spec(), "a", "c");
    expect(edit.ok).toBe(true);
    if (!edit.ok) return;
    expect(order(edit.spec)).toEqual(["a", "b", "c"]);
    expect(find(edit.spec, "c").needs).toEqual(["a"]);
  });

  it("is a no-op when the edge already exists", () => {
    const edit = connect(spec(), "a", "b");
    expect(edit.ok).toBe(true);
    if (!edit.ok) return;
    expect(find(edit.spec, "b").needs).toEqual(["a"]);
  });

  it("backward moves the target and its dependents after the source", () => {
    const independent = connect(spec({ b: { needs: [] } }), "c", "a");
    expect(independent.ok).toBe(true);
    if (!independent.ok) return;
    expect(order(independent.spec)).toEqual(["b", "c", "a"]);
    expect(find(independent.spec, "a").needs).toEqual(["c"]);

    // `b` needs `a`, so it travels with `a` and keeps its relative order.
    const withDependent = connect(spec(), "c", "a");
    expect(withDependent.ok).toBe(true);
    if (!withDependent.ok) return;
    expect(order(withDependent.spec)).toEqual(["c", "a", "b"]);
    expect(find(withDependent.spec, "a").needs).toEqual(["c"]);
    expect(find(withDependent.spec, "b").needs).toEqual(["a"]);
  });

  it("refuses a cycle with cause and fix", () => {
    const edit = connect(spec(), "b", "a");
    expect(edit.ok).toBe(false);
    if (edit.ok) return;
    expect(edit.refused.cause).toContain("`a`");
    expect(edit.refused.cause).toContain("`b`");
    expect(edit.refused.fix.length).toBeGreaterThan(0);

    // A `when` reference counts as an edge too.
    const viaWhen = connect(spec({ b: { needs: [], when: { succeeded: "a" } } }), "b", "a");
    expect(viaWhen.ok).toBe(false);
  });

  it("refuses frames, self, and unknown steps", () => {
    for (const [source, target] of [
      [INPUTS_NODE, "a"],
      ["a", VERDICT_NODE],
      ["a", "a"],
      ["a", "nope"],
    ]) {
      const edit = connect(spec(), source, target);
      expect(edit.ok, `${source} -> ${target}`).toBe(false);
    }
  });

  it("never mutates the input spec", () => {
    const before = spec();
    const snapshot = JSON.stringify(before);
    connect(before, "c", "a");
    connect(before, "a", "c");
    expect(JSON.stringify(before)).toBe(snapshot);
  });
});

describe("disconnect and setEdgeKind", () => {
  it("disconnect removes a needs entry or resets when", () => {
    const flow = spec({ c: { when: { failed: "b" } } });
    expect(find(disconnect(flow, "needs:a->b"), "b").needs).toEqual([]);
    expect(find(disconnect(flow, "failed:b->c"), "c").when).toBe("needs_succeeded");
    expect(disconnect(flow, "terminal:c")).toEqual(flow);
  });

  it("setEdgeKind flips needs to succeeded and back, replacing an existing when", () => {
    const flow = spec({ c: { needs: ["a"], when: { failed: "b" } } });
    const flipped = setEdgeKind(flow, "needs:a->c", "succeeded");
    expect(flipped.ok).toBe(true);
    if (!flipped.ok) return;
    expect(find(flipped.spec, "c")).toMatchObject({ needs: [], when: { succeeded: "a" } });
    expect(toGraph(flipped.spec).edges.map((edge) => edge.id)).not.toContain("failed:b->c");

    const back = setEdgeKind(flipped.spec, "succeeded:a->c", "needs");
    expect(back.ok).toBe(true);
    if (!back.ok) return;
    expect(find(back.spec, "c")).toMatchObject({ needs: ["a"], when: "needs_succeeded" });

    const same = setEdgeKind(flow, "needs:a->c", "needs");
    expect(same.ok && same.spec).toEqual(flow);
    expect(setEdgeKind(flow, "needs:a->zzz", "failed").ok).toBe(false);
  });
});

describe("steps", () => {
  it("addStep picks the first free step-N id and defaults every field", () => {
    const first = addStep(spec(), "command");
    expect(first.id).toBe("step-1");
    expect(order(first.spec)).toEqual(["a", "b", "c", "step-1"]);
    expect(find(first.spec, "step-1")).toEqual({
      id: "step-1",
      action: { kind: "command", argv: ["git", "status"] },
      timeout: "5m",
      effect: "read_only",
      role: "observe",
      output: "compact",
      needs: [],
      when: "needs_succeeded",
      retry: { attempts: 1, backoff: "500ms" },
      approval: "none",
      env: {},
    });

    const second = addStep(first.spec, "connector");
    expect(second.id).toBe("step-2");
    expect(find(second.spec, "step-2").action).toEqual({
      kind: "connector",
      connector: "github",
      call: "runs",
      with: {},
    });
    expect(defaultStep("x", "connector")).toMatchObject({ id: "x", role: "observe" });
  });

  it("removeStep drops references in later steps", () => {
    const flow = spec({ c: { when: { succeeded: "a" } } });
    const after = removeStep(flow, "a");
    expect(order(after)).toEqual(["b", "c"]);
    expect(find(after, "b").needs).toEqual([]);
    expect(find(after, "c").when).toBe("needs_succeeded");
  });

  it("updateStep patches fields and renaming an id rewrites references", () => {
    const flow = spec({ c: { when: { failed: "a" } } });
    const renamed = updateStep(flow, "a", { id: "alpha" });
    expect(order(renamed)).toEqual(["alpha", "b", "c"]);
    expect(find(renamed, "b").needs).toEqual(["alpha"]);
    expect(find(renamed, "c").when).toEqual({ failed: "alpha" });

    const patched = updateStep(flow, "b", { timeout: "1m", approval: "required" });
    expect(find(patched, "b")).toMatchObject({ timeout: "1m", approval: "required" });
    expect(find(patched, "a")).toEqual(find(flow, "a"));
  });

  it("updateStep trims a note and removes the key when nothing is left", () => {
    const noted = updateStep(spec(), "a", { note: "  keep me  " });
    expect(find(noted, "a").note).toBe("keep me");
    expect(find(noted, "b")).not.toHaveProperty("note");
    const blank = updateStep(noted, "a", { note: "   " });
    expect(find(blank, "a")).not.toHaveProperty("note");
    expect(updateStep(noted, "a", { timeout: "1m" }).steps[0].note).toBe("keep me");
    expect(find(updateStep(noted, "a", { note: "" }), "a")).not.toHaveProperty("note");
  });

  it("moveStep refuses to move a step before one it needs", () => {
    const up = moveStep(spec(), "b", -1);
    expect(up.ok).toBe(false);
    if (up.ok) return;
    expect(up.refused.cause).toContain("`a`");

    const down = moveStep(spec(), "a", 1);
    expect(down.ok).toBe(false);

    const cUp = moveStep(spec(), "c", -1);
    expect(cUp.ok && order(cUp.spec)).toEqual(["a", "c", "b"]);
    expect(moveStep(spec(), "a", -1).ok).toBe(false);
    expect(moveStep(spec(), "c", 1).ok).toBe(false);
  });

  it("updateInputs replaces the declared inputs", () => {
    const after = updateInputs(spec(), { base: { description: "branch", default: null } });
    expect(after.inputs).toEqual({ base: { description: "branch", default: null } });
    expect(after.steps).toEqual(spec().steps);
  });
});

describe("toRaw", () => {
  it("emits run for commands and connector/call/with for connectors", () => {
    const flow = spec({
      c: {
        action: { kind: "connector", connector: "jira", call: "issue", with: { key: "PAM-1" } },
        when: { succeeded: "a" },
        env: { CI: "1" },
      },
    });
    const raw = toRaw(flow);
    expect(raw).toMatchObject({
      schema: 1,
      id: "fixture",
      name: "Fixture",
      description: "three steps",
      inputs: flow.inputs,
    });
    expect(raw.steps[0]).toEqual({
      id: "a",
      run: ["git", "a"],
      timeout: "5m",
      effect: "read_only",
      role: "observe",
      output: "compact",
      needs: [],
      when: "needs_succeeded",
      retry: { attempts: 1, backoff: "500ms" },
      approval: "none",
      env: {},
    });
    expect(raw.steps[1].needs).toEqual(["a"]);
    expect(raw.steps[2]).toMatchObject({
      connector: "jira",
      call: "issue",
      with: { key: "PAM-1" },
      when: { succeeded: "a" },
      env: { CI: "1" },
    });
    for (const step of raw.steps) {
      expect(step).not.toHaveProperty("action");
      expect(step).not.toHaveProperty("kind");
    }
    expect(raw.steps[2]).not.toHaveProperty("run");
  });

  it("copies a step note only when it says something", () => {
    const raw = toRaw(spec({ a: { note: "watch the exit code" }, b: { note: "" } }));
    expect(raw.steps[0].note).toBe("watch the exit code");
    expect(raw.steps[1]).not.toHaveProperty("note");
    expect(raw.steps[2]).not.toHaveProperty("note");
  });
});

describe("markerFor", () => {
  it("maps steps[N] to the step id and inputs. to the frame", () => {
    const flow = spec();
    expect(markerFor({ path: "steps[1].run[0]", message: "no shells" }, flow)).toEqual({
      node: "b",
      marker: { path: "steps[1].run[0]", message: "no shells", field: "run[0]" },
    });
    expect(markerFor({ path: "steps[2]", message: "needs run or connector" }, flow)).toEqual({
      node: "c",
      marker: { path: "steps[2]", message: "needs run or connector", field: "" },
    });
    expect(markerFor({ path: "inputs.repo.default", message: "secret" }, flow)).toEqual({
      node: INPUTS_NODE,
      marker: { path: "inputs.repo.default", message: "secret", field: "repo.default" },
    });
    expect(markerFor({ path: "id", message: "bad id" }, flow)).toEqual({
      node: null,
      marker: { path: "id", message: "bad id", field: "id" },
    });
    expect(markerFor({ path: "steps[9].id", message: "gone" }, flow).node).toBeNull();
    expect(markerFor(null, flow)).toEqual({ node: null, marker: null });
  });
});

describe("argv and ids", () => {
  it("splitArgv keeps double-quoted tokens whole and joinArgv re-quotes spaces", () => {
    const line = 'cargo clippy -- -D warnings "two words"';
    const argv = splitArgv(line);
    expect(argv).toEqual(["cargo", "clippy", "--", "-D", "warnings", "two words"]);
    expect(joinArgv(argv)).toBe(line);
    expect(splitArgv("  git   status ")).toEqual(["git", "status"]);
    expect(splitArgv("")).toEqual([]);
    expect(joinArgv(["echo", ""])).toBe('echo ""');
  });

  it("isStepId accepts [a-z0-9-]{1,64} only", () => {
    expect(isStepId("clippy-2")).toBe(true);
    expect(isStepId("a".repeat(64))).toBe(true);
    expect(isStepId("a".repeat(65))).toBe(false);
    expect(isStepId("")).toBe(false);
    expect(isStepId("Clippy")).toBe(false);
    expect(isStepId("has space")).toBe(false);
  });
});

it("preserves command output assertions through designer serialization", () => {
  const raw = toRaw(spec({ a: { expect_empty_output: true } }));
  expect(raw.steps[0].expect_empty_output).toBe(true);
});

it("preserves connector status assertions through designer serialization", () => {
  const raw = toRaw(spec({ a: { expect_status: "OK" } }));
  expect(raw.steps[0].expect_status).toBe("OK");
});
