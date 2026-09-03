import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { FlowSpec, FlowStep } from "../../lib/ipc";
import type { Selection } from "./FlowCanvas";
import { defaultStep } from "./graph";
import { Inspector, type InspectorProps } from "./Inspector";

/**
 * The inspector against the pure graph model: every section edits one
 * thing about the selected step, edge, the inputs, or the flow itself,
 * and every edit arrives as the next whole spec through onChange. What
 * the daemon would refuse (bad ids, a stateful step without approval, a
 * move that puts a dependency after its dependent) never leaves the GUI.
 */

function fixture(): FlowSpec {
  const a: FlowStep = {
    ...defaultStep("a", "command"),
    action: { kind: "command", argv: ["git", "status", "--porcelain"] },
  };
  const b: FlowStep = {
    ...defaultStep("b", "command"),
    action: { kind: "command", argv: ["cargo", "clippy", "--", "-D", "warnings"] },
    needs: ["a"],
    env: { CI: "1" },
  };
  const c: FlowStep = {
    ...defaultStep("c", "connector"),
    action: { kind: "connector", connector: "github", call: "runs", with: { repo: "pam" } },
    when: { succeeded: "b" },
    effect: "stateful",
    approval: "required",
  };
  return {
    id: "fx",
    name: "Fixture",
    description: "three steps",
    inputs: { repo: { description: "the repo", default: "{{ repo.root }}" } },
    steps: [a, b, c],
  };
}

function renderInspector(selection: Selection, overrides: Partial<InspectorProps> = {}) {
  const props: InspectorProps = {
    spec: fixture(),
    selection,
    onChange: vi.fn(),
    onSelect: vi.fn(),
    error: null,
    ...overrides,
  };
  render(<Inspector {...props} />);
  return props;
}

function lastSpec(props: InspectorProps): FlowSpec {
  const calls = (props.onChange as ReturnType<typeof vi.fn>).mock.calls;
  return calls[calls.length - 1][0] as FlowSpec;
}

function step(spec: FlowSpec, id: string): FlowStep {
  const found = spec.steps.find((candidate) => candidate.id === id);
  if (!found) throw new Error(`no step ${id}`);
  return found;
}

describe("Inspector", () => {
  it("edits the flow's name and description when nothing is selected", () => {
    const props = renderInspector({ kind: "none" });
    fireEvent.change(screen.getByLabelText("flow name"), { target: { value: "Readiness" } });
    expect(lastSpec(props).name).toBe("Readiness");
    fireEvent.change(screen.getByLabelText("flow description"), {
      target: { value: "what I check first" },
    });
    expect(lastSpec(props).description).toBe("what I check first");
    expect(screen.getByLabelText("flow description")).toHaveAttribute("rows", "3");
  });

  it("adds and removes input rows", () => {
    const props = renderInspector({ kind: "inputs" });
    expect(screen.getByLabelText("input name")).toHaveValue("repo");
    expect(screen.getByLabelText("input default")).toHaveValue("{{ repo.root }}");
    fireEvent.click(screen.getByRole("button", { name: "Add input" }));
    expect(Object.keys(lastSpec(props).inputs)).toEqual(["repo", "input-1"]);
    expect(lastSpec(props).inputs["input-1"]).toEqual({ description: "", default: null });
    fireEvent.click(screen.getByRole("button", { name: "remove repo" }));
    expect(lastSpec(props).inputs).toEqual({});
    fireEvent.change(screen.getByLabelText("input description"), {
      target: { value: "the repo to check" },
    });
    expect(lastSpec(props).inputs.repo.description).toBe("the repo to check");
  });

  it("refuses a malformed or duplicate step id inline and never calls onChange for it", () => {
    const props = renderInspector({ kind: "step", id: "b" });
    const id = screen.getByLabelText("step id");
    expect(id).toHaveValue("b");
    fireEvent.change(id, { target: { value: "Bad Id" } });
    expect(screen.getByText("ids are [a-z0-9-], unique")).toBeInTheDocument();
    expect(props.onChange).not.toHaveBeenCalled();
    fireEvent.change(id, { target: { value: "a" } });
    expect(screen.getByText("ids are [a-z0-9-], unique")).toBeInTheDocument();
    expect(props.onChange).not.toHaveBeenCalled();
    fireEvent.change(id, { target: { value: "beta" } });
    expect(screen.queryByText("ids are [a-z0-9-], unique")).toBeNull();
    expect(lastSpec(props).steps.map((candidate) => candidate.id)).toEqual(["a", "beta", "c"]);
    expect(step(lastSpec(props), "c").when).toEqual({ succeeded: "beta" });
    expect(props.onSelect).toHaveBeenCalledWith({ kind: "step", id: "beta" });
  });

  it("splits the argv line into argv on Enter and on blur", () => {
    const props = renderInspector({ kind: "step", id: "b" });
    const argv = screen.getByLabelText("argv");
    expect(argv).toHaveValue("cargo clippy -- -D warnings");
    fireEvent.change(argv, { target: { value: 'cargo test "two words"' } });
    expect(props.onChange).not.toHaveBeenCalled();
    fireEvent.keyDown(argv, { key: "Enter" });
    expect(step(lastSpec(props), "b").action).toEqual({
      kind: "command",
      argv: ["cargo", "test", "two words"],
    });
    fireEvent.change(argv, { target: { value: "cargo fmt --check" } });
    fireEvent.blur(argv);
    expect(step(lastSpec(props), "b").action).toEqual({
      kind: "command",
      argv: ["cargo", "fmt", "--check"],
    });
  });

  it("edits env rows on a command step", () => {
    const props = renderInspector({ kind: "step", id: "b" });
    expect(screen.getByLabelText("env name")).toHaveValue("CI");
    fireEvent.change(screen.getByLabelText("env value"), { target: { value: "true" } });
    expect(step(lastSpec(props), "b").env).toEqual({ CI: "true" });
    fireEvent.click(screen.getByRole("button", { name: "Add env" }));
    expect(Object.keys(step(lastSpec(props), "b").env)).toEqual(["CI", "VAR_1"]);
    fireEvent.click(screen.getByRole("button", { name: "remove CI" }));
    expect(step(lastSpec(props), "b").env).toEqual({});
  });

  it("flips the kind to connector with github, its first call, and the required with rows", () => {
    const props = renderInspector({ kind: "step", id: "b" });
    const command = screen.getByRole("button", { name: "command" });
    const connector = screen.getByRole("button", { name: "connector" });
    expect(command).toHaveAttribute("aria-pressed", "true");
    expect(connector).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(connector);
    expect(step(lastSpec(props), "b").action).toEqual({
      kind: "connector",
      connector: "github",
      call: "runs",
      with: { repo: "" },
    });
  });

  it("feeds the call select from the connector's table and pre-lists its arguments", () => {
    const props = renderInspector({ kind: "step", id: "c" });
    expect(screen.getByLabelText("connector")).toHaveValue("github");
    const call = screen.getByLabelText("call");
    expect(call).toHaveValue("runs");
    expect(
      within(call)
        .getAllByRole("option")
        .map((option) => option.textContent),
    ).toEqual(["runs", "run", "job_log"]);
    expect(screen.getByLabelText("with repo")).toHaveValue("pam");
    expect(screen.getByLabelText("with repo")).toHaveAttribute("required");
    expect(screen.getByLabelText("with status")).not.toHaveAttribute("required");

    fireEvent.change(screen.getByLabelText("with limit"), { target: { value: "5" } });
    expect(step(lastSpec(props), "c").action).toMatchObject({
      with: { repo: "pam", limit: 5 },
    });

    fireEvent.change(call, { target: { value: "run" } });
    expect(step(lastSpec(props), "c").action).toEqual({
      kind: "connector",
      connector: "github",
      call: "run",
      with: { repo: "pam", run_id: "" },
    });

    fireEvent.change(screen.getByLabelText("connector"), { target: { value: "jenkins" } });
    expect(step(lastSpec(props), "c").action).toEqual({
      kind: "connector",
      connector: "jenkins",
      call: "jobs",
      with: {},
    });
  });

  it("forces approval to required on a stateful step", () => {
    const props = renderInspector({ kind: "step", id: "b" });
    expect(screen.getByLabelText("approval")).toBeEnabled();
    fireEvent.change(screen.getByLabelText("effect"), { target: { value: "stateful" } });
    expect(step(lastSpec(props), "b")).toMatchObject({
      effect: "stateful",
      approval: "required",
    });
  });

  it("shows the forced approval as a disabled select with a note", () => {
    renderInspector({ kind: "step", id: "c" });
    const approval = screen.getByLabelText("approval");
    expect(approval).toBeDisabled();
    expect(approval).toHaveValue("required");
    expect(screen.getByText("stateful steps always need approval")).toBeInTheDocument();
  });

  it("edits timeout, role, output, and clamps retry attempts to 1–5", () => {
    const props = renderInspector({ kind: "step", id: "b" });
    fireEvent.change(screen.getByLabelText("timeout"), { target: { value: "1m" } });
    expect(step(lastSpec(props), "b").timeout).toBe("1m");
    fireEvent.change(screen.getByLabelText("role"), { target: { value: "verify" } });
    expect(step(lastSpec(props), "b").role).toBe("verify");
    fireEvent.change(screen.getByLabelText("output"), { target: { value: "summarize" } });
    expect(step(lastSpec(props), "b").output).toBe("summarize");
    fireEvent.change(screen.getByLabelText("retry attempts"), { target: { value: "9" } });
    expect(step(lastSpec(props), "b").retry.attempts).toBe(5);
    fireEvent.change(screen.getByLabelText("retry attempts"), { target: { value: "0" } });
    expect(step(lastSpec(props), "b").retry.attempts).toBe(1);
    fireEvent.change(screen.getByLabelText("retry backoff"), { target: { value: "2s" } });
    expect(step(lastSpec(props), "b").retry.backoff).toBe("2s");
    expect(screen.getByLabelText("when")).toHaveTextContent("runs when needs succeeded");
  });

  it("round-trips a step note through the textarea, trimmed, and drops a blank one", () => {
    const spec = fixture();
    spec.steps[1] = { ...spec.steps[1], note: "watch the exit code" };
    const props = renderInspector({ kind: "step", id: "b" }, { spec });
    const note = screen.getByLabelText("note");
    expect(note).toHaveValue("watch the exit code");
    expect(note).toHaveAttribute("rows", "3");
    fireEvent.change(note, { target: { value: "  flaky on CI  " } });
    expect(props.onChange).not.toHaveBeenCalled();
    fireEvent.blur(note);
    expect(step(lastSpec(props), "b").note).toBe("flaky on CI");
    expect(step(lastSpec(props), "a")).not.toHaveProperty("note");
    fireEvent.change(note, { target: { value: "   " } });
    fireEvent.blur(note);
    expect(step(lastSpec(props), "b")).not.toHaveProperty("note");
  });

  it("moves steps through the list and shows a refused move inline", () => {
    const spec = fixture();
    spec.steps[2] = { ...spec.steps[2], when: "needs_succeeded" };
    const props = renderInspector({ kind: "step", id: "b" }, { spec });
    fireEvent.click(screen.getByRole("button", { name: "move b up" }));
    expect(props.onChange).not.toHaveBeenCalled();
    expect(screen.getByLabelText("move refused")).toHaveTextContent("`a`");
    fireEvent.click(screen.getByRole("button", { name: "move c up" }));
    expect(lastSpec(props).steps.map((candidate) => candidate.id)).toEqual(["a", "c", "b"]);
    expect(screen.queryByLabelText("move refused")).toBeNull();
    expect(screen.getByRole("button", { name: "move a up" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "select a" }));
    expect(props.onSelect).toHaveBeenCalledWith({ kind: "step", id: "a" });
  });

  it("flips an edge's kind through the radio", () => {
    const props = renderInspector({ kind: "edge", id: "needs:a->b" });
    expect(screen.getByLabelText("edge")).toHaveTextContent("a → b");
    expect(screen.getByRole("radio", { name: "needs" })).toBeChecked();
    fireEvent.click(screen.getByRole("radio", { name: "succeeded" }));
    expect(step(lastSpec(props), "b")).toMatchObject({ needs: [], when: { succeeded: "a" } });
    expect(props.onSelect).toHaveBeenCalledWith({ kind: "edge", id: "succeeded:a->b" });
  });

  it("shows the validation error only for the thing it belongs to", () => {
    const error = { path: "steps[1].run[0]", message: "shells are refused" };
    const { unmount } = render(
      <Inspector
        spec={fixture()}
        selection={{ kind: "step", id: "b" }}
        onChange={vi.fn()}
        onSelect={vi.fn()}
        error={error}
      />,
    );
    expect(screen.getByText(/flow · shells are refused/)).toBeInTheDocument();
    unmount();
    render(
      <Inspector
        spec={fixture()}
        selection={{ kind: "step", id: "a" }}
        onChange={vi.fn()}
        onSelect={vi.fn()}
        error={error}
      />,
    );
    expect(screen.queryByText(/shells are refused/)).toBeNull();
  });
});
