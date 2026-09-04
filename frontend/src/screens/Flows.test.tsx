import { QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createAppQueryClient } from "../App";
import type {
  ActivityRow,
  EvidenceContent,
  EvidenceMeta,
  FlowListEntry,
  FlowNormalizeReply,
  FlowResult,
  FlowSpec,
  FlowStep,
  PamEventPayload,
  RawFlow,
} from "../lib/ipc";
import { defaultStep, type CanvasNode } from "./flow-canvas/graph";
import { withId } from "./FlowEditor";
import { CANVAS_QUIET_MS, FlowsScreen, YAML_QUIET_MS } from "./Flows";
import { flowIdOf } from "./FlowRuns";

/**
 * The Flows screen against a mocked bridge — the whole loop a human
 * walks: pick a flow off the shelf, read its YAML, clone a builtin, save
 * one and be refused legibly, start a run and watch its events, then
 * read the verdict out of evidence and find it again in the history.
 */

const mocks = vi.hoisted(() => ({
  flowsList: vi.fn(),
  flowsGet: vi.fn(),
  flowsSave: vi.fn(),
  flowsDelete: vi.fn(),
  flowsNormalize: vi.fn(),
  flowsRun: vi.fn(),
  callersList: vi.fn(),
  activityList: vi.fn(),
  evidenceList: vi.fn(),
  evidenceGet: vi.fn(),
  subscribeEvents: vi.fn(),
}));

vi.mock("../lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/ipc")>();
  return { ...actual, ...mocks };
});

// The canvas is real here; only ELK is kept out — a resolved grid stands
// in for the layout so the bundled engine never loads under jsdom.
vi.mock("./flow-canvas/layout", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./flow-canvas/layout")>();
  return {
    ...actual,
    autoLayout: vi.fn(async (nodes: CanvasNode[]) =>
      Object.fromEntries(nodes.map((node, index) => [node.id, { x: index * 300, y: 0 }])),
    ),
  };
});

const nowSec = Math.floor(Date.now() / 1000);

function entry(overrides: Partial<FlowListEntry>): FlowListEntry {
  return {
    id: "pr-readiness",
    name: "PR readiness",
    description: "Everything I check before you open a pull request.",
    source: "builtin",
    valid: true,
    digest: "sha256:abcd",
    steps: 3,
    inputs: [],
    ...overrides,
  };
}

const FLOWS: FlowListEntry[] = [
  entry({}),
  entry({
    id: "after-merge-checks",
    name: "After-merge checks",
    inputs: [{ name: "base", description: "the branch to compare against", default: "main" }],
  }),
  entry({
    id: "mine",
    name: "Mine",
    source: "library",
    path: "/Users/dev/.pam/flows/mine.yaml",
  }),
  entry({
    id: "broken",
    name: "Half-written flow",
    source: "library",
    valid: false,
    error: "steps[0].run: a command step needs a program",
    digest: "",
    steps: 0,
  }),
];

/** The parsed shape of pr-readiness: three commands, a needs edge, a when edge. */
const SPEC: FlowSpec = {
  id: "pr-readiness",
  name: "PR readiness",
  description: "Everything I check before you open a pull request.",
  inputs: {},
  steps: [
    { ...defaultStep("fmt", "command"), action: { kind: "command", argv: ["cargo", "fmt"] } },
    {
      ...defaultStep("clippy", "command"),
      action: { kind: "command", argv: ["cargo", "clippy"] },
      needs: ["fmt"],
    },
    {
      ...defaultStep("tests", "command"),
      action: { kind: "command", argv: ["cargo", "test"] },
      when: { failed: "clippy" },
    },
  ],
};

/** What the daemon would resolve a raw file shape into, defaults filled. */
function resolve(raw: RawFlow): FlowSpec {
  return {
    id: raw.id,
    name: raw.name,
    description: raw.description ?? "",
    inputs: Object.fromEntries(
      Object.entries(raw.inputs ?? {}).map(([name, input]) => [
        name,
        { description: input.description ?? "", default: input.default ?? null },
      ]),
    ),
    steps: raw.steps.map((step): FlowStep => ({
      ...defaultStep(step.id, step.run ? "command" : "connector"),
      ...(step.run ? { action: { kind: "command", argv: step.run } } : {}),
      needs: step.needs ?? [],
      when: step.when ?? "needs_succeeded",
    })),
  };
}

/** The canonical YAML the normalizer answers a raw flow with. */
function canonical(raw: RawFlow): string {
  return `schema: 1\nid: ${raw.id}\nname: ${raw.name}\n# steps: ${raw.steps
    .map((step) => step.id)
    .join(", ")}\n`;
}

const VERDICT: FlowResult = {
  flow: { id: "pr-readiness", name: "PR readiness", source: "builtin", digest: "sha256:abcd" },
  repo: "/Users/dev/work/pam",
  inputs: {},
  outcome: "verified",
  summary: "Every check passed; this branch is ready to open.",
  steps: [
    {
      id: "fmt",
      kind: "command",
      status: "succeeded",
      attempts: 1,
      duration_ms: 420,
      exit_status: 0,
      evidence: [],
    },
    {
      id: "tests",
      kind: "command",
      status: "failed",
      attempts: 2,
      duration_ms: 90_000,
      exit_status: 101,
      evidence: [],
      error: {
        cause: "exit_status",
        detail: "cargo test exited 101",
        recovery: "Read the compacted log in this run's evidence.",
      },
    },
  ],
};

function evidenceMeta(overrides: Partial<EvidenceMeta>): EvidenceMeta {
  return {
    id: "ev_v",
    request_id: "req_run",
    kind: "flow.result",
    bytes: 400,
    sha256: "abc",
    meta: null,
    ts: nowSec,
    ...overrides,
  };
}

function activity(overrides: Partial<ActivityRow>): ActivityRow {
  return {
    id: "req_run",
    capability: "flow.run",
    repo: "/Users/dev/work/pam",
    agent: "pam-gui",
    args: { id: "pr-readiness", inputs: {} },
    state: "done",
    outcome: "verified",
    created_ts: nowSec - 60,
    updated_ts: nowSec - 10,
    ...overrides,
  };
}

/** Feeds the events the screen subscribed to, as the daemon would. */
let feed: (payload: PamEventPayload) => void = () => {};

beforeEach(() => {
  mocks.flowsList.mockResolvedValue({ flows: FLOWS });
  mocks.flowsGet.mockImplementation((id: string) =>
    Promise.resolve({
      ...(FLOWS.find((flow) => flow.id === id) ?? FLOWS[0]),
      yaml: `id: ${id}\nname: PR readiness\nsteps: []\n`,
      normalized_yaml: `id: ${id}\n`,
      flow: id === "broken" ? null : { ...SPEC, id },
    }),
  );
  mocks.flowsNormalize.mockImplementation(
    (input: { yaml: string } | { flow: RawFlow }): Promise<FlowNormalizeReply> =>
      Promise.resolve(
        "flow" in input
          ? { valid: true, yaml: canonical(input.flow), flow: resolve(input.flow), digest: "d" }
          : { valid: true, yaml: input.yaml, flow: SPEC, digest: "d" },
      ),
  );
  mocks.flowsSave.mockResolvedValue(entry({ id: "mine", source: "library" }));
  mocks.flowsDelete.mockResolvedValue({ id: "mine", revealed_builtin: false });
  mocks.flowsRun.mockResolvedValue({ ticket: "req_run", position: 0 });
  mocks.callersList.mockResolvedValue({
    callers: [
      { agent: "claude", repo: "/Users/dev/work/pam", first_seen: nowSec, last_seen: nowSec },
    ],
  });
  mocks.activityList.mockResolvedValue({ requests: [activity({})] });
  mocks.evidenceList.mockResolvedValue({ evidence: [evidenceMeta({})] });
  mocks.evidenceGet.mockImplementation((id: string) =>
    Promise.resolve({
      ...evidenceMeta({ id }),
      text: JSON.stringify(VERDICT),
      text_bytes: 400,
      truncated: false,
    } satisfies EvidenceContent),
  );
  mocks.subscribeEvents.mockImplementation((handler: (payload: PamEventPayload) => void) => {
    feed = handler;
    return Promise.resolve(() => {});
  });
});

function renderFlows() {
  render(
    <QueryClientProvider client={createAppQueryClient()}>
      <FlowsScreen />
    </QueryClientProvider>,
  );
  return screen.findByRole("heading", { name: "Flows", level: 1 });
}

/** Waits until the editor holds the named flow's own text. */
async function editorFor(id: string): Promise<HTMLTextAreaElement> {
  fireEvent.click(await screen.findByRole("tab", { name: "YAML" }));
  const editor = (await screen.findByLabelText(`${id} yaml`)) as HTMLTextAreaElement;
  await waitFor(() => expect(editor.value).toContain(`id: ${id}`));
  return editor;
}

/** Picks a flow off the shelf and waits for its editor to follow. */
async function pick(id: string) {
  const library = within(await screen.findByLabelText("flow library"));
  fireEvent.click(library.getByTitle(id));
  return editorFor(id);
}

/** A step's card on the canvas. */
async function nodeFor(id: string): Promise<HTMLElement> {
  return screen.findByLabelText(`step ${id}`);
}

/** Lets a debounce elapse and the reply land. */
/** The step card's status rail, the run's voice on the canvas. */
function rail(id: string): HTMLElement {
  return within(screen.getByLabelText(`step ${id}`)).getByTestId("rail");
}

async function quiet(ms: number) {
  await act(async () => {
    vi.advanceTimersByTime(ms);
  });
}

/** Starts a run of the selected flow from its card and waits for the ticket. */
async function startRun() {
  fireEvent.click(screen.getByRole("tab", { name: "Run flow" }));
  const card = within(await screen.findByLabelText("run this flow"));
  fireEvent.change(card.getByLabelText("repo path"), {
    target: { value: "/Users/dev/work/pam" },
  });
  fireEvent.click(card.getByRole("button", { name: "Run" }));
  await waitFor(() => expect(mocks.subscribeEvents).toHaveBeenCalled());
  fireEvent.click(screen.getByRole("tab", { name: "Canvas" }));
}

describe("the library column", () => {
  it("names each flow once and marks custom copies", async () => {
    await renderFlows();
    const library = within(await screen.findByLabelText("flow library"));
    for (const flow of FLOWS)
      expect(library.getByRole("button", { name: new RegExp(flow.name) })).toBeInTheDocument();
    expect(library.getAllByText("Custom")).toHaveLength(2);
    expect(library.queryByText("builtin")).not.toBeInTheDocument();
  });

  it("marks an unparseable flow invalid and says why, twice over", async () => {
    await renderFlows();
    const library = within(await screen.findByLabelText("flow library"));
    const badge = library.getByText("invalid");
    expect(badge).toHaveAttribute("title", "steps[0].run: a command step needs a program");
    expect(
      library.getByText("steps[0].run: a command step needs a program"),
    ).toBeInTheDocument();
  });

  it("opens the first flow on the shelf without being asked", async () => {
    await renderFlows();
    expect(await screen.findByRole("heading", { name: "PR readiness" })).toBeInTheDocument();
  });

  it("preselects the flow named by the route search", async () => {
    render(
      <QueryClientProvider client={createAppQueryClient()}>
        <FlowsScreen initialFlow="after-merge-checks" />
      </QueryClientProvider>,
    );
    expect(
      await screen.findByRole("region", { name: "flow after-merge-checks" }),
    ).toBeInTheDocument();
  });

  it("falls back to the top of the shelf when the search names an unknown flow", async () => {
    render(
      <QueryClientProvider client={createAppQueryClient()}>
        <FlowsScreen initialFlow="no-such-flow" />
      </QueryClientProvider>,
    );
    expect(
      await screen.findByRole("region", { name: "flow pr-readiness" }),
    ).toBeInTheDocument();
  });
});

describe("the YAML tab", () => {
  it("shows the flow's own text in the data voice", async () => {
    await renderFlows();
    const editor = await editorFor("pr-readiness");
    expect(editor).toHaveValue("id: pr-readiness\nname: PR readiness\nsteps: []\n");
    expect(editor.className).toContain("font-data");
  });

  it("saves a library flow under its own id", async () => {
    await renderFlows();
    await pick("mine");
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(mocks.flowsSave).toHaveBeenCalledWith(
        "mine",
        "id: mine\nname: PR readiness\nsteps: []\n",
      ),
    );
  });

  it("renders the daemon's validation refusal as a FailureNote naming the path", async () => {
    mocks.flowsSave.mockRejectedValue({
      cause: "flow_invalid",
      detail: 'saving "mine": steps[1].connector: unknown connector "gitlab"',
      recovery: "Open Pam → Flows and fix the file.",
    });
    await renderFlows();
    await pick("mine");
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText(/flow · flow_invalid/)).toBeInTheDocument();
    expect(screen.getByText(/steps\[1\]\.connector/)).toBeInTheDocument();
  });

  it("turns Save into Clone on a builtin and demands a new id", async () => {
    await renderFlows();
    await editorFor("pr-readiness");
    const clone = screen.getByRole("button", { name: "Clone" });
    expect(screen.queryByRole("button", { name: "Save" })).not.toBeInTheDocument();
    expect(clone).toBeDisabled();

    fireEvent.change(screen.getByLabelText("new flow id"), { target: { value: "my-prs" } });
    fireEvent.click(screen.getByRole("button", { name: "Clone" }));
    // The YAML's own id line follows the new name, or the daemon would
    // refuse the pair with `id_mismatch`.
    await waitFor(() =>
      expect(mocks.flowsSave).toHaveBeenCalledWith(
        "my-prs",
        "id: my-prs\nname: PR readiness\nsteps: []\n",
      ),
    );
  });

  it("offers Delete on a library flow only, behind the two-tap confirm", async () => {
    await renderFlows();
    await editorFor("pr-readiness");
    expect(screen.queryByRole("button", { name: "Delete" })).not.toBeInTheDocument();

    await pick("mine");
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(mocks.flowsDelete).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "delete it?" }));
    await waitFor(() => expect(mocks.flowsDelete).toHaveBeenCalledWith("mine"));
  });

  it("rewrites only the top-level id line when cloning", () => {
    expect(withId("id: a\nname: A\n", "b")).toBe("id: b\nname: A\n");
    expect(withId("name: A\n", "b")).toBe("id: b\nname: A\n");
    expect(withId("id: a\nsteps:\n  - id: inner\n", "b")).toBe(
      "id: b\nsteps:\n  - id: inner\n",
    );
  });
});

describe("the run card", () => {
  it("offers the repos pam has seen and takes a free-text path too", async () => {
    await renderFlows();
    fireEvent.click(await screen.findByRole("tab", { name: "Run flow" }));
    const card = within(await screen.findByLabelText("run this flow"));
    await waitFor(() =>
      expect(card.getByRole("option", { name: "/Users/dev/work/pam" })).toBeInTheDocument(),
    );
    fireEvent.change(card.getByLabelText("known repo"), {
      target: { value: "/Users/dev/work/pam" },
    });
    expect(card.getByLabelText("repo path")).toHaveValue("/Users/dev/work/pam");

    fireEvent.change(card.getByLabelText("repo path"), { target: { value: "/tmp/other" } });
    expect(card.getByLabelText("repo path")).toHaveValue("/tmp/other");
  });

  it("gives every declared input a field, prefilled with its default", async () => {
    await renderFlows();
    await pick("after-merge-checks");
    fireEvent.click(await screen.findByRole("tab", { name: "Run flow" }));
    const card = within(screen.getByLabelText("run this flow"));
    expect(card.getByLabelText("base")).toHaveValue("main");
    expect(card.getByText("the branch to compare against")).toBeInTheDocument();
  });

  it("runs, narrates the ticket's progress, then lands the verdict", async () => {
    await renderFlows();
    fireEvent.click(await screen.findByRole("tab", { name: "Run flow" }));
    const card = within(await screen.findByLabelText("run this flow"));
    fireEvent.change(card.getByLabelText("repo path"), {
      target: { value: "/Users/dev/work/pam" },
    });
    fireEvent.click(card.getByRole("button", { name: "Run" }));
    await waitFor(() =>
      expect(mocks.flowsRun).toHaveBeenCalledWith("pr-readiness", "/Users/dev/work/pam", {}),
    );

    await waitFor(() => expect(mocks.subscribeEvents).toHaveBeenCalled());
    feed({ ticket: "req_run", event: { kind: "progress", note: "step 2/3 · cargo test" } });
    expect(await screen.findByText("step 2/3 · cargo test")).toBeInTheDocument();

    // Another ticket's events are not this run's business.
    feed({ ticket: "req_other", event: { kind: "progress", note: "not mine" } });
    expect(screen.queryByText("not mine")).not.toBeInTheDocument();

    feed({ ticket: "req_run", event: { kind: "done" } });
    const verdict = within(await screen.findByLabelText("run verdict"));
    expect(verdict.getByText("verified")).toBeInTheDocument();
    expect(
      verdict.getByText("Every check passed; this branch is ready to open."),
    ).toBeInTheDocument();
    expect(verdict.getByText("fmt")).toBeInTheDocument();
    expect(verdict.getByText("failed")).toBeInTheDocument();
    expect(verdict.getByText(/cargo test exited 101/)).toBeInTheDocument();
    expect(mocks.evidenceList).toHaveBeenCalledWith("req_run");
  });

  it("says so plainly when the daemon refuses the run outright", async () => {
    mocks.flowsRun.mockRejectedValue({
      cause: "capability_denied",
      detail: 'capability "flow.run" is not granted',
      recovery: "Grant it in Pam → Settings → Security.",
    });
    await renderFlows();
    fireEvent.click(await screen.findByRole("tab", { name: "Run flow" }));
    const card = within(await screen.findByLabelText("run this flow"));
    fireEvent.change(card.getByLabelText("repo path"), { target: { value: "/tmp/x" } });
    fireEvent.click(card.getByRole("button", { name: "Run" }));
    expect(await screen.findByText(/run · capability_denied/)).toBeInTheDocument();
  });

  it("shows a mid-run refusal instead of pretending a verdict exists", async () => {
    await renderFlows();
    fireEvent.click(await screen.findByRole("tab", { name: "Run flow" }));
    const card = within(await screen.findByLabelText("run this flow"));
    fireEvent.change(card.getByLabelText("repo path"), { target: { value: "/tmp/x" } });
    fireEvent.click(card.getByRole("button", { name: "Run" }));
    await waitFor(() => expect(mocks.subscribeEvents).toHaveBeenCalled());
    feed({ ticket: "req_run", event: { kind: "refused" } });
    expect(await screen.findByText(/run · refused/)).toBeInTheDocument();
  });
});

describe("the Runs tab", () => {
  it("asks the tide for this flow's runs only, and expands one into its verdict", async () => {
    mocks.activityList.mockResolvedValue({
      requests: [
        activity({}),
        activity({ id: "req_other", args: { id: "after-merge-checks" }, outcome: "solved" }),
      ],
    });
    await renderFlows();
    await editorFor("pr-readiness");
    fireEvent.click(screen.getByRole("tab", { name: "Run history" }));

    await waitFor(() =>
      expect(mocks.activityList).toHaveBeenCalledWith({ capability: "flow.run", limit: 50 }),
    );
    const runs = within(await screen.findByLabelText("runs"));
    const rows = runs.getAllByRole("listitem");
    expect(rows).toHaveLength(1);
    expect(runs.getByText("verified")).toBeInTheDocument();
    expect(runs.getByText("pam")).toBeInTheDocument();

    fireEvent.click(runs.getByRole("button", { expanded: false }));
    const verdict = within(await screen.findByLabelText("run verdict"));
    expect(verdict.getByText("tests")).toBeInTheDocument();
    // The request's whole evidence strip rides along.
    expect(await screen.findByRole("group", { name: "evidence" })).toBeInTheDocument();
  });

  it("reads the flow id off a request's parsed args, defensively", () => {
    expect(flowIdOf({ id: "mine" })).toBe("mine");
    expect(flowIdOf({ id: 7 })).toBeNull();
    expect(flowIdOf(null)).toBeNull();
    expect(flowIdOf("mine")).toBeNull();
  });

  it("says the flow has never run rather than showing an empty table", async () => {
    mocks.activityList.mockResolvedValue({ requests: [] });
    await renderFlows();
    await editorFor("pr-readiness");
    fireEvent.click(screen.getByRole("tab", { name: "Run history" }));
    expect(await screen.findByText(/This flow has not run yet/)).toBeInTheDocument();
  });
});

describe("the canvas tab", () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("opens on the canvas tab with one node per step", async () => {
    await renderFlows();
    const tabs = within(screen.getByRole("tablist", { name: "flow view" }));
    expect(tabs.getAllByRole("tab").map((tab) => tab.textContent)).toEqual([
      "Canvas",
      "YAML",
      "Run flow",
      "Run history",
    ]);
    expect(tabs.getByRole("tab", { name: "Canvas" })).toHaveAttribute("aria-selected", "true");
    for (const [id, order] of [
      ["fmt", "1"],
      ["clippy", "2"],
      ["tests", "3"],
    ]) {
      expect(within(await nodeFor(id)).getByLabelText(`order ${order}`)).toHaveTextContent(
        order,
      );
    }
    expect(screen.getByLabelText("inspector")).toBeInTheDocument();
    // Canvas has shared save/run actions, but no duplicate YAML editor.
    expect(screen.queryByLabelText("pr-readiness yaml")).not.toBeInTheDocument();
    expect(screen.getByLabelText("run this flow")).not.toBeVisible();
    expect(screen.getByRole("tab", { name: "Run flow" })).toBeInTheDocument();
    expect(mocks.flowsNormalize).not.toHaveBeenCalled();
  });

  it("a canvas edit normalizes and rewrites the yaml tab's text", async () => {
    await renderFlows();
    await nodeFor("fmt");
    fireEvent.click(screen.getByRole("button", { name: "Add command" }));
    // The node is there at once; the daemon is asked only after the quiet.
    expect(await nodeFor("step-1")).toBeInTheDocument();
    expect(screen.getByLabelText("draft status")).toHaveTextContent("unsaved");
    expect(mocks.flowsNormalize).not.toHaveBeenCalled();

    await quiet(CANVAS_QUIET_MS);
    await waitFor(() => expect(mocks.flowsNormalize).toHaveBeenCalledTimes(1));
    const sent = mocks.flowsNormalize.mock.calls[0][0] as { flow: RawFlow };
    expect(sent.flow.schema).toBe(1);
    expect(sent.flow.steps.map((step) => step.id)).toEqual([
      "fmt",
      "clippy",
      "tests",
      "step-1",
    ]);
    expect(sent.flow.steps[3].run).toEqual(["git", "status"]);
    expect(sent.flow.steps[3]).not.toHaveProperty("action");
    expect(sent.flow.steps[1].needs).toEqual(["fmt"]);
    expect(sent.flow.steps[2].when).toEqual({ failed: "clippy" });

    fireEvent.click(screen.getByRole("tab", { name: "YAML" }));
    await waitFor(() =>
      expect(screen.getByLabelText("pr-readiness yaml")).toHaveValue(canonical(sent.flow)),
    );
    // The canvas keeps the resolved reply, not its own guess.
    fireEvent.click(screen.getByRole("tab", { name: "Canvas" }));
    expect(await nodeFor("step-1")).toBeInTheDocument();
    expect(screen.getByLabelText("draft status")).toHaveTextContent("Save writes it");
  });

  it("a yaml edit re-parses into the canvas after the debounce", async () => {
    await renderFlows();
    await pick("mine");
    const typed = "id: mine\nname: Mine\nsteps:\n  - id: extra\n    run: [git, log]\n";
    mocks.flowsNormalize.mockResolvedValue({
      valid: true,
      yaml: "schema: 1\nid: mine\n# canonical\n",
      flow: {
        ...SPEC,
        id: "mine",
        steps: [
          {
            ...defaultStep("extra", "command"),
            action: { kind: "command", argv: ["git", "log"] },
          },
        ],
      },
      digest: "d2",
    });
    fireEvent.change(screen.getByLabelText("mine yaml"), { target: { value: typed } });
    expect(screen.getByLabelText("draft status")).toHaveTextContent("checking the flow…");

    await quiet(YAML_QUIET_MS - 1);
    expect(mocks.flowsNormalize).not.toHaveBeenCalled();
    await quiet(1);
    await waitFor(() => expect(mocks.flowsNormalize).toHaveBeenCalledWith({ yaml: typed }));

    // The human's text is theirs until Save; the reply never rewrites it.
    expect(screen.getByLabelText("mine yaml")).toHaveValue(typed);
    fireEvent.click(screen.getByRole("tab", { name: "Canvas" }));
    expect(await nodeFor("extra")).toBeInTheDocument();
    expect(screen.queryByLabelText("step fmt")).toBeNull();
    expect(screen.getByRole("button", { name: "Save" })).toBeEnabled();
  });

  it("switching to the canvas flushes a pending yaml check and drops stale replies", async () => {
    await renderFlows();
    await pick("mine");
    fireEvent.click(screen.getByRole("tab", { name: "YAML" }));
    let answer: (reply: FlowNormalizeReply) => void = () => {};
    mocks.flowsNormalize.mockImplementationOnce(
      () =>
        new Promise<FlowNormalizeReply>((resolvePromise) => {
          answer = resolvePromise;
        }),
    );
    fireEvent.change(screen.getByLabelText("mine yaml"), { target: { value: "id: mine\n" } });
    expect(mocks.flowsNormalize).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("tab", { name: "Canvas" }));
    expect(mocks.flowsNormalize).toHaveBeenCalledTimes(1);

    // A newer edit lands while the first answer is still out: when that
    // first answer finally arrives it is ignored, and only the second counts.
    fireEvent.click(screen.getByRole("button", { name: "Add command" }));
    await quiet(CANVAS_QUIET_MS);
    await waitFor(() => expect(mocks.flowsNormalize).toHaveBeenCalledTimes(2));
    await waitFor(() =>
      expect(screen.getByLabelText("draft status")).toHaveTextContent("Save"),
    );
    await act(async () => {
      answer({
        valid: false,
        error: { path: "steps[0].run", message: "stale answer, must be dropped" },
      });
    });
    expect(screen.queryByText(/stale answer/)).toBeNull();
    expect(screen.getByRole("button", { name: "Save" })).toBeEnabled();
  });

  it("an invalid reply marks the node and disables Save", async () => {
    await renderFlows();
    await pick("mine");
    mocks.flowsNormalize.mockResolvedValue({
      valid: false,
      error: { path: "steps[1].run[0]", message: "shells are refused" },
    });
    fireEvent.change(screen.getByLabelText("mine yaml"), {
      target: { value: "id: mine\nsteps:\n  - run: [bash]\n" },
    });
    await quiet(YAML_QUIET_MS);
    await waitFor(() => expect(mocks.flowsNormalize).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByRole("tab", { name: "Canvas" }));
    const clippy = await nodeFor("clippy");
    await waitFor(() =>
      expect(within(clippy).getByLabelText("validation marker")).toHaveAttribute(
        "title",
        "shells are refused",
      ),
    );
    expect(clippy.className).toContain("ring-danger");
    expect(within(await nodeFor("fmt")).queryByLabelText("validation marker")).toBeNull();
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    expect(screen.getByLabelText("draft status")).toHaveTextContent("will not run as written");

    // A flow-level path has no node to sit on: it is said above the canvas.
    mocks.flowsNormalize.mockResolvedValue({
      valid: false,
      error: { path: "id", message: "ids are [a-z0-9-]" },
    });
    fireEvent.click(screen.getByRole("tab", { name: "YAML" }));
    fireEvent.change(screen.getByLabelText("mine yaml"), { target: { value: "id: Mine!\n" } });
    await quiet(YAML_QUIET_MS);
    fireEvent.click(screen.getByRole("tab", { name: "Canvas" }));
    // Said above the canvas, and again in the inspector's own note.
    expect(await screen.findAllByText(/flow · ids are \[a-z0-9-\]/)).toHaveLength(2);
    expect(within(await nodeFor("clippy")).queryByLabelText("validation marker")).toBeNull();
  });

  it("run notes paint rims and the verdict settles them", async () => {
    await renderFlows();
    await nodeFor("fmt");
    await startRun();

    act(() =>
      feed({ ticket: "req_run", event: { kind: "progress", note: "fmt: running (1/3)" } }),
    );
    await waitFor(() => expect(rail("fmt").className).toContain("animate-breathe"));
    act(() => feed({ ticket: "req_run", event: { kind: "progress", note: "fmt: succeeded" } }));
    act(() =>
      feed({ ticket: "req_run", event: { kind: "progress", note: "queued · nothing" } }),
    );
    act(() =>
      feed({ ticket: "req_run", event: { kind: "progress", note: "clippy: running (2/3)" } }),
    );
    await waitFor(() => {
      expect(rail("fmt").className).toContain("bg-success");
      expect(rail("clippy").className).toContain("animate-breathe");
    });
    expect(rail("tests").className).toContain("bg-line");

    // Done: the verdict from evidence paints the final rails and the outcome chip.
    act(() => feed({ ticket: "req_run", event: { kind: "done" } }));
    await screen.findByLabelText("run verdict");
    await waitFor(() => {
      expect(rail("tests").className).toContain("bg-danger");
      expect(rail("fmt").className).toContain("bg-success");
    });
    expect(rail("clippy").className).toContain("bg-line");
    const verdictFrame = within(screen.getByLabelText("verdict frame"));
    expect(verdictFrame.getByText("verified").className).not.toContain("opacity-40");
    expect(verdictFrame.getByText("blocked").className).toContain("opacity-40");
  });

  it("editing after a run clears the rails", async () => {
    await renderFlows();
    await nodeFor("fmt");
    await startRun();
    act(() => feed({ ticket: "req_run", event: { kind: "progress", note: "fmt: succeeded" } }));
    await waitFor(() => expect(rail("fmt").className).toContain("bg-success"));

    fireEvent.click(screen.getByRole("button", { name: "Add command" }));
    await waitFor(() => expect(rail("fmt").className).not.toContain("bg-success"));

    // The same from the textarea.
    act(() => feed({ ticket: "req_run", event: { kind: "progress", note: "fmt: failed" } }));
    await waitFor(() => expect(rail("fmt").className).toContain("bg-danger"));
    fireEvent.click(screen.getByRole("tab", { name: "YAML" }));
    fireEvent.change(screen.getByLabelText("pr-readiness yaml"), {
      target: { value: "id: pr-readiness\n" },
    });
    fireEvent.click(screen.getByRole("tab", { name: "Canvas" }));
    await waitFor(() => expect(rail("fmt").className).not.toContain("bg-danger"));
  });
});
