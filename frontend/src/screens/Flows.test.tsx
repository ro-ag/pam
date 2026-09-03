import { QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAppQueryClient } from "../App";
import type {
  ActivityRow,
  EvidenceContent,
  EvidenceMeta,
  FlowListEntry,
  FlowResult,
  PamEventPayload,
} from "../lib/ipc";
import { withId } from "./FlowEditor";
import { FlowsScreen } from "./Flows";
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
    }),
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
  const editor = (await screen.findByLabelText(`${id} yaml`)) as HTMLTextAreaElement;
  await waitFor(() => expect(editor.value).toContain(`id: ${id}`));
  return editor;
}

/** Picks a flow off the shelf and waits for its editor to follow. */
async function pick(id: string) {
  fireEvent.click(await screen.findByText(id));
  return editorFor(id);
}

describe("the library column", () => {
  it("shelves every flow with its source badge", async () => {
    await renderFlows();
    const library = within(await screen.findByLabelText("flow library"));
    for (const flow of FLOWS) expect(library.getByText(flow.id)).toBeInTheDocument();
    expect(library.getAllByText("builtin")).toHaveLength(2);
    expect(library.getAllByText("library")).toHaveLength(2);
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
    expect(await screen.findByLabelText("pr-readiness yaml")).toBeInTheDocument();
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
      expect(mocks.flowsSave).toHaveBeenCalledWith("mine", "id: mine\nname: PR readiness\nsteps: []\n"),
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
    expect(withId("id: a\nsteps:\n  - id: inner\n", "b")).toBe("id: b\nsteps:\n  - id: inner\n");
  });
});

describe("the run card", () => {
  it("offers the repos pam has seen and takes a free-text path too", async () => {
    await renderFlows();
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
    const card = within(screen.getByLabelText("run this flow"));
    expect(card.getByLabelText("base")).toHaveValue("main");
    expect(card.getByText("the branch to compare against")).toBeInTheDocument();
  });

  it("runs, narrates the ticket's progress, then lands the verdict", async () => {
    await renderFlows();
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
    const card = within(await screen.findByLabelText("run this flow"));
    fireEvent.change(card.getByLabelText("repo path"), { target: { value: "/tmp/x" } });
    fireEvent.click(card.getByRole("button", { name: "Run" }));
    expect(await screen.findByText(/run · capability_denied/)).toBeInTheDocument();
  });

  it("shows a mid-run refusal instead of pretending a verdict exists", async () => {
    await renderFlows();
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
    fireEvent.click(screen.getByRole("button", { name: "runs" }));

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
    fireEvent.click(screen.getByRole("button", { name: "runs" }));
    expect(await screen.findByText(/This flow has not run yet/)).toBeInTheDocument();
  });
});
