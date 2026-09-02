import { createMemoryHistory } from "@tanstack/react-router";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import { createAppRouter } from "../router";
import type { ActivityRow, PamEventPayload } from "../lib/ipc";
import { EVENT_REFRESH_MS } from "./Activity";

/**
 * The Activity tide against a mocked bridge. The whole App mounts (shell
 * included) so URL search params, the query provider, and the screen are
 * exercised together, exactly as shipped.
 */

const mocks = vi.hoisted(() => ({
  activityList: vi.fn(),
  callersList: vi.fn(),
  subscribeEvents: vi.fn(),
  daemonStatus: vi.fn(),
  approvalsPending: vi.fn(),
  evidenceStats: vi.fn(),
  evidenceList: vi.fn(),
  evidenceGet: vi.fn(),
  logCompress: vi.fn(),
}));

vi.mock("../lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/ipc")>();
  return { ...actual, ...mocks };
});

// The band's odometer rolls with `motion`; pinned still here so the tide's
// own assertions never race an animation frame.
vi.mock("motion/react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("motion/react")>();
  return { ...actual, useReducedMotion: () => true };
});

/** Handlers captured from every subscribeEvents call (screen + beacon). */
let eventHandlers: Array<(payload: PamEventPayload) => void>;

function row(overrides: Partial<ActivityRow>): ActivityRow {
  return {
    id: "req_1",
    capability: "echo",
    repo: "/Users/dev/pam",
    agent: "claude",
    args: { hello: "water" },
    state: "done",
    outcome: "solved",
    created_ts: Math.floor(Date.now() / 1000) - 185,
    updated_ts: Math.floor(Date.now() / 1000) - 100,
    ...overrides,
  };
}

const TIDE: ActivityRow[] = [
  row({ id: "req_run", capability: "compress.log", state: "running", outcome: null }),
  row({ id: "req_done", capability: "echo", state: "done", outcome: "solved" }),
  row({
    id: "req_ref",
    capability: "repo.push",
    repo: "/Users/dev/other",
    agent: "codex",
    state: "refused",
    outcome: null,
  }),
];

beforeEach(() => {
  eventHandlers = [];
  mocks.activityList.mockResolvedValue({ requests: TIDE });
  mocks.callersList.mockResolvedValue({
    callers: [
      { agent: "claude", repo: "/Users/dev/pam", first_seen: 1, last_seen: 2 },
      { agent: "codex", repo: "/Users/dev/other", first_seen: 1, last_seen: 2 },
    ],
  });
  mocks.subscribeEvents.mockImplementation((handler: (payload: PamEventPayload) => void) => {
    eventHandlers.push(handler);
    return Promise.resolve(() => {});
  });
  mocks.daemonStatus.mockResolvedValue({ connected: false, status: null });
  mocks.approvalsPending.mockResolvedValue({ pending: [] });
  mocks.evidenceStats.mockResolvedValue({
    since_ts: 1_700_000_000,
    compressions: 0,
    source_bytes: 0,
    compact_bytes: 0,
    tokens_avoided_est: 0,
  });
  mocks.evidenceList.mockResolvedValue({ evidence: [] });
  mocks.evidenceGet.mockResolvedValue(null);
  mocks.logCompress.mockResolvedValue(null);
});

afterEach(() => {
  vi.useRealTimers();
  window.localStorage.clear();
  delete document.documentElement.dataset.theme;
  delete document.documentElement.dataset.mode;
});

function renderActivity(path = "/activity") {
  const router = createAppRouter(createMemoryHistory({ initialEntries: [path] }));
  render(<App router={router} />);
  return router;
}

describe("the tide", () => {
  it("renders one row per request with capability, agent, repo tail, and verdict", async () => {
    renderActivity();
    expect(await screen.findByText("compress.log")).toBeInTheDocument();
    expect(screen.getByText("repo.push")).toBeInTheDocument();
    // Truth vocabulary + live states as badges, scoped to the tide list
    // ("refused" is also a segment label in the header).
    const tide = within(screen.getByRole("list"));
    expect(tide.getByText("solved")).toBeInTheDocument();
    expect(tide.getByText("running")).toBeInTheDocument();
    expect(tide.getByText("refused")).toBeInTheDocument();
    // Repo renders as its tail, full path on the title attribute.
    const tail = screen.getAllByTitle("/Users/dev/pam")[0];
    expect(tail).toHaveTextContent(/^pam$/);
    expect(screen.getAllByText("claude").length).toBeGreaterThan(0);
    expect(mocks.activityList).toHaveBeenCalledWith({
      limit: 100,
      repo: undefined,
      agent: undefined,
      state: undefined,
    });
  });

  it("opens a row into its detail with pretty args and exact stamps", async () => {
    renderActivity();
    const rowButton = (await screen.findByText("compress.log")).closest("button");
    expect(rowButton).not.toBeNull();
    expect(rowButton).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(rowButton as HTMLElement);
    expect(rowButton).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("req_run")).toBeInTheDocument();
    expect(screen.getByText(/"hello": "water"/)).toBeInTheDocument();
    fireEvent.click(rowButton as HTMLElement);
    expect(screen.queryByText("req_run")).not.toBeInTheDocument();
  });

  it("asks for the expanded request's evidence", async () => {
    renderActivity();
    const rowButton = (await screen.findByText("compress.log")).closest("button");
    expect(mocks.evidenceList).not.toHaveBeenCalled();
    fireEvent.click(rowButton as HTMLElement);
    await waitFor(() => expect(mocks.evidenceList).toHaveBeenCalledWith("req_run"));
    // No evidence, no new furniture in the detail.
    expect(screen.queryByRole("group", { name: "evidence" })).not.toBeInTheDocument();
  });
});

describe("filters", () => {
  it("puts the repo filter in the URL and refetches with it", async () => {
    const router = renderActivity();
    await screen.findByText("compress.log");
    fireEvent.change(screen.getByRole("combobox", { name: "repo filter" }), {
      target: { value: "/Users/dev/other" },
    });
    await waitFor(() =>
      expect(mocks.activityList).toHaveBeenLastCalledWith(
        expect.objectContaining({ repo: "/Users/dev/other" }),
      ),
    );
    expect(router.state.location.search).toEqual({ repo: "/Users/dev/other" });
  });

  it("maps the state segments onto store states and the URL", async () => {
    const router = renderActivity();
    await screen.findByText("compress.log");
    fireEvent.click(screen.getByRole("button", { name: "refused", pressed: false }));
    await waitFor(() =>
      expect(mocks.activityList).toHaveBeenLastCalledWith(
        expect.objectContaining({ state: "refused" }),
      ),
    );
    expect(router.state.location.search).toEqual({ state: "refused" });
    expect(screen.getByRole("button", { name: "refused", pressed: true })).toBeInTheDocument();
  });

  it("narrows the active lens client-side (queued+running, one unfiltered fetch)", async () => {
    renderActivity("/activity?state=active");
    expect(await screen.findByText("compress.log")).toBeInTheDocument();
    expect(screen.queryByText("repo.push")).not.toBeInTheDocument();
    expect(mocks.activityList).toHaveBeenCalledWith(
      expect.objectContaining({ state: undefined }),
    );
  });

  it("restores filters from a shared URL, keeping unlisted values selectable", async () => {
    renderActivity("/activity?repo=/gone/repo&state=failed");
    await screen.findByRole("heading", { name: "Activity" });
    await waitFor(() =>
      expect(mocks.activityList).toHaveBeenCalledWith(
        expect.objectContaining({ repo: "/gone/repo", state: "failed" }),
      ),
    );
    expect(screen.getByRole("combobox", { name: "repo filter" })).toHaveValue("/gone/repo");
  });
});

describe("live updates", () => {
  it("coalesces an event burst into one debounced refetch", async () => {
    renderActivity();
    await screen.findByText("compress.log");
    await waitFor(() => expect(eventHandlers.length).toBeGreaterThan(0));
    const initialCalls = mocks.activityList.mock.calls.length;

    vi.useFakeTimers();
    const burst: PamEventPayload = { ticket: "t1", event: { kind: "done" } };
    act(() => {
      for (const handler of eventHandlers) handler(burst);
      for (const handler of eventHandlers) handler(burst);
      for (const handler of eventHandlers) handler(burst);
    });
    // Inside the debounce window nothing has refetched yet.
    expect(mocks.activityList.mock.calls.length).toBe(initialCalls);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(EVENT_REFRESH_MS);
    });
    expect(mocks.activityList.mock.calls.length).toBe(initialCalls + 1);
  });
});

describe("quiet and broken water", () => {
  it("speaks in Pam's voice when the log is empty", async () => {
    mocks.activityList.mockResolvedValue({ requests: [] });
    renderActivity();
    expect(await screen.findByText(/watching the water/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Clear filters" })).not.toBeInTheDocument();
  });

  it("offers to clear the lens when filters leave nothing", async () => {
    mocks.activityList.mockResolvedValue({ requests: [] });
    const router = renderActivity("/activity?agent=codex");
    expect(await screen.findByText(/matches this lens/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    await waitFor(() => expect(router.state.location.search).toEqual({}));
  });

  it("renders the disconnected banner from the uniform failure shape", async () => {
    const { BridgeUnavailable } =
      await vi.importActual<typeof import("../lib/ipc")>("../lib/ipc");
    mocks.activityList.mockRejectedValue(new BridgeUnavailable());
    renderActivity();
    expect(await screen.findByText(/disconnected · bridge_unavailable/)).toBeInTheDocument();
    expect(screen.getByText(/pam -- gui/)).toBeInTheDocument();
    // A broken bridge never claims calm water.
    expect(screen.queryByText(/watching the water/)).not.toBeInTheDocument();
  });
});
