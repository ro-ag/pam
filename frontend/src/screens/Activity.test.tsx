import { createMemoryHistory } from "@tanstack/react-router";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import { createAppRouter } from "../router";
import type { ActivityRow, PamEventPayload, RefusalEntry } from "../lib/ipc";
import { EVENT_REFRESH_MS, rowEnter, toLanes } from "./Activity";

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
  auditRequest: vi.fn(),
}));

vi.mock("../lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/ipc")>();
  return { ...actual, ...mocks };
});

// The band's odometer and the lane rows move with `motion`; pinned still
// here so the tide's own assertions never race an animation frame. The one
// test that watches a row land flips `reduced` for itself.
const motionPrefs = vi.hoisted(() => ({ reduced: true }));

vi.mock("motion/react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("motion/react")>();
  return { ...actual, useReducedMotion: () => motionPrefs.reduced };
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
  mocks.auditRequest.mockResolvedValue({ request_id: "req_run", rows: [] });
});

afterEach(() => {
  motionPrefs.reduced = true;
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
  it("shows requests directly without exposing internal compression controls", async () => {
    const router = renderActivity("/activity?state=refused");
    await screen.findByRole("region", { name: "Requests" });
    expect(screen.queryByRole("tablist", { name: "Activity views" })).toBeNull();
    expect(screen.queryByText("Log compression")).toBeNull();
    expect(screen.queryByLabelText("log path")).toBeNull();
    expect(screen.queryByRole("button", { name: "Compress" })).toBeNull();
    expect(mocks.logCompress).not.toHaveBeenCalled();
    expect(router.state.location.search.state).toBe("refused");
  });

  it("renders one row per request with capability, agent, repo tail, and verdict", async () => {
    renderActivity();
    expect(await screen.findByText("compress.log")).toBeInTheDocument();
    expect(screen.getByText("repo.push")).toBeInTheDocument();
    // Truth vocabulary + live states as badges, scoped to the lanes
    // ("refused" is also a segment label in the header).
    const tide = within(screen.getByRole("group", { name: "lanes" }));
    expect(tide.getByText("solved")).toBeInTheDocument();
    expect(tide.getByText("running")).toBeInTheDocument();
    expect(tide.getByText("refused")).toBeInTheDocument();
    // Repo renders as its tail, full path on the title attribute.
    const tail = screen.getAllByTitle("/Users/dev/pam")[0];
    expect(tail).toHaveTextContent(/^pam$/);
    expect(screen.getAllByText("claude").length).toBeGreaterThan(0);
    // The GUI's own polling never appears in its own tide.
    expect(mocks.activityList).toHaveBeenCalledWith({
      limit: 100,
      repo: undefined,
      agent: undefined,
      state: undefined,
      hide_probes: true,
      // The ledger cannot hold a refusal decided before admission; the human is owed it here.
      include_refusals: true,
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

  it("shows the request's audit trail under its evidence, in the daemon's words", async () => {
    mocks.auditRequest.mockResolvedValue({
      request_id: "req_ref",
      rows: [
        {
          id: 1,
          action: "gate",
          decision: "refuse",
          actor: "system",
          detail: {
            cause: "capability_denied",
            detail: "repo.push is not granted",
            recovery: "Grant it in Settings › Security.",
          },
          ts: 1_756_684_800,
        },
        {
          id: 2,
          action: "execute",
          decision: "allow",
          actor: "human",
          detail: "note",
          ts: 1_756_684_860,
        },
      ],
    });
    renderActivity();
    fireEvent.click((await screen.findByText("repo.push")).closest("button") as HTMLElement);
    await waitFor(() => expect(mocks.auditRequest).toHaveBeenCalledWith("req_ref"));
    const trail = within(await screen.findByRole("list", { name: "audit trail" }));
    const rows = trail.getAllByRole("listitem");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("gate · refuse · system");
    expect(rows[0]).toHaveTextContent(
      "capability_denied — repo.push is not granted — Grant it in Settings › Security.",
    );
    expect(rows[1]).toHaveTextContent("execute · allow · human");
    expect(rows[1]).toHaveTextContent("note");
  });

  it("says so when a request left no audit rows", async () => {
    renderActivity();
    fireEvent.click((await screen.findByText("compress.log")).closest("button") as HTMLElement);
    expect(await screen.findByText("no audit rows for this request")).toBeInTheDocument();
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
    fireEvent.click(screen.getByRole("button", { name: "repo other" }));
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
    // A repo nobody reports any more still gets its (pressed) chip, so the
    // lens carried in from a shared URL stays visible and clearable.
    expect(screen.getByRole("button", { name: "repo repo", pressed: true })).toHaveAttribute(
      "title",
      "/gone/repo",
    );
  });
});

describe("lanes", () => {
  /** The daemon narrows server-side; the mock does the same for chips. */
  function serverFilters() {
    mocks.activityList.mockImplementation(
      ({ repo, agent }: { repo?: string; agent?: string }) =>
        Promise.resolve({
          requests: TIDE.filter(
            (candidate) =>
              (repo === undefined || candidate.repo === repo) &&
              (agent === undefined || candidate.agent === agent),
          ),
        }),
    );
  }

  it("groups rows into one lane per agent, alphabetical, newest on top", async () => {
    renderActivity();
    const claude = within(await screen.findByRole("region", { name: "claude" }));
    const codex = within(screen.getByRole("region", { name: "codex" }));
    expect(claude.getAllByRole("listitem")).toHaveLength(2);
    expect(codex.getAllByRole("listitem")).toHaveLength(1);
    const lanes = screen
      .getAllByRole("region")
      .filter((region) =>
        ["claude", "codex"].includes(region.getAttribute("aria-label") ?? ""),
      );
    expect(lanes.map((lane) => lane.getAttribute("aria-label"))).toEqual(["claude", "codex"]);
    // The lane header carries the agent once; the rows no longer repeat it.
    expect(claude.getAllByText("claude")).toHaveLength(1);
    expect(screen.getByText(/3 requests · 2 lanes · newest first/)).toBeInTheDocument();
    // Width follows traffic: each lane grows by its row count.
    expect(lanes.map((lane) => lane.style.getPropertyValue("--lane-share"))).toEqual([
      "2",
      "1",
    ]);
  });

  it("gives each lane a width share equal to its (capped) row count", () => {
    const tide = [
      ...Array.from({ length: 7 }, (_, index) => row({ id: `codex_${index}`, agent: "codex" })),
      ...Array.from({ length: 60 }, (_, index) => row({ id: `claude_${index}` })),
    ];
    const lanes = toLanes(tide);
    expect(lanes.map((lane) => [lane.agent, lane.share])).toEqual([
      ["claude", 50],
      ["codex", 7],
    ]);
    expect(lanes[0]?.rows).toHaveLength(50);
  });

  it("labels the filter groups and keeps every chip a 32px target", async () => {
    renderActivity();
    await screen.findByText("compress.log");
    const state = screen.getByRole("group", { name: "state filter" });
    expect(within(state).getByText("State")).toBeInTheDocument();
    const agents = screen.getByRole("group", { name: "Agent filters" });
    const repos = screen.getByRole("group", { name: "Repository filters" });
    expect(within(agents).getByText("Agent")).toBeInTheDocument();
    expect(within(repos).getByText("Repository")).toBeInTheDocument();
    for (const chip of [
      ...within(agents).getAllByRole("button"),
      ...within(state).getAllByRole("button"),
    ]) {
      expect(chip.className).toContain("h-8");
    }
  });

  it("shows agent and repo chips; an agent chip narrows to one lane and writes the URL", async () => {
    serverFilters();
    const router = renderActivity();
    fireEvent.click(await screen.findByRole("button", { name: "agent codex" }));
    await waitFor(() => expect(router.state.location.search).toMatchObject({ agent: "codex" }));
    await waitFor(() => expect(screen.queryByRole("region", { name: "claude" })).toBeNull());
    expect(screen.getByRole("region", { name: "codex" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "repo other" }));
    await waitFor(() =>
      expect(router.state.location.search).toMatchObject({ repo: "/Users/dev/other" }),
    );
    // A pressed chip is a toggle: clicking it again lets the water back in.
    fireEvent.click(screen.getByRole("button", { name: "agent codex", pressed: true }));
    await waitFor(() =>
      expect(router.state.location.search).toEqual({ repo: "/Users/dev/other" }),
    );
  });

  it("says so when the chips leave nothing, and clears them", async () => {
    serverFilters();
    const router = renderActivity("/activity?repo=/Users/dev/other");
    fireEvent.click(await screen.findByRole("button", { name: "agent claude" }));
    expect(await screen.findByText(/No requests match these filters/)).toBeInTheDocument();
    expect(screen.queryByRole("group", { name: "lanes" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    await waitFor(() => expect(router.state.location.search).toEqual({}));
    expect(await screen.findByRole("region", { name: "claude" })).toBeInTheDocument();
  });

  /**
   * One event burst that lands a new claude row, settled: the debounce,
   * then two ticks for the refetch to resolve and paint. Fake timers hold
   * the enter animation at its first frame, which is what we came to see.
   */
  async function landLiveRow(ticket: string): Promise<HTMLElement | null> {
    mocks.activityList.mockResolvedValue({
      requests: [
        row({ id: "req_new", capability: "flow.run", state: "running", outcome: null }),
        ...TIDE,
      ],
    });
    vi.useFakeTimers();
    act(() => {
      for (const handler of eventHandlers) handler({ ticket, event: { kind: "done" } });
    });
    for (const step of [EVENT_REFRESH_MS, 1, 1]) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(step);
      });
    }
    const claude = within(screen.getByRole("region", { name: "claude" }));
    return claude.getByText("flow.run").closest("li");
  }

  it("lands a live row in its lane with the enter slide", async () => {
    motionPrefs.reduced = false;
    renderActivity();
    await screen.findByRole("region", { name: "claude" });
    await waitFor(() => expect(eventHandlers.length).toBeGreaterThan(0));

    const landed = await landLiveRow("t2");
    // Mounted at the enter frame: transparent, 4px above its resting place.
    expect(landed?.style.opacity).toBe("0");
    expect(landed?.style.transform).toContain("-4");
    expect(rowEnter(false)).toEqual({ opacity: 0, y: -4 });
  });

  it("lands the same live row still, under reduced motion", async () => {
    renderActivity();
    await screen.findByRole("region", { name: "claude" });
    await waitFor(() => expect(eventHandlers.length).toBeGreaterThan(0));

    const landed = await landLiveRow("t3");
    expect(landed).not.toBeNull();
    expect(landed?.style.opacity).not.toBe("0");
    expect(rowEnter(true)).toBe(false);
  });
});

describe("live updates", () => {
  it("coalesces an event burst into one debounced refetch", async () => {
    renderActivity();
    await screen.findByText("compress.log");
    await waitFor(() => expect(eventHandlers.length).toBeGreaterThan(0));
    // Count the tide's own reads.
    const tideCalls = () =>
      mocks.activityList.mock.calls.filter(([args]) => args.hide_probes === true).length;
    const initialCalls = tideCalls();

    vi.useFakeTimers();
    const burst: PamEventPayload = { ticket: "t1", event: { kind: "done" } };
    act(() => {
      for (const handler of eventHandlers) handler(burst);
      for (const handler of eventHandlers) handler(burst);
      for (const handler of eventHandlers) handler(burst);
    });
    // Inside the debounce window nothing has refetched yet.
    expect(tideCalls()).toBe(initialCalls);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(EVENT_REFRESH_MS);
    });
    expect(tideCalls()).toBe(initialCalls + 1);
  });
});

describe("quiet and broken water", () => {
  it("speaks in Pam's voice when the log is empty", async () => {
    mocks.activityList.mockResolvedValue({ requests: [] });
    renderActivity();
    expect(await screen.findByText(/No activity yet/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Clear filters" })).not.toBeInTheDocument();
  });

  it("offers to clear the lens when filters leave nothing", async () => {
    mocks.activityList.mockResolvedValue({ requests: [] });
    const router = renderActivity("/activity?agent=codex");
    expect(await screen.findByText(/No requests match these filters/)).toBeInTheDocument();
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
    expect(screen.queryByText(/No activity yet/)).not.toBeInTheDocument();
    // Retry asks again instead of leaving the human to reload.
    const before = mocks.activityList.mock.calls.length;
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => expect(mocks.activityList.mock.calls.length).toBeGreaterThan(before));
  });
});

/** One refusal the daemon decided before a request row existed. */
function refusal(overrides: Partial<RefusalEntry>): RefusalEntry {
  return {
    kind: "refusal",
    id: "refusal_1",
    cause: "client_version_mismatch",
    detail: "this client is 0.4.0 and the daemon is 0.5.0",
    count: 1,
    capability: null,
    repo: null,
    agent: null,
    request_id: null,
    created_ts: Math.floor(Date.now() / 1000) - 60,
    updated_ts: Math.floor(Date.now() / 1000) - 60,
    ingress: "public",
    peer_uid: 501,
    peer_pid: 4242,
    peer_exe: "/usr/local/bin/pam",
    ...overrides,
  };
}

describe("refused before admission", () => {
  async function section() {
    return within(await screen.findByRole("region", { name: "Refused before admission" }));
  }

  it("asks for refusals and shows each with its cause, its count and who knocked", async () => {
    mocks.activityList.mockResolvedValue({
      requests: [
        refusal({
          id: "refusal_2",
          cause: "request_rate_exhausted",
          count: 1_000,
          capability: "status",
          agent: "poller",
          peer_pid: 777,
          peer_exe: "/opt/agent/bin/agent",
        }),
        ...TIDE,
        refusal({ id: "refusal_1" }),
      ],
    });
    renderActivity();
    const refused = await section();
    expect(mocks.activityList).toHaveBeenCalledWith(
      expect.objectContaining({ include_refusals: true }),
    );
    const rows = refused.getAllByRole("listitem");
    expect(rows).toHaveLength(2);
    // Newest first, as the daemon sent them; the cause as words.
    expect(rows[0]).toHaveTextContent("request rate exhausted");
    expect(rows[0]).toHaveTextContent("status");
    expect(rows[0]).toHaveTextContent("×1,000");
    // The kernel's view of the peer wins over whatever the client called itself.
    expect(rows[0]).toHaveTextContent("agent (pid 777)");
    expect(rows[1]).toHaveTextContent("client version mismatch");
    expect(rows[1]).toHaveTextContent("pam (pid 4242)");
    expect(rows[1]).toHaveTextContent("refused");
    expect(refused.getByText(/2 refusals · 1,001 attempts/)).toBeInTheDocument();
    // They are not requests: no lane, and the request count is unchanged.
    expect(screen.getByText(/3 requests · 2 lanes/)).toBeInTheDocument();
  });

  it("says a claimed label is a claim, and a missing peer is unknown", async () => {
    mocks.activityList.mockResolvedValue({
      requests: [
        refusal({
          id: "refusal_a",
          peer_pid: null,
          peer_uid: null,
          peer_exe: null,
          agent: "claude",
        }),
        refusal({
          id: "refusal_b",
          peer_pid: null,
          peer_uid: null,
          peer_exe: null,
          agent: null,
        }),
        refusal({ id: "refusal_c", peer_pid: 9, peer_exe: null }),
      ],
    });
    renderActivity();
    const rows = (await section()).getAllByRole("listitem");
    expect(rows[0]).toHaveTextContent("claude (claimed)");
    expect(rows[1]).toHaveTextContent("unknown peer");
    expect(rows[2]).toHaveTextContent("pid 9");
  });

  it("renders everything a client chose through SafeText, hidden characters spelled out", async () => {
    mocks.activityList.mockResolvedValue({
      requests: [
        refusal({
          agent: "cla\u202Eude",
          peer_pid: null,
          peer_uid: null,
          peer_exe: null,
          capability: "echo\u200B",
          detail: "evil\u202Etxt.exe",
          repo: "/r\u202Ep",
          request_id: "req\u0007",
        }),
      ],
    });
    renderActivity();
    const refused = await section();
    // The row: agent and capability.
    expect(
      refused.getAllByTitle("a hidden character, shown as its escape").length,
    ).toBeGreaterThan(1);
    fireEvent.click(
      refused.getAllByRole("listitem")[0]!.querySelector("button") as HTMLElement,
    );
    // The escapes appear in the row and in each field the client chose.
    const escapes = refused.getAllByText("\\u{202E}");
    expect(escapes.length).toBeGreaterThanOrEqual(4);
    expect(refused.getByText("\\u{0007}")).toBeInTheDocument();
    // Detail, repo and request id are escaped too: no raw override reaches the DOM.
    expect(refused.getByRole("list").textContent).not.toContain("\u202E");
    expect(refused.getByRole("list").textContent).not.toContain("\u0007");
  });

  it("opens into the facts and says there is no audit trail to read", async () => {
    mocks.activityList.mockResolvedValue({
      requests: [
        refusal({
          count: 25,
          agent: "claude",
          repo: "/Users/dev/pam",
          capability: "echo",
          request_id: "req_never",
        }),
      ],
    });
    renderActivity();
    const refused = await section();
    fireEvent.click(
      refused.getAllByRole("listitem")[0]!.querySelector("button") as HTMLElement,
    );
    expect(refused.getByText(/no request row exists/)).toBeInTheDocument();
    expect(
      refused.getByText("this client is 0.4.0 and the daemon is 0.5.0"),
    ).toBeInTheDocument();
    expect(refused.getByText("25")).toBeInTheDocument();
    expect(refused.getByText("/usr/local/bin/pam")).toBeInTheDocument();
    expect(refused.getByText("req_never")).toBeInTheDocument();
    // There is no request to read an audit trail of.
    expect(mocks.auditRequest).not.toHaveBeenCalled();
    expect(mocks.evidenceList).not.toHaveBeenCalled();
  });

  it("shows refusals under the all and refused lenses only", async () => {
    mocks.activityList.mockResolvedValue({ requests: [...TIDE, refusal({})] });
    renderActivity("/activity?state=refused");
    expect(
      await screen.findByRole("region", { name: "Refused before admission" }),
    ).toBeInTheDocument();
  });

  it("hides them under every other lens even if the daemon sent them", async () => {
    mocks.activityList.mockResolvedValue({ requests: [...TIDE, refusal({})] });
    renderActivity("/activity?state=active");
    expect(await screen.findByText("compress.log")).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Refused before admission" })).toBeNull();
  });

  it("is not 'no activity yet' when only refusals exist", async () => {
    mocks.activityList.mockResolvedValue({ requests: [refusal({})] });
    renderActivity();
    await section();
    expect(screen.queryByText(/No activity yet/)).not.toBeInTheDocument();
    expect(screen.queryByRole("group", { name: "lanes" })).toBeNull();
  });

  it("keeps a long list short until asked, then shows all", async () => {
    mocks.activityList.mockResolvedValue({
      requests: Array.from({ length: 9 }, (_, index) =>
        refusal({ id: `refusal_${index}`, cause: `cause_${index}` }),
      ),
    });
    renderActivity();
    const refused = await section();
    expect(refused.getAllByRole("listitem")).toHaveLength(6);
    fireEvent.click(refused.getByRole("button", { name: "Show all 9" }));
    expect(refused.getAllByRole("listitem")).toHaveLength(9);
    fireEvent.click(refused.getByRole("button", { name: "Show fewer" }));
    expect(refused.getAllByRole("listitem")).toHaveLength(6);
  });

  it("offers the refusing agent as a chip", async () => {
    mocks.activityList.mockResolvedValue({
      requests: [refusal({ agent: "poller", repo: "/Users/dev/polled" })],
    });
    renderActivity();
    await section();
    expect(await screen.findByRole("button", { name: "agent poller" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "repo polled" })).toBeInTheDocument();
  });
});
