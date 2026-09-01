import { createMemoryHistory } from "@tanstack/react-router";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import type { PamEventPayload, PendingApproval } from "../lib/ipc";
import { createAppRouter } from "../router";
import {
  APPROVAL_TIMEOUT_S,
  WARNING_AFTER_S,
  approvalMeaning,
  waitingClock,
} from "./Approvals";

/**
 * The raised-hand cards against a mocked bridge. The whole App mounts
 * (shell included) so the query provider, the event stream, and the
 * screen are exercised together, exactly as shipped.
 */

const mocks = vi.hoisted(() => ({
  activityList: vi.fn(),
  callersList: vi.fn(),
  subscribeEvents: vi.fn(),
  daemonStatus: vi.fn(),
  approvalsPending: vi.fn(),
  approvalsResolve: vi.fn(),
}));

vi.mock("../lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/ipc")>();
  return { ...actual, ...mocks };
});

/** Handlers captured from every subscribeEvents call (screen + beacon). */
let eventHandlers: Array<(payload: PamEventPayload) => void>;

const nowSec = () => Math.floor(Date.now() / 1000);

function hand(overrides: Partial<PendingApproval>): PendingApproval {
  return {
    request_id: "req_a",
    capability: "repo.push",
    repo: "/Users/dev/pam",
    agent: "claude",
    requested_ts: nowSec() - 185,
    ...overrides,
  };
}

beforeEach(() => {
  eventHandlers = [];
  mocks.approvalsPending.mockResolvedValue({
    pending: [
      hand({ request_id: "req_a", capability: "repo.push" }),
      hand({
        request_id: "req_b",
        capability: "echo",
        repo: "/Users/dev/other",
        agent: "codex",
      }),
    ],
  });
  mocks.approvalsResolve.mockResolvedValue({
    request_id: "req_a",
    resolution: "approved",
    remember: false,
  });
  mocks.activityList.mockResolvedValue({ requests: [] });
  mocks.callersList.mockResolvedValue({ callers: [] });
  mocks.subscribeEvents.mockImplementation((handler: (payload: PamEventPayload) => void) => {
    eventHandlers.push(handler);
    return Promise.resolve(() => {});
  });
  mocks.daemonStatus.mockResolvedValue({ connected: false, status: null });
});

afterEach(() => {
  vi.useRealTimers();
  window.localStorage.clear();
  delete document.documentElement.dataset.theme;
  delete document.documentElement.dataset.mode;
});

function renderApprovals() {
  const router = createAppRouter(createMemoryHistory({ initialEntries: ["/approvals"] }));
  render(<App router={router} />);
  return router;
}

/** Scope queries to one card by its accessible name. */
function card(capability: string) {
  return within(screen.getByRole("region", { name: `approval ${capability}` }));
}

describe("raised hands", () => {
  it("renders one raised card per pending approval, with a live count", async () => {
    renderApprovals();
    expect(await screen.findByText("approvals · 2 hands raised")).toBeInTheDocument();
    // Capability in the data voice, agent chip, repo tail with full path.
    const pushCard = card("repo.push");
    expect(pushCard.getByText("claude")).toBeInTheDocument();
    expect(pushCard.getByTitle("/Users/dev/pam")).toHaveTextContent(/^pam$/);
    // The serif sentence names the family's blast radius.
    expect(pushCard.getByText(/alter shared history/)).toBeInTheDocument();
    // Unknown families fall back to the generic sentence.
    expect(card("echo").getByText(/lets it continue this once/)).toBeInTheDocument();
    expect(screen.getByText(/2 waiting · oldest first/)).toBeInTheDocument();
  });

  it("phrases what approving means per capability family", () => {
    expect(approvalMeaning("repo.push").after).toMatch(/shared history/);
    expect(approvalMeaning("fs.write").after).toMatch(/beyond its sandbox/);
    expect(approvalMeaning("net.fetch").after).toMatch(/traffic leave/);
    expect(approvalMeaning("shell.run").after).toMatch(/execute this once/);
    expect(approvalMeaning("mystery.cap").after).toMatch(/continue this once/);
  });
});

describe("resolving", () => {
  it("approves with the remember flag once the checkbox is ticked", async () => {
    renderApprovals();
    await screen.findByText("approvals · 2 hands raised");
    const pushCard = card("repo.push");
    fireEvent.click(pushCard.getByRole("checkbox", { name: "remember this capability" }));
    fireEvent.click(pushCard.getByRole("button", { name: "Approve" }));
    await waitFor(() =>
      expect(mocks.approvalsResolve).toHaveBeenCalledWith("req_a", "approved", {
        remember: true,
      }),
    );
  });

  it("approves without remembering by default", async () => {
    renderApprovals();
    await screen.findByText("approvals · 2 hands raised");
    fireEvent.click(card("echo").getByRole("button", { name: "Approve" }));
    await waitFor(() =>
      expect(mocks.approvalsResolve).toHaveBeenCalledWith("req_b", "approved", {
        remember: false,
      }),
    );
  });

  it("denies carrying the optional note", async () => {
    renderApprovals();
    await screen.findByText("approvals · 2 hands raised");
    const pushCard = card("repo.push");
    fireEvent.click(pushCard.getByRole("button", { name: "add note" }));
    fireEvent.change(pushCard.getByRole("textbox", { name: "resolution note" }), {
      target: { value: "  not on main  " },
    });
    fireEvent.click(pushCard.getByRole("button", { name: "Deny" }));
    await waitFor(() =>
      expect(mocks.approvalsResolve).toHaveBeenCalledWith("req_a", "denied", {
        note: "not on main",
      }),
    );
  });

  it("removes the card optimistically while the bridge still thinks", async () => {
    // A resolve that never settles: the card must not wait for it.
    mocks.approvalsResolve.mockImplementation(() => new Promise(() => {}));
    renderApprovals();
    await screen.findByText("approvals · 2 hands raised");
    fireEvent.click(card("repo.push").getByRole("button", { name: "Approve" }));
    await waitFor(() =>
      expect(
        screen.queryByRole("region", { name: "approval repo.push" }),
      ).not.toBeInTheDocument(),
    );
    // The other hand is untouched.
    expect(screen.getByRole("region", { name: "approval echo" })).toBeInTheDocument();
  });

  it("returns the card with the uniform failure shape when resolving fails", async () => {
    mocks.approvalsResolve.mockRejectedValue({
      cause: "daemon_unreachable",
      detail: "the daemon went away mid-answer",
      recovery: "Retry; the daemon restarts lazily.",
    });
    renderApprovals();
    await screen.findByText("approvals · 2 hands raised");
    fireEvent.click(card("repo.push").getByRole("button", { name: "Approve" }));
    expect(await screen.findByText(/resolve failed · daemon_unreachable/)).toBeInTheDocument();
    const pushCard = card("repo.push");
    expect(pushCard.getByText(/went away mid-answer/)).toBeInTheDocument();
    expect(pushCard.getByRole("button", { name: "Approve" })).toBeEnabled();
  });
});

describe("the waiting clock", () => {
  it("turns urgent at exactly 10 of the 15 minutes", () => {
    const nowMs = 1_756_000_000_000;
    const base = Math.floor(nowMs / 1000);
    expect(waitingClock(base - (WARNING_AFTER_S - 1), nowMs).urgent).toBe(false);
    const atThreshold = waitingClock(base - WARNING_AFTER_S, nowMs);
    expect(atThreshold.urgent).toBe(true);
    expect(atThreshold.label).toMatch(/times out in 5m/);
    expect(waitingClock(base - APPROVAL_TIMEOUT_S, nowMs).label).toMatch(/timing out now/);
  });

  it("shifts the card's clock to the warning as the wait crosses 10m", async () => {
    // Fake timers from the start so the clock's interval is controllable;
    // shouldAdvanceTime keeps queries and findBy* flowing.
    vi.useFakeTimers({ shouldAdvanceTime: true });
    mocks.approvalsPending.mockResolvedValue({
      // 30s shy of the threshold: calm at render, urgent after one tick.
      pending: [hand({ request_id: "req_a", requested_ts: nowSec() - (WARNING_AFTER_S - 30) })],
    });
    renderApprovals();
    await screen.findByText("approvals · 1 hand raised");
    expect(screen.queryByText(/times out in/)).not.toBeInTheDocument();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(40_000);
    });
    expect(screen.getByText(/times out in/)).toBeInTheDocument();
  });
});

describe("live updates", () => {
  it("surfaces a newly raised hand after one debounced refetch", async () => {
    mocks.approvalsPending.mockResolvedValue({
      pending: [hand({ request_id: "req_a", capability: "repo.push" })],
    });
    renderApprovals();
    await screen.findByText("approvals · 1 hand raised");
    await waitFor(() => expect(eventHandlers.length).toBeGreaterThan(0));

    mocks.approvalsPending.mockResolvedValue({
      pending: [
        hand({ request_id: "req_a", capability: "repo.push" }),
        hand({ request_id: "req_new", capability: "net.fetch", agent: "codex" }),
      ],
    });
    act(() => {
      const raised: PamEventPayload = { ticket: "t1", event: { kind: "approval_pending" } };
      for (const handler of eventHandlers) handler(raised);
    });
    // Real timers on purpose: findByText's default 1s budget IS the
    // acceptance bar — event to visible card in under a second.
    expect(
      await screen.findByRole("region", { name: "approval net.fetch" }),
    ).toBeInTheDocument();
    expect(screen.getByText("approvals · 2 hands raised")).toBeInTheDocument();
  });
});

describe("lowered hands and broken water", () => {
  it("lowers the hand in Pam's voice when nothing is pending", async () => {
    mocks.approvalsPending.mockResolvedValue({ pending: [] });
    renderApprovals();
    expect(await screen.findByText(/No hands raised/)).toBeInTheDocument();
    expect(screen.getByText(/no agent or CLI can answer for you/)).toBeInTheDocument();
    expect(screen.getByText("approvals · no hands raised")).toBeInTheDocument();
  });

  it("renders the disconnected banner from the uniform failure shape", async () => {
    const { BridgeUnavailable } =
      await vi.importActual<typeof import("../lib/ipc")>("../lib/ipc");
    mocks.approvalsPending.mockRejectedValue(new BridgeUnavailable());
    renderApprovals();
    expect(await screen.findByText(/disconnected · bridge_unavailable/)).toBeInTheDocument();
    expect(screen.getByText(/pam -- gui/)).toBeInTheDocument();
    // A broken bridge never claims calm water.
    expect(screen.queryByText(/No hands raised/)).not.toBeInTheDocument();
  });
});
