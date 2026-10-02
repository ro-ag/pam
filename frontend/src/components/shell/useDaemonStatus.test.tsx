import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PamEventPayload, PendingApproval } from "../../lib/ipc";

vi.mock("../../lib/ipc", () => ({
  daemonStatus: vi.fn(),
  approvalsPending: vi.fn(),
  subscribeEvents: vi.fn(),
}));

import { approvalsPending, daemonStatus, subscribeEvents } from "../../lib/ipc";
import {
  APPROVALS_PENDING_KEY,
  DAEMON_STATUS_KEY,
  OFFLINE_AFTER_MISSES,
  STATUS_POLL_MS,
  useDaemonStatus,
} from "./useDaemonStatus";

const mockStatus = vi.mocked(daemonStatus);
const mockPending = vi.mocked(approvalsPending);
const mockSubscribe = vi.mocked(subscribeEvents);

const approval: PendingApproval = {
  request_id: "req_01ABC",
  capability: "fs.write",
  repo: "/tmp/repo",
  agent: "claude",
  requested_ts: 1_756_684_800,
  args: null,
  repository: null,
  effect: null,
};

const up = { connected: true, status: {}, base_dir: "/tmp/pam" };
const down = { connected: false, status: null, base_dir: "/tmp/pam" };

/** The hook lives on the app's query client; each test gets a fresh one. */
let client: QueryClient;

/**
 * Advances the fake clock, then one more millisecond: react-query hands
 * the settled fetch to observers on a timer of its own that lands just
 * after the interval's.
 */
async function tick(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
    await vi.advanceTimersByTimeAsync(1);
  });
}

function mount() {
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
  return renderHook(() => useDaemonStatus(), { wrapper });
}

beforeEach(() => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  // Browser-dev default: no event stream; the hook must cope quietly.
  mockSubscribe.mockRejectedValue(new Error("no bridge"));
  mockPending.mockResolvedValue({ pending: [] });
});

afterEach(() => {
  vi.useRealTimers();
  client.clear();
});

describe("useDaemonStatus", () => {
  it("says connecting until the first poll answers, then green with nothing pending", async () => {
    mockStatus.mockResolvedValue(up);
    const { result } = mount();
    expect(result.current).toBe("connecting");
    await waitFor(() => expect(result.current).toBe("connected"));
  });

  it("turns amber while approvals wait", async () => {
    mockStatus.mockResolvedValue(up);
    mockPending.mockResolvedValue({ pending: [approval] });
    const { result } = mount();
    await waitFor(() => expect(result.current).toBe("pending"));
  });

  it("goes red on the first miss when it was never green (plain-browser dev)", async () => {
    mockStatus.mockRejectedValue({
      cause: "bridge_unavailable",
      detail: "no shell",
      recovery: "open the app",
    });
    const { result } = mount();
    await waitFor(() => expect(result.current).toBe("down"));
    expect(mockPending).not.toHaveBeenCalled();
  });

  it("reads a disconnected reply as red, not as an error", async () => {
    mockStatus.mockResolvedValue(down);
    const { result } = mount();
    await waitFor(() => expect(result.current).toBe("down"));
    expect(mockPending).not.toHaveBeenCalled();
  });

  it("keeps green when only the pending count fails", async () => {
    mockStatus.mockResolvedValue(up);
    mockPending.mockRejectedValue({ cause: "reply_timeout", detail: "", recovery: "" });
    const { result } = mount();
    await waitFor(() => expect(result.current).toBe("connected"));
  });

  it("tolerates one missed poll while green and turns red on the second", async () => {
    vi.useFakeTimers();
    mockStatus.mockResolvedValue(up);
    const { result } = mount();
    await tick(0);
    expect(result.current).toBe("connected");

    // A busy daemon misses one poll: still green.
    mockStatus.mockResolvedValue(down);
    await tick(STATUS_POLL_MS);
    expect(mockStatus).toHaveBeenCalledTimes(2);
    expect(result.current).toBe("connected");

    // The second consecutive miss is the honest red.
    await tick(STATUS_POLL_MS);
    expect(mockStatus).toHaveBeenCalledTimes(3);
    expect(result.current).toBe("down");
    expect(OFFLINE_AFTER_MISSES).toBe(2);
  });

  it("re-polls on the interval and follows the daemon back up", async () => {
    vi.useFakeTimers();
    mockStatus.mockResolvedValue(down);
    const { result } = mount();
    await tick(0);
    expect(result.current).toBe("down");
    expect(mockStatus).toHaveBeenCalledTimes(1);

    mockStatus.mockResolvedValue(up);
    await tick(STATUS_POLL_MS);
    expect(mockStatus).toHaveBeenCalledTimes(2);
    expect(result.current).toBe("connected");
  });

  it("re-polls immediately when a daemon event arrives", async () => {
    let handler: ((payload: PamEventPayload) => void) | undefined;
    mockSubscribe.mockImplementation((h) => {
      handler = h;
      return Promise.resolve(() => {});
    });
    mockStatus.mockResolvedValue(up);
    const { result } = mount();
    await waitFor(() => expect(result.current).toBe("connected"));
    await waitFor(() => expect(handler).toBeDefined());

    mockPending.mockResolvedValue({ pending: [approval] });
    act(() => {
      handler?.({ ticket: "req_01ABC", event: { kind: "approval_pending" } });
    });
    await waitFor(() => expect(result.current).toBe("pending"));
  });

  describe("the status feedback loop (issue 35)", () => {
    const busy = {
      cause: "request_capacity_exhausted",
      detail: "the control pool is full",
      recovery: "Retry shortly.",
    };

    /** Mounts with the event stream wired and returns the captured handler. */
    async function mountWithEvents() {
      let handler: ((payload: PamEventPayload) => void) | undefined;
      mockSubscribe.mockImplementation((h) => {
        handler = h;
        return Promise.resolve(() => {});
      });
      mockStatus.mockResolvedValue(up);
      const hook = mount();
      await tick(0);
      expect(handler).toBeDefined();
      return { hook, emit: (payload: PamEventPayload) => act(() => handler?.(payload)) };
    }

    it("turns a burst of events into at most one approvals refetch and no status poll", async () => {
      vi.useFakeTimers();
      const { emit } = await mountWithEvents();
      const statusCalls = mockStatus.mock.calls.length;
      const pendingCalls = mockPending.mock.calls.length;

      // Two hundred done/refused/approval events, the way a busy agent (or the daemon's own
      // lifecycle events for our status polls) would deliver them.
      for (let index = 0; index < 200; index += 1) {
        emit({ ticket: `req_${index}`, event: { kind: index % 2 ? "done" : "refused" } });
      }
      await tick(2_000);
      expect(mockPending.mock.calls.length).toBe(pendingCalls + 1);
      // Events are hints for the approvals only: the status call (public socket) is never
      // event-driven, so a status poll's own events cannot start the next status poll.
      expect(mockStatus.mock.calls.length).toBe(statusCalls);
    });

    it("ignores queued, started and progress events altogether", async () => {
      vi.useFakeTimers();
      const { emit } = await mountWithEvents();
      const pendingCalls = mockPending.mock.calls.length;
      for (const event of [
        { kind: "queued" },
        { kind: "started" },
        { kind: "progress", note: "x" },
      ] as const) {
        emit({ ticket: "req_1", event });
      }
      await tick(4_000);
      expect(mockPending.mock.calls.length).toBe(pendingCalls);
    });

    it("re-reads the approvals once when the stream says it may have missed events", async () => {
      vi.useFakeTimers();
      const { emit } = await mountWithEvents();
      const pendingCalls = mockPending.mock.calls.length;
      const statusCalls = mockStatus.mock.calls.length;
      // The pump sends a resync after every reconnect and at a counter skip: an approval raised
      // while the stream was down must not wait out the poll interval.
      emit({ ticket: "", event: { kind: "resync" } });
      emit({ ticket: "", event: { kind: "resync" } });
      await tick(2_000);
      expect(mockPending.mock.calls.length).toBe(pendingCalls + 1);
      expect(mockStatus.mock.calls.length).toBe(statusCalls);
    });

    it("never restarts a poll that is still in flight when events arrive", async () => {
      vi.useFakeTimers();
      let release: (value: typeof up) => void = () => {};
      let signalAborted = false;
      const { emit } = await mountWithEvents();
      mockPending.mockImplementation(
        () =>
          new Promise((resolve) => {
            release = () => resolve({ pending: [] });
            signalAborted = false;
          }),
      );
      emit({ ticket: "req_1", event: { kind: "done" } });
      await tick(400);
      const started = mockPending.mock.calls.length;
      for (let index = 0; index < 20; index += 1) {
        emit({ ticket: "req_2", event: { kind: "done" } });
        await tick(500);
      }
      // Still the one in-flight fetch: nothing was cancelled and restarted.
      expect(mockPending.mock.calls.length).toBe(started);
      expect(signalAborted).toBe(false);
      release(up);
    });

    it("backs off exponentially while the daemon answers request_capacity_exhausted", async () => {
      vi.useFakeTimers();
      mockStatus.mockRejectedValue(busy);
      mount();
      await tick(0);
      expect(mockStatus).toHaveBeenCalledTimes(1);

      // Failure 1 -> asked again after the base 5 s; failure 2 -> 10 s; failure 3 -> 20 s.
      await tick(STATUS_POLL_MS);
      expect(mockStatus).toHaveBeenCalledTimes(2);
      await tick(STATUS_POLL_MS);
      expect(mockStatus).toHaveBeenCalledTimes(2);
      await tick(STATUS_POLL_MS);
      expect(mockStatus).toHaveBeenCalledTimes(3);
      await tick(3 * STATUS_POLL_MS);
      expect(mockStatus).toHaveBeenCalledTimes(3);
      await tick(STATUS_POLL_MS);
      expect(mockStatus).toHaveBeenCalledTimes(4);
    });

    it("returns to the base cadence once the daemon answers again", async () => {
      vi.useFakeTimers();
      mockStatus.mockRejectedValueOnce(busy).mockRejectedValueOnce(busy);
      mockStatus.mockResolvedValue(up);
      mount();
      await tick(0);
      await tick(STATUS_POLL_MS);
      await tick(2 * STATUS_POLL_MS);
      expect(mockStatus).toHaveBeenCalledTimes(3);
      // Healthy again: the next poll is a plain 5 s away.
      await tick(STATUS_POLL_MS);
      expect(mockStatus).toHaveBeenCalledTimes(4);
    });

    it("does not read a busy refusal as the daemon being down", async () => {
      vi.useFakeTimers();
      mockStatus.mockResolvedValueOnce(up);
      const { result } = mount();
      await tick(0);
      expect(result.current).toBe("connected");
      mockStatus.mockRejectedValue(busy);
      for (let poll = 0; poll < 4; poll += 1) await tick(STATUS_POLL_MS * 2 ** poll);
      // Four refusals in a row: the daemon is saturated, not gone.
      expect(result.current).toBe("connected");
    });
  });

  it("shares its queries with the screens under the documented keys", async () => {
    mockStatus.mockResolvedValue(up);
    const { result } = mount();
    await waitFor(() => expect(result.current).toBe("connected"));
    expect(client.getQueryData(DAEMON_STATUS_KEY)).toEqual(up);
    expect(client.getQueryData(APPROVALS_PENDING_KEY)).toEqual({ pending: [] });
  });
});
