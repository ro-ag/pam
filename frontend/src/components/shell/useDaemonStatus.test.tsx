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

  it("shares its queries with the screens under the documented keys", async () => {
    mockStatus.mockResolvedValue(up);
    const { result } = mount();
    await waitFor(() => expect(result.current).toBe("connected"));
    expect(client.getQueryData(DAEMON_STATUS_KEY)).toEqual(up);
    expect(client.getQueryData(APPROVALS_PENDING_KEY)).toEqual({ pending: [] });
  });
});
