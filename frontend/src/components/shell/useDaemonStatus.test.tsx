import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PamEventPayload, PendingApproval } from "../../lib/ipc";

vi.mock("../../lib/ipc", () => ({
  daemonStatus: vi.fn(),
  approvalsPending: vi.fn(),
  subscribeEvents: vi.fn(),
}));

import { approvalsPending, daemonStatus, subscribeEvents } from "../../lib/ipc";
import { STATUS_POLL_MS, useDaemonStatus } from "./useDaemonStatus";

const mockStatus = vi.mocked(daemonStatus);
const mockPending = vi.mocked(approvalsPending);
const mockSubscribe = vi.mocked(subscribeEvents);

const approval: PendingApproval = {
  request_id: "req_01ABC",
  capability: "fs.write",
  repo: "/tmp/repo",
  agent: "claude",
  requested_ts: "2026-09-01T00:00:00Z",
};

beforeEach(() => {
  // Browser-dev default: no event stream; the hook must cope quietly.
  mockSubscribe.mockRejectedValue(new Error("no bridge"));
});

afterEach(() => {
  vi.useRealTimers();
});

describe("useDaemonStatus", () => {
  it("turns green when the daemon answers with nothing pending", async () => {
    mockStatus.mockResolvedValue({ connected: true, status: {} });
    mockPending.mockResolvedValue({ pending: [] });
    const { result } = renderHook(() => useDaemonStatus());
    expect(result.current).toBe("down");
    await waitFor(() => expect(result.current).toBe("connected"));
  });

  it("turns amber while approvals wait", async () => {
    mockStatus.mockResolvedValue({ connected: true, status: {} });
    mockPending.mockResolvedValue({ pending: [approval] });
    const { result } = renderHook(() => useDaemonStatus());
    await waitFor(() => expect(result.current).toBe("pending"));
  });

  it("stays red when the bridge rejects (plain-browser dev)", async () => {
    mockStatus.mockRejectedValue({
      cause: "bridge_unavailable",
      detail: "no shell",
      recovery: "open the app",
    });
    const { result } = renderHook(() => useDaemonStatus());
    await waitFor(() => expect(mockStatus).toHaveBeenCalled());
    expect(result.current).toBe("down");
    expect(mockPending).not.toHaveBeenCalled();
  });

  it("reads a disconnected reply as red, not as an error", async () => {
    mockStatus.mockResolvedValue({ connected: false, status: null });
    const { result } = renderHook(() => useDaemonStatus());
    await waitFor(() => expect(mockStatus).toHaveBeenCalled());
    expect(result.current).toBe("down");
    expect(mockPending).not.toHaveBeenCalled();
  });

  it("keeps green when only the pending count fails", async () => {
    mockStatus.mockResolvedValue({ connected: true, status: {} });
    mockPending.mockRejectedValue({ cause: "reply_timeout", detail: "", recovery: "" });
    const { result } = renderHook(() => useDaemonStatus());
    await waitFor(() => expect(result.current).toBe("connected"));
  });

  it("re-polls on the interval and follows the daemon back up", async () => {
    vi.useFakeTimers();
    mockStatus.mockResolvedValue({ connected: false, status: null });
    const { result } = renderHook(() => useDaemonStatus());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(result.current).toBe("down");
    expect(mockStatus).toHaveBeenCalledTimes(1);

    mockStatus.mockResolvedValue({ connected: true, status: {} });
    mockPending.mockResolvedValue({ pending: [] });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(STATUS_POLL_MS);
    });
    expect(mockStatus).toHaveBeenCalledTimes(2);
    expect(result.current).toBe("connected");
  });

  it("re-polls immediately when a daemon event arrives", async () => {
    let handler: ((payload: PamEventPayload) => void) | undefined;
    mockSubscribe.mockImplementation((h) => {
      handler = h;
      return Promise.resolve(() => {});
    });
    mockStatus.mockResolvedValue({ connected: true, status: {} });
    mockPending.mockResolvedValue({ pending: [] });
    const { result } = renderHook(() => useDaemonStatus());
    await waitFor(() => expect(result.current).toBe("connected"));
    await waitFor(() => expect(handler).toBeDefined());

    mockPending.mockResolvedValue({ pending: [approval] });
    act(() => {
      handler?.({ ticket: "req_01ABC", event: { kind: "approval_pending" } });
    });
    await waitFor(() => expect(result.current).toBe("pending"));
  });
});
