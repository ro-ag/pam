import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { act, render } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PamEventPayload } from "./ipc";

vi.mock("./ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./ipc")>();
  return { ...actual, subscribeEvents: vi.fn() };
});

import { subscribeEvents } from "./ipc";
import {
  EVENT_REFRESH_MIN_MS,
  EVENT_SETTLE_MS,
  createRefreshScheduler,
  useEventRefresh,
} from "./useEventRefresh";

const mockSubscribe = vi.mocked(subscribeEvents);

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("createRefreshScheduler", () => {
  it("turns a burst of events into one refresh", () => {
    const refresh = vi.fn();
    const scheduler = createRefreshScheduler({ refresh, isBusy: () => false });
    for (let index = 0; index < 100; index += 1) scheduler.notify();
    expect(refresh).not.toHaveBeenCalled();
    vi.advanceTimersByTime(EVENT_SETTLE_MS);
    expect(refresh).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(10_000);
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it("never refreshes more than once per interval, however many events arrive", () => {
    const refresh = vi.fn();
    const scheduler = createRefreshScheduler({ refresh, isBusy: () => false });
    scheduler.notify();
    vi.advanceTimersByTime(EVENT_SETTLE_MS);
    expect(refresh).toHaveBeenCalledTimes(1);

    // A steady drip of events for ten seconds.
    for (let elapsed = 0; elapsed < 10_000; elapsed += 100) {
      scheduler.notify();
      vi.advanceTimersByTime(100);
    }
    // ~10 s at one refresh per 1.5 s is at most 7 more, not 100.
    expect(refresh.mock.calls.length).toBeLessThanOrEqual(
      1 + Math.ceil(10_000 / EVENT_REFRESH_MIN_MS),
    );
    expect(refresh.mock.calls.length).toBeGreaterThan(1);
  });

  it("waits out a refresh that is still in flight instead of starting another", () => {
    let busy = true;
    const refresh = vi.fn();
    const scheduler = createRefreshScheduler({ refresh, isBusy: () => busy });
    scheduler.notify();
    vi.advanceTimersByTime(30_000);
    expect(refresh).not.toHaveBeenCalled();
    busy = false;
    vi.advanceTimersByTime(EVENT_SETTLE_MS);
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it("drops a pending refresh on dispose", () => {
    const refresh = vi.fn();
    const scheduler = createRefreshScheduler({ refresh, isBusy: () => false });
    scheduler.notify();
    scheduler.dispose();
    vi.advanceTimersByTime(10_000);
    expect(refresh).not.toHaveBeenCalled();
  });
});

/**
 * The hook against a real query client: a probe query refetched by events. Bursts coalesce,
 * and an event that lands while the probe is mid-fetch neither cancels nor restarts it.
 */
describe("useEventRefresh", () => {
  let handler: ((payload: PamEventPayload) => void) | undefined;
  let client: QueryClient;

  beforeEach(() => {
    handler = undefined;
    mockSubscribe.mockImplementation((h) => {
      handler = h;
      return Promise.resolve(() => {});
    });
    client = new QueryClient({
      defaultOptions: { queries: { retry: false, staleTime: 60_000 } },
    });
  });

  afterEach(() => client.clear());

  const done: PamEventPayload = { ticket: "t", event: { kind: "done" } };

  function Probe({ queryFn }: { queryFn: (signal: AbortSignal) => Promise<string> }) {
    useQuery({ queryKey: ["probe"], queryFn: ({ signal }) => queryFn(signal) });
    useEventRefresh([["probe"]]);
    return null;
  }

  function mount(queryFn: (signal: AbortSignal) => Promise<string>): ReactNode {
    return (
      <QueryClientProvider client={client}>
        <Probe queryFn={queryFn} />
      </QueryClientProvider>
    );
  }

  async function settle(ms: number) {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(ms);
    });
  }

  it("N events in a burst cause at most one refetch", async () => {
    const queryFn = vi.fn().mockResolvedValue("ok");
    render(mount(queryFn));
    await settle(0);
    expect(queryFn).toHaveBeenCalledTimes(1);

    act(() => {
      for (let index = 0; index < 200; index += 1) handler?.(done);
    });
    await settle(EVENT_SETTLE_MS + 1);
    expect(queryFn).toHaveBeenCalledTimes(2);
    await settle(30_000);
    expect(queryFn).toHaveBeenCalledTimes(2);
  });

  it("an event during an in-flight fetch does not cancel or restart it", async () => {
    let release: (value: string) => void = () => {};
    const signals: AbortSignal[] = [];
    const queryFn = vi.fn((signal: AbortSignal) => {
      signals.push(signal);
      if (queryFn.mock.calls.length === 1) return Promise.resolve("first");
      return new Promise<string>((resolve) => {
        release = resolve;
      });
    });
    render(mount(queryFn));
    await settle(0);
    expect(queryFn).toHaveBeenCalledTimes(1);

    // The first refetch starts and hangs.
    act(() => handler?.(done));
    await settle(EVENT_SETTLE_MS + 1);
    expect(queryFn).toHaveBeenCalledTimes(2);

    // Events keep arriving while it is in flight: nothing new starts, nothing is aborted.
    for (let index = 0; index < 5; index += 1) {
      act(() => handler?.(done));
      await settle(EVENT_REFRESH_MIN_MS);
    }
    expect(queryFn).toHaveBeenCalledTimes(2);
    expect(signals[1]?.aborted).toBe(false);

    // Once it settles, the events that arrived meanwhile earn exactly one more refetch.
    release("second");
    await settle(0);
    await settle(EVENT_SETTLE_MS + 1);
    expect(queryFn).toHaveBeenCalledTimes(3);
    expect(signals[1]?.aborted).toBe(false);
  });

  it("treats a resync, a lagged stream's reconnect, as one refresh however many arrive", async () => {
    const queryFn = vi.fn().mockResolvedValue("ok");
    render(mount(queryFn));
    await settle(0);
    expect(queryFn).toHaveBeenCalledTimes(1);

    // The pump says "events may have been missed" after a reconnect and again at a counter skip;
    // together with the events around them they are still a single refetch.
    const resync: PamEventPayload = { ticket: "", event: { kind: "resync" } };
    act(() => {
      handler?.(resync);
      handler?.(resync);
      handler?.({ ticket: "t", event: { kind: "started" }, n: 41, ingress: "public" });
    });
    await settle(EVENT_SETTLE_MS + 1);
    expect(queryFn).toHaveBeenCalledTimes(2);
    await settle(30_000);
    expect(queryFn).toHaveBeenCalledTimes(2);
  });

  it("ignores progress notes, which stream by the dozen during a run", async () => {
    const queryFn = vi.fn().mockResolvedValue("ok");
    render(mount(queryFn));
    await settle(0);
    act(() => {
      for (let index = 0; index < 50; index += 1)
        handler?.({ ticket: "t", event: { kind: "progress", note: "step" } });
    });
    await settle(10_000);
    expect(queryFn).toHaveBeenCalledTimes(1);
  });
});
