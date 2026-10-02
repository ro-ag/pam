import { describe, expect, it } from "vitest";
import {
  POLL_BACKOFF_MAX_MS,
  backoffMs,
  backoffRefetchInterval,
  isBusyRefusal,
} from "./polling";

/** A react-query query reduced to the fields the interval reads. */
function query<T>(state: {
  status: "pending" | "error" | "success";
  data?: T;
  dataUpdatedAt?: number;
  errorUpdatedAt?: number;
}) {
  return {
    state: {
      status: state.status,
      data: state.data,
      dataUpdatedAt: state.dataUpdatedAt ?? 0,
      errorUpdatedAt: state.errorUpdatedAt ?? 0,
    },
  };
}

describe("backoffMs", () => {
  it("keeps the base for the first failure, then doubles up to the cap", () => {
    expect(backoffMs(5_000, 0)).toBe(5_000);
    expect(backoffMs(5_000, 1)).toBe(5_000);
    expect(backoffMs(5_000, 2)).toBe(10_000);
    expect(backoffMs(5_000, 3)).toBe(20_000);
    expect(backoffMs(5_000, 4)).toBe(40_000);
    expect(backoffMs(5_000, 5)).toBe(POLL_BACKOFF_MAX_MS);
    expect(backoffMs(5_000, 50)).toBe(POLL_BACKOFF_MAX_MS);
  });
});

describe("isBusyRefusal", () => {
  it("recognises the daemon being busy or restarting, and nothing else", () => {
    for (const cause of [
      "request_capacity_exhausted",
      "request_rate_exhausted",
      "daemon_shutting_down",
      "reply_timeout",
    ]) {
      expect(isBusyRefusal({ cause, detail: "d", recovery: "r" })).toBe(true);
    }
    expect(isBusyRefusal({ cause: "not_granted", detail: "d", recovery: "r" })).toBe(false);
    expect(isBusyRefusal(new Error("boom"))).toBe(false);
    expect(isBusyRefusal(null)).toBe(false);
  });
});

describe("backoffRefetchInterval", () => {
  it("backs off per consecutive rejected poll and snaps back on success", () => {
    const interval = backoffRefetchInterval<string>({ baseMs: 5_000 });
    const q = query<string>({ status: "pending" });
    expect(interval(q)).toBe(5_000);

    // Poll 1 fails, poll 2 fails, poll 3 fails: 5 s, 10 s, 20 s.
    q.state = { ...q.state, status: "error", errorUpdatedAt: 1 };
    expect(interval(q)).toBe(5_000);
    q.state = { ...q.state, errorUpdatedAt: 2 };
    expect(interval(q)).toBe(10_000);
    q.state = { ...q.state, errorUpdatedAt: 3 };
    expect(interval(q)).toBe(20_000);
    // Asking twice about the same settled poll does not count it twice.
    expect(interval(q)).toBe(20_000);

    // One good answer resets the cadence.
    q.state = { ...q.state, status: "success", data: "ok", dataUpdatedAt: 4 };
    expect(interval(q)).toBe(5_000);
  });

  it("treats a resolved-but-unhealthy answer as a failure when told to", () => {
    const interval = backoffRefetchInterval<{ connected: boolean }>({
      baseMs: 5_000,
      failed: (reply) => !reply.connected,
    });
    const q = query<{ connected: boolean }>({
      status: "success",
      data: { connected: false },
      dataUpdatedAt: 1,
    });
    expect(interval(q)).toBe(5_000);
    q.state = { ...q.state, dataUpdatedAt: 2 };
    expect(interval(q)).toBe(10_000);
    q.state = { ...q.state, data: { connected: true }, dataUpdatedAt: 3 };
    expect(interval(q)).toBe(5_000);
  });

  it("lets the base follow the data (a busy download polls faster)", () => {
    const interval = backoffRefetchInterval<"busy" | "idle">({
      baseMs: (data) => (data === "busy" ? 2_000 : 10_000),
    });
    expect(interval(query({ status: "success", data: "busy", dataUpdatedAt: 1 }))).toBe(2_000);
    expect(interval(query({ status: "success", data: "idle", dataUpdatedAt: 1 }))).toBe(10_000);
  });
});
