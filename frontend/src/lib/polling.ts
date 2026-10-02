/**
 * Polling that backs off instead of hammering.
 *
 * Every poller in the GUI shares the daemon's public control budget with the agents it
 * watches. A daemon that answers `request_capacity_exhausted`, is rate limited, is draining
 * (`daemon_shutting_down`) or restarting, or is simply unreachable is not helped by being asked
 * again every five seconds: the interval doubles per consecutive failure up to a cap, and snaps
 * back to the base the moment one poll succeeds.
 */

/** The longest a failing poller waits between asks. */
export const POLL_BACKOFF_MAX_MS = 60_000;

/** Failure causes that mean "busy or restarting", not "broken": the daemon is alive. */
const BUSY_CAUSES: readonly string[] = [
  "request_capacity_exhausted",
  "request_rate_exhausted",
  "daemon_shutting_down",
  "daemon_outdated",
  "deadline_exceeded",
  "reply_timeout",
];

/** True when `error` is the daemon saying it is momentarily busy or restarting. */
export function isBusyRefusal(error: unknown): boolean {
  if (typeof error !== "object" || error === null || !("cause" in error)) return false;
  const cause = (error as { cause: unknown }).cause;
  return typeof cause === "string" && BUSY_CAUSES.includes(cause);
}

/**
 * The wait before the next poll after `failures` consecutive failures: the base for the
 * first, then doubling, never past `maxMs`.
 */
export function backoffMs(
  baseMs: number,
  failures: number,
  maxMs = POLL_BACKOFF_MAX_MS,
): number {
  if (failures <= 1) return baseMs;
  return Math.min(maxMs, baseMs * 2 ** (failures - 1));
}

/** The slice of a react-query `Query` the interval needs (structural, so any query fits). */
interface QueryLike<TData> {
  state: {
    status: "pending" | "error" | "success";
    data: TData | undefined;
    dataUpdatedAt: number;
    errorUpdatedAt: number;
  };
}

/**
 * A `refetchInterval` that backs off while the query keeps failing.
 *
 * A poll fails when it rejects, or resolves with data `failed` calls a failure (the status
 * call answers `connected: false` rather than rejecting). Consecutive failures are counted per
 * query, once per settled poll, so any number of observers sharing one query agree on the
 * interval when they share one function. `baseMs` may depend on the last data (Models polls
 * faster while a download runs).
 */
export function backoffRefetchInterval<TData>(options: {
  baseMs: number | ((data: TData | undefined) => number);
  maxMs?: number;
  failed?: (data: TData) => boolean;
}): (query: QueryLike<TData>) => number {
  const seen = new WeakMap<object, { stamp: number; failures: number }>();
  return (query) => {
    const { status, data, dataUpdatedAt, errorUpdatedAt } = query.state;
    const stamp = Math.max(dataUpdatedAt, errorUpdatedAt);
    let record = seen.get(query) ?? { stamp: 0, failures: 0 };
    if (stamp !== record.stamp) {
      const failed =
        status === "error" || (data !== undefined && (options.failed?.(data) ?? false));
      record = { stamp, failures: failed ? record.failures + 1 : 0 };
      seen.set(query, record);
    }
    const base = typeof options.baseMs === "function" ? options.baseMs(data) : options.baseMs;
    return backoffMs(base, record.failures, options.maxMs);
  };
}
