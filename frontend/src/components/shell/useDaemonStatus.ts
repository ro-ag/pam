import { useQuery } from "@tanstack/react-query";
import { useRef } from "react";
import { approvalsPending, daemonStatus, type PamEventPayload } from "../../lib/ipc";
import { backoffRefetchInterval, isBusyRefusal } from "../../lib/polling";
import { useEventRefresh } from "../../lib/useEventRefresh";
import type { BeaconState } from "./Beacon";

/** How often the beacon re-asks the daemon for its health. */
export const STATUS_POLL_MS = 5_000;

/** Missed polls a connected beacon tolerates before it reads as offline. */
export const OFFLINE_AFTER_MISSES = 2;

/** The query keys the beacon shares with Home and Settings, so one poll serves all three. */
export const DAEMON_STATUS_KEY = ["daemon", "status"] as const;
export const APPROVALS_PENDING_KEY = ["approvals", "pending"] as const;

/**
 * The shared poll intervals: every observer of these queries (the beacon, Home, Settings)
 * passes the **same** function, so they agree on one cadence, and the cadence backs off —
 * doubling per failed poll up to a minute — while the daemon is unreachable, refusing
 * (`request_capacity_exhausted`, rate, `shutting_down`) or reports `connected: false`,
 * instead of asking a struggling daemon every five seconds.
 */
export const statusRefetchInterval = backoffRefetchInterval<{ connected: boolean }>({
  baseMs: STATUS_POLL_MS,
  failed: (reply) => !reply.connected,
});
export const approvalsRefetchInterval = backoffRefetchInterval<unknown>({
  baseMs: STATUS_POLL_MS,
});

/**
 * Which daemon events can change what the beacon shows: an approval raised, or a request
 * ending (terminal events resolve waits), or a `resync` (the stream reconnected or skipped, so
 * an approval may have been missed). `queued`/`started`/`progress` change neither the pending
 * count nor liveness, and ignoring them is what keeps a burst of agent traffic from becoming a
 * burst of admin polls.
 */
export function isBeaconEvent(payload: PamEventPayload): boolean {
  const kind = payload.event.kind;
  return (
    kind === "approval_pending" || kind === "done" || kind === "refused" || kind === "resync"
  );
}

/**
 * Daemon liveness for the beacon, wired to the real IPC bridge through the
 * same react-query keys Home and Settings › Daemon read, so the three
 * never race three separate 5 s pollers: green when `daemon_status`
 * answers connected (the call also lazily starts the daemon); amber when
 * connected **and** approvals are waiting; red when the daemon is
 * unreachable — including plain-browser dev and jsdom, where every bridge
 * call rejects with `BridgeUnavailable`.
 *
 * Before the first answer the beacon says "connecting" rather than
 * guessing. A daemon busy with a long request can miss one poll; a
 * beacon that was green stays green for one miss and turns red on the
 * second, so a slow answer does not flash "Offline" every time.
 *
 * The daemon event stream adds liveness — an `approval_pending` or
 * terminal event refreshes the pending approvals so the beacon turns amber
 * (and back) without waiting out the interval. Events are only hints: they
 * go through the shared trailing throttle (`useEventRefresh`), so a burst
 * costs at most one refetch per ~1.5 s, an in-flight poll is never
 * cancelled, and the daemon's own lifecycle events for a status poll can
 * never make the next poll. The status query itself is **not** event
 * driven; the interval (which backs off while the daemon refuses or is
 * unreachable) is its only trigger.
 *
 * A daemon that answers "busy" (`request_capacity_exhausted` and friends)
 * is alive: that reply is neither a hit nor a miss, so it never turns the
 * beacon red.
 */
export function useDaemonStatus(): BeaconState {
  const status = useQuery({
    queryKey: DAEMON_STATUS_KEY,
    queryFn: daemonStatus,
    refetchInterval: statusRefetchInterval,
    retry: false,
  });
  const connected = status.data?.connected === true;
  const pending = useQuery({
    queryKey: APPROVALS_PENDING_KEY,
    queryFn: approvalsPending,
    refetchInterval: approvalsRefetchInterval,
    retry: false,
    enabled: connected,
  });
  useEventRefresh([APPROVALS_PENDING_KEY], isBeaconEvent);

  // Consecutive misses (a rejected poll or a `connected: false` reply),
  // counted once per settled poll rather than once per render. A busy
  // refusal proves the daemon is there and is not counted.
  const misses = useRef(0);
  const settledAt = Math.max(status.dataUpdatedAt, status.errorUpdatedAt);
  const lastCounted = useRef(0);
  if (settledAt !== lastCounted.current) {
    lastCounted.current = settledAt;
    const busy = status.isError && isBusyRefusal(status.error);
    if (connected) misses.current = 0;
    else if (!busy) misses.current += 1;
  }
  // The last state the beacon showed while the daemon answered.
  const lastGood = useRef<BeaconState | null>(null);

  if (settledAt === 0) return "connecting";
  if (connected) {
    // The pending count is best-effort: a failed read keeps green.
    const next: BeaconState = (pending.data?.pending.length ?? 0) > 0 ? "pending" : "connected";
    lastGood.current = next;
    return next;
  }
  if (lastGood.current !== null && misses.current < OFFLINE_AFTER_MISSES)
    return lastGood.current;
  lastGood.current = null;
  return "down";
}
