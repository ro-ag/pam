import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { approvalsPending, daemonStatus, subscribeEvents } from "../../lib/ipc";
import type { BeaconState } from "./Beacon";

/** How often the beacon re-asks the daemon for its health. */
export const STATUS_POLL_MS = 5_000;

/** Missed polls a connected beacon tolerates before it reads as offline. */
export const OFFLINE_AFTER_MISSES = 2;

/** The query keys the beacon shares with Home and Settings, so one poll serves all three. */
export const DAEMON_STATUS_KEY = ["daemon", "status"] as const;
export const APPROVALS_PENDING_KEY = ["approvals", "pending"] as const;

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
 * terminal event invalidates both queries so the beacon turns amber (and
 * back) without waiting out the interval.
 */
export function useDaemonStatus(): BeaconState {
  const queryClient = useQueryClient();
  const status = useQuery({
    queryKey: DAEMON_STATUS_KEY,
    queryFn: daemonStatus,
    refetchInterval: STATUS_POLL_MS,
    retry: false,
  });
  const connected = status.data?.connected === true;
  const pending = useQuery({
    queryKey: APPROVALS_PENDING_KEY,
    queryFn: approvalsPending,
    refetchInterval: STATUS_POLL_MS,
    retry: false,
    enabled: connected,
  });

  // Consecutive misses (a rejected poll or a `connected: false` reply),
  // counted once per settled poll rather than once per render.
  const misses = useRef(0);
  const settledAt = Math.max(status.dataUpdatedAt, status.errorUpdatedAt);
  const lastCounted = useRef(0);
  if (settledAt !== lastCounted.current) {
    lastCounted.current = settledAt;
    misses.current = connected ? 0 : misses.current + 1;
  }
  // The last state the beacon showed while the daemon answered.
  const lastGood = useRef<BeaconState | null>(null);

  useEffect(() => {
    let cancelled = false;
    let unlisten: (() => void) | undefined;
    subscribeEvents((payload) => {
      // Approval raised or resolved (terminal events resolve waits):
      // reflect it now instead of on the next tick.
      if (payload.event.kind === "progress") return;
      void queryClient.invalidateQueries({ queryKey: DAEMON_STATUS_KEY });
      void queryClient.invalidateQueries({ queryKey: APPROVALS_PENDING_KEY });
    })
      .then((stop) => {
        if (cancelled) stop();
        else unlisten = stop;
      })
      .catch(() => {
        // No bridge (browser dev) or no stream yet; polling covers it.
      });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [queryClient]);

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
