import { useQueryClient, type QueryKey } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { subscribeEvents, type PamEventPayload } from "./ipc";

/**
 * Events are hints, never triggers.
 *
 * The daemon publishes lifecycle events for every request, and a screen that refetched on
 * every event could feed itself: its own refetch causes events, which cause the next refetch.
 * Every event-driven refresh in the GUI therefore goes through one trailing throttle:
 *
 * - a burst of events marks the data stale **once** and yields at most one refetch;
 * - refetches are at least `EVENT_REFRESH_MIN_MS` apart, however many events arrive;
 * - a refetch already in flight is never cancelled or restarted — the scheduler waits for it
 *   to settle and then refreshes once more if events arrived meanwhile.
 */

/** Fewest milliseconds between two event-driven refetches of the same screen. */
export const EVENT_REFRESH_MIN_MS = 1_500;

/** How long a burst is allowed to settle before its single refetch. */
export const EVENT_SETTLE_MS = 250;

export interface RefreshScheduler {
  /** An event arrived: the data is stale. */
  notify: () => void;
  /** Drops any pending refetch (unmount). */
  dispose: () => void;
}

/**
 * The scheduling rule, free of React and react-query so it can be tested on a fake clock.
 * `refresh` starts the refetch; `isBusy` says whether one is still in flight.
 */
export function createRefreshScheduler(options: {
  refresh: () => void;
  isBusy: () => boolean;
  minIntervalMs?: number;
  settleMs?: number;
  now?: () => number;
}): RefreshScheduler {
  const minIntervalMs = options.minIntervalMs ?? EVENT_REFRESH_MIN_MS;
  const settleMs = options.settleMs ?? EVENT_SETTLE_MS;
  const now = options.now ?? Date.now;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let dirty = false;
  let lastRefresh = Number.NEGATIVE_INFINITY;

  const run = () => {
    timer = undefined;
    if (!dirty) return;
    if (options.isBusy()) {
      // Never cancel work in flight; look again shortly.
      timer = setTimeout(run, settleMs);
      return;
    }
    dirty = false;
    lastRefresh = now();
    options.refresh();
  };

  return {
    notify: () => {
      dirty = true;
      if (timer !== undefined) return;
      const wait = Math.max(settleMs, lastRefresh + minIntervalMs - now());
      timer = setTimeout(run, wait);
    },
    dispose: () => {
      dirty = false;
      if (timer !== undefined) clearTimeout(timer);
      timer = undefined;
    },
  };
}

/** The events worth a refresh by default: everything but streaming progress notes. */
export function isRefreshEvent(payload: PamEventPayload): boolean {
  return payload.event.kind !== "progress";
}

/**
 * Subscribes to the daemon event stream and refreshes the queries under `keys` through the
 * shared throttle ([`createRefreshScheduler`]). `accept` narrows which events count; the
 * default ignores `progress`.
 */
export function useEventRefresh(
  keys: readonly QueryKey[],
  accept: (payload: PamEventPayload) => boolean = isRefreshEvent,
): void {
  const queryClient = useQueryClient();
  const latest = useRef({ keys, accept });
  useEffect(() => {
    latest.current = { keys, accept };
  });

  useEffect(() => {
    const scheduler = createRefreshScheduler({
      isBusy: () =>
        latest.current.keys.some((queryKey) => queryClient.isFetching({ queryKey }) > 0),
      refresh: () => {
        for (const queryKey of latest.current.keys) {
          // `cancelRefetch: false`: a fetch in flight is joined, never aborted and restarted.
          void queryClient.invalidateQueries({ queryKey }, { cancelRefetch: false });
        }
      },
    });
    let cancelled = false;
    let unlisten: (() => void) | undefined;
    subscribeEvents((payload) => {
      if (latest.current.accept(payload)) scheduler.notify();
    })
      .then((stop) => {
        if (cancelled) stop();
        else unlisten = stop;
      })
      .catch(() => {
        // No bridge (browser dev) or no stream yet: the polling intervals cover it.
      });
    return () => {
      cancelled = true;
      scheduler.dispose();
      unlisten?.();
    };
  }, [queryClient]);
}
